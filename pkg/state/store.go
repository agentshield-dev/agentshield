package state

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// ErrNotMaterialized is returned by graph reads before any contribution has
// been published.
var ErrNotMaterialized = errors.New("graph is not materialized")

// ErrGraphEntityNotFound is returned by current-projection detail reads.
var ErrGraphEntityNotFound = errors.New("graph entity not found")

// Source health values accepted on a Contribution. They describe the upstream
// source, independently of contribution readiness.
const (
	SourceHealthHealthy  = "healthy"
	SourceHealthDegraded = "degraded"
	SourceHealthStale    = "stale"
	SourceHealthUnknown  = "unknown"
)

// PostgreSQL advisory lock keys. Each is an arbitrary fixed 64-bit value
// spelling an ASCII tag so it is recognizable in pg_locks.
const (
	// migrationLockKey ("AgentShi") serializes schema migration across
	// processes starting concurrently against one database.
	migrationLockKey int64 = 0x4167656e74536869
)

//go:embed migrations/*.sql
var migrations embed.FS

// Config configures the PostgreSQL store. Zero values select defaults.
type Config struct {
	DatabaseURL     string
	MaxConnections  int32
	MinConnections  int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	// UnresolvedRetention sets expires_at on projected unresolved
	// relationships. It is recorded for consumers but not enforced: an
	// unresolved edge leaves the projection only when its endpoints resolve
	// or its owning contribution omits it. Default 24h.
	UnresolvedRetention time.Duration
	// PublicationTimeout bounds one whole publication so a stuck publication
	// cannot hold a pooled connection indefinitely. It is also the transaction's
	// idle_in_transaction_session_timeout. Default 5m.
	PublicationTimeout time.Duration
	// PublicationLockTimeout is the publication transaction's lock_timeout.
	// Default 2m.
	PublicationLockTimeout time.Duration
	// PublicationStatementTimeout is the publication transaction's
	// statement_timeout. Default 2m.
	PublicationStatementTimeout time.Duration
	// MigrationTimeout bounds schema migration in Open. Migration does not
	// inherit the caller's deadline, because a migration that rebuilds a
	// constraint on a large table can outlast a short startup budget and
	// would then fail every start. Default 30m.
	MigrationTimeout time.Duration
	// InvestigationMaxAttempts fails an investigation job instead of
	// reclaiming it once an expired lease would bring its attempt count to
	// this value. An expired lease counts as a failed attempt, so a job that
	// crashes its worker cannot be re-leased forever. Default 5, matching the
	// investigation worker's default.
	InvestigationMaxAttempts int
}

func (config Config) withDefaults() Config {
	if config.MaxConnections == 0 {
		config.MaxConnections = 20
	}
	if config.MinConnections == 0 {
		config.MinConnections = 2
	}
	if config.MaxConnLifetime == 0 {
		config.MaxConnLifetime = time.Hour
	}
	if config.MaxConnIdleTime == 0 {
		config.MaxConnIdleTime = 15 * time.Minute
	}
	if config.UnresolvedRetention == 0 {
		config.UnresolvedRetention = 24 * time.Hour
	}
	if config.PublicationTimeout == 0 {
		config.PublicationTimeout = 5 * time.Minute
	}
	if config.PublicationLockTimeout == 0 {
		config.PublicationLockTimeout = 2 * time.Minute
	}
	if config.PublicationStatementTimeout == 0 {
		config.PublicationStatementTimeout = 2 * time.Minute
	}
	if config.MigrationTimeout == 0 {
		config.MigrationTimeout = 30 * time.Minute
	}
	if config.InvestigationMaxAttempts == 0 {
		config.InvestigationMaxAttempts = 5
	}
	return config
}

func (config Config) validate() error {
	if strings.TrimSpace(config.DatabaseURL) == "" {
		return errors.New("PostgreSQL database URL is required")
	}
	if config.MaxConnections < 1 {
		return errors.New("PostgreSQL max connections must be positive")
	}
	if config.MinConnections < 0 || config.MinConnections > config.MaxConnections {
		return errors.New("PostgreSQL min connections must be between zero and max connections")
	}
	if config.PublicationTimeout < time.Millisecond || config.PublicationLockTimeout < time.Millisecond ||
		config.PublicationStatementTimeout < time.Millisecond || config.MigrationTimeout < time.Millisecond {
		return errors.New("PostgreSQL publication and migration timeouts must be at least one millisecond")
	}
	if config.InvestigationMaxAttempts < 1 {
		return errors.New("investigation max attempts must be positive")
	}
	return nil
}

// Contribution is the complete assertion set owned by one plugin, source, and
// name. Advancing its generation replaces membership and retracts omissions.
type Contribution struct {
	PluginID   string      `json:"pluginId"`
	SourceID   string      `json:"sourceId"`
	Name       string      `json:"name"`
	Generation uint64      `json:"generation"`
	Input      graph.Input `json:"input"`
	// SourceObservedAt is when the source state behind Input was observed.
	// Zero defaults to the publication time.
	SourceObservedAt time.Time `json:"sourceObservedAt"`
	// Ready reports that Input reflects a coherent source view. It is
	// independent of collection readiness and of SourceHealth.
	Ready bool `json:"ready"`
	// SourceHealth is one of the SourceHealth constants; empty means healthy.
	SourceHealth string `json:"sourceHealth"`
	// Retired marks a terminal empty generation; see RetireContribution.
	Retired bool `json:"retired,omitempty"`
	// UpdatedAt is set by the store at publication time.
	UpdatedAt time.Time `json:"updatedAt"`
}

// GraphView is a compiled canonical graph with its SHA-256 digest.
// GeneratedAt is the most recent contribution head update.
type GraphView struct {
	GeneratedAt time.Time      `json:"generatedAt"`
	SHA256      string         `json:"sha256"`
	Snapshot    graph.Snapshot `json:"snapshot"`
}

// NativeEvent is one provider observation delivered through the discovery hub.
// PostgreSQL retains its metadata and content digest, not Payload. EventID must
// be stable: re-recording an ID with the same content is a no-op and with
// different content is an error.
type NativeEvent struct {
	EventID    string          `json:"eventId"`
	PluginID   string          `json:"pluginId"`
	SourceID   string          `json:"sourceId"`
	Collection string          `json:"collection"`
	Key        string          `json:"key"`
	Revision   string          `json:"revision,omitempty"`
	Operation  string          `json:"operation"`
	ObservedAt time.Time       `json:"observedAt"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

// Neighborhood is a bounded subgraph around one resource.
type Neighborhood struct {
	SHA256        string               `json:"sha256"`
	Resources     []graph.Resource     `json:"resources"`
	Relationships []graph.Relationship `json:"relationships"`
}

// Store is the PostgreSQL-backed graph and reasoning store. It is safe for
// concurrent use.
type Store struct {
	pool                *pgxpool.Pool
	compiler            *graph.Compiler
	unresolvedRetention time.Duration
	publication         publicationLimits
	materializerMu      sync.Mutex
	materialized        *materializedGraph
	// investigationMaxAttempts bounds expired-lease reclaims; see
	// Config.InvestigationMaxAttempts.
	investigationMaxAttempts int
}

// publicationLimits bounds one publication transaction; see the Publication
// fields of Config.
type publicationLimits struct {
	timeout          time.Duration
	lockTimeout      time.Duration
	statementTimeout time.Duration
}

// Open connects to PostgreSQL and applies pending embedded migrations. The
// compiler must be built from a registry containing every identity scheme
// that stored assertions use, because startup may rebuild the materialized view.
func Open(ctx context.Context, config Config, compiler *graph.Compiler) (*Store, error) {
	if compiler == nil {
		return nil, errors.New("graph compiler is required")
	}
	config = config.withDefaults()
	if err := config.validate(); err != nil {
		return nil, err
	}
	poolConfig, err := pgxpool.ParseConfig(config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL configuration: %w", err)
	}
	poolConfig.MaxConns = config.MaxConnections
	poolConfig.MinConns = config.MinConnections
	poolConfig.MaxConnLifetime = config.MaxConnLifetime
	poolConfig.MaxConnIdleTime = config.MaxConnIdleTime
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "agentshield"
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL pool: %w", err)
	}
	store := &Store{
		pool: pool, compiler: compiler,
		unresolvedRetention: config.UnresolvedRetention,
		publication: publicationLimits{
			timeout: config.PublicationTimeout, lockTimeout: config.PublicationLockTimeout, statementTimeout: config.PublicationStatementTimeout,
		},
		investigationMaxAttempts: config.InvestigationMaxAttempts,
	}
	if err := store.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	// Migration keeps the caller's values but not its deadline or
	// cancellation; see Config.MigrationTimeout.
	migrationContext, cancelMigration := context.WithTimeout(context.WithoutCancel(ctx), config.MigrationTimeout)
	defer cancelMigration()
	if err := store.migrate(migrationContext); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

// migrate applies embedded schema files in version order in one transaction.
// Applied files are checksum-verified. Changing a baseline requires an empty
// database while the project remains greenfield.
func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("lock schema migration: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version integer PRIMARY KEY,
			sha256 bytea NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("prepare schema migration ledger: %w", err)
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list schema migrations: %w", err)
	}
	slices.Sort(names)
	for _, name := range names {
		versionText, _, found := strings.Cut(strings.TrimPrefix(name, "migrations/"), "_")
		if !found {
			return fmt.Errorf("schema migration %q has no numeric version prefix", name)
		}
		version, err := strconv.Atoi(versionText)
		if err != nil || version < 1 {
			return fmt.Errorf("schema migration %q has invalid version %q", name, versionText)
		}
		schema, err := migrations.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read schema migration %03d: %w", version, err)
		}
		digest := sha256.Sum256(schema)
		var appliedDigest []byte
		err = tx.QueryRow(ctx, `SELECT sha256 FROM schema_migrations WHERE version=$1`, version).Scan(&appliedDigest)
		switch {
		case err == nil:
			if !equalBytes(appliedDigest, digest[:]) {
				return fmt.Errorf("schema migration %03d checksum does not match the applied migration", version)
			}
			continue
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return fmt.Errorf("read schema migration %03d: %w", version, err)
		}
		if _, err := tx.Exec(ctx, string(schema)); err != nil {
			return fmt.Errorf("apply schema migration %03d: %w", version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, sha256) VALUES ($1,$2)`, version, digest[:]); err != nil {
			return fmt.Errorf("record schema migration %03d: %w", version, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit schema migration: %w", err)
	}
	return nil
}

// Close closes the connection pool.
func (s *Store) Close() error {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
	return nil
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL store is closed")
	}
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping PostgreSQL: %w", err)
	}
	return nil
}

// ReplaceContribution publishes contribution as the complete current output of
// its (plugin, source, name) tuple. Replacement semantics: any assertion the
// tuple owned before and that is absent now is retracted, so a plugin removes
// a fact by omitting it, never by sending a delete. Assertions owned by other
// contributions are untouched even when they describe the same entities.
//
// Validation and compilation happen before the transaction so malformed input
// never enters the commit path. Assertion provenance must match the
// contribution owner; it is rejected, not rewritten.
//
// The returned view is the graph compiled and committed by this publication.
// An idempotent retry reads the latest committed view because it performs no
// compilation of its own.
func (s *Store) ReplaceContribution(ctx context.Context, contribution Contribution) (GraphView, error) {
	if err := validateContribution(contribution); err != nil {
		return GraphView{}, err
	}
	if contribution.Generation > math.MaxInt64 {
		return GraphView{}, errors.New("contribution generation exceeds PostgreSQL bigint range")
	}
	contribution.UpdatedAt = time.Now().UTC()
	if contribution.SourceObservedAt.IsZero() {
		contribution.SourceObservedAt = contribution.UpdatedAt
	} else {
		contribution.SourceObservedAt = contribution.SourceObservedAt.UTC()
	}
	if contribution.SourceHealth == "" {
		contribution.SourceHealth = SourceHealthHealthy
	}
	inputDigest, err := contributionInputDigest(contribution.Input)
	if err != nil {
		return GraphView{}, err
	}
	compiled, err := s.compiler.CompileContribution(contribution.Input)
	if err != nil {
		return GraphView{}, fmt.Errorf("compile contribution: %w", err)
	}
	publication, err := s.publishContribution(ctx, contribution, inputDigest, compiled)
	if err != nil {
		return GraphView{}, err
	}
	if publication.HasView {
		return publication.View, nil
	}
	view, err := s.Latest(ctx)
	if err != nil {
		slog.WarnContext(ctx, "read graph after committed contribution publication",
			"plugin", contribution.PluginID, "source", contribution.SourceID, "contribution", contribution.Name,
			"generation", contribution.Generation, "error", err)
		return GraphView{}, nil
	}
	return view, nil
}

// contributionInputDigest identifies the submitted input for same-generation
// retry detection.
//
// The encoding is deterministic: graph.Input contains only structs, strings,
// uint64 counts, string slices, and map[string]string, and encoding/json
// emits struct fields in declaration order and sorts map keys. There are no
// floats or interface values. The digest is order-sensitive, though: the same
// assertions in a different slice order, or with unsorted evidence IDs, hash
// differently. That is safe because a same-generation retry resubmits the
// same in-memory input (plugins recover the durable generation at startup and
// publish above it), and projectors must be deterministic. A mismatch fails
// closed as a generation conflict rather than publishing.
//
// Only the input is hashed. A same-generation retry that changes Ready,
// SourceHealth, or SourceObservedAt resolves to the existing version; publish
// a new generation to change source state.
func contributionInputDigest(input graph.Input) ([32]byte, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return [32]byte{}, fmt.Errorf("encode contribution input: %w", err)
	}
	return sha256.Sum256(encoded), nil
}

// RetireContribution publishes an empty terminal generation, retracting every
// active assertion of the tuple and marking its head retired. generation must
// be newer than the current one.
func (s *Store) RetireContribution(ctx context.Context, pluginID, sourceID, name string, generation uint64, observedAt time.Time) (GraphView, error) {
	return s.ReplaceContribution(ctx, Contribution{
		PluginID: pluginID, SourceID: sourceID, Name: name, Generation: generation,
		SourceObservedAt: observedAt, SourceHealth: SourceHealthUnknown, Retired: true,
	})
}

// RecordNative stores a provider observation idempotently by EventID. The
// content digest covers provenance, collection, key, revision, operation, and
// normalized payload but not ObservedAt, so a redelivery observed later is
// still the same event.
func (s *Store) RecordNative(ctx context.Context, event NativeEvent) error {
	if event.EventID == "" || event.PluginID == "" || event.SourceID == "" || event.Collection == "" || event.Key == "" || event.Operation == "" {
		return errors.New("native event requires identity, source, collection, key, and operation")
	}
	if event.ObservedAt.IsZero() {
		event.ObservedAt = time.Now().UTC()
	} else {
		event.ObservedAt = event.ObservedAt.UTC()
	}
	digest, err := nativeEventDigest(event)
	if err != nil {
		return err
	}
	command, err := s.pool.Exec(ctx, `
		INSERT INTO native_events (event_id, plugin_id, source_id, collection, object_key, source_revision, operation, observed_at, content_sha256)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (event_id) DO NOTHING`, event.EventID, event.PluginID, event.SourceID, event.Collection, event.Key, event.Revision, event.Operation, event.ObservedAt, digest[:])
	if err != nil {
		return fmt.Errorf("record native event: %w", err)
	}
	if command.RowsAffected() == 1 {
		return nil
	}
	var storedDigest []byte
	if err := s.pool.QueryRow(ctx, `SELECT content_sha256 FROM native_events WHERE event_id=$1`, event.EventID).Scan(&storedDigest); err != nil {
		return fmt.Errorf("read existing native event: %w", err)
	}
	if !equalBytes(storedDigest, digest[:]) {
		return fmt.Errorf("native event %q was reused with different content", event.EventID)
	}
	return nil
}

func nativeEventDigest(event NativeEvent) ([32]byte, error) {
	payload := event.Payload
	if len(payload) == 0 {
		payload = []byte("null")
	} else {
		var value any
		if err := json.Unmarshal(payload, &value); err != nil {
			return [32]byte{}, fmt.Errorf("decode native event payload: %w", err)
		}
		var err error
		payload, err = json.Marshal(value)
		if err != nil {
			return [32]byte{}, fmt.Errorf("normalize native event payload: %w", err)
		}
	}
	semantic := struct {
		PluginID   string
		SourceID   string
		Collection string
		Key        string
		Revision   string
		Operation  string
		Payload    json.RawMessage
	}{event.PluginID, event.SourceID, event.Collection, event.Key, event.Revision, event.Operation, payload}
	encoded, err := json.Marshal(semantic)
	if err != nil {
		return [32]byte{}, fmt.Errorf("encode native event identity: %w", err)
	}
	return sha256.Sum256(encoded), nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// ContributionGeneration returns the highest durable generation across all
// named contributions of (plugin, source), or zero. Plugins call it at startup
// and publish from the next value, which keeps generations monotonic across
// restarts without a per-process counter.
func (s *Store) ContributionGeneration(ctx context.Context, pluginID, sourceID string) (uint64, error) {
	if pluginID == "" || sourceID == "" {
		return 0, errors.New("contribution generation requires plugin and source IDs")
	}
	var generation int64
	if err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(max(h.generation), 0)
		FROM contributions c
		LEFT JOIN contribution_heads h ON h.contribution_id=c.contribution_id
		WHERE c.plugin_id=$1 AND c.source_id=$2`, pluginID, sourceID).Scan(&generation); err != nil {
		return 0, fmt.Errorf("load durable contribution generation: %w", err)
	}
	return uint64(generation), nil
}

func validateContribution(contribution Contribution) error {
	if contribution.PluginID == "" || contribution.SourceID == "" || contribution.Name == "" || contribution.Generation == 0 {
		return errors.New("contribution requires plugin ID, source ID, name, and positive generation")
	}
	switch contribution.SourceHealth {
	case "", SourceHealthHealthy, SourceHealthDegraded, SourceHealthStale, SourceHealthUnknown:
	default:
		return errors.New("contribution source health must be healthy, degraded, stale, or unknown")
	}
	for index, assertion := range contribution.Input.Resources {
		if assertion.PluginID != contribution.PluginID || assertion.SourceID != contribution.SourceID {
			return fmt.Errorf("resource assertion %d provenance %q/%q does not match contribution owner %q/%q", index, assertion.PluginID, assertion.SourceID, contribution.PluginID, contribution.SourceID)
		}
	}
	for index, assertion := range contribution.Input.Facets {
		if assertion.PluginID != contribution.PluginID || assertion.SourceID != contribution.SourceID {
			return fmt.Errorf("facet assertion %d provenance %q/%q does not match contribution owner %q/%q", index, assertion.PluginID, assertion.SourceID, contribution.PluginID, contribution.SourceID)
		}
	}
	for index, assertion := range contribution.Input.Relationships {
		if assertion.PluginID != contribution.PluginID || assertion.SourceID != contribution.SourceID {
			return fmt.Errorf("relationship assertion %d provenance %q/%q does not match contribution owner %q/%q", index, assertion.PluginID, assertion.SourceID, contribution.PluginID, contribution.SourceID)
		}
	}
	for index, assertion := range contribution.Input.Telemetry {
		if assertion.PluginID != contribution.PluginID || assertion.SourceID != contribution.SourceID {
			return fmt.Errorf("telemetry assertion %d provenance %q/%q does not match contribution owner %q/%q", index, assertion.PluginID, assertion.SourceID, contribution.PluginID, contribution.SourceID)
		}
	}
	return nil
}
