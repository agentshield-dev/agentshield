package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// clickHouseIdentifier restricts database and table names because they are
// interpolated into the INSERT query rather than bound as parameters.
var clickHouseIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ClickHouseConfig configures a ClickHouseSink. Password is sent as HTTP basic
// auth; use HTTPS when the endpoint is not local.
type ClickHouseConfig struct {
	Endpoint string
	Database string
	Table    string
	Username string
	Password string
	Client   *http.Client
}

// ClickHouseSink inserts batches over the ClickHouse HTTP interface as gzip
// JSONEachRow. The target table is expected to be the ReplacingMergeTree from
// deploy/clickhouse/schema.sql, whose ordering key includes the observation
// date, plugin_id, source_id, and event_id, so events resent in later batches
// collapse on merge. Each insert carries a deterministic
// insert_deduplication_token, so a retried batch is not inserted, or counted
// by the minute rollup view, twice.
type ClickHouseSink struct {
	config ClickHouseConfig
}

// NewClickHouseSink validates config. A nil Client gets a 30-second timeout.
func NewClickHouseSink(config ClickHouseConfig) (*ClickHouseSink, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" {
		return nil, errors.New("ClickHouse endpoint must be an HTTP(S) URL")
	}
	if !clickHouseIdentifier.MatchString(config.Database) || !clickHouseIdentifier.MatchString(config.Table) {
		return nil, errors.New("ClickHouse database and table must be identifiers")
	}
	if config.Client == nil {
		config.Client = &http.Client{Timeout: 30 * time.Second}
	}
	config.Endpoint = endpoint.String()
	return &ClickHouseSink{config: config}, nil
}

// WriteBatch inserts events in one request. A non-2xx response returns an
// error including up to 4 KiB of the ClickHouse response body; that body is
// left out when the error is logged through log/slog.
func (sink *ClickHouseSink) WriteBatch(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	encoder := json.NewEncoder(writer)
	for _, event := range events {
		row := clickHouseRow{
			EventID: event.EventID, ObservedAt: event.ObservedAt, Kind: event.Kind, PluginID: event.PluginID,
			SubjectSchemeGroup: event.Subject.Scheme.Group, SubjectSchemeVersion: event.Subject.Scheme.Version, SubjectSchemeKind: event.Subject.Scheme.Kind,
			SubjectAuthority: event.Subject.AuthorityID, SubjectKey: event.Subject.ImmutableKey,
			ObjectSchemeGroup: event.Object.Scheme.Group, ObjectSchemeVersion: event.Object.Scheme.Version, ObjectSchemeKind: event.Object.Scheme.Kind,
			ObjectAuthority: event.Object.AuthorityID, ObjectKey: event.Object.ImmutableKey,
			Operation: event.Operation, Outcome: event.Outcome, Coverage: event.Coverage, Count: event.Count,
			Properties: event.Properties, SourceID: event.SourceID, EvidenceIDs: event.EvidenceIDs,
		}
		if err := encoder.Encode(row); err != nil {
			_ = writer.Close()
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	endpoint, _ := url.Parse(sink.config.Endpoint)
	query := endpoint.Query()
	query.Set("database", sink.config.Database)
	query.Set("query", fmt.Sprintf("INSERT INTO %s FORMAT JSONEachRow", sink.config.Table))
	query.Set("insert_deduplication_token", deduplicationToken(events))
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), &compressed)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-ndjson")
	request.Header.Set("Content-Encoding", "gzip")
	if sink.config.Username != "" {
		request.SetBasicAuth(sink.config.Username, sink.config.Password)
	}
	response, err := sink.config.Client.Do(request)
	if err != nil {
		return fmt.Errorf("write ClickHouse telemetry: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return &clickHouseStatusError{
			statusCode: response.StatusCode, exceptionCode: response.Header.Get("X-ClickHouse-Exception-Code"),
			body: strings.TrimSpace(string(message)),
		}
	}
	return nil
}

// deduplicationToken derives the insert_deduplication_token from the
// batch's ordered event identities. The pipeline retries a failed batch
// unchanged, so a retry of an insert that ClickHouse already committed
// carries the same token and is skipped, together with the summing
// materialized view insert that would double count it.
func deduplicationToken(events []Event) string {
	digest := sha256.New()
	for _, event := range events {
		_, _ = io.WriteString(digest, event.PluginID+"\x00"+event.SourceID+"\x00"+event.EventID+"\n")
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// clickHouseStatusError is a non-2xx ClickHouse response. ClickHouse parse
// errors can quote the rejected row, including telemetry properties, so the
// slog form omits the body.
type clickHouseStatusError struct {
	statusCode    int
	exceptionCode string
	body          string
}

func (err *clickHouseStatusError) Error() string {
	return fmt.Sprintf("write ClickHouse telemetry: status %d: %s", err.statusCode, err.body)
}

func (err *clickHouseStatusError) LogValue() slog.Value {
	if err.exceptionCode == "" {
		return slog.StringValue(fmt.Sprintf("write ClickHouse telemetry: status %d", err.statusCode))
	}
	return slog.StringValue(fmt.Sprintf("write ClickHouse telemetry: status %d, exception code %s", err.statusCode, err.exceptionCode))
}

type clickHouseRow struct {
	EventID              string            `json:"event_id"`
	ObservedAt           time.Time         `json:"observed_at"`
	Kind                 string            `json:"kind"`
	PluginID             string            `json:"plugin_id"`
	SubjectSchemeGroup   string            `json:"subject_scheme_group"`
	SubjectSchemeVersion string            `json:"subject_scheme_version"`
	SubjectSchemeKind    string            `json:"subject_scheme_kind"`
	SubjectAuthority     string            `json:"subject_authority"`
	SubjectKey           string            `json:"subject_key"`
	ObjectSchemeGroup    string            `json:"object_scheme_group"`
	ObjectSchemeVersion  string            `json:"object_scheme_version"`
	ObjectSchemeKind     string            `json:"object_scheme_kind"`
	ObjectAuthority      string            `json:"object_authority"`
	ObjectKey            string            `json:"object_key"`
	Operation            string            `json:"operation"`
	Outcome              string            `json:"outcome"`
	Coverage             string            `json:"coverage"`
	Count                uint64            `json:"count"`
	Properties           map[string]string `json:"properties"`
	SourceID             string            `json:"source_id"`
	EvidenceIDs          []string          `json:"evidence_ids"`
}
