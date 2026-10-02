package telemetry

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Mapping registry errors. Both reject the record rather than guessing an owner.
var (
	ErrNoTelemetryMapper        = errors.New("no telemetry mapper matched the record")
	ErrAmbiguousTelemetryMapper = errors.New("multiple telemetry mappers matched the record")
)

// ErrSkipRecord is returned by a Mapper's Map for a well-formed record it
// deliberately does not project, such as a provider alert type the mapper
// does not handle. The registry then returns no events and no error, so the
// record is neither ingested nor counted as rejected.
var ErrSkipRecord = errors.New("telemetry record is not projected by its mapper")

// MappingError reports a record that matched one mapping but could not be mapped.
type MappingError struct {
	PluginID string
	SourceID string
	Err      error
}

// Error implements error.
func (err *MappingError) Error() string {
	return fmt.Sprintf("map telemetry for plugin %q source %q: %v", err.PluginID, err.SourceID, err.Err)
}

// Unwrap returns the mapper's error.
func (err *MappingError) Unwrap() error { return err.Err }

// LogRecord is a provider-neutral view of one OTLP log record. Attribute values
// keep their OTLP types; see OTLPReceiver for the conversion.
type LogRecord struct {
	Timestamp          time.Time
	ObservedTimestamp  time.Time
	SeverityNumber     int32
	SeverityText       string
	Body               any
	Attributes         map[string]any
	ResourceAttributes map[string]any
	ScopeName          string
	ScopeVersion       string
	TraceID            string
	SpanID             string
}

// Attribute returns a log record attribute.
func (record LogRecord) Attribute(name string) (any, bool) {
	value, found := record.Attributes[name]
	return value, found
}

// ResourceAttribute returns an attribute of the record's OTLP resource.
func (record LogRecord) ResourceAttribute(name string) (any, bool) {
	value, found := record.ResourceAttributes[name]
	return value, found
}

// Mapper translates log records from one telemetry source into events. Match
// must be cheap and side-effect free because it runs for every record against
// every registered mapper. Map should derive a stable event ID from the record
// (a producer-supplied ID or a digest of identifying content) so retries map
// to the same ID.
type Mapper interface {
	Match(LogRecord) bool
	Map(context.Context, LogRecord) ([]Event, error)
}

// MapperFuncs adapts a pair of functions to Mapper. A nil MatchFunc never
// matches.
type MapperFuncs struct {
	MatchFunc func(LogRecord) bool
	MapFunc   func(context.Context, LogRecord) ([]Event, error)
}

// Match calls MatchFunc.
func (mapper MapperFuncs) Match(record LogRecord) bool {
	return mapper.MatchFunc != nil && mapper.MatchFunc(record)
}

// Map calls MapFunc.
func (mapper MapperFuncs) Map(ctx context.Context, record LogRecord) ([]Event, error) {
	if mapper.MapFunc == nil {
		return nil, errors.New("telemetry mapper function is required")
	}
	return mapper.MapFunc(ctx, record)
}

// Mapping binds a mapper to the trusted plugin and source that own its events.
type Mapping struct {
	PluginID string
	SourceID string
	Mapper   Mapper
}

// MappingRegistry routes each log record to exactly one Mapping.
type MappingRegistry struct {
	mappings []Mapping
}

// NewMappingRegistry validates and copies mappings.
func NewMappingRegistry(mappings ...Mapping) (*MappingRegistry, error) {
	registered := slices.Clone(mappings)
	for index := range registered {
		registered[index].PluginID = strings.TrimSpace(registered[index].PluginID)
		registered[index].SourceID = strings.TrimSpace(registered[index].SourceID)
		if registered[index].PluginID == "" || registered[index].SourceID == "" || registered[index].Mapper == nil {
			return nil, fmt.Errorf("telemetry mapping %d requires plugin ID, source ID, and mapper", index)
		}
	}
	return &MappingRegistry{mappings: registered}, nil
}

// Map routes record to its single matching mapper and returns normalized
// events stamped with that mapping's plugin and source IDs. Events without an
// ObservedAt inherit the record timestamp, falling back to its observed
// timestamp. Any failure rejects the whole record. A record the mapper skips
// with ErrSkipRecord yields no events and no error.
func (registry *MappingRegistry) Map(ctx context.Context, record LogRecord) ([]Event, error) {
	var matched *Mapping
	for index := range registry.mappings {
		if !registry.mappings[index].Mapper.Match(record) {
			continue
		}
		// Every mapper is checked, and a second match is rejected rather than
		// resolved by registration order. First-match-wins would let a
		// too-broad Match silently claim another plugin's records and stamp
		// them with the wrong trusted provenance. The full scan costs one
		// cheap Match call per registered mapping per record.
		if matched != nil {
			return nil, ErrAmbiguousTelemetryMapper
		}
		matched = &registry.mappings[index]
	}
	if matched == nil {
		return nil, ErrNoTelemetryMapper
	}
	events, err := matched.Mapper.Map(ctx, record)
	if errors.Is(err, ErrSkipRecord) {
		return nil, nil
	}
	if err != nil {
		return nil, &MappingError{PluginID: matched.PluginID, SourceID: matched.SourceID, Err: err}
	}
	if len(events) == 0 {
		return nil, &MappingError{PluginID: matched.PluginID, SourceID: matched.SourceID, Err: errors.New("mapper returned no events")}
	}
	for index := range events {
		events[index].PluginID = matched.PluginID
		events[index].SourceID = matched.SourceID
		if events[index].ObservedAt.IsZero() {
			events[index].ObservedAt = record.Timestamp
			if events[index].ObservedAt.IsZero() {
				events[index].ObservedAt = record.ObservedTimestamp
			}
		}
		if err := events[index].normalize(); err != nil {
			return nil, &MappingError{PluginID: matched.PluginID, SourceID: matched.SourceID, Err: fmt.Errorf("event %d: %w", index, err)}
		}
	}
	return events, nil
}
