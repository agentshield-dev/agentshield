package telemetry

import (
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	collectorlogsv1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	// defaultMaxOTLPRequestBytes bounds both the compressed request body and the
	// decompressed payload, which also limits gzip expansion.
	defaultMaxOTLPRequestBytes = 16 << 20
	// Rejection logs are summarized per request and bounded so a flood of
	// malformed records cannot flood the log.
	maxLoggedRejectionReasons = 16
	maxRejectionReasonBytes   = 256
	// defaultMaxConcurrentOTLPRequests bounds requests being read, decoded,
	// or mapped at once, and so the memory they hold.
	defaultMaxConcurrentOTLPRequests = 8
	// retryAfterSeconds is the Retry-After hint on 429 responses.
	retryAfterSeconds = "1"
)

// EventIngestor accepts normalized events. Pipeline implements it. Ingest
// must not drop events: it either accepts the whole request or returns an
// error, such as ErrPipelineOverloaded, and accepts none of it.
type EventIngestor interface {
	Ingest(context.Context, ...Event) error
}

// OTLPReceiverConfig configures an [OTLPReceiver]. Zero fields take defaults.
type OTLPReceiverConfig struct {
	// MaxRequestBytes limits the request body and the decompressed payload
	// separately. Default 16 MiB.
	MaxRequestBytes int64
	// MaxConcurrentRequests limits requests handled at once; more get 429.
	// Default 8.
	MaxConcurrentRequests int
	// Logger receives rejected-record summaries; nil uses slog.Default().
	Logger *slog.Logger
}

// OTLPReceiver is an OTLP/HTTP logs endpoint (the handler for /v1/logs).
//
// Request handling:
//
//  1. Accept only POST with Content-Type application/x-protobuf or
//     application/json, and Content-Encoding identity or gzip; other methods
//     get 405, other media types 415, and other encodings 400. Beyond
//     MaxConcurrentRequests in flight, a request gets 429 with Retry-After
//     before its body is read.
//  2. Read at most MaxRequestBytes of body and of decompressed payload;
//     larger or undecodable requests get 400.
//  3. Convert each log record to a provider-neutral LogRecord. OTLP values
//     keep their types (string, bool, int64, float64, []byte, []any,
//     map[string]any); resource attributes are shared by the records under
//     them; trace and span IDs become lowercase hex.
//  4. Route each record through the MappingRegistry. Exactly one mapper must
//     match. The mapper, not this receiver, extracts the stable event ID and
//     the original event timestamp from the record, so a collector retry of
//     the same record produces the same event. When the mapper leaves
//     ObservedAt unset, the record's time_unix_nano is used, then its
//     observed_time_unix_nano; a record with neither is rejected. Plugin and
//     source IDs are overwritten from mapper registration, so payloads
//     cannot spoof provenance. A mapper may skip a record it deliberately
//     does not project ([ErrSkipRecord]); a skipped record is neither
//     ingested nor rejected.
//  5. Records that match no mapper, match several, or fail mapping or
//     validation are counted in OTLP partial_success.rejected_log_records and
//     the rest of the request proceeds. The rejection message carries only a
//     count, never record content. The receiver also logs one bounded
//     warning per distinct rejection reason in the request, with the owning
//     plugin and source, or the producer's service.name when no mapper
//     matched.
//  6. Ingest the accepted events, all or none. When the pipeline queue
//     cannot take them all, the receiver returns 429 with Retry-After; when
//     the pipeline is shutting down or the request was cancelled, 503. OTLP
//     exporters retry both, and nothing from the request was queued. A
//     request with more events than the whole queue gets 413.
//  7. Respond 200 with an ExportLogsServiceResponse in the request's encoding.
//     A 200 means the events are queued, not yet written to the sink; see the
//     package documentation for when queued events can be lost.
//
// The receiver has no authentication. Bind it to loopback or put it behind an
// authenticated proxy, and restrict which producers can set the attributes
// mappers match on. Record bodies and attributes may hold secrets; the
// receiver never logs them. Rejection logs carry only mapper error text,
// which mappers must keep free of payload values.
type OTLPReceiver struct {
	config   OTLPReceiverConfig
	registry *MappingRegistry
	ingestor EventIngestor
	inFlight chan struct{}
}

// NewOTLPReceiver returns a receiver that maps records through registry and
// passes events to ingestor.
func NewOTLPReceiver(config OTLPReceiverConfig, registry *MappingRegistry, ingestor EventIngestor) (*OTLPReceiver, error) {
	if registry == nil {
		return nil, errors.New("OTLP telemetry mapping registry is required")
	}
	if ingestor == nil {
		return nil, errors.New("OTLP telemetry ingestor is required")
	}
	if config.MaxRequestBytes <= 0 {
		config.MaxRequestBytes = defaultMaxOTLPRequestBytes
	}
	if config.MaxConcurrentRequests <= 0 {
		config.MaxConcurrentRequests = defaultMaxConcurrentOTLPRequests
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &OTLPReceiver{
		config: config, registry: registry, ingestor: ingestor,
		inFlight: make(chan struct{}, config.MaxConcurrentRequests),
	}, nil
}

// TooManyRequests writes a 429 with a Retry-After hint. Receivers sharing an
// [EventIngestor] use it for ErrPipelineOverloaded and their own admission
// limits.
func TooManyRequests(writer http.ResponseWriter, message string) {
	writer.Header().Set("Retry-After", retryAfterSeconds)
	http.Error(writer, message, http.StatusTooManyRequests)
}

// ServeHTTP handles one OTLP logs export; see OTLPReceiver.
func (receiver *OTLPReceiver) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/x-protobuf" && mediaType != "application/json") {
		http.Error(writer, "OTLP logs require application/x-protobuf or application/json", http.StatusUnsupportedMediaType)
		return
	}
	select {
	case receiver.inFlight <- struct{}{}:
		defer func() { <-receiver.inFlight }()
	default:
		TooManyRequests(writer, "too many concurrent OTLP requests")
		return
	}
	payload, err := receiver.readPayload(writer, request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	exportRequest := &collectorlogsv1.ExportLogsServiceRequest{}
	if mediaType == "application/json" {
		err = protojson.Unmarshal(payload, exportRequest)
	} else {
		err = proto.Unmarshal(payload, exportRequest)
	}
	if err != nil {
		http.Error(writer, "decode OTLP logs: "+err.Error(), http.StatusBadRequest)
		return
	}

	var events []Event
	var rejected int64
	rejections := make(map[rejectionKey]int64)
	for _, resourceLogs := range exportRequest.ResourceLogs {
		if resourceLogs == nil {
			continue
		}
		resourceAttributes := attributes(resourceLogs.GetResource().GetAttributes())
		for _, scopeLogs := range resourceLogs.ScopeLogs {
			if scopeLogs == nil {
				continue
			}
			for _, log := range scopeLogs.LogRecords {
				if log == nil {
					continue
				}
				record := LogRecord{
					Timestamp:          unixNano(log.TimeUnixNano),
					ObservedTimestamp:  unixNano(log.ObservedTimeUnixNano),
					SeverityNumber:     int32(log.SeverityNumber),
					SeverityText:       log.SeverityText,
					Body:               anyValue(log.Body),
					Attributes:         attributes(log.Attributes),
					ResourceAttributes: resourceAttributes,
					ScopeName:          scopeLogs.GetScope().GetName(),
					ScopeVersion:       scopeLogs.GetScope().GetVersion(),
					TraceID:            hex.EncodeToString(log.TraceId),
					SpanID:             hex.EncodeToString(log.SpanId),
				}
				mapped, mapErr := receiver.registry.Map(request.Context(), record)
				if mapErr != nil {
					rejected++
					rejections[newRejectionKey(record, mapErr)]++
					continue
				}
				events = append(events, mapped...)
			}
		}
	}
	receiver.logRejections(request.Context(), rejections)
	if len(events) > 0 {
		// The error is not echoed: it may describe event content.
		if err := receiver.ingestor.Ingest(request.Context(), events...); err != nil {
			switch {
			case errors.Is(err, ErrPipelineOverloaded):
				TooManyRequests(writer, "telemetry queue is full")
			case errors.Is(err, ErrRequestTooLarge):
				http.Error(writer, "OTLP request has more events than the telemetry queue holds", http.StatusRequestEntityTooLarge)
			default:
				http.Error(writer, "enqueue OTLP telemetry", http.StatusServiceUnavailable)
			}
			return
		}
	}
	response := &collectorlogsv1.ExportLogsServiceResponse{}
	if rejected > 0 {
		response.PartialSuccess = &collectorlogsv1.ExportLogsPartialSuccess{
			RejectedLogRecords: rejected,
			ErrorMessage:       fmt.Sprintf("%d log records were not accepted by a telemetry mapping", rejected),
		}
	}
	if mediaType == "application/json" {
		encoded, marshalErr := protojson.Marshal(response)
		if marshalErr != nil {
			http.Error(writer, "encode OTLP response", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(encoded)
		return
	}
	encoded, err := proto.Marshal(response)
	if err != nil {
		http.Error(writer, "encode OTLP response", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/x-protobuf")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

// rejectionKey groups rejected records by owner and reason. Mapper errors must
// not carry payload values; the reason is still truncated before logging.
type rejectionKey struct {
	pluginID    string
	sourceID    string
	serviceName string
	reason      string
}

func newRejectionKey(record LogRecord, err error) rejectionKey {
	key := rejectionKey{reason: err.Error()}
	if mappingErr, ok := errors.AsType[*MappingError](err); ok {
		key.pluginID, key.sourceID, key.reason = mappingErr.PluginID, mappingErr.SourceID, mappingErr.Err.Error()
	} else if service, ok := record.ResourceAttributes["service.name"].(string); ok {
		// Unmatched records have no trusted owner; the producer's service name identifies them.
		key.serviceName = service
	}
	key.reason = truncate(key.reason, maxRejectionReasonBytes)
	key.serviceName = truncate(key.serviceName, maxRejectionReasonBytes)
	return key
}

func (receiver *OTLPReceiver) logRejections(ctx context.Context, rejections map[rejectionKey]int64) {
	keys := make([]rejectionKey, 0, len(rejections))
	for key := range rejections {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(left, right rejectionKey) int {
		return strings.Compare(left.pluginID+"\x00"+left.sourceID+"\x00"+left.serviceName+"\x00"+left.reason, right.pluginID+"\x00"+right.sourceID+"\x00"+right.serviceName+"\x00"+right.reason)
	})
	var omitted int64
	for index, key := range keys {
		if index >= maxLoggedRejectionReasons {
			omitted += rejections[key]
			continue
		}
		attributes := []any{"count", rejections[key], "reason", key.reason}
		if key.pluginID != "" {
			attributes = append(attributes, "plugin", key.pluginID, "source", key.sourceID)
		} else if key.serviceName != "" {
			attributes = append(attributes, "service_name", key.serviceName)
		}
		receiver.config.Logger.WarnContext(ctx, "rejected OTLP log records", attributes...)
	}
	if omitted > 0 {
		receiver.config.Logger.WarnContext(ctx, "rejected OTLP log records", "count", omitted, "reason", "additional distinct reasons omitted")
	}
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return strings.ToValidUTF8(value[:limit], "")
}

// readPayload enforces the size limit twice: MaxBytesReader caps bytes on the
// wire and LimitReader caps the decompressed result, so a small gzip bomb
// cannot expand past the limit.
func (receiver *OTLPReceiver) readPayload(writer http.ResponseWriter, request *http.Request) ([]byte, error) {
	request.Body = http.MaxBytesReader(writer, request.Body, receiver.config.MaxRequestBytes)
	defer request.Body.Close()
	var reader io.Reader = request.Body
	encoding := strings.TrimSpace(strings.ToLower(request.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		if encoding != "gzip" {
			return nil, fmt.Errorf("unsupported OTLP content encoding %q", encoding)
		}
		compressed, err := gzip.NewReader(request.Body)
		if err != nil {
			return nil, errors.New("decode gzip OTLP payload")
		}
		defer func() { _ = compressed.Close() }()
		reader = compressed
	}
	payload, err := io.ReadAll(io.LimitReader(reader, receiver.config.MaxRequestBytes+1))
	if err != nil {
		return nil, errors.New("read OTLP payload")
	}
	if int64(len(payload)) > receiver.config.MaxRequestBytes {
		return nil, errors.New("OTLP payload exceeds request limit")
	}
	return payload, nil
}

// unixNano converts an OTLP timestamp; zero means unset and maps to the zero
// time so mapping can fall back to another timestamp.
func unixNano(value uint64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(value)).UTC()
}

func attributes(values []*commonv1.KeyValue) map[string]any {
	result := make(map[string]any, len(values))
	for _, value := range values {
		if value != nil && value.Key != "" {
			result[value.Key] = anyValue(value.Value)
		}
	}
	return result
}

// anyValue converts an OTLP AnyValue to plain Go values. Bytes are copied so
// mapped values never share memory with the decoded request.
func anyValue(value *commonv1.AnyValue) any {
	if value == nil {
		return nil
	}
	switch typed := value.Value.(type) {
	case *commonv1.AnyValue_StringValue:
		return typed.StringValue
	case *commonv1.AnyValue_BoolValue:
		return typed.BoolValue
	case *commonv1.AnyValue_IntValue:
		return typed.IntValue
	case *commonv1.AnyValue_DoubleValue:
		return typed.DoubleValue
	case *commonv1.AnyValue_BytesValue:
		return slices.Clone(typed.BytesValue)
	case *commonv1.AnyValue_ArrayValue:
		if typed.ArrayValue == nil {
			return []any(nil)
		}
		items := make([]any, 0, len(typed.ArrayValue.Values))
		for _, item := range typed.ArrayValue.Values {
			items = append(items, anyValue(item))
		}
		return items
	case *commonv1.AnyValue_KvlistValue:
		if typed.KvlistValue == nil {
			return map[string]any{}
		}
		return attributes(typed.KvlistValue.Values)
	default:
		return nil
	}
}
