package aws

import (
	"compress/gzip"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

const (
	// FirehosePath is the HTTP route the service mounts for Firehose HTTP endpoint
	// deliveries of VPC Flow Logs.
	FirehosePath           = "/v1/aws/firehose/vpc-flow-logs"
	maxFirehoseRequestSize = 96 << 20
	maxFirehoseRecordSize  = 1_024_000
	// maxFirehoseInFlight bounds concurrent deliveries; each may hold up to
	// maxFirehoseRequestSize of body plus its decoded events.
	maxFirehoseInFlight = 4
)

// FirehoseConfig binds the receiver to one Firehose stream. AccessKey is the
// shared secret Firehose sends in X-Amz-Firehose-Access-Key; it is compared
// in constant time and never logged.
type FirehoseConfig struct {
	StreamARN string
	AccessKey string
}

type firehoseReceiver struct {
	projection ProjectionContext
	streamARN  string
	accessKey  string
	ingestor   telemetry.EventIngestor
	inFlight   chan struct{}
}

type firehoseRequest struct {
	RequestID string `json:"requestId"`
	Records   []struct {
		Data string `json:"data"`
	} `json:"records"`
}

type firehoseResponse struct {
	RequestID    string `json:"requestId"`
	Timestamp    int64  `json:"timestamp"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// FirehoseHandler returns an HTTP handler that accepts VPC Flow Log
// deliveries for the configured stream. The stream's account and region must
// match this plugin's source so flow endpoints resolve under the same
// authority as its inventory. A 200 response means the events are queued in
// the telemetry pipeline, not yet written to its sink.
func (p *Plugin) FirehoseHandler(config FirehoseConfig, ingestor telemetry.EventIngestor) (http.Handler, error) {
	config.StreamARN = strings.TrimSpace(config.StreamARN)
	if config.StreamARN == "" || config.AccessKey == "" {
		return nil, errors.New("AWS Firehose receiver requires stream ARN and access key")
	}
	parsedARN, err := arn.Parse(config.StreamARN)
	if err != nil {
		return nil, fmt.Errorf("parse AWS Firehose stream ARN: %w", err)
	}
	source := strings.Split(p.config.SourceID, "/")
	if len(source) != 4 || source[0] != "aws" || source[1] != p.config.Partition || source[3] != p.config.Region || !validAccountID(source[2]) {
		return nil, errors.New("AWS Firehose receiver requires a canonical AWS source ID")
	}
	if parsedARN.Partition != p.config.Partition || parsedARN.Service != "firehose" || parsedARN.Region != p.config.Region || parsedARN.AccountID != source[2] || !strings.HasPrefix(parsedARN.Resource, "deliverystream/") || len(parsedARN.Resource) == len("deliverystream/") {
		return nil, errors.New("AWS Firehose stream ARN must identify a delivery stream in the plugin account and region")
	}
	if ingestor == nil {
		return nil, errors.New("AWS Firehose receiver requires a telemetry ingestor")
	}
	return &firehoseReceiver{
		projection: ProjectionContext{Partition: p.config.Partition, Region: p.config.Region, SourceID: p.config.SourceID},
		streamARN:  config.StreamARN, accessKey: config.AccessKey, ingestor: ingestor,
		inFlight: make(chan struct{}, maxFirehoseInFlight),
	}, nil
}

// TelemetryReceivers registers the optional Firehose transport owned by this
// AWS source. The host supplies only the shared event ingestor.
func (p *Plugin) TelemetryReceivers(ingestor telemetry.EventIngestor) ([]discovery.TelemetryReceiver, error) {
	if strings.TrimSpace(p.config.FirehoseStreamARN) == "" {
		return nil, nil
	}
	handler, err := p.FirehoseHandler(FirehoseConfig{
		StreamARN: p.config.FirehoseStreamARN, AccessKey: p.config.FirehoseAccessKey,
	}, ingestor)
	if err != nil {
		return nil, err
	}
	return []discovery.TelemetryReceiver{{Method: http.MethodPost, Path: FirehosePath, Handler: handler}}, nil
}

func (receiver *firehoseReceiver) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := strings.TrimSpace(request.Header.Get("X-Amz-Firehose-Request-Id"))
	fail := func(status int, err error) {
		writeFirehoseResponse(writer, status, firehoseResponse{RequestID: requestID, Timestamp: time.Now().UnixMilli(), ErrorMessage: err.Error()})
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		fail(http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		fail(http.StatusUnsupportedMediaType, errors.New("AWS Firehose requires application/json"))
		return
	}
	if request.Header.Get("X-Amz-Firehose-Protocol-Version") != "1.0" || requestID == "" {
		fail(http.StatusBadRequest, errors.New("invalid AWS Firehose protocol headers"))
		return
	}
	if request.Header.Get("X-Amz-Firehose-Source-Arn") != receiver.streamARN {
		fail(http.StatusForbidden, errors.New("unexpected AWS Firehose source ARN"))
		return
	}
	providedKey := request.Header.Get("X-Amz-Firehose-Access-Key")
	if len(providedKey) != len(receiver.accessKey) || subtle.ConstantTimeCompare([]byte(providedKey), []byte(receiver.accessKey)) != 1 {
		fail(http.StatusUnauthorized, errors.New("invalid AWS Firehose access key"))
		return
	}
	// Firehose retries any non-200 delivery, so excess deliveries are turned
	// away before their bodies are read.
	select {
	case receiver.inFlight <- struct{}{}:
		defer func() { <-receiver.inFlight }()
	default:
		writer.Header().Set("Retry-After", "1")
		fail(http.StatusTooManyRequests, errors.New("too many concurrent AWS Firehose deliveries"))
		return
	}
	payload, err := readFirehosePayload(writer, request)
	if err != nil {
		fail(http.StatusBadRequest, err)
		return
	}
	var batch firehoseRequest
	if err := json.Unmarshal(payload, &batch); err != nil {
		fail(http.StatusBadRequest, errors.New("decode AWS Firehose request"))
		return
	}
	if batch.RequestID == "" || batch.RequestID != requestID || len(batch.Records) == 0 || len(batch.Records) > 10_000 {
		fail(http.StatusBadRequest, errors.New("invalid AWS Firehose request envelope"))
		return
	}
	var events []telemetry.Event
	for recordIndex, record := range batch.Records {
		decoded, err := base64.StdEncoding.DecodeString(record.Data)
		if err != nil || len(decoded) > maxFirehoseRecordSize {
			fail(http.StatusBadRequest, fmt.Errorf("decode AWS Firehose record %d", recordIndex))
			return
		}
		for _, line := range strings.Split(string(decoded), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			event, err := NormalizeVPCFlowLog(receiver.projection, line)
			if errors.Is(err, errNoFlowData) {
				continue
			}
			if err != nil {
				fail(http.StatusBadRequest, fmt.Errorf("normalize AWS Firehose record %d: %w", recordIndex, err))
				return
			}
			events = append(events, event)
		}
	}
	if len(events) > 0 {
		if err := receiver.ingestor.Ingest(request.Context(), events...); err != nil {
			switch {
			case errors.Is(err, telemetry.ErrPipelineOverloaded):
				writer.Header().Set("Retry-After", "1")
				fail(http.StatusTooManyRequests, errors.New("telemetry queue is full"))
			case errors.Is(err, telemetry.ErrRequestTooLarge):
				fail(http.StatusRequestEntityTooLarge, errors.New("AWS Firehose request exceeds telemetry queue capacity"))
			default:
				fail(http.StatusServiceUnavailable, errors.New("enqueue AWS VPC Flow Logs"))
			}
			return
		}
	}
	writeFirehoseResponse(writer, http.StatusOK, firehoseResponse{RequestID: requestID, Timestamp: time.Now().UnixMilli()})
}

func readFirehosePayload(writer http.ResponseWriter, request *http.Request) ([]byte, error) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxFirehoseRequestSize)
	defer request.Body.Close()
	var reader io.Reader = request.Body
	encoding := strings.ToLower(strings.TrimSpace(request.Header.Get("Content-Encoding")))
	if encoding != "" {
		if encoding != "gzip" {
			return nil, fmt.Errorf("unsupported AWS Firehose content encoding %q", encoding)
		}
		compressed, err := gzip.NewReader(request.Body)
		if err != nil {
			return nil, errors.New("decode gzip AWS Firehose payload")
		}
		defer func() { _ = compressed.Close() }()
		reader = compressed
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maxFirehoseRequestSize+1))
	if err != nil {
		return nil, errors.New("read AWS Firehose payload")
	}
	if len(payload) > maxFirehoseRequestSize {
		return nil, errors.New("AWS Firehose payload exceeds request limit")
	}
	return payload, nil
}

func writeFirehoseResponse(writer http.ResponseWriter, status int, response firehoseResponse) {
	payload, err := json.Marshal(response)
	if err != nil {
		http.Error(writer, "encode AWS Firehose response", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	writer.WriteHeader(status)
	_, _ = writer.Write(payload)
}
