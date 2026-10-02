package aws

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

func TestFirehoseReceiverAuthenticatesDecodesAndIngests(t *testing.T) {
	plugin, err := New(Config{
		Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1", EC2: initialFailureEC2{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ingestor := &recordingIngestor{}
	handler, err := plugin.FirehoseHandler(FirehoseConfig{
		StreamARN: "arn:aws:firehose:us-east-1:111111111111:deliverystream/agentshield", AccessKey: "secret",
	}, ingestor)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(firehoseRequestFixture{
		RequestID: "request-1",
		Records: []firehoseRecordFixture{
			{Data: base64.StdEncoding.EncodeToString([]byte(flowLogLine("ingress", "198.51.100.10", "10.0.0.2", "OK") + "\n"))},
			{Data: base64.StdEncoding.EncodeToString([]byte(flowLogLine("ingress", "-", "-", "NODATA")))},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, FirehosePath, &compressed)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", "gzip")
	request.Header.Set("X-Amz-Firehose-Protocol-Version", "1.0")
	request.Header.Set("X-Amz-Firehose-Request-Id", "request-1")
	request.Header.Set("X-Amz-Firehose-Source-Arn", "arn:aws:firehose:us-east-1:111111111111:deliverystream/agentshield")
	request.Header.Set("X-Amz-Firehose-Access-Key", "secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(ingestor.events) != 1 {
		t.Fatalf("status = %d, body = %s, events = %#v", response.Code, response.Body.String(), ingestor.events)
	}
	var result firehoseResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.RequestID != "request-1" || result.Timestamp == 0 || result.ErrorMessage != "" {
		t.Fatalf("response = %#v", result)
	}
}

func TestTelemetryReceiversRegistersPluginOwnedFirehoseRoute(t *testing.T) {
	plugin, err := New(Config{
		Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1", EC2: initialFailureEC2{},
		FirehoseStreamARN: "arn:aws:firehose:us-east-1:111111111111:deliverystream/agentshield",
		FirehoseAccessKey: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	receivers, err := plugin.TelemetryReceivers(&recordingIngestor{})
	if err != nil {
		t.Fatal(err)
	}
	if len(receivers) != 1 || receivers[0].Method != http.MethodPost ||
		receivers[0].Path != FirehosePath || receivers[0].Handler == nil {
		t.Fatalf("plugin telemetry receivers = %#v", receivers)
	}
}

func TestFirehoseReceiverRejectsWrongAccessKey(t *testing.T) {
	plugin, err := New(Config{
		Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1", EC2: initialFailureEC2{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ingestor := &recordingIngestor{}
	handler, err := plugin.FirehoseHandler(FirehoseConfig{
		StreamARN: "arn:aws:firehose:us-east-1:111111111111:deliverystream/agentshield", AccessKey: "secret",
	}, ingestor)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, FirehosePath, bytes.NewReader([]byte(`{}`)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Amz-Firehose-Protocol-Version", "1.0")
	request.Header.Set("X-Amz-Firehose-Request-Id", "request-1")
	request.Header.Set("X-Amz-Firehose-Source-Arn", "arn:aws:firehose:us-east-1:111111111111:deliverystream/agentshield")
	request.Header.Set("X-Amz-Firehose-Access-Key", "wrong")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || len(ingestor.events) != 0 {
		t.Fatalf("status = %d, events = %#v", response.Code, ingestor.events)
	}
}

func TestFirehoseReceiverRejectsForeignStream(t *testing.T) {
	plugin, err := New(Config{
		Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1", EC2: initialFailureEC2{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.FirehoseHandler(FirehoseConfig{
		StreamARN: "arn:aws:firehose:us-east-1:222222222222:deliverystream/agentshield", AccessKey: "secret",
	}, &recordingIngestor{}); err == nil {
		t.Fatal("foreign Firehose stream was accepted")
	}
}

type firehoseRequestFixture struct {
	RequestID string                  `json:"requestId"`
	Records   []firehoseRecordFixture `json:"records"`
}

type firehoseRecordFixture struct {
	Data string `json:"data"`
}

type recordingIngestor struct {
	events []telemetry.Event
}

func (ingestor *recordingIngestor) Ingest(_ context.Context, events ...telemetry.Event) error {
	ingestor.events = append(ingestor.events, events...)
	return nil
}

func TestFirehoseReceiverMapsIngestBackpressure(t *testing.T) {
	plugin, err := New(Config{
		Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1", EC2: initialFailureEC2{},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(firehoseRequestFixture{
		RequestID: "request-1",
		Records: []firehoseRecordFixture{
			{Data: base64.StdEncoding.EncodeToString([]byte(flowLogLine("ingress", "198.51.100.10", "10.0.0.2", "OK")))},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		err        error
		status     int
		retryAfter bool
	}{
		{err: telemetry.ErrPipelineOverloaded, status: http.StatusTooManyRequests, retryAfter: true},
		{err: telemetry.ErrRequestTooLarge, status: http.StatusRequestEntityTooLarge},
		{err: telemetry.ErrPipelineClosed, status: http.StatusServiceUnavailable},
	} {
		handler, err := plugin.FirehoseHandler(FirehoseConfig{
			StreamARN: "arn:aws:firehose:us-east-1:111111111111:deliverystream/agentshield", AccessKey: "secret",
		}, failingIngestor{err: test.err})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, FirehosePath, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Amz-Firehose-Protocol-Version", "1.0")
		request.Header.Set("X-Amz-Firehose-Request-Id", "request-1")
		request.Header.Set("X-Amz-Firehose-Source-Arn", "arn:aws:firehose:us-east-1:111111111111:deliverystream/agentshield")
		request.Header.Set("X-Amz-Firehose-Access-Key", "secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || (response.Header().Get("Retry-After") != "") != test.retryAfter {
			t.Fatalf("%v: status = %d, Retry-After = %q", test.err, response.Code, response.Header().Get("Retry-After"))
		}
	}
}

type failingIngestor struct{ err error }

func (ingestor failingIngestor) Ingest(context.Context, ...telemetry.Event) error {
	return ingestor.err
}
