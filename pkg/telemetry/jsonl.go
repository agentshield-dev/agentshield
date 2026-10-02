package telemetry

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// JSONLSink appends events as JSON lines to a local file, fsyncing each
// batch. It is meant for development: it does not deduplicate retried events
// and has no rotation. The file is created with mode 0600 because events may
// contain sensitive properties.
type JSONLSink struct {
	mu   sync.Mutex
	file *os.File
}

// OpenJSONLSink opens or creates path for appending, creating parent
// directories as needed.
func OpenJSONLSink(path string) (*JSONLSink, error) {
	if path == "" {
		return nil, errors.New("telemetry JSONL path is required")
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Clean(path)), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open telemetry JSONL sink: %w", err)
	}
	return &JSONLSink{file: file}, nil
}

// WriteBatch appends events and syncs the file before returning.
func (sink *JSONLSink) WriteBatch(ctx context.Context, events []Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.file == nil {
		return errors.New("telemetry JSONL sink is closed")
	}
	writer := bufio.NewWriterSize(sink.file, 256*1024)
	encoder := json.NewEncoder(writer)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	return sink.file.Sync()
}

// Close closes the file. Later writes fail.
func (sink *JSONLSink) Close() error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.file == nil {
		return nil
	}
	err := sink.file.Close()
	sink.file = nil
	return err
}
