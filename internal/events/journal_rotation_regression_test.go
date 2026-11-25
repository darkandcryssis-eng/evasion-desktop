package events

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriterKeepsLoggingAfterRotationRenameFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	blocker := path + ".1"
	if err := os.Mkdir(blocker, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocker, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := Open(Config{Path: path, MaxFileBytes: 1, MaxRotated: 1, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for range 3 {
		w.Enqueue(Event{Kind: KindClientHelloSeen})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(data, []byte{'\n'}); got != 3 {
		t.Fatalf("record count after rotation failure = %d, want 3", got)
	}
}

func TestWriterPreservesRecordOrderAcrossBufferBoundaries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	w, err := Open(Config{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	payloads := []string{
		strings.Repeat("a", writeBufferSize*2/3),
		strings.Repeat("b", writeBufferSize*2/3),
		strings.Repeat("c", writeBufferSize+1),
		"d",
	}
	for _, payload := range payloads {
		w.Enqueue(Event{Kind: KindClientHelloSeen, Attrs: map[string]any{"payload": payload}})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
	if len(lines) != len(payloads) {
		t.Fatalf("record count = %d, want %d", len(lines), len(payloads))
	}
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		if e.Attrs["payload"] != payloads[i] {
			t.Fatalf("record %d: incorrect payload", i)
		}
	}
}
