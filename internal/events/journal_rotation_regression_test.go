package events

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFailedActiveRenamePreservesArchives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	// The active path is unavailable for rename, but the writer still has a file.
	file, err := os.Create(filepath.Join(dir, "open"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	w := &Writer{cfg: Config{Path: path, MaxRotated: 3}, file: file}
	for i := 1; i <= w.cfg.MaxRotated; i++ {
		slot := strconv.Itoa(i)
		if err := os.WriteFile(path+"."+slot, []byte(slot), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.rotateLocked(); err == nil {
		t.Fatal("rotation succeeded with no active path")
	}
	for i := 1; i <= w.cfg.MaxRotated; i++ {
		slot := strconv.Itoa(i)
		data, err := os.ReadFile(path + "." + slot)
		if err != nil || string(data) != slot {
			t.Fatalf("archive %s = %q, %v; want %q", slot, data, err, slot)
		}
	}
}

func TestWriterBacksOffRotationAfterFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	slot := path + ".1"
	if err := os.Mkdir(slot, 0o755); err != nil {
		t.Fatal(err)
	}
	w := &Writer{cfg: Config{Path: path, MaxFileBytes: 1, MaxRotated: 1}}
	defer func() {
		if w.file != nil {
			w.file.Close()
		}
	}()
	buffer := make([]byte, 0, writeBufferSize)
	w.flush([]Event{{Kind: KindClientHelloSeen}}, buffer)
	if err := os.Remove(slot); err != nil {
		t.Fatal(err)
	}
	w.flush([]Event{{Kind: KindClientHelloSeen}}, buffer)
	if _, err := os.Stat(slot); !os.IsNotExist(err) {
		t.Fatalf("archive before retry delay elapsed: %v", err)
	}
	w.rotateAfter = time.Now().Add(-time.Second)
	w.flush([]Event{{Kind: KindClientHelloSeen}}, buffer)
	data, err := os.ReadFile(slot)
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(data, []byte{'\n'}); got != 3 {
		t.Fatalf("record count after rotation retry = %d, want 3", got)
	}
}

func TestFailedPartialArchiveShiftIsRolledBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	for _, suffix := range []string{"", ".1", ".3", ".4"} {
		if err := os.WriteFile(path+suffix, []byte("data"+suffix), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	blocker := path + ".2"
	if err := os.Mkdir(blocker, 0o755); err != nil {
		t.Fatal(err)
	}
	w := &Writer{cfg: Config{Path: path, MaxRotated: 4}}
	for range 2 {
		if err := w.openActive(); err != nil {
			t.Fatal(err)
		}
		if err := w.rotateLocked(); err == nil {
			t.Fatal("rotation succeeded past the blocked archive slot")
		}
		for _, suffix := range []string{"", ".1", ".3", ".4"} {
			data, err := os.ReadFile(path + suffix)
			if err != nil || string(data) != "data"+suffix {
				t.Fatalf("file %q = %q, %v; want %q", suffix, data, err, "data"+suffix)
			}
		}
		for _, suffix := range []string{".rotating", ".retiring"} {
			if _, err := os.Stat(path + suffix); !os.IsNotExist(err) {
				t.Fatalf("unfinished rotation file %q: %v", suffix, err)
			}
		}
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := w.openActive(); err != nil {
		t.Fatal(err)
	}
	if err := w.rotateLocked(); err != nil {
		t.Fatal(err)
	}
	for slot, want := range map[string]string{".1": "data", ".2": "data.1", ".4": "data.3"} {
		data, err := os.ReadFile(path + slot)
		if err != nil || string(data) != want {
			t.Fatalf("archive %q after retry = %q, %v; want %q", slot, data, err, want)
		}
	}
}

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
