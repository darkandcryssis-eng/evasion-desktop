package events

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnqueueAndReadBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	w, err := Open(Config{Path: path, FlushInterval: 10 * time.Millisecond, BatchSize: 1})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	w.Enqueue(Event{Kind: KindClientHelloSeen, Attrs: map[string]any{"sni": "example.com"}})
	w.Enqueue(Event{Kind: KindStrategyApplied, FlowID: FlowID(0x1234), Attrs: map[string]any{"strategy": "fake-badsum"}})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open readback: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) != 2 {
		t.Fatalf("прочитано строк %d, ожидали 2:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	// Каждая строка — валидный JSON с полями at, kind.
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("строка %d не JSON: %v (%q)", i, err, line)
		}
		if e.Kind == "" {
			t.Fatalf("строка %d: пустое Kind", i)
		}
		if e.At.IsZero() {
			t.Fatalf("строка %d: пустое At", i)
		}
	}
}

func TestEnqueueOnClosedDrops(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	w, _ := Open(Config{Path: path})
	_ = w.Close()
	// Повторный Close идемпотентен.
	_ = w.Close()
	w.Enqueue(Event{Kind: KindClientHelloSeen})
	if w.Dropped() == 0 {
		t.Fatal("Enqueue на закрытом должен отбрасывать и инкрементировать Dropped")
	}
}

func TestQueueOverflow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	w, _ := Open(Config{Path: path, QueueSize: 2, FlushInterval: time.Hour}) // медленный flush
	defer w.Close()
	// Кладём больше, чем влезает: часть должна отбрасываться.
	for i := 0; i < 100; i++ {
		w.Enqueue(Event{Kind: KindClientHelloSeen})
	}
	if w.Dropped() == 0 {
		t.Fatal("ожидали отбрасывания при переполнении, Dropped=0")
	}
}

func TestFlowIDHex(t *testing.T) {
	e := Event{Kind: KindStrategyApplied, FlowID: FlowID(0xdeadbeef)}
	b, _ := json.Marshal(e)
	if !strings.Contains(string(b), `"flow":"00000000deadbeef"`) {
		t.Fatalf("FlowID не в hex 16-символ формате: %s", b)
	}
}

func TestFlowIDOmittedWhenZero(t *testing.T) {
	e := Event{Kind: KindClientHelloSeen}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), `"flow"`) {
		t.Fatalf("нулевой FlowID не должен попадать в JSON: %s", b)
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	w, _ := Open(Config{
		Path:          path,
		FlushInterval: 5 * time.Millisecond,
		BatchSize:     1,
		MaxFileBytes:  200, // маленький для теста ротации
		MaxRotated:    3,
	})
	// Пишем много событий, чтобы заставить ротацию.
	for i := 0; i < 100; i++ {
		w.Enqueue(Event{Kind: KindClientHelloSeen, Attrs: map[string]any{"n": i}})
	}
	time.Sleep(100 * time.Millisecond) // даём flush/rotate доработать
	_ = w.Close()
	// Должен появиться хотя бы один rotated-файл .1.
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotated-файл .1 не создан: %v", err)
	}
}
