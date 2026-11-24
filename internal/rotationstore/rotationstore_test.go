package rotationstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
)

func TestRoundTrip(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "rotation.json"))
	now := time.Date(2025, 2, 3, 4, 5, 6, 0, time.UTC)
	want := map[string]core.StrategyID{"video": "strategy-a", "voice": "strategy-b"}
	if err := store.Save("network-a", want, now); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load("network-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("Load = %v, want %v", got, want)
	}
	for group, id := range want {
		if got[group] != id {
			t.Fatalf("Load[%q] = %s, want %s", group, got[group], id)
		}
	}

	data, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version  int `json:"version"`
		Networks map[string]map[string]struct {
			Strategy string `json:"strategy"`
			Updated  string `json:"updated"`
		} `json:"networks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 {
		t.Fatalf("version = %d, want 1", doc.Version)
	}
	entry := doc.Networks["network-a"]["video"]
	if entry.Strategy != "strategy-a" {
		t.Fatalf("stored strategy = %q, want strategy-a", entry.Strategy)
	}
	updated, err := time.Parse(time.RFC3339, entry.Updated)
	if err != nil {
		t.Fatalf("updated timestamp %q is not RFC3339: %v", entry.Updated, err)
	}
	if !updated.Equal(now) {
		t.Fatalf("updated timestamp = %s, want %s", updated, now)
	}
}

func TestEvictsOldestNetwork(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "rotation.json"))
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < maxNetworks+1; i++ {
		if err := store.Save(
			fmt.Sprintf("network-%02d", i),
			map[string]core.StrategyID{"group": core.StrategyID(fmt.Sprintf("id-%02d", i))},
			start.Add(time.Duration(i)*time.Minute),
		); err != nil {
			t.Fatal(err)
		}
	}
	networks, err := NetworkFingerprints(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != maxNetworks {
		t.Fatalf("stored networks = %d, want %d", len(networks), maxNetworks)
	}
	if _, err := store.Load("network-00"); err != nil {
		t.Fatal(err)
	}
	oldest, _ := store.Load("network-00")
	if len(oldest) != 0 {
		t.Fatalf("oldest network was not evicted: %v", oldest)
	}
	newest, _ := store.Load("network-32")
	if newest["group"] != "id-32" {
		t.Fatalf("newest network = %v", newest)
	}
}

func TestCorruptFileIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rotation.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := New(path)
	got, err := store.Load("network-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("Load of corrupt file = %v, want empty", got)
	}
	if err := store.Save("network-a", map[string]core.StrategyID{"video": "id"}, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestAtomicWriteLeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	store := New(filepath.Join(dir, "rotation.json"))
	if err := store.Save("network-a", map[string]core.StrategyID{"video": "id"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "rotation.json" {
		t.Fatalf("files left after atomic write: %v", entries)
	}
}
