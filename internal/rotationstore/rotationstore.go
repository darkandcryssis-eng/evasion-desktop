package rotationstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
)

const (
	version     = 1
	maxNetworks = 32
)

type Store struct {
	path string
	mu   sync.Mutex
}

type entry struct {
	Strategy string    `json:"strategy"`
	Updated  time.Time `json:"updated"`
}

type document struct {
	Version  int                         `json:"version"`
	Networks map[string]map[string]entry `json:"networks"`
}

func New(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Load(fingerprint string) (map[string]core.StrategyID, error) {
	out := make(map[string]core.StrategyID)
	if s == nil || s.path == "" || fingerprint == "" {
		return out, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := readDocument(s.path)
	if err != nil {
		return out, err
	}
	for group, value := range doc.Networks[fingerprint] {
		if group != "" && value.Strategy != "" {
			out[group] = core.StrategyID(value.Strategy)
		}
	}
	return out, nil
}

func (s *Store) Save(fingerprint string, active map[string]core.StrategyID, now time.Time) error {
	if s == nil || s.path == "" || fingerprint == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	doc, err := readDocument(s.path)
	if err != nil {
		return err
	}
	if doc.Networks == nil {
		doc.Networks = make(map[string]map[string]entry)
	}
	entries := make(map[string]entry, len(active))
	for group, id := range active {
		if group == "" || id == "" {
			continue
		}
		entries[group] = entry{Strategy: id.String(), Updated: now.UTC()}
	}
	doc.Networks[fingerprint] = entries
	for len(doc.Networks) > maxNetworks {
		evictOldest(doc.Networks)
	}
	doc.Version = version
	return writeDocument(s.path, doc)
}

func readDocument(path string) (document, error) {
	doc := document{Version: version, Networks: make(map[string]map[string]entry)}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return doc, nil
	}
	if err != nil {
		return document{}, fmt.Errorf("rotationstore: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Version != version || doc.Networks == nil {
		return document{Version: version, Networks: make(map[string]map[string]entry)}, nil
	}
	return doc, nil
}

func evictOldest(networks map[string]map[string]entry) {
	var oldestKey string
	var oldest time.Time
	first := true
	for fingerprint, entries := range networks {
		var latest time.Time
		for _, value := range entries {
			if value.Updated.After(latest) {
				latest = value.Updated
			}
		}
		if first || latest.Before(oldest) || latest.Equal(oldest) && fingerprint < oldestKey {
			oldestKey, oldest, first = fingerprint, latest, false
		}
	}
	delete(networks, oldestKey)
}

func writeDocument(path string, doc document) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("rotationstore: create %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("rotationstore: encode: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".rotation-*.tmp")
	if err != nil {
		return fmt.Errorf("rotationstore: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("rotationstore: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("rotationstore: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("rotationstore: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("rotationstore: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rotationstore: replace %s: %w", path, err)
	}
	return nil
}

func NetworkFingerprints(docPath string) ([]string, error) {
	doc, err := readDocument(docPath)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Networks))
	for fingerprint := range doc.Networks {
		out = append(out, fingerprint)
	}
	sort.Strings(out)
	return out, nil
}
