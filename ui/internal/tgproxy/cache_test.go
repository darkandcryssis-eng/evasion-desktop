package tgproxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRouteCachePersistsOnlyPreference(t *testing.T) {
	path, key := filepath.Join(t.TempDir(), "routes.json"), strings.Repeat("a", 64)
	r := newRouter(nil, true)
	r.enableCache(path, key)
	candidate := routesFor(2, false)[0]
	r.known[candidate.id] = candidate
	r.success(candidate.id, 120*time.Millisecond)
	r.cache.close()
	saved := loadRouteCache(path, key, true, time.Now())
	if len(saved) != 1 || saved[candidate.id].DC != 2 {
		t.Fatal(saved)
	}
	r2 := newRouter(nil, true)
	r2.enableCache(path, key)
	defer r2.cache.close()
	h := r2.health[candidate.id]
	if !h.preferred || h.success || !h.checked.IsZero() {
		t.Fatal("history advertised as verified", h)
	}
	if routeRank(h) <= routeRank(routeHealth{}) || routeRank(h) >= routeRank(routeHealth{success: true}) {
		t.Fatal("invalid priority")
	}
	r2.failure(candidate.id)
	if r2.health[candidate.id].preferred {
		t.Fatal("failed preference retained")
	}
	r2.cache.close()
	if len(loadRouteCache(path, key, true, time.Now())) != 0 {
		t.Fatal("failed route persisted")
	}
}

func TestRouteCacheRejectsUnsafeEntries(t *testing.T) {
	path, key := filepath.Join(t.TempDir(), "routes.json"), strings.Repeat("a", 64)
	now := time.Now()
	r := routesFor(2, false)[0]
	good := savedRoute{DC: 2, ID: r.id, LatencyMS: 120, At: now}
	for _, tc := range []struct {
		name   string
		change func(*savedRoute)
	}{
		{"old", func(v *savedRoute) { v.At = now.Add(-25 * time.Hour) }},
		{"future", func(v *savedRoute) { v.At = now.Add(2 * time.Minute) }},
		{"unknown-host", func(v *savedRoute) { v.ID = "wss:evil.example" }},
		{"unknown-dc", func(v *savedRoute) { v.DC = 999 }},
		{"negative", func(v *savedRoute) { v.LatencyMS = -1 }},
		{"huge-latency", func(v *savedRoute) { v.LatencyMS = 60001 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := good
			tc.change(&v)
			b, _ := json.Marshal(routeCacheData{Schema: 1, Network: key, Routes: []savedRoute{v}})
			os.WriteFile(path, b, 0600)
			if len(loadRouteCache(path, key, true, now)) > 0 {
				t.Fatal("unsafe entry accepted")
			}
		})
	}
	b, _ := json.Marshal(routeCacheData{Schema: 1, Network: key, Routes: []savedRoute{good}})
	os.WriteFile(path, b, 0600)
	if len(loadRouteCache(path, strings.Repeat("b", 64), true, now)) != 0 {
		t.Fatal("other network accepted")
	}
	os.WriteFile(path, []byte("{"), 0600)
	if len(loadRouteCache(path, key, true, now)) != 0 {
		t.Fatal("corrupt cache accepted")
	}
	v := savedRoute{DC: 2, ID: "relay:kws2." + communityDomains[0], At: now}
	if _, ok := routeFromCache(v, false); ok {
		t.Fatal("community opt-out ignored")
	}
	if _, ok := routeFromCache(v, true); !ok {
		t.Fatal("allowed community rejected")
	}
}

func TestRouteCacheRestoresLegacyMediaPreferenceInItsOwnScope(t *testing.T) {
	path, network := filepath.Join(t.TempDir(), "routes.json"), strings.Repeat("a", 64)
	now := time.Now()
	regular, media := routesFor(4, false)[0], routesFor(4, true)[3]
	b, err := json.Marshal(routeCacheData{Schema: 1, Network: network, Routes: []savedRoute{
		{DC: 4, Media: true, ID: regular.id, LatencyMS: 120, At: now},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	entries := loadRouteCache(path, network, true, now)
	if len(entries) != 1 || !entries[media.id].Media || entries[regular.id].ID != "" {
		t.Fatal("legacy media preference was lost or loaded as a message route", entries)
	}
}

func TestRouteCacheConcurrentFlush(t *testing.T) {
	path, key := filepath.Join(t.TempDir(), "routes.json"), strings.Repeat("a", 64)
	r := newRouter(nil)
	r.enableCache(path, key)
	candidate := routesFor(2, false)[0]
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				r.cache.remember(candidate, time.Millisecond)
				if j%2 == 0 {
					r.cache.forget(candidate.id)
				}
			}
		}()
	}
	wg.Wait()
	r.cache.remember(candidate, time.Millisecond)
	r.cache.close()
	if len(loadRouteCache(path, key, true, time.Now())) != 1 {
		t.Fatal("last write lost")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret", "auth", "127.0.0.1", "token"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("cache contains client data", secret)
		}
	}
	r2 := newRouter(nil)
	r2.enableCache("", key)
	if r2.cache != nil {
		t.Fatal("disabled cache created")
	}
}
