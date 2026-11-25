package tgproxy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type savedRoute struct {
	DC             int       `json:"dc"`
	Media          bool      `json:"media"`
	ID             string    `json:"id"`
	LatencyMS      int64     `json:"latencyMs"`
	Successes      int       `json:"successes,omitempty"`
	MidStreamDrops int       `json:"midStreamDrops,omitempty"`
	AvgLifetimeMS  int64     `json:"avgLifetimeMs,omitempty"`
	At             time.Time `json:"at"`
}
type routeCacheData struct {
	Schema  int          `json:"schema"`
	Network string       `json:"network"`
	Routes  []savedRoute `json:"routes"`
}
type routeCache struct {
	mu            sync.Mutex
	path, network string
	entries       map[string]savedRoute
	signal        chan struct{}
	done          chan struct{}
	cancel        context.CancelFunc
}

func routeFromCache(v savedRoute, community bool) (route, bool) {
	if _, ok := dcIPs[v.DC]; !ok {
		return route{}, false
	}
	candidates := routesFor(v.DC, v.Media)
	if community {
		for _, domain := range communityDomains {
			candidates = append(candidates, communityRoutes(v.DC, v.Media, domain)...)
		}
	}
	for _, candidate := range candidates {
		legacyID, _, _ := strings.Cut(candidate.id, "/")
		if v.ID == candidate.id || v.ID == legacyID {
			return candidate, true
		}
	}
	return route{}, false
}

func loadRouteCache(path, network string, community bool, now time.Time) map[string]savedRoute {
	out := map[string]savedRoute{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > 64<<10 {
		return out
	}
	var data routeCacheData
	if json.NewDecoder(f).Decode(&data) != nil || data.Schema != 1 || data.Network != network {
		return out
	}
	for _, v := range data.Routes {
		if len(out) >= 24 {
			break
		}
		if v.LatencyMS < 0 || v.LatencyMS > 60000 || v.At.After(now.Add(time.Minute)) || now.Sub(v.At) > 24*time.Hour {
			continue
		}
		if candidate, ok := routeFromCache(v, community); ok {
			v.ID = candidate.id
			out[v.ID] = v
		}
	}
	return out
}

func (r *router) enableCache(path, network string) {
	_, keyErr := hex.DecodeString(network)
	if path == "" || len(network) != 64 || keyErr != nil {
		return
	}
	entries := loadRouteCache(path, network, r.community, time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	c := &routeCache{path: path, network: network, entries: entries, signal: make(chan struct{}, 1), done: make(chan struct{}), cancel: cancel}
	r.cache = c
	for id, v := range entries {
		route, _ := routeFromCache(v, r.community)
		r.known[id] = route
		r.health[id] = routeHealth{
			preferred:      true,
			latency:        time.Duration(v.LatencyMS) * time.Millisecond,
			successes:      max(0, v.Successes),
			midStreamDrops: max(0, v.MidStreamDrops),
			ewmaLifetime:   time.Duration(max(0, v.AvgLifetimeMS)) * time.Millisecond,
		}
	}
	go func() {
		defer close(c.done)
		for {
			select {
			case <-ctx.Done():
				c.flush()
				return
			case <-c.signal:
				timer := time.NewTimer(500 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					c.flush()
					return
				case <-timer.C:
					c.flush()
				}
			}
		}
	}()
}

func (c *routeCache) remember(r route, latency time.Duration) {
	c.rememberWithStats(r, latency, 1, 0, 0)
}

func (c *routeCache) rememberWithStats(r route, latency time.Duration, successes, drops int, avgLifetime time.Duration) {
	if r.tcp || r.dc == 0 {
		return
	}
	c.mu.Lock()
	if len(c.entries) >= 24 && c.entries[r.id].ID == "" {
		var oldest string
		for id, v := range c.entries {
			if oldest == "" || v.At.Before(c.entries[oldest].At) {
				oldest = id
			}
		}
		delete(c.entries, oldest)
	}
	c.entries[r.id] = savedRoute{
		DC:             r.dc,
		Media:          r.media,
		ID:             r.id,
		LatencyMS:      max(0, latency.Milliseconds()),
		Successes:      max(0, successes),
		MidStreamDrops: max(0, drops),
		AvgLifetimeMS:  max(0, avgLifetime.Milliseconds()),
		At:             time.Now().UTC(),
	}
	c.mu.Unlock()
	select {
	case c.signal <- struct{}{}:
	default:
	}
}

func (c *routeCache) forget(id string) {
	c.mu.Lock()
	delete(c.entries, id)
	c.mu.Unlock()
	select {
	case c.signal <- struct{}{}:
	default:
	}
}

func (c *routeCache) flush() {
	c.mu.Lock()
	data := routeCacheData{Schema: 1, Network: c.network, Routes: make([]savedRoute, 0, len(c.entries))}
	for _, v := range c.entries {
		data.Routes = append(data.Routes, v)
	}
	c.mu.Unlock()
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	_ = saveCacheFile(c.path, b)
}

func saveCacheFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".routes-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(b)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, path)
}

func (c *routeCache) close() {
	if c != nil {
		c.cancel()
		<-c.done
	}
}
