package hops

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

const FallbackTTL = 6

const (
	defaultCapacity = 4096
	medianWindow    = 64
)

var Default = NewTable(defaultCapacity, 10*time.Minute)

type observation struct {
	hops int
	at   time.Time
	seq  uint64
}

type Table struct {
	mu       sync.Mutex
	entries  map[netip.Addr]observation
	recent   []observation
	capacity int
	maxAge   time.Duration
	now      func() time.Time
	seq      uint64
}

func NewTable(capacity int, maxAge time.Duration) *Table {
	if capacity < 1 {
		capacity = 1
	}
	return &Table{
		entries:  make(map[netip.Addr]observation, capacity),
		capacity: capacity,
		maxAge:   maxAge,
		now:      time.Now,
	}
}

func HopsFromTTL(ttl uint8) int {
	initial := 255
	switch {
	case ttl <= 64:
		initial = 64
	case ttl <= 128:
		initial = 128
	}
	return initial - int(ttl)
}

func (t *Table) Observe(src netip.Addr, ttl uint8) {
	if t == nil {
		return
	}
	src = src.Unmap()
	if !src.IsValid() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	t.seq++
	o := observation{hops: HopsFromTTL(ttl), at: now, seq: t.seq}
	if _, exists := t.entries[src]; !exists && len(t.entries) >= t.capacity {
		var oldest netip.Addr
		oldestSeq := ^uint64(0)
		for addr, entry := range t.entries {
			if entry.seq < oldestSeq {
				oldest, oldestSeq = addr, entry.seq
			}
		}
		delete(t.entries, oldest)
	}
	t.entries[src] = o
	t.recent = append(t.recent, o)
	if len(t.recent) > medianWindow {
		copy(t.recent, t.recent[len(t.recent)-medianWindow:])
		t.recent = t.recent[:medianWindow]
	}
}

func (t *Table) Hops(dst netip.Addr) (int, bool) {
	if t == nil {
		return 0, false
	}
	dst = dst.Unmap()
	if !dst.IsValid() {
		return 0, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	if exact, ok := t.entries[dst]; ok && t.fresh(exact, now) {
		return exact.hops, true
	}

	prefix := prefixFor(dst)
	var newest observation
	foundPrefix := false
	for addr, entry := range t.entries {
		if !t.fresh(entry, now) {
			continue
		}
		if prefixFor(addr) == prefix && (!foundPrefix || entry.seq > newest.seq) {
			newest = entry
			foundPrefix = true
		}
	}
	if foundPrefix {
		return newest.hops, true
	}

	values := make([]int, 0, len(t.recent))
	for _, entry := range t.recent {
		if t.fresh(entry, now) {
			values = append(values, entry.hops)
		}
	}
	if len(values) == 0 {
		return 0, false
	}
	sort.Ints(values)
	mid := len(values) / 2
	if len(values)%2 == 1 {
		return values[mid], true
	}
	return (values[mid-1] + values[mid]) / 2, true
}

func (t *Table) FakeTTL(dst netip.Addr, delta int, fallback uint8) uint8 {
	if t == nil {
		return fallback
	}
	hops, ok := t.Hops(dst)
	if !ok {
		return fallback
	}
	if delta <= 0 {
		delta = 1
	}
	if hops <= 1 || delta >= hops {
		return 1
	}
	return uint8(hops - delta)
}

func (t *Table) fresh(o observation, now time.Time) bool {
	return now.Sub(o.at) <= t.maxAge
}

func prefixFor(addr netip.Addr) netip.Prefix {
	if addr.Is4() {
		return netip.PrefixFrom(addr, 24).Masked()
	}
	return netip.PrefixFrom(addr, 48).Masked()
}
