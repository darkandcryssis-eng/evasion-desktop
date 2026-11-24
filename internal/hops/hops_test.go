package hops

import (
	"net/netip"
	"testing"
	"time"
)

func TestHopsFromTTL(t *testing.T) {
	for _, tc := range []struct {
		ttl  uint8
		want int
	}{
		{0, 64}, {1, 63}, {63, 1}, {64, 0},
		{65, 63}, {127, 1}, {128, 0}, {129, 126}, {255, 0},
	} {
		if got := HopsFromTTL(tc.ttl); got != tc.want {
			t.Errorf("HopsFromTTL(%d) = %d, want %d", tc.ttl, got, tc.want)
		}
	}
}

func TestTableExactPrefixMedianAndExpiry(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	table := NewTable(10, time.Minute)
	table.now = func() time.Time { return now }

	a := netip.MustParseAddr("192.0.2.1")
	table.Observe(a, 55)
	if got, ok := table.Hops(a); !ok || got != 9 {
		t.Fatalf("exact lookup = %d, %v; want 9, true", got, ok)
	}

	table.Observe(netip.MustParseAddr("192.0.2.99"), 50)
	if got, ok := table.Hops(netip.MustParseAddr("192.0.2.200")); !ok || got != 14 {
		t.Fatalf("prefix lookup = %d, %v; want 14, true", got, ok)
	}

	// Different prefixes use the median of recent observations: 9, 14, 24.
	table.Observe(netip.MustParseAddr("198.51.100.1"), 40)
	if got, ok := table.Hops(netip.MustParseAddr("203.0.113.1")); !ok || got != 14 {
		t.Fatalf("median lookup = %d, %v; want 14, true", got, ok)
	}

	now = now.Add(2 * time.Minute)
	if got, ok := table.Hops(a); ok {
		t.Fatalf("expired lookup = %d, true; want false", got)
	}
}

func TestTableIPv6Prefix(t *testing.T) {
	table := NewTable(8, time.Minute)
	table.Observe(netip.MustParseAddr("2001:db8:1:2::1"), 60)
	if got, ok := table.Hops(netip.MustParseAddr("2001:db8:1:2::99")); !ok || got != 4 {
		t.Fatalf("IPv6 prefix lookup = %d, %v; want 4, true", got, ok)
	}
}

func TestFakeTTLClampAndFallback(t *testing.T) {
	table := NewTable(8, time.Minute)
	table.Observe(netip.MustParseAddr("192.0.2.1"), 55) // 9 hops
	dst := netip.MustParseAddr("192.0.2.1")
	for _, tc := range []struct {
		delta int
		want  uint8
	}{
		{-1, 8}, {0, 8}, {1, 8}, {8, 1}, {20, 1},
	} {
		if got := table.FakeTTL(dst, tc.delta, FallbackTTL); got != tc.want {
			t.Errorf("FakeTTL(delta=%d) = %d, want %d", tc.delta, got, tc.want)
		}
	}
	empty := NewTable(8, time.Minute)
	if got := empty.FakeTTL(netip.MustParseAddr("203.0.113.9"), 1, FallbackTTL); got != FallbackTTL {
		t.Fatalf("unknown FakeTTL = %d, want fallback %d", got, FallbackTTL)
	}
	var nilTable *Table
	if got := nilTable.FakeTTL(dst, 1, FallbackTTL); got != FallbackTTL {
		t.Fatalf("nil FakeTTL = %d, want fallback %d", got, FallbackTTL)
	}
}

func TestTableCapacityEvictsOldest(t *testing.T) {
	now := time.Now()
	table := NewTable(2, time.Minute)
	table.now = func() time.Time { return now }
	old := netip.MustParseAddr("192.0.2.1")
	table.Observe(old, 55)
	now = now.Add(time.Second)
	table.Observe(netip.MustParseAddr("198.51.100.1"), 54)
	now = now.Add(time.Second)
	table.Observe(netip.MustParseAddr("203.0.113.1"), 53)
	if _, ok := table.entries[old]; ok {
		t.Fatal("oldest observation was not evicted")
	}
}

func TestTableKeepsLast64ForMedian(t *testing.T) {
	table := NewTable(100, time.Minute)
	for i := 0; i < medianWindow; i++ {
		table.Observe(netip.AddrFrom4([4]byte{10, 0, byte(i / 250), byte(i%250 + 1)}), 60)
	}
	if len(table.recent) != medianWindow {
		t.Fatalf("recent observations = %d, want %d", len(table.recent), medianWindow)
	}
}
