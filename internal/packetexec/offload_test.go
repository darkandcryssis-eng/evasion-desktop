package packetexec

import (
	"context"
	"testing"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/windivert"
)

// WinDivert 2.2 recalculates a checksum when its address flag is unset.
func TestFakeChecksumSurvivesWinDivertOffloadRepair(t *testing.T) {
	for _, flags := range []byte{1 << 1, (1 << 1) | (1 << 5) | (1 << 6), 0xff} {
		sink := &capture.SyntheticSink{}
		var address windivert.Address
		for i := range address {
			address[i] = byte(i)
		}
		address[10] = flags
		conn := newConn(t, sink, address)
		s := helloRule(dup(tamper(strategy.TamperParams{Field: strategy.FieldTCPChecksum, Mode: strategy.TamperCorrupt}, send()), send()))
		if err := New().Execute(context.Background(), s, conn); err != nil {
			t.Fatal(err)
		}
		for i, p := range sink.Sent() {
			metadata, ok := p.Reinject.(windivert.Address)
			if !ok {
				t.Fatal("reinjection address lost")
			}
			data := append([]byte(nil), p.Data...)
			d, _, _ := dissect(t, p)
			if metadata[10]&(1<<6) == 0 {
				if !d.RecomputeChecksums(data) {
					t.Fatal("driver checksum repair failed")
				}
			}
			if i == 0 && d.VerifyChecksums(data) {
				t.Fatalf("offload flags %02x: driver repaired the deliberately invalid TCP checksum", flags)
			}
			if i == 1 && !d.VerifyChecksums(data) {
				t.Fatal("real packet checksum broken")
			}
			want := address
			want[10] |= (1 << 5) | (1 << 6)
			if metadata != want {
				t.Fatalf("unexpected reinjection metadata for flags %02x", flags)
			}
		}
	}
}
