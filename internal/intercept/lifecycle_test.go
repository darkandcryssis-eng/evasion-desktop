package intercept

import (
	"context"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/packet"
)

func TestFlowCapacityRecoversAfterIdle(t *testing.T) {
	sink := &capture.SyntheticSink{}
	e := buildEngine(t, capture.NewSyntheticSource(), sink, fixedParser("example.com"), fakeProvider{})
	e.flows = flow.NewTable(2, 2*time.Second, testDetector)
	now := time.Unix(100, 0)
	e.now = func() time.Time { return now }
	for port := uint16(1000); port < 1003; port++ {
		e.handle(context.Background(), packetV4Port(t, helloPayload, core.DirectionOutbound, port))
	}
	if e.helloComplete != 2 || e.flows.Len() != 2 {
		t.Fatal("full table must forward new flows without evicting active flows")
	}
	now = now.Add(3 * time.Second)
	e.handle(context.Background(), packetV4Port(t, helloPayload, core.DirectionOutbound, 1003))
	if e.helloComplete != 3 || e.flows.Len() != 1 || len(sink.Sent()) != 4 {
		t.Fatal("expired flows must release capacity and restore ClientHello processing")
	}
}

func TestFlowMaintenanceOverManySessions(t *testing.T) {
	e := buildEngine(t, capture.NewSyntheticSource(), &capture.SyntheticSink{}, fixedParser("example.com"), fakeProvider{})
	e.flows = flow.NewTable(2, time.Second, testDetector)
	now := time.Unix(100, 0)
	e.now = func() time.Time { return now }
	for session := 0; session < 100; session++ {
		e.handle(context.Background(), packetV4Port(t, helloPayload, core.DirectionOutbound, uint16(1000+session)))
		now = now.Add(2 * time.Second)
	}
	if e.helloComplete != 100 || e.flows.Len() != 1 {
		t.Fatalf("processing degraded: hellos=%d flows=%d", e.helloComplete, e.flows.Len())
	}
}

func TestNewSYNResetsReusedTuple(t *testing.T) {
	e := buildEngine(t, capture.NewSyntheticSource(), &capture.SyntheticSink{}, fixedParser("example.com"), fakeProvider{})
	ctx := context.Background()
	e.handle(ctx, packetV4(t, helloPayload, core.DirectionOutbound))
	syn := packetV4(t, nil, core.DirectionOutbound)
	syn.Data[33] = packet.FlagSYN
	e.handle(ctx, syn)
	e.handle(ctx, packetV4(t, helloPayload, core.DirectionOutbound))
	if e.helloComplete != 2 {
		t.Fatal("new connection on a reused tuple must process its ClientHello")
	}
}

func TestClosedFlowReleasesCapacity(t *testing.T) {
	for name, flags := range map[string]uint8{"FIN": packet.FlagFIN | packet.FlagACK, "RST": packet.FlagRST} {
		t.Run(name, func(t *testing.T) {
			sink := &capture.SyntheticSink{}
			e := buildEngine(t, capture.NewSyntheticSource(), sink, fixedParser("example.com"), fakeProvider{})
			e.handle(context.Background(), packetV4(t, helloPayload, core.DirectionOutbound))
			end := packetV4(t, nil, core.DirectionOutbound)
			end.Data[33] = flags
			e.handle(context.Background(), end)
			if e.flows.Len() != 0 || len(sink.Sent()) != 2 {
				t.Fatal("closed flow must be removed and its closing packet forwarded")
			}
		})
	}
}
