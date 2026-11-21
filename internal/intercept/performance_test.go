package intercept

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/packetexec"
)

type benchmarkSink struct{}

func (benchmarkSink) Send(capture.Packet) error { return nil }

func BenchmarkEstablishedTCPForward(b *testing.B) {
	data := make([]byte, 40+1200)
	data[0], data[8], data[9], data[32], data[33] = 0x45, 64, 6, 0x50, 0x18
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	copy(data[12:16], []byte{10, 0, 0, 1})
	copy(data[16:20], []byte{93, 184, 216, 34})
	binary.BigEndian.PutUint16(data[20:22], 50000)
	binary.BigEndian.PutUint16(data[22:24], 443)
	e, err := New(Options{Source: capture.NewSyntheticSource(), Sink: benchmarkSink{}, Flows: flow.NewTable(4096, time.Minute, testDetector), Provider: fakeProvider{}, Exec: packetexec.New(), Parse: fixedParser("example.com")})
	if err != nil {
		b.Fatal(err)
	}
	pkt := capture.Packet{Data: data, Dir: core.DirectionOutbound}
	ctx := context.Background()
	e.handle(ctx, pkt)
	b.SetBytes(1200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.handle(ctx, pkt)
	}
}
