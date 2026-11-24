package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/tlsfake"
)

func TestShippedStrategyRotationsBuildForIPv4AndIPv6(t *testing.T) {
	cfg, err := loadConfig(filepath.Join("..", "..", "examples", "config.json"))
	if err != nil {
		t.Fatalf("load examples/config.json: %v", err)
	}
	hello := tlsfake.FreshGoogleClientHello()
	if _, _, ok := intercept.TLSHelloParser(hello); !ok {
		t.Fatal("FreshGoogleClientHello was not parsed")
	}

	groups := make([]string, 0, len(cfg.StrategiesRotation))
	for group := range cfg.StrategiesRotation {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	for _, group := range groups {
		for i, strat := range cfg.StrategiesRotation[group] {
			if _, err := strategy.ComputeID(strat); err != nil {
				t.Fatalf("group %s rotation[%d] validation: %v", group, i, err)
			}
			for _, family := range []string{"IPv4", "IPv6"} {
				t.Run(fmt.Sprintf("%s/rotation-%d/%s", group, i, family), func(t *testing.T) {
					pkt := rotationClientHelloPacket(t, family == "IPv6", hello)
					sink := &capture.SyntheticSink{}
					provider, err := proxy.NewStaticProvider(strat)
					if err != nil {
						t.Fatalf("provider: %v", err)
					}
					observer := &rotationBuildObserver{}
					engine, err := intercept.New(intercept.Options{
						ShortHelloFallback: true,
						Source: capture.NewSyntheticSource(capture.Packet{
							Data: pkt,
							Dir:  core.DirectionOutbound,
						}),
						Sink:     sink,
						Flows:    flow.NewTable(16, time.Minute, intercept.TLSHelloDetector),
						Provider: provider,
						Exec:     packetexec.New(),
						Parse:    intercept.TLSHelloParser,
						Observer: observer,
					})
					if err != nil {
						t.Fatalf("intercept.New: %v", err)
					}
					if err := engine.Run(context.Background()); err != nil {
						t.Fatalf("Engine.Run: %v", err)
					}
					if observer.applied != 1 || len(observer.failed) != 0 {
						t.Fatalf("strategy execution: applied=%d failed=%v", observer.applied, observer.failed)
					}
				})
			}
		}
	}
}

func rotationClientHelloPacket(t *testing.T, ipv6 bool, payload []byte) []byte {
	t.Helper()
	const tcpLen = 20
	ipLen := 20
	if ipv6 {
		ipLen = 40
	}
	buf := make([]byte, ipLen+tcpLen+len(payload))
	if ipv6 {
		buf[0] = 0x60
		binary.BigEndian.PutUint16(buf[4:6], uint16(tcpLen+len(payload)))
		buf[6], buf[7] = byte(packet.ProtoTCP), 64
		copy(buf[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
		copy(buf[24:40], netip.MustParseAddr("2001:db8::34").AsSlice())
	} else {
		buf[0] = 0x45
		binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
		buf[8], buf[9] = 64, byte(packet.ProtoTCP)
		copy(buf[12:16], netip.MustParseAddr("192.0.2.1").AsSlice())
		copy(buf[16:20], netip.MustParseAddr("93.184.216.34").AsSlice())
	}
	binary.BigEndian.PutUint16(buf[ipLen:ipLen+2], 50000)
	binary.BigEndian.PutUint16(buf[ipLen+2:ipLen+4], 443)
	binary.BigEndian.PutUint32(buf[ipLen+4:ipLen+8], 1000)
	buf[ipLen+12], buf[ipLen+13] = 0x50, 0x18
	binary.BigEndian.PutUint16(buf[ipLen+14:ipLen+16], 65535)
	copy(buf[ipLen+tcpLen:], payload)
	d, err := packet.Dissect(buf)
	if err != nil {
		t.Fatalf("dissect packet: %v", err)
	}
	if !d.RecomputeChecksums(buf) {
		t.Fatal("could not compute packet checksums")
	}
	return buf
}

type rotationBuildObserver struct {
	applied int
	failed  []string
}

func (o *rotationBuildObserver) OnClientHelloSeen(uint64, string, bool) {}

func (o *rotationBuildObserver) OnStrategyApplied(uint64, string, core.StrategyID) {
	o.applied++
}

func (o *rotationBuildObserver) OnStrategyFailed(_ uint64, _ string, _ core.StrategyID, reason string) {
	o.failed = append(o.failed, reason)
}

func (o *rotationBuildObserver) OnPassiveRetransmit(uint64, string, string, core.StrategyID) {}
