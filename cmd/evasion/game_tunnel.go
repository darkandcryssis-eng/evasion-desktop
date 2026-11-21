package main

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/fitting-1c/evasion/internal/gamefilter"
	"github.com/fitting-1c/evasion/internal/gameproxy"
)

func runGameSOCKS(ctx context.Context, o gamefilter.Options, p *gamefilter.Processor, owners *gamefilter.Owners, endpoint string, jsonOut bool) error {
	p.ObserveOnly = true
	p.SetTunnel()
	b, err := gameproxy.Start(ctx, gameproxy.Options{Proxy: endpoint, TCP: o.TCP(), UDP: o.UDP(), Owner: owners, Observe: p.ObserveTunnel, Opened: p.RecordTunnelFlow, Error: p.RecordSendError})
	if err != nil {
		return err
	}
	defer b.Close()
	g := &gameRuntime{owners: owners, processor: p}
	g.save()
	if jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"filter": "selected game sockets · tunnel", "quic_mode": "off"})
	}
	ticker := time.NewTicker(350 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-b.Done():
			return b.Err()
		case <-ticker.C:
			g.save()
		}
	}
}
