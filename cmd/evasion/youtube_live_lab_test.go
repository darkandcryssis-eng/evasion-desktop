//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/windivert"
	"github.com/fitting-1c/evasion/internal/youtubetune"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestYouTubeScopedLiveCandidates(t *testing.T) {
	if os.Getenv("EVASION_YOUTUBE_LIVE") != "1" {
		t.Skip("explicit live network test")
	}
	for _, profile := range []string{"split", "overlap"} {
		for _, host := range []string{"www.youtube.com", "i.ytimg.com", "youtubei.googleapis.com"} {
			for _, short := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/short=%v", profile, host, short), func(t *testing.T) {
					t.Parallel()
					l, err := net.ListenTCP("tcp4", &net.TCPAddr{})
					if err != nil {
						t.Fatal(err)
					}
					port := l.Addr().(*net.TCPAddr).Port
					l.Close()
					strat, err := youtubetune.Profile(profile, nil)
					if err != nil {
						t.Fatal(err)
					}
					cfg := config.Default()
					cfg.Groups = map[string][]string{"video": {host}}
					domains, _ := cfg.DomainSet([]string{"video"})
					provider, _ := proxy.NewGroupProvider(strat, domains)
					h, err := windivert.OpenPriority(fmt.Sprintf("outbound and tcp and tcp.SrcPort == %d and tcp.DstPort == 443 and not impostor", port), 100)
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithCancel(context.Background())
					done := make(chan struct{})
					engine, err := intercept.New(intercept.Options{Source: h, Sink: h, Flows: flow.NewTable(flowCapacity, flowTTL, intercept.TLSHelloDetector), Provider: provider, Exec: packetexec.New(), Parse: intercept.TLSHelloParser})
					if err != nil {
						h.Close()
						cancel()
						t.Fatal(err)
					}
					go func() { defer close(done); _ = engine.Run(ctx) }()
					defer func() { cancel(); h.Close(); <-done }()
					tc := &tls.Config{MinVersion: tls.VersionTLS12}
					if short {
						tc.CurvePreferences = []tls.CurveID{tls.X25519}
					}
					tr := &http.Transport{TLSClientConfig: tc, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
						d := net.Dialer{LocalAddr: &net.TCPAddr{Port: port}, Timeout: 4 * time.Second}
						return d.DialContext(ctx, "tcp4", addr)
					}, TLSHandshakeTimeout: 4 * time.Second, DisableKeepAlives: true}
					defer tr.CloseIdleConnections()
					client := &http.Client{Transport: tr, Timeout: 6 * time.Second}
					start := time.Now()
					r, err := client.Get("https://" + host + "/generate_204")
					if err != nil {
						t.Logf("UNAVAILABLE %v", err)
						return
					}
					defer r.Body.Close()
					io.Copy(io.Discard, io.LimitReader(r.Body, 1024))
					t.Logf("HTTP %d / %d ms", r.StatusCode, time.Since(start).Milliseconds())
				})
			}
		}
	}
}
