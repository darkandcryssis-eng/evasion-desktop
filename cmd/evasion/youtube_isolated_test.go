//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/windivert"
	"github.com/fitting-1c/evasion/internal/youtubetune"
	quicgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type isolatedYouTubeSink struct{ h *windivert.Handle }

func (s isolatedYouTubeSink) Send(p capture.Packet) error {
	return (youtubePacketSink{s.h}).Send(p)
}

func TestYouTubeIsolatedHTTP3(t *testing.T) {
	if os.Getenv("EVASION_YOUTUBE_H3") != "1" {
		t.Skip("explicit isolated HTTP/3 validation")
	}
	host := os.Getenv("EVASION_YOUTUBE_CDN")
	if host == "" {
		host = "redirector.googlevideo.com"
	}
	remote, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, "443"))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	local := seed.LocalAddr().(*net.UDPAddr).IP
	seed.Close()
	scope, _ := (&config.Config{Groups: map[string][]string{"video": youtubetune.Domains}}).DomainSet(nil)
	good := false
	for _, mode := range []string{"native", "desync"} {
		t.Run(mode, func(t *testing.T) {
			pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local})
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			port := pc.LocalAddr().(*net.UDPAddr).Port
			h, err := windivert.OpenPriority(fmt.Sprintf("outbound and udp and udp.SrcPort == %d and udp.DstPort == 443 and ip.DstAddr == %s", port, remote.IP), 300)
			if err != nil {
				t.Fatal(err)
			}
			inject, err := windivert.OpenPriority("false", -3000)
			if err != nil {
				h.Close()
				t.Fatal(err)
			}
			defer inject.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					p, e := h.Recv()
					if e != nil {
						return
					}
					if mode == "desync" {
						p, _, _ = quicDesyncPacket(p, scope)
					}
					inject.Send(p)
				}
			}()
			defer func() { h.ShutdownReceive(); <-done; h.Close() }()
			tr := &http3.Transport{Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quicgo.Config) (*quicgo.Conn, error) {
				return quicgo.DialEarly(ctx, pc, remote, tc, qc)
			}, QUICConfig: &quicgo.Config{Versions: []quicgo.Version{quicgo.Version1}, HandshakeIdleTimeout: 4 * time.Second, MaxIdleTimeout: 5 * time.Second}}
			defer tr.Close()
			r, e := (&http.Client{Transport: tr, Timeout: 6 * time.Second}).Get("https://" + host + "/generate_204")
			if e != nil {
				t.Log("UNAVAILABLE", e)
				return
			}
			r.Body.Close()
			t.Logf("HTTP %d protocol=%s", r.StatusCode, r.Proto)
			good = good || r.ProtoMajor == 3 && (r.StatusCode == 204 || r.StatusCode == 404)
		})
	}
	if !good {
		t.Fatal("no HTTP/3 method reached the selected video server")
	}
}

func TestYouTubeVerifiedRecoveryLive(t *testing.T) {
	if os.Getenv("EVASION_YOUTUBE_VERIFIED") != "1" {
		t.Skip("explicit live recovery validation")
	}
	cfg, e := config.Load(os.Getenv("EVASION_YOUTUBE_NATIVE_CONFIG"))
	if e != nil {
		t.Fatal(e)
	}
	d, _ := cfg.DomainSet(nil)
	d, on := prepareYouTubeAuto(cfg, d, nil)
	if !on {
		t.Fatal("YouTube scope not available")
	}
	s := cfg.Strategies["video"]
	if s == nil {
		s = cfg.Strategy
	}
	base, e := proxy.NewGroupProvider(s, d)
	if e != nil {
		t.Fatal(e)
	}
	p, e := newYouTubeMux(base, d)
	if e != nil {
		t.Fatal(e)
	}
	inject, e := windivert.OpenPriority("false", -3000)
	if e != nil {
		t.Fatal(e)
	}
	defer inject.Close()
	if host := os.Getenv("EVASION_YOUTUBE_CDN"); validMediaHost(host) {
		p.media = host
		p.mediaAt = time.Now()
	}
	p.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
		if e != nil {
			return nil, e
		}
		port := c.LocalAddr().(*net.TCPAddr).Port
		h, e := windivert.OpenPriority(fmt.Sprintf("outbound and tcp and tcp.SrcPort == %d and tcp.DstPort == 443 and not impostor", port), 300)
		if e != nil {
			c.Close()
			return nil, e
		}
		engine, e := intercept.New(intercept.Options{Source: h, Sink: isolatedYouTubeSink{inject}, Flows: flow.NewTable(8, time.Minute, intercept.TLSHelloDetector), Provider: p, Exec: packetexec.New(), Parse: intercept.TLSHelloParser, IncludePacketMetadata: true})
		if e != nil {
			h.Close()
			c.Close()
			return nil, e
		}
		done := make(chan struct{})
		go func() { defer close(done); engine.Run(context.Background()) }()
		return &youtubeConn{Conn: c, release: func() {
			engine.SetTransparent(true)
			h.ShutdownReceive()
			select {
			case <-done:
			case <-time.After(time.Second):
				h.Close()
				<-done
			}
			h.Close()
		}}, nil
	}
	dir := t.TempDir()
	if v := os.Getenv("EVASION_YOUTUBE_NATIVE_STATE"); v != "" {
		dir = v
	}
	cold := os.Getenv("EVASION_YOUTUBE_COLD") == "1"
	coldProfile := os.Getenv("EVASION_YOUTUBE_PROFILE")
	if coldProfile == "" {
		coldProfile = "media-sld"
	}
	if cold {
		media, observed := p.mediaHost()
		if !observed {
			t.Fatal("cold-start validation requires EVASION_YOUTUBE_CDN")
		}
		id := youtubeIdentity(cfg)
		if id == "" {
			t.Fatal("no network identity")
		}
		writeYouTubeJSON(dir+"/youtube-known-good.json", youtubeWarmProfile{Identity: id, Profile: coldProfile, At: time.Now(), Media: media})
		p.media = ""
	}
	a := newYouTubeRecovery(p, cfg, dir)
	if cold {
		media, observed := a.p.mediaHost()
		if a.p.current() != coldProfile || !observed || media == "redirector.googlevideo.com" {
			t.Fatal("cold start did not restore the verified profile and media endpoint")
		}
	}
	if os.Getenv("EVASION_YOUTUBE_FORCE_RECOVERY") == "1" {
		a.network = a.identity()
		p.set("overlap")
	}
	a.publish = func(s youtubeHealth) { t.Logf("phase=%s profile=%s checks=%+v", s.Phase, s.Profile, s.Checks) }
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	good := 0
	targetGood := 2
	if cold {
		targetGood = 5
	}
	started := time.Now()
	for i := 0; i < 10; i++ {
		a.round(ctx)
		if a.state.Phase == "healthy" || a.state.Phase == "recovered" || a.state.Phase == "awaiting_media" {
			good++
		} else {
			good = 0
		}
		if good >= targetGood {
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	if good < targetGood {
		t.Fatal("real probes could not maintain a verified profile", a.state)
	}
	if cold && (a.state.Switches != 0 || a.p.current() != coldProfile) {
		t.Fatal("cold start switched away from the verified profile", a.state)
	}
	t.Logf("validated %d consecutive healthy rounds in %s", good, time.Since(started).Round(time.Millisecond))
	if os.Getenv("EVASION_YOUTUBE_FORCE_RECOVERY") == "1" && a.state.Switches == 0 {
		t.Fatal("forced failed profile was not replaced")
	}

}

func TestYouTubeIsolatedProfiles(t *testing.T) {
	if os.Getenv("EVASION_YOUTUBE_ISOLATED") != "1" {
		t.Skip("explicit scoped network test")
	}
	host := os.Getenv("EVASION_YOUTUBE_CDN")
	if host == "" {
		host = "www.youtube.com"
	}
	good := 0
	for _, name := range []string{"split-forward", "fake-split", "fake-overlap", "overlap", "split-sld", "multisplit", "fake-multisplit", "fake-disorder"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(host, "443"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			port := c.LocalAddr().(*net.TCPAddr).Port
			h, err := windivert.OpenPriority(fmt.Sprintf("outbound and tcp and tcp.SrcPort == %d and tcp.DstPort == 443 and not impostor", port), 300)
			if err != nil {
				t.Fatal(err)
			}
			strat, err := youtubetune.Profile(name, nil)
			if err != nil {
				h.Close()
				t.Fatal(err)
			}
			p, _ := proxy.NewStaticProvider(strat)
			inject, err := windivert.OpenPriority("false", -3000)
			if err != nil {
				h.Close()
				t.Fatal(err)
			}
			defer inject.Close()
			e, err := intercept.New(intercept.Options{Source: h, Sink: isolatedYouTubeSink{inject}, Flows: flow.NewTable(8, time.Minute, intercept.TLSHelloDetector), Provider: p, Exec: packetexec.New(), Parse: intercept.TLSHelloParser})
			if err != nil {
				h.Close()
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { defer close(done); e.Run(context.Background()) }()
			defer func() {
				e.SetTransparent(true)
				h.ShutdownReceive()
				select {
				case <-done:
				case <-time.After(time.Second):
					h.Close()
					<-done
				}
				h.Close()
			}()
			tc := tls.Client(c, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
			tc.SetDeadline(time.Now().Add(5 * time.Second))
			if err = tc.HandshakeContext(ctx); err != nil {
				t.Log("UNAVAILABLE", err)
				return
			}
			tr := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return tc, nil }, DisableKeepAlives: true}
			defer tr.CloseIdleConnections()
			r, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + host + "/generate_204")
			if err != nil {
				t.Log("UNAVAILABLE", err)
				return
			}
			defer r.Body.Close()
			io.Copy(io.Discard, io.LimitReader(r.Body, 1024))
			t.Log("HTTP", r.StatusCode)
			if r.StatusCode == 204 || r.StatusCode == 404 {
				good++
			}
		})
	}
	if good == 0 {
		t.Fatal("no DPI profile reached the selected endpoint")
	}
}
