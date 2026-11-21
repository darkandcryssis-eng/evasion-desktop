package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/quic"
	quicgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestYouTubeProbesRequireTLSAndExpectedResponse(t *testing.T) {
	status := 204
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	old := youtubeProbeURLs["site"]
	youtubeProbeURLs["site"] = srv.URL
	defer func() { youtubeProbeURLs["site"] = old }()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	trusted := &tls.Config{RootCAs: roots}
	if !probeYouTubeHTTP(context.Background(), "site", "tcp", trusted).OK {
		t.Fatal("valid TLS response failed")
	}
	if probeYouTubeHTTP(context.Background(), "site", "tcp", nil).OK {
		t.Fatal("untrusted TLS accepted")
	}
	for _, code := range []int{200, 302, 403, 503} {
		status = code
		if probeYouTubeHTTP(context.Background(), "site", "tcp", trusted).OK {
			t.Fatal("wrong status accepted", code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if probeYouTubeHTTP(ctx, "site", "tcp", trusted).OK {
		t.Fatal("cancellation ignored")
	}
}

func TestYouTubeProbeRealHTTP3(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsServer.Close()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: tlsServer.TLS.Clone(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(conn) }()
	defer func() { server.Close(); conn.Close(); <-done }()
	old := youtubeProbeURLs["site"]
	youtubeProbeURLs["site"] = "https://" + conn.LocalAddr().String()
	defer func() { youtubeProbeURLs["site"] = old }()
	roots := x509.NewCertPool()
	roots.AddCert(tlsServer.Certificate())
	result := probeYouTubeHTTP(context.Background(), "site", "h3", &tls.Config{RootCAs: roots})
	if !result.OK {
		t.Fatal("real HTTP/3 response failed", result)
	}
}

type youtubeQUICConn struct{ packets, sent []capture.Packet }

func (c *youtubeQUICConn) Recv() (capture.Packet, error) {
	if len(c.packets) == 0 {
		return capture.Packet{}, io.EOF
	}
	p := c.packets[0]
	c.packets = c.packets[1:]
	return p, nil
}
func (c *youtubeQUICConn) Send(p capture.Packet) error { c.sent = append(c.sent, p); return nil }

func initialForYouTube(t *testing.T) []byte {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = quicgo.DialAddr(ctx, listener.LocalAddr().String(), &tls.Config{ServerName: "youtube.com", CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"h3"}}, &quicgo.Config{Versions: []quicgo.Version{quicgo.Version1}})
	}()
	listener.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 4096)
	n, _, err := listener.ReadFrom(b)
	cancel()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if sni, ok := quic.PeekSNI(b[:n]); !ok || sni != "youtube.com" {
		t.Fatal("invalid test Initial", sni)
	}
	return b[:n]
}

func TestScopedYouTubeQUICPreservesOtherTraffic(t *testing.T) {
	yt := capture.Packet{Data: udp4(443, initialForYouTube(t)), Dir: core.DirectionOutbound}
	other := capture.Packet{Data: udp4(443, mustHex(t, clientInitialExampleCom)), Dir: core.DirectionOutbound}
	for _, tc := range []struct {
		name              string
		global, yt        config.QUICMode
		wantYT, wantOther bool
		rewritten         bool
	}{
		{"youtube-only-block", config.QUICOff, config.QUICBlock, false, true, false},
		{"youtube-exempt", config.QUICBlock, config.QUICOff, true, false, false},
		{"youtube-desync-unsupported-initial-passed-safely", config.QUICOff, config.QUICDesync, true, true, false},
		{"unchanged-block", config.QUICBlock, config.QUICBlock, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &youtubeQUICConn{packets: []capture.Packet{yt, other}}
			runQUICBlock(context.Background(), c, domainSetFor(t, "youtube.com", "example.com"), tc.global, quic.NewReassembler(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)), tc.yt)
			want := 0
			if tc.wantYT {
				want++
			}
			if tc.wantOther {
				want++
			}
			if len(c.sent) != want {
				t.Fatalf("sent=%d want=%d", len(c.sent), want)
			}
			if tc.wantYT && tc.rewritten == bytes.Equal(c.sent[0].Data, yt.Data) {
				t.Fatal("wrong YouTube rewrite")
			}
			if tc.wantOther && !bytes.Equal(c.sent[len(c.sent)-1].Data, other.Data) {
				t.Fatal("other service packet changed")
			}
		})
	}
}
