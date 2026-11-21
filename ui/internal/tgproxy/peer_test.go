package tgproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestWebSocketStreamsLargePacketsAndRejectsTruncatedSource(t *testing.T) {
	payload := bytes.Repeat([]byte{1, 2, 3, 4}, 512<<10)
	received := make(chan int, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{Subprotocols: []string{"binary"}}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, body, err := c.NextReader()
		if err != nil {
			return
		}
		data, err := io.ReadAll(body)
		if err != nil {
			return
		}
		if !bytes.Equal(data, payload) {
			return
		}
		received <- len(data)
		_ = c.WriteMessage(websocket.BinaryMessage, []byte("ok"))
		_, _, _ = c.NextReader()
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: pool}, Subprotocols: []string{"binary"}}
	c, _, err := dialer.Dial("wss"+strings.TrimPrefix(server.URL, "https"), nil)
	if err != nil {
		t.Fatal(err)
	}
	p := newWSPeer(c)
	defer p.Close()
	if err := p.WritePacket(bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(p, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "ok" || <-received != len(payload) {
		t.Fatal("large fragmented WebSocket packet was corrupted")
	}
	if err := p.WritePacket(bytes.NewReader([]byte{1}), 10); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated source accepted: %v", err)
	}
}

func TestSuccessfulDialSurvivesHandshakeContextCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{Subprotocols: []string{"binary"}}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			kind, data, err := c.ReadMessage()
			if err != nil {
				return
			}
			if err := c.WriteMessage(kind, data); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	dial := newNetworkDialer(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	ctx, cancel := context.WithCancel(context.Background())
	p, err := dial(ctx, route{host: strings.TrimPrefix(server.URL, "https://")})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer p.Close()
	cancel()
	if err := p.WritePacket(bytes.NewReader([]byte("keep")), 4); err != nil {
		t.Fatalf("winning socket was closed after dial: %v", err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(p, response); err != nil || string(response) != "keep" {
		t.Fatalf("read after dial cancellation: %q %v", response, err)
	}
}
