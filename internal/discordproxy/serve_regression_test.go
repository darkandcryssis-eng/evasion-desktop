package discordproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeClosesRelaysOnAcceptError(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upstream, peer := net.Pipe()
	defer peer.Close()
	s := &Server{Dial: func(context.Context, string, string) (net.Conn, error) {
		return upstream, nil
	}}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	client, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(client, "CONNECT gateway.discord.gg:443 HTTP/1.1\r\nHost: gateway.discord.gg:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", response.StatusCode)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after the listener closed")
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("relay read after Serve returned = %v, want EOF", err)
	}
}
