package youtubeproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAllowedHost(t *testing.T) {
	for _, host := range []string{"youtube.com", "www.youtube.com", "rr1---sn-example.googlevideo.com", "i.ytimg.com", "youtubei.googleapis.com", "yt3.ggpht.com", "YOUTU.BE."} {
		if !AllowedHost(host) {
			t.Errorf("rejected %s", host)
		}
	}
	for _, host := range []string{"discord.com", "googleapis.com", "www.googleapis.com", "googleusercontent.com", "youtube.com.example.com", "notyoutube.com", "127.0.0.1", ""} {
		if AllowedHost(host) {
			t.Errorf("allowed %s", host)
		}
	}
}

func TestPACRoutesOnlyYouTubeHTTPS(t *testing.T) {
	pac := PAC("127.0.0.1:17658")
	for _, want := range []string{`PROXY 127.0.0.1:17658; DIRECT`, `host == "youtube.com"`, `host == "googlevideo.com"`, `host == "youtubei.googleapis.com"`, `shExpMatch(url, "https://*")`, `return "DIRECT"`} {
		if !strings.Contains(pac, want) {
			t.Errorf("PAC does not contain %q", want)
		}
	}
	for _, unwanted := range []string{"discord", `host == "googleapis.com"`, `host == "googleusercontent.com"`} {
		if strings.Contains(pac, unwanted) {
			t.Errorf("PAC contains overly broad rule %q", unwanted)
		}
	}
}

func TestRouterUsesTunnelAndFallsBackToDirect(t *testing.T) {
	directConn, directPeer := net.Pipe()
	defer directPeer.Close()
	tunnelConn, tunnelPeer := net.Pipe()
	defer tunnelPeer.Close()
	var directCalls, tunnelCalls atomic.Int32
	r := &Router{
		Direct: func(context.Context, string, string) (net.Conn, error) {
			directCalls.Add(1)
			return directConn, nil
		},
		Tunnel: func(context.Context, string, string) (net.Conn, error) {
			tunnelCalls.Add(1)
			return tunnelConn, nil
		},
	}
	if conn, err := r.DialContext(t.Context(), "tcp", "www.youtube.com:443"); err != nil || conn != directConn {
		t.Fatalf("direct route: conn=%p err=%v", conn, err)
	}
	r.SetTunnel(true)
	if conn, err := r.DialContext(t.Context(), "tcp", "www.youtube.com:443"); err != nil || conn != tunnelConn {
		t.Fatalf("tunnel route: conn=%p err=%v", conn, err)
	}
	r.Tunnel = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unavailable") }
	if conn, err := r.DialContext(t.Context(), "tcp", "www.youtube.com:443"); err != nil || conn != directConn {
		t.Fatalf("direct fallback: conn=%p err=%v", conn, err)
	}
	if directCalls.Load() != 2 || tunnelCalls.Load() != 1 {
		t.Fatalf("direct=%d tunnel=%d", directCalls.Load(), tunnelCalls.Load())
	}
}

func TestConnectAndPAC(t *testing.T) {
	echo := echoServer(t)
	var dialed string
	proxyAddr := serve(t, &Router{Direct: func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		return net.Dial("tcp", echo)
	}})
	conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "CONNECT www.youtube.com:443 HTTP/1.1\r\nHost: www.youtube.com:443\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || dialed != "www.youtube.com:443" {
		t.Fatalf("status=%s dialed=%q", response.Status, dialed)
	}
	fmt.Fprint(conn, "ping")
	buf := make([]byte, 4)
	if _, err = io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("relay=%q err=%v", buf, err)
	}
	conn.Close()

	body, err := http.Get("http://" + proxyAddr + "/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	defer body.Body.Close()
	pac, _ := io.ReadAll(body.Body)
	if body.StatusCode != http.StatusOK || !strings.Contains(string(pac), proxyAddr) {
		t.Fatalf("PAC status=%s body=%q", body.Status, pac)
	}
}

func TestRejectsOtherServices(t *testing.T) {
	var dialed atomic.Bool
	proxyAddr := serve(t, &Router{Direct: func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, fmt.Errorf("unexpected dial")
	}})
	for _, target := range []string{"discord.com:443", "googleapis.com:443", "www.youtube.com:80", "www.youtube.com.example.com:443"} {
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		conn.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %s", target, response.Status)
		}
	}
	if dialed.Load() {
		t.Fatal("rejected target reached dialer")
	}
}

func serve(t *testing.T, router *Router) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{Router: router}
	done := make(chan struct{})
	go func() {
		_ = s.Serve(ctx, ln)
		close(done)
	}()
	s.PAC = PAC(ln.Addr().String())
	t.Cleanup(func() {
		cancel()
		ln.Close()
		<-done
	})
	return ln.Addr().String()
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return strings.TrimSpace(ln.Addr().String())
}
