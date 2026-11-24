package discordproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAllowedHost(t *testing.T) {
	for _, host := range []string{"discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net", "updates.discord.com", "eu123.discord.media", "DISCORD.COM."} {
		if !AllowedHost(host) {
			t.Errorf("rejected %s", host)
		}
	}
	for _, host := range []string{"youtube.com", "evildiscord.com", "discord.com.example.com", "127.0.0.1", ""} {
		if AllowedHost(host) {
			t.Errorf("allowed %s", host)
		}
	}
}

func TestConnect(t *testing.T) {
	echo := echoServer(t)
	var dialed string
	proxyAddr := serve(t, func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		return net.Dial("tcp", echo)
	})
	conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT gateway.discord.gg:443 HTTP/1.1\r\nHost: gateway.discord.gg:443\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || dialed != "gateway.discord.gg:443" {
		t.Fatalf("status=%s dialed=%q", response.Status, dialed)
	}
	fmt.Fprint(conn, "ping")
	buf := make([]byte, 4)
	if _, err = io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("relay=%q err=%v", buf, err)
	}
}

func TestRejectsOtherServices(t *testing.T) {
	dialed := false
	proxyAddr := serve(t, func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, fmt.Errorf("unexpected dial")
	})
	for _, target := range []string{"www.youtube.com:443", "discord.com.example.com:443", "discord.com:80"} {
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
	if dialed {
		t.Fatal("rejected target reached dialer")
	}
}

func serve(t *testing.T, dial DialContextFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{Dial: dial}
	done := make(chan struct{})
	go func() {
		_ = s.Serve(ctx, ln)
		close(done)
	}()
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

func TestPassthroughForOtherServices(t *testing.T) {
	echo := echoServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var direct, through string
	server := &Server{
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			direct = address
			return net.Dial("tcp", echo)
		},
		Passthrough: func(_ context.Context, _, address string) (net.Conn, error) {
			through = address
			return net.Dial("tcp", echo)
		},
	}
	go func() { _ = server.Serve(ctx, ln) }()

	status := func(target string) int {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if got := status("hcaptcha.com:443"); got != http.StatusOK || through != "hcaptcha.com:443" || direct != "" {
		t.Fatalf("сторонний узел: status=%d through=%q direct=%q", got, through, direct)
	}
	if got := status("example.com:25"); got != http.StatusForbidden {
		t.Fatalf("чужой порт пропущен: %d", got)
	}
	if got := status("discord.com:443"); got != http.StatusOK || direct != "discord.com:443" {
		t.Fatalf("узел Discord: status=%d direct=%q", got, direct)
	}
}

func TestSummaryCountsRelayedBytes(t *testing.T) {
	echo := echoServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server := &Server{Dial: func(context.Context, string, string) (net.Conn, error) { return net.Dial("tcp", echo) }}
	served := make(chan struct{})
	go func() { _ = server.Serve(ctx, ln); close(served) }()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "CONNECT discord.com:443 HTTP/1.1\r\nHost: discord.com:443\r\n\r\n")
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	fmt.Fprint(conn, "ping")
	if _, err = io.ReadFull(reader, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	if live := server.Summary(); !strings.Contains(live, "открыто 1, без ответа 0, отправлено 4 Б, получено 4 Б, тишина 0 с") {
		t.Fatalf("сводка по открытому соединению: %q", live)
	}
	conn.Close()
	cancel()
	<-served
	want := "discord.com: соединений 1, открыто 0, без ответа 0, отправлено 4 Б, получено 4 Б"
	if got := server.Summary(); got != want {
		t.Fatalf("сводка %q, ожидалась %q", got, want)
	}
	if got := server.Summary(); got != "" {
		t.Fatalf("повторная сводка без изменений: %q", got)
	}
}

func TestRerouteSendsDiscordHostThroughPassthrough(t *testing.T) {
	echo := echoServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var direct, through string
	server := &Server{
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			direct = address
			return net.Dial("tcp", echo)
		},
		Passthrough: func(_ context.Context, _, address string) (net.Conn, error) {
			through = address
			return net.Dial("tcp", echo)
		},
		Reroute: func(host string) bool { return host == "gateway.discord.gg" },
	}
	go func() { _ = server.Serve(ctx, ln) }()
	for _, target := range []string{"gateway.discord.gg:443", "discord.com:443"} {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
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
	}
	if through != "gateway.discord.gg:443" || direct != "discord.com:443" {
		t.Fatalf("through=%q direct=%q", through, direct)
	}
}
