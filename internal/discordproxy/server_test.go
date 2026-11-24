package discordproxy

import (
	"bufio"
	"context"
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

func TestNoReplyDropsSilentUpstream(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{NoReply: 100 * time.Millisecond, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Addr().String())
	}}
	go func() { _ = s.Serve(ctx, ln) }()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT discord.com:443 HTTP/1.1\r\nHost: discord.com:443\r\n\r\n")
	buf := make([]byte, 64)
	if _, err = c.Read(buf); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("\x16\x03\x01\x00\x05hello"))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err = c.Read(buf); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("silent upstream not dropped: err=%v after %v", err, time.Since(start))
	}
}

func TestStalledHandshakeIsDroppedAndReported(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 16)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("server flight"))
				n, _ := c.Read(buf)
				if n > 0 && buf[0] == 23 {
					_, _ = c.Write([]byte("ticket"))
				}
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stalled := make(chan string, 1)
	s := &Server{NoReply: 100 * time.Millisecond, OnStall: func(host string) { stalled <- host }, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Addr().String())
	}}
	go func() { _ = s.Serve(ctx, ln) }()
	open := func() net.Conn {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, "CONNECT discord.com:443 HTTP/1.1\r\nHost: discord.com:443\r\n\r\n")
		buf := make([]byte, 39)
		if _, err = io.ReadFull(c, buf); err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("\x16\x03\x01\x00\x05hello"))
		return c
	}
	// Клиент ответил на рукопожатие сервера — соединение живое, его не трогают.
	alive := open()
	defer alive.Close()
	buf := make([]byte, 64)
	if _, err = alive.Read(buf); err != nil {
		t.Fatal(err)
	}
	_, _ = alive.Write([]byte("\x17\x03\x03\x00\x03fin"))
	if _, err = alive.Read(buf); err != nil {
		t.Fatal(err)
	}
	// Узел прислал начало ответа и замолчал, клиент не может завершить
	// рукопожатие (но успел отправить ChangeCipherSpec).
	stuck := open()
	defer stuck.Close()
	if _, err = stuck.Read(buf); err != nil {
		t.Fatal(err)
	}
	_, _ = stuck.Write([]byte("\x14\x03\x03\x00\x01\x01"))
	select {
	case host := <-stalled:
		if host != "discord.com" {
			t.Fatalf("host = %q", host)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stalled handshake not reported")
	}
	_ = alive.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	if _, err = alive.Read(buf); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("live connection was dropped: %v", err)
	}
	select {
	case <-stalled:
		t.Fatal("live connection reported as stalled")
	default:
	}
}

func TestTLSRecordsDetectsAppData(t *testing.T) {
	var done atomic.Bool
	var down, flight atomic.Int64
	r := &tlsRecords{done: &done, down: &down, flight: &flight}
	hello := append([]byte{22, 3, 1, 0, 4}, 1, 2, 3, 4)
	for _, b := range hello {
		r.feed([]byte{b})
	}
	r.feed([]byte{20, 3, 3, 0, 1, 1})
	if done.Load() {
		t.Fatal("handshake records marked as finished")
	}
	r.feed([]byte{23, 3, 3})
	if done.Load() {
		t.Fatal("partial header marked as finished")
	}
	r.feed([]byte{0, 1, 9})
	if !done.Load() {
		t.Fatal("application data not detected")
	}
}

func TestSilenceAfterHandshakeIsDropped(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 16)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("server flight"))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stalled := make(chan string, 1)
	s := &Server{NoReply: 100 * time.Millisecond, OnStall: func(host string) { stalled <- host }, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Addr().String())
	}}
	go func() { _ = s.Serve(ctx, ln) }()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT discord.com:443 HTTP/1.1\r\nHost: discord.com:443\r\n\r\n")
	buf := make([]byte, 39)
	if _, err = io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("\x16\x03\x01\x00\x05hello"))
	if _, err = c.Read(buf); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("\x14\x03\x03\x00\x01\x01\x17\x03\x03\x00\x03fin"))
	select {
	case <-stalled:
	case <-time.After(3 * time.Second):
		t.Fatal("silence after handshake not reported")
	}
}

func TestUnansweredRequestIsDropped(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("server flight"))
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("tickets"))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stalled := make(chan string, 2)
	s := &Server{NoReply: 100 * time.Millisecond, OnStall: func(host string) { stalled <- host }, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Addr().String())
	}}
	go func() { _ = s.Serve(ctx, ln) }()
	open := func(request int) net.Conn {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, "CONNECT discord.com:443 HTTP/1.1\r\nHost: discord.com:443\r\n\r\n")
		buf := make([]byte, 64)
		if _, err = io.ReadFull(c, buf[:39]); err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("\x16\x03\x01\x00\x05hello"))
		if _, err = c.Read(buf); err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("\x17\x03\x03\x00\x03fin"))
		if _, err = c.Read(buf); err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(make([]byte, request))
		return c
	}
	// Мелкая служебная запись без ответа — соединение простаивает, его не трогают.
	idle := open(31)
	defer idle.Close()
	select {
	case <-stalled:
		t.Fatal("idle connection reported as stalled")
	case <-time.After(700 * time.Millisecond):
	}
	busy := open(600)
	defer busy.Close()
	select {
	case <-stalled:
	case <-time.After(3 * time.Second):
		t.Fatal("unanswered request not reported")
	}
}

func TestRecordCutMarksPartialRecord(t *testing.T) {
	var partial atomic.Bool
	cut := &recordCut{partial: &partial}
	cut.feed([]byte("\x17\x03\x03\x00\x04ab"))
	if !partial.Load() {
		t.Fatal("запись получена не целиком, а поток не помечен")
	}
	cut.feed([]byte("cd"))
	if partial.Load() {
		t.Fatal("запись получена целиком, а поток помечен")
	}
	cut.feed([]byte("\x17\x03"))
	if !partial.Load() {
		t.Fatal("заголовок записи оборван, а поток не помечен")
	}
	cut.feed([]byte("\x03\x00\x01x"))
	if partial.Load() {
		t.Fatal("после целой записи поток помечен")
	}
	cut.feed([]byte("plain text"))
	if partial.Load() {
		t.Fatal("поток не TLS должен сниматься с наблюдения")
	}
}

// Узел завершает обмен как положено, а затем присылает начало большой записи
// и замолкает: соединение обязано быть оборвано, сколько бы оно ни прожило.
func TestResponseFrozenMidRecordIsDropped(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("\x17\x03\x03\x00\x02ok"))
				_, _ = c.Read(buf)
				if string(buf[:4]) == "cut!" {
					_, _ = c.Write([]byte("\x17\x03\x03\x40\x00start of a long record"))
				} else {
					_, _ = c.Write([]byte("\x17\x03\x03\x00\x04done"))
				}
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stalled := make(chan string, 2)
	s := &Server{NoReply: 100 * time.Millisecond, OnStall: func(host string) { stalled <- host }, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Addr().String())
	}}
	go func() { _ = s.Serve(ctx, ln) }()
	open := func(second string) net.Conn {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, "CONNECT gateway.discord.gg:443 HTTP/1.1\r\nHost: gateway.discord.gg:443\r\n\r\n")
		buf := make([]byte, 64)
		if _, err = io.ReadFull(c, buf[:39]); err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("\x17\x03\x03\x00\x05hello"))
		if _, err = io.ReadFull(c, buf[:7]); err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte(second))
		return c
	}
	healthy := open("fine")
	defer healthy.Close()
	frozen := open("cut!")
	defer frozen.Close()
	select {
	case host := <-stalled:
		if host != "gateway.discord.gg" {
			t.Fatalf("оборван узел %q", host)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("соединение с ответом, замершим посреди записи, не оборвано")
	}
	_ = frozen.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.Copy(io.Discard, frozen); err != nil {
		t.Fatalf("замёрзшее соединение не закрыто: %v", err)
	}
	select {
	case host := <-stalled:
		t.Fatalf("оборвано и живое соединение %q", host)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestServesPAC(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{PAC: func() string { return "function FindProxyForURL(url, host) { return \"DIRECT\"; }" }}
	go func() { _ = s.Serve(ctx, ln) }()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET /proxy.pac?v=3 HTTP/1.1\r\nHost: "+ln.Addr().String()+"\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	body, _ := io.ReadAll(c)
	if !strings.Contains(string(body), "200 OK") || !strings.Contains(string(body), "application/x-ns-proxy-autoconfig") || !strings.Contains(string(body), "FindProxyForURL") {
		t.Fatalf("ответ на запрос сценария: %q", body)
	}
}
