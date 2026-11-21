package telegramproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestAllowedTarget(t *testing.T) {
	for _, target := range []string{"149.154.167.51:443", "149.154.175.50:443", "91.105.192.100:443"} {
		if _, err := allowedTarget(target); err != nil {
			t.Errorf("rejected %s: %v", target, err)
		}
	}
	for _, target := range []string{"149.154.167.51:80", "149.154.167.52:443", "www.telegram.org:443", "127.0.0.1:443", ""} {
		if _, err := allowedTarget(target); err == nil {
			t.Errorf("allowed %s", target)
		}
	}
}

func TestConnectAndRejectOtherServices(t *testing.T) {
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()
	var dialed string
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{Dial: func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		return net.Dial("tcp", echo.Addr().String())
	}}
	done := make(chan struct{})
	go func() { _ = server.Serve(ctx, ln); close(done) }()
	defer func() { cancel(); ln.Close(); <-done }()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT 149.154.167.51:443 HTTP/1.1\r\nHost: 149.154.167.51:443\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || dialed != "149.154.167.51:443" {
		t.Fatalf("status=%s dialed=%q", response.Status, dialed)
	}
	fmt.Fprint(conn, "ping")
	buf := make([]byte, 4)
	if _, err = io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("relay=%q err=%v", buf, err)
	}
	other, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	fmt.Fprint(other, "CONNECT www.youtube.com:443 HTTP/1.1\r\nHost: www.youtube.com:443\r\n\r\n")
	response, err = http.ReadResponse(bufio.NewReader(other), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected target status: %s", response.Status)
	}
}
