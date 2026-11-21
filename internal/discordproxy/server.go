package discordproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DialContextFunc func(context.Context, string, string) (net.Conn, error)

type Server struct {
	Dial   DialContextFunc
	Logger *slog.Logger
	wg     sync.WaitGroup
}

func AllowedHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, domain := range []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discord.co", "discordstatus.com"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func allowedTarget(address string) (string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || !AllowedHost(host) {
		return "", fmt.Errorf("адрес не относится к Discord")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", fmt.Errorf("некорректный порт")
	}
	switch port {
	case 443, 2053, 2083, 2087, 2096, 8443:
	default:
		return "", fmt.Errorf("порт запрещён")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-closed:
		}
	}()
	defer close(closed)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return ctx.Err()
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	stopClient := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stopClient()

	reader := bufio.NewReader(client)
	req, err := http.ReadRequest(reader)
	if err != nil {
		writeError(client, http.StatusBadRequest)
		return
	}
	if req.Method != http.MethodConnect {
		writeError(client, http.StatusMethodNotAllowed)
		return
	}
	target, err := allowedTarget(req.Host)
	if err != nil {
		writeError(client, http.StatusForbidden)
		return
	}
	dial := s.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	upstream, err := dial(ctx, "tcp", target)
	if err != nil {
		writeError(client, http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stopUpstream()
	if _, err = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, reader)
		_ = upstream.Close()
		_ = client.Close()
		close(done)
	}()
	_, _ = io.Copy(client, upstream)
	_ = upstream.Close()
	_ = client.Close()
	<-done
}

func writeError(w io.Writer, status int) {
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
}
