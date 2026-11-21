package youtubeproxy

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
	"sync/atomic"
	"time"

	"github.com/fitting-1c/evasion/internal/youtubetune"
)

type DialContextFunc func(context.Context, string, string) (net.Conn, error)

type Router struct {
	Direct DialContextFunc
	Tunnel DialContextFunc
	tunnel atomic.Bool
}

func (r *Router) SetTunnel(enabled bool) { r.tunnel.Store(enabled) }
func (r *Router) UsingTunnel() bool      { return r.tunnel.Load() }

func (r *Router) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	direct := r.Direct
	if direct == nil {
		direct = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	if r.UsingTunnel() && r.Tunnel != nil {
		conn, err := r.Tunnel(ctx, network, address)
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
	}
	return direct(ctx, network, address)
}

type Server struct {
	Router *Router
	Logger *slog.Logger
	PAC    string
	Trace  bool
	wg     sync.WaitGroup
}

func AllowedHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	return youtubetune.IsYouTube(host)
}

func allowedTarget(address string) (string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || !AllowedHost(host) {
		return "", fmt.Errorf("адрес не относится к YouTube")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port != 443 {
		return "", fmt.Errorf("разрешён только HTTPS-порт 443")
	}
	return net.JoinHostPort(host, "443"), nil
}

func PAC(proxyAddress string) string {
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n")
	b.WriteString("  host = host.toLowerCase();\n")
	b.WriteString("  if (shExpMatch(url, \"https://*\") && (\n")
	for i, domain := range youtubetune.Domains {
		if i > 0 {
			b.WriteString(" ||\n")
		}
		fmt.Fprintf(&b, "      host == %q || dnsDomainIs(host, %q)", domain, "."+domain)
	}
	b.WriteString(")) {\n")
	fmt.Fprintf(&b, "    return \"PROXY %s; DIRECT\";\n", proxyAddress)
	b.WriteString("  }\n  return \"DIRECT\";\n}\n")
	return b.String()
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
	if req.Method == http.MethodGet && req.URL.Path == "/proxy.pac" && s.PAC != "" {
		_ = client.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = fmt.Fprintf(client, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nCache-Control: no-cache\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(s.PAC), s.PAC)
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
	if s.Router == nil {
		writeError(client, http.StatusBadGateway)
		return
	}
	if s.Trace && s.Logger != nil {
		s.Logger.Info("YouTube CONNECT", "target", target, "vless", s.Router.UsingTunnel())
	}
	upstream, err := s.Router.DialContext(ctx, "tcp", target)
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
