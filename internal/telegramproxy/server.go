package telegramproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

type DialContextFunc func(context.Context, string, string) (net.Conn, error)

type Server struct {
	Dial DialContextFunc
	wg   sync.WaitGroup
}

var dataCenterIPs = map[netip.Addr]bool{
	netip.MustParseAddr("149.154.175.50"):  true,
	netip.MustParseAddr("149.154.167.51"):  true,
	netip.MustParseAddr("149.154.175.100"): true,
	netip.MustParseAddr("149.154.167.91"):  true,
	netip.MustParseAddr("149.154.171.5"):   true,
	netip.MustParseAddr("91.105.192.100"):  true,
}

func allowedTarget(address string) (string, error) {
	target, err := netip.ParseAddrPort(address)
	if err != nil || target.Port() != 443 || !dataCenterIPs[target.Addr().Unmap()] {
		return "", fmt.Errorf("разрешены только дата-центры Telegram на порту 443")
	}
	return net.JoinHostPort(target.Addr().Unmap().String(), "443"), nil
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
