package tgproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	xproxy "golang.org/x/net/proxy"
)

func SOCKSDialer(endpoint string) dialFunc {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return func(context.Context, route) (peer, error) { return nil, err }
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return func(context.Context, route) (peer, error) {
			return nil, errors.New("резервный SOCKS Telegram разрешён только на loopback")
		}
	}
	dialer, err := xproxy.SOCKS5("tcp", endpoint, nil, xproxy.Direct)
	if err != nil {
		return func(context.Context, route) (peer, error) { return nil, err }
	}
	contextDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		return func(context.Context, route) (peer, error) {
			return nil, errors.New("локальный канал Telegram не поддерживает контекст")
		}
	}
	return func(ctx context.Context, candidate route) (peer, error) {
		if !candidate.tunnel || candidate.address == "" {
			return nil, fmt.Errorf("недопустимая цель канала Telegram")
		}
		conn, err := contextDialer.DialContext(ctx, "tcp", candidate.address)
		if err != nil {
			return nil, err
		}
		tuneSocket(conn)
		return &tcpPeer{conn}, nil
	}
}

func CONNECTDialer(endpoint string) dialFunc {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return func(context.Context, route) (peer, error) { return nil, err }
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return func(context.Context, route) (peer, error) {
			return nil, errors.New("резервный CONNECT Telegram разрешён только на loopback")
		}
	}
	return func(ctx context.Context, candidate route) (peer, error) {
		if !candidate.tunnel || candidate.address == "" {
			return nil, fmt.Errorf("недопустимая цель канала Telegram")
		}
		conn, err := (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", endpoint)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", candidate.address, candidate.address); err != nil {
			_ = conn.Close()
			return nil, err
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			_ = conn.Close()
			return nil, fmt.Errorf("локальный канал Telegram: HTTP %d", response.StatusCode)
		}
		_ = conn.SetDeadline(time.Time{})
		tuneSocket(conn)
		return &tcpPeer{conn}, nil
	}
}
