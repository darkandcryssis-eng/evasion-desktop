package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/fitting-1c/evasion/internal/gameproxy"
	"github.com/fitting-1c/evasion/internal/telegramproxy"
	xproxy "golang.org/x/net/proxy"
)

const defaultTelegramTunnelListen = "127.0.0.1:17659"

type telegramTunnel struct {
	Listen string
	worker *gameproxy.Worker
	ln     net.Listener
	cancel context.CancelFunc
	done   chan struct{}
	err    error
	once   sync.Once
}

func startTelegramTunnel(parent context.Context, profile, xray, listen string) (*telegramTunnel, error) {
	if profile == "" {
		return nil, errors.New("не задан профиль маршрута Telegram")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, errors.New("некорректный адрес локального прокси Telegram")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return nil, errors.New("прокси Telegram разрешён только на loopback")
	}
	if xray == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		xray = filepath.Join(filepath.Dir(exe), "xray.exe")
	}
	ctx, cancel := context.WithCancel(parent)
	worker, err := gameproxy.StartWorker(ctx, profile, xray)
	if err != nil {
		cancel()
		return nil, err
	}
	dialer, err := xproxy.SOCKS5("tcp", worker.Endpoint, nil, xproxy.Direct)
	if err != nil {
		worker.Close()
		cancel()
		return nil, fmt.Errorf("не удалось настроить локальный канал Telegram: %w", err)
	}
	contextDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		worker.Close()
		cancel()
		return nil, errors.New("локальный канал Telegram не поддерживает контекст")
	}
	ln, err := net.Listen("tcp4", listen)
	if err != nil {
		worker.Close()
		cancel()
		return nil, fmt.Errorf("не удалось открыть локальный прокси Telegram: %w", err)
	}
	t := &telegramTunnel{Listen: ln.Addr().String(), worker: worker, ln: ln, cancel: cancel, done: make(chan struct{})}
	server := &telegramproxy.Server{Dial: contextDialer.DialContext}
	go func() {
		err := server.Serve(ctx, ln)
		if ctx.Err() == nil {
			t.err = err
		}
		close(t.done)
	}()
	go func() {
		select {
		case <-worker.Done():
			cancel()
			_ = ln.Close()
		case <-ctx.Done():
		}
	}()
	return t, nil
}

func (t *telegramTunnel) Close() {
	t.once.Do(func() {
		t.cancel()
		_ = t.ln.Close()
		t.worker.Close()
		<-t.done
	})
}
