package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/fitting-1c/evasion/internal/gameproxy"
	"github.com/fitting-1c/evasion/internal/youtubeproxy"
	xproxy "golang.org/x/net/proxy"
)

const defaultYouTubeTunnelListen = "127.0.0.1:17658"

type youtubeTunnel struct {
	Listen      string
	Router      *youtubeproxy.Router
	worker      *gameproxy.Worker
	ln          net.Listener
	cancel      context.CancelFunc
	done        chan struct{}
	err         error
	once        sync.Once
	restoreOnce sync.Once
	restore     func()
	logger      *slog.Logger
}

func startYouTubeTunnel(parent context.Context, profile, xray, listen, stateDir string, usePAC, trace bool, logger *slog.Logger) (*youtubeTunnel, error) {
	if profile == "" {
		return nil, errors.New("не задан профиль маршрута YouTube")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, errors.New("некорректный адрес локального прокси YouTube")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return nil, errors.New("прокси YouTube разрешён только на loopback")
	}
	if xray == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		xray = filepath.Join(filepath.Dir(exe), "xray.exe")
	}
	ctx, cancel := context.WithCancel(parent)
	worker, err := gameproxy.StartWorkerWithProbe(ctx, profile, xray, "https://redirector.googlevideo.com/generate_204")
	if err != nil {
		cancel()
		return nil, err
	}
	dialer, err := xproxy.SOCKS5("tcp", worker.Endpoint, nil, xproxy.Direct)
	if err != nil {
		worker.Close()
		cancel()
		return nil, fmt.Errorf("не удалось настроить локальный канал YouTube: %w", err)
	}
	contextDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		worker.Close()
		cancel()
		return nil, errors.New("локальный канал YouTube не поддерживает контекст")
	}
	ln, err := net.Listen("tcp4", listen)
	if err != nil {
		worker.Close()
		cancel()
		return nil, fmt.Errorf("не удалось открыть локальный прокси YouTube: %w", err)
	}
	t := &youtubeTunnel{Listen: ln.Addr().String(), worker: worker, ln: ln, cancel: cancel, done: make(chan struct{}), restore: func() {}, logger: logger}
	t.Router = &youtubeproxy.Router{Tunnel: contextDialer.DialContext}
	if usePAC {
		restore, err := installYouTubePAC(windowsPACSettings{}, filepath.Join(stateDir, "youtube-pac-backup.json"), "http://"+t.Listen+"/proxy.pac")
		if err != nil {
			_ = ln.Close()
			worker.Close()
			cancel()
			return nil, err
		}
		t.restore = restore
	}
	server := &youtubeproxy.Server{Router: t.Router, Logger: logger, PAC: youtubeproxy.PAC(t.Listen), Trace: trace}
	go func() {
		err := server.Serve(ctx, ln)
		if ctx.Err() == nil {
			t.err = err
		}
		t.restoreSettings()
		close(t.done)
	}()
	go func() {
		select {
		case <-worker.Done():
			logger.Error("резервный маршрут YouTube остановился")
			cancel()
			_ = ln.Close()
		case <-ctx.Done():
		}
	}()
	return t, nil
}

func (t *youtubeTunnel) Measure(ctx context.Context, short bool) []youtubeCheck {
	p := &youtubeMux{dial: t.Router.Tunnel, media: "redirector.googlevideo.com", leases: map[youtubeLease]string{}}
	return p.measure(ctx, "active", short)
}

func (t *youtubeTunnel) restoreSettings() {
	t.restoreOnce.Do(t.restore)
}

func (t *youtubeTunnel) Close() {
	t.once.Do(func() {
		t.cancel()
		_ = t.ln.Close()
		t.worker.Close()
		<-t.done
		t.restoreSettings()
	})
}

func youtubeProxyCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("youtube-proxy", flag.ContinueOnError)
	profile := fs.String("profile", "", "зашифрованный профиль VLESS")
	xray := fs.String("xray", "", "путь к xray.exe")
	listen := fs.String("listen", "127.0.0.1:0", "адрес loopback HTTP CONNECT-прокси")
	stateDir := fs.String("state-dir", defaultStateDir, "каталог состояния")
	usePAC := fs.Bool("system-pac", false, "установить per-user PAC Windows только для YouTube")
	useVLESS := fs.Bool("vless", false, "принудительно использовать VLESS вместо прямого маршрута")
	trace := fs.Bool("trace", false, "логировать разрешённые CONNECT-цели")
	jsonOut := fs.Bool("json", false, "машинно-читаемый вывод")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger := newLogger(os.Stderr, *jsonOut)
	t, err := startYouTubeTunnel(ctx, *profile, *xray, *listen, *stateDir, *usePAC, *trace, logger)
	if err != nil {
		return err
	}
	defer t.Close()
	t.Router.SetTunnel(*useVLESS)
	route := "direct"
	if *useVLESS {
		route = "vless"
	}
	if *jsonOut {
		if err = json.NewEncoder(os.Stdout).Encode(map[string]string{"listen": t.Listen, "route": route}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(os.Stdout, "%s %s\n", t.Listen, route)
	}
	select {
	case <-ctx.Done():
		return nil
	case <-t.done:
		if t.err != nil {
			return t.err
		}
		return errors.New("резервный маршрут YouTube остановился")
	}
}
