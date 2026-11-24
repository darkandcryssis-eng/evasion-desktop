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

	"github.com/fitting-1c/evasion/internal/discordproxy"
	"github.com/fitting-1c/evasion/internal/gameproxy"
	"github.com/fitting-1c/evasion/internal/netbind"
	"github.com/fitting-1c/evasion/internal/windivert"
	xproxy "golang.org/x/net/proxy"
)

const defaultDiscordTunnelListen = "127.0.0.1:17657"

type discordTunnel struct {
	Listen string
	worker *gameproxy.Worker
	ln     net.Listener
	cancel context.CancelFunc
	done   chan struct{}
	err    error
	once   sync.Once
}

func startDiscordTunnel(parent context.Context, profile, xray, listen string, logger *slog.Logger) (*discordTunnel, error) {
	if profile == "" {
		return nil, errors.New("не задан профиль маршрута Discord")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, errors.New("некорректный адрес локального прокси Discord")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return nil, errors.New("прокси Discord разрешён только на loopback")
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
		return nil, fmt.Errorf("не удалось настроить локальный канал Discord: %w", err)
	}
	contextDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		worker.Close()
		cancel()
		return nil, errors.New("локальный канал Discord не поддерживает контекст")
	}
	ln, err := net.Listen("tcp4", listen)
	if err != nil {
		worker.Close()
		cancel()
		return nil, fmt.Errorf("не удалось открыть локальный прокси Discord: %w", err)
	}
	t := &discordTunnel{Listen: ln.Addr().String(), worker: worker, ln: ln, cancel: cancel, done: make(chan struct{})}
	server := &discordproxy.Server{Dial: contextDialer.DialContext, Logger: logger}
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
			logger.Error("резервный маршрут Discord остановился")
			cancel()
			_ = ln.Close()
		case <-ctx.Done():
		}
	}()
	return t, nil
}

// discordDirectProxy — loopback CONNECT-прокси Discord, чьи исходящие
// соединения привязаны к физическому адаптеру. Поднимается, когда маршрут по
// умолчанию занят сторонним VPN: Discord идёт мимо туннеля и под десинк.
type discordDirectProxy struct {
	Listen string
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func startDiscordDirectProxy(parent context.Context, ifIndex uint32, listen string, logger *slog.Logger) (*discordDirectProxy, error) {
	ln, err := net.Listen("tcp4", listen)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть локальный прокси Discord: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	p := &discordDirectProxy{Listen: ln.Addr().String(), cancel: cancel, done: make(chan struct{})}
	server := &discordproxy.Server{Dial: discordproxy.DialContextFunc(netbind.Dialer(ifIndex)), Logger: logger}
	go func() {
		_ = server.Serve(ctx, ln)
		close(p.done)
	}()
	return p, nil
}

func (p *discordDirectProxy) Close() {
	p.once.Do(func() {
		p.cancel()
		<-p.done
	})
}

// detectBypassRoute ищет сторонний VPN на маршруте по умолчанию и выводит его
// интерфейс из-под перехвата: внутри туннеля десинк бесполезен и вреден.
func detectBypassRoute(logger *slog.Logger) netbind.Route {
	route, err := netbind.Detect()
	if err != nil {
		logger.Debug("маршрут по умолчанию не определён", "err", err)
		return netbind.Route{}
	}
	if !route.Tunnel {
		return route
	}
	windivert.SetExcludedInterface(route.Default.Index)
	logger.Warn("обнаружен сторонний VPN: его интерфейс исключён из обхода",
		"vpn", route.Default.Name, "адаптер", route.Physical.Name)
	return route
}

func (t *discordTunnel) Close() {
	t.once.Do(func() {
		t.cancel()
		_ = t.ln.Close()
		t.worker.Close()
		<-t.done
	})
}

func discordProxyCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("discord-proxy", flag.ContinueOnError)
	profile := fs.String("profile", "", "зашифрованный профиль VLESS")
	xray := fs.String("xray", "", "путь к xray.exe")
	listen := fs.String("listen", "127.0.0.1:0", "адрес loopback HTTP CONNECT-прокси")
	jsonOut := fs.Bool("json", false, "машинно-читаемый вывод")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger := newLogger(os.Stderr, *jsonOut)
	t, err := startDiscordTunnel(ctx, *profile, *xray, *listen, logger)
	if err != nil {
		return err
	}
	defer t.Close()
	if *jsonOut {
		if err = json.NewEncoder(os.Stdout).Encode(map[string]string{"listen": t.Listen}); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(os.Stdout, t.Listen)
	}
	select {
	case <-ctx.Done():
		return nil
	case <-t.done:
		if t.err != nil {
			return t.err
		}
		return errors.New("резервный маршрут Discord остановился")
	}
}
