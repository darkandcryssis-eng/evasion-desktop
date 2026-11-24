package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

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
	server := &discordproxy.Server{
		Dial:        discordproxy.DialContextFunc(netbind.Dialer(ifIndex)),
		Passthrough: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		Logger:      logger,
	}
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
		logger.Warn("маршрут по умолчанию не определён, VPN не распознаётся", "err", err)
		return netbind.Route{}
	}
	if !route.Tunnel {
		logger.Info("маршрут по умолчанию: стороннего VPN нет",
			"по_умолчанию", route.Default.Name, "физический", route.Physical.Name)
		return route
	}
	windivert.SetExcludedInterface(route.Default.Index)
	logger.Warn("обнаружен сторонний VPN: его интерфейс исключён из обхода",
		"vpn", route.Default.Name, "адаптер", route.Physical.Name)
	return route
}

// discordSelfCheckHosts — узлы, без которых клиент Discord не проходит запуск.
var discordSelfCheckHosts = []string{"updates.discord.com", "discord.com", "gateway.discord.gg", "cdn.discordapp.com"}

// startDiscordSelfCheck через несколько секунд после старта перехвата сам
// проверяет TCP и TLS до узлов Discord и пишет итог в журнал: по маршруту по
// умолчанию и, если он занят VPN, отдельно через физический адаптер. Журнал
// тогда сам отвечает, где рвётся соединение, без ручных команд.
func startDiscordSelfCheck(ctx context.Context, route netbind.Route, logger *slog.Logger) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
		paths := []struct {
			name string
			dial netbind.DialContextFunc
		}{{"по умолчанию", (&net.Dialer{}).DialContext}}
		if route.Tunnel {
			paths = append(paths, struct {
				name string
				dial netbind.DialContextFunc
			}{"мимо VPN", netbind.Dialer(route.Physical.Index)})
		}
		for _, path := range paths {
			for _, host := range discordSelfCheckHosts {
				logger.Info("самопроверка Discord", "узел", host, "маршрут", path.name, "итог", discordSelfCheck(ctx, path.dial, host))
			}
		}
	}()
}

func discordSelfCheck(ctx context.Context, dial netbind.DialContextFunc, host string) string {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := dial(ctx, "tcp4", net.JoinHostPort(host, "443"))
	if err != nil {
		return "TCP не установлен: " + err.Error()
	}
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	tcpTime := time.Since(start).Milliseconds()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Sprintf("TLS сорван (%s, TCP %d мс): %v", remote, tcpTime, err)
	}
	result := fmt.Sprintf("ok (%s, TCP %d мс, TLS %d мс)", remote, tcpTime, time.Since(start).Milliseconds())
	if host != "gateway.discord.gg" {
		return result
	}
	// Для gateway одного TLS мало: клиент стоит на «Starting…», пока не
	// поднимется WebSocket. Проверяем сам апгрейд.
	request := "GET /?v=10&encoding=json HTTP/1.1\r\nHost: " + host + "\r\n" +
		"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: https://discord.com\r\n\r\n"
	if _, err := io.WriteString(tlsConn, request); err != nil {
		return result + "; WebSocket: запрос не отправлен: " + err.Error()
	}
	response, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		return result + "; WebSocket: нет ответа: " + err.Error()
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Sprintf("%s; WebSocket ОТКАЗ: HTTP %d", result, response.StatusCode)
	}
	return result + "; WebSocket ok"
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
