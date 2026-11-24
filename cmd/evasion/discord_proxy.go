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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/discordproxy"
	"github.com/fitting-1c/evasion/internal/gameproxy"
	"github.com/fitting-1c/evasion/internal/netbind"
	"github.com/fitting-1c/evasion/internal/proxy"
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

func startDiscordDirectProxy(parent context.Context, route netbind.Route, listen string, logger *slog.Logger) (*discordDirectProxy, error) {
	ln, err := net.Listen("tcp4", listen)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть локальный прокси Discord: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	p := &discordDirectProxy{Listen: ln.Addr().String(), cancel: cancel, done: make(chan struct{})}
	server := &discordproxy.Server{
		Dial:        discordproxy.DialContextFunc(netbind.Dialer(route.Physical.Index)),
		Passthrough: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		// Сигнальные соединения голосовых серверов остаются в VPN всегда:
		// проверка прямого пути их не покрывает, а на прямом пути провайдер
		// душит их после рукопожатия — клиент виснет на аутентификации.
		Reroute: func(host string) bool { return isDiscordVoiceHost(host) || !discordDirectProven.Load() },
		Logger:  logger,
	}
	voice := newVoiceRouter(route.Physical, logger)
	voice.Preload()
	stopVoice := startVoiceObserver(ctx, route, voice, func() int {
		return server.Drop(isDiscordVoiceHost)
	}, logger)
	go func() {
		_ = server.Serve(ctx, ln)
		stopVoice()
		voice.Close()
		close(p.done)
	}()
	return p, nil
}

// startDiscordWatchProxy — тот же loopback-прокси для сети без стороннего VPN.
// Маршрут он не меняет: соединения идут обычным путём под десинк. Нужен он,
// чтобы журнал показывал, на каком узле застрял клиент, и чтобы соединение без
// ответа обрывалось сразу — клиент повторяет его уже со следующей стратегией.
func startDiscordWatchProxy(parent context.Context, listen string, logger *slog.Logger) (*discordDirectProxy, error) {
	ln, err := net.Listen("tcp4", listen)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть локальный прокси Discord: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	p := &discordDirectProxy{Listen: ln.Addr().String(), cancel: cancel, done: make(chan struct{})}
	dial := (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	server := &discordproxy.Server{Dial: dial, Passthrough: dial, NoReply: discordNoReply, Logger: logger, OnStall: func(host string) {
		if report := discordStallReport.Load(); report != nil {
			(*report)(host)
		}
	}}
	go func() {
		_ = server.Serve(ctx, ln)
		close(p.done)
	}()
	return p, nil
}

// discordNoReply — сколько ждать первого байта ответа узла Discord. Рукопожатие
// у живого соединения укладывается в сотни миллисекунд.
const discordNoReply = 5 * time.Second

// discordStallReport — куда прокси сообщает о соединении, застрявшем в начале:
// перехват засчитывает срыв текущей стратегии узла. Задаётся после сборки
// провайдера стратегий.
var discordStallReport atomic.Pointer[func(host string)]

// newDiscordStallReport засчитывает срыв стратегии, действующей сейчас для
// узла. Срывы по одному узлу чаще раза в 2 секунды сливаются в один: клиент
// открывает соединения пачкой, и пачка не должна прокрутить всю ротацию.
func newDiscordStallReport(provider proxy.StrategyProvider, reporter interface {
	ReportFailure(sni string, failed core.StrategyID)
}) func(host string) {
	var mu sync.Mutex
	last := map[string]time.Time{}
	return func(host string) {
		now := time.Now()
		mu.Lock()
		recent := now.Sub(last[host]) < 2*time.Second
		if !recent {
			last[host] = now
		}
		mu.Unlock()
		if recent {
			return
		}
		sel := provider.Select(proxy.ConnMeta{Host: host, SNI: host, Port: 443, IsClientHello: true})
		if sel.Strategy != nil {
			reporter.ReportFailure(host, sel.ID)
		}
	}
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
			result := "ok: Hello, пинг и ответ на вход получены"
			if err := discordGatewayExchange(ctx, path.dial); err != nil {
				result = "СОРВАН: " + err.Error()
			}
			logger.Info("самопроверка Discord: обмен с gateway", "маршрут", path.name, "итог", result)
			for _, host := range discordSelfCheckHosts {
				logger.Info("самопроверка Discord", "узел", host, "маршрут", path.name, "итог", discordSelfCheck(ctx, path.dial, host))
			}
			download, _ := discordDownloadCheck(ctx, path.dial)
			logger.Info("самопроверка Discord: большая загрузка", "маршрут", path.name, "итог", download)
			discordUpdateSelfCheck(ctx, path.name, path.dial, logger)
		}
		if !route.Tunnel {
			return
		}
		// При стороннем VPN Discord идёт через VPN, пока тот отвечает: на
		// прямом пути провайдер то пропускает соединения, то замораживает их
		// после рукопожатия, и разовая удачная проверка этого не ловит. Прямой
		// путь — резерв: на него Discord уходит, только когда путь через VPN
		// дважды подряд не прошёл обмен, а прямой дважды подряд прошёл.
		// Проверка идёт всё время работы и возвращает Discord в VPN, как только
		// тот оживает.
		direct := netbind.Dialer(route.Physical.Index)
		viaVPN := (&net.Dialer{Timeout: 10 * time.Second}).DialContext
		var gate discordDirectGate
		vpnFails, bothDown := 0, false
		for {
			vpnErr := discordGatewayExchange(ctx, viaVPN)
			if ctx.Err() != nil {
				return
			}
			if vpnErr == nil {
				vpnFails = 0
			} else {
				vpnFails++
			}
			useDirect, reason := false, ""
			if vpnFails >= 2 {
				if err := discordGatewayExchange(ctx, direct); err != nil {
					reason = "обмен с gateway: " + err.Error()
				} else if download, ok := discordDownloadCheck(ctx, direct); !ok {
					reason = "загрузка: " + download
				}
				if ctx.Err() != nil {
					return
				}
				useDirect, _ = gate.observe(reason == "")
			} else {
				gate = discordDirectGate{}
			}
			was := discordDirectProven.Swap(useDirect)
			switch {
			case useDirect && !was:
				logger.Warn("Discord: путь через VPN не отвечает, прямой прошёл полный обмен — новые соединения идут напрямую", "vpn", vpnErr)
			case !useDirect && was && vpnFails == 0:
				logger.Info("Discord: путь через VPN снова отвечает, новые соединения идут через VPN")
			case !useDirect && was:
				logger.Warn("Discord: прямой путь перестал работать, соединения идут через VPN", "причина", reason)
			}
			down := vpnFails >= 2 && reason != ""
			if down && !bothDown {
				logger.Warn("Discord не отвечает ни через VPN, ни напрямую", "vpn", vpnErr, "напрямую", reason)
			}
			bothDown = down
			wait := 2 * time.Minute
			switch {
			case vpnFails == 1:
				wait = 10 * time.Second
			case vpnFails >= 2 && reason == "" && !useDirect:
				wait = 5 * time.Second
			case vpnFails >= 2:
				wait = 30 * time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}()
}

var discordAssetRef = regexp.MustCompile(`/assets/[A-Za-z0-9._-]+\.js`)

// discordDownloadCheck качает страницу клиента и её самый первый скрипт.
// Рукопожатие проходит и там, где DPI замораживает соединение после первых
// килобайт ответа, поэтому считаем полученные байты, а не только соединение.
func discordDownloadCheck(ctx context.Context, dial netbind.DialContextFunc) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DialContext: dial, ForceAttemptHTTP2: true, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	fetch := func(url string) ([]byte, int64, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		head, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		rest, restErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 8*1024*1024))
		if err == nil {
			err = restErr
		}
		return head, int64(len(head)) + rest, err
	}
	start := time.Now()
	page, pageBytes, err := fetch("https://discord.com/app")
	if err != nil {
		return fmt.Sprintf("страница оборвана на %d байт за %d мс: %v", pageBytes, time.Since(start).Milliseconds(), err), false
	}
	asset := discordAssetRef.Find(page)
	if asset == nil {
		return fmt.Sprintf("страница ok (%d байт), скрипт в ней не найден", pageBytes), true
	}
	start = time.Now()
	_, assetBytes, err := fetch("https://discord.com" + string(asset))
	if err != nil {
		return fmt.Sprintf("страница ok (%d байт); скрипт ОБОРВАН на %d байт за %d мс: %v", pageBytes, assetBytes, time.Since(start).Milliseconds(), err), false
	}
	return fmt.Sprintf("страница ok (%d байт); скрипт ok (%d байт за %d мс)", pageBytes, assetBytes, time.Since(start).Milliseconds()), true
}

const (
	discordUpdateManifestURL = "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=win&arch=x64"
	discordUpdatePackageSize = 1 << 20
	discordUpdateMinBytes    = 64 << 10
)

func discordUpdateURL(body []byte) (string, error) {
	var manifest struct {
		Full struct {
			URL string `json:"url"`
		} `json:"full"`
		Deltas []struct {
			URL string `json:"url"`
		} `json:"deltas"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return "", fmt.Errorf("не удалось разобрать манифест: %w", err)
	}
	selected := ""
	for _, delta := range manifest.Deltas {
		if candidate := strings.TrimSpace(delta.URL); candidate != "" {
			selected = candidate
			break
		}
	}
	if selected == "" {
		selected = strings.TrimSpace(manifest.Full.URL)
	}
	if selected == "" {
		return "", errors.New("в манифесте нет URL пакета")
	}
	parsed, err := url.Parse(selected)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return "", fmt.Errorf("некорректный URL пакета %q", selected)
	}
	return selected, nil
}

func discordUpdateSelfCheck(ctx context.Context, route string, dial netbind.DialContextFunc, logger *slog.Logger) {
	retry := waitForDiscordStallReport(ctx)
	if ctx.Err() != nil {
		return
	}
	attempts := 1
	if retry {
		attempts = 10
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		result, host, ok := discordUpdateCheckAttempt(ctx, dial)
		if ctx.Err() != nil {
			return
		}
		logger.Info("самопроверка Discord: обновление",
			"маршрут", route, "итог", result, "попытка", attempt)
		if ok || !retry || attempt == attempts {
			return
		}
		if report := discordStallReport.Load(); report != nil && *report != nil {
			(*report)(host)
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func waitForDiscordStallReport(ctx context.Context) bool {
	hasReporter := func() bool {
		report := discordStallReport.Load()
		return report != nil && *report != nil
	}
	if hasReporter() {
		return true
	}
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timeout.C:
			return hasReporter()
		case <-ticker.C:
			if hasReporter() {
				return true
			}
		}
	}
}

func discordUpdateCheckAttempt(ctx context.Context, dial netbind.DialContextFunc) (string, string, bool) {
	transport := &http.Transport{Proxy: nil, DialContext: dial, ForceAttemptHTTP2: true, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	fetch := func(target, rangeHeader string, limit int64) ([]byte, time.Duration, error) {
		requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		start := time.Now()
		req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, target, nil)
		if err != nil {
			return nil, time.Since(start), err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
		req.Header.Set("Accept-Encoding", "identity")
		if rangeHeader != "" {
			req.Header.Set("Range", rangeHeader)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, time.Since(start), err
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit))
		elapsed := time.Since(start)
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return body, elapsed, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if readErr != nil {
			return body, elapsed, readErr
		}
		return body, elapsed, nil
	}

	manifest, manifestTime, err := fetch(discordUpdateManifestURL, "", 1<<20)
	if err != nil {
		return fmt.Sprintf("манифест ошибка (%d байт за %d мс): %v", len(manifest), manifestTime.Milliseconds(), err), "updates.discord.com", false
	}
	packageURL, err := discordUpdateURL(manifest)
	if err != nil {
		return fmt.Sprintf("манифест ошибка (%d байт за %d мс): %v", len(manifest), manifestTime.Milliseconds(), err), "updates.discord.com", false
	}
	parsedURL, _ := url.Parse(packageURL)
	packageHost := parsedURL.Hostname()

	pkg, packageTime, err := fetch(packageURL, "bytes=0-1048575", discordUpdatePackageSize)
	if err == nil && len(pkg) < discordUpdateMinBytes {
		err = fmt.Errorf("прочитано меньше 64 КиБ")
	}
	if err != nil {
		return fmt.Sprintf("манифест ok (%d байт за %d мс); пакет ошибка (%d байт за %d мс): %v",
			len(manifest), manifestTime.Milliseconds(), len(pkg), packageTime.Milliseconds(), err), packageHost, false
	}
	return fmt.Sprintf("манифест ok (%d байт за %d мс); пакет ok (%d байт за %d мс)",
		len(manifest), manifestTime.Milliseconds(), len(pkg), packageTime.Milliseconds()), packageHost, true
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
