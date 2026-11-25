package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/tunnel"
	"github.com/fitting-1c/evasion/internal/warp"
)

// Последняя ступень лестницы: узел, который не пробивается ни сменой
// стратегии, ни другим адресом, уходит в туннель Cloudflare WARP. Туннель
// живёт внутри процесса и маршрутов системы не меняет: в него попадают только
// соединения узлов, набравших срывы; остальное идёт прямым путём.
const (
	warpFailWindow    = 2 * time.Minute
	warpFailLimit     = 6                // очков срыва за окно, после которых узел уходит в туннель
	warpDialWeight    = 3                // соединение не установлено вовсе: два таких подряд — уже туннель
	warpStallWeight   = 1                // узел замолчал: ротация стратегий ещё может помочь
	warpStallGap      = 2 * time.Second  // пачка обрывов одного узла считается одним срывом
	warpHostTTL       = 30 * time.Minute // после этого узел снова пробуется напрямую
	warpRetry         = 3 * time.Minute  // пауза после неудачного подъёма туннеля
	warpPortWait      = 3 * time.Second
	warpProbeAddr     = "1.1.1.1:443"
	warpRegisterHost  = "api.cloudflareclient.com"
	warpRegisterTries = 8
	warpRegisterWait  = 12 * time.Second
	warpBrokenDials   = 3 // столько отказов туннеля подряд — туннель поднимается заново
)

type warpDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	Close() error
}

type warpHost struct {
	points    []warpPoint
	lastStall time.Time
	until     time.Time
}

type warpPoint struct {
	at     time.Time
	weight int
}

type warpRoute struct {
	direct func(context.Context, string, string) (net.Conn, error)
	open   func(context.Context) (warpDialer, error)
	log    *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	hosts   map[string]*warpHost
	tunnel  warpDialer
	opening bool
	retryAt time.Time
	broken  int
	carried map[string]bool // узлы, о соединении которых через туннель уже записано
}

func newWARPRoute(dir string, direct func(context.Context, string, string) (net.Conn, error), logger *slog.Logger) *warpRoute {
	r := &warpRoute{direct: direct, log: logger, now: time.Now, hosts: map[string]*warpHost{}}
	r.open = func(ctx context.Context) (warpDialer, error) { return openWARP(ctx, dir, logger) }
	return r
}

// Dial ведёт соединение прямым путём, а узел, набравший срывы, — через туннель.
func (r *warpRoute) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return r.direct(ctx, network, addr)
	}
	if tn := r.routed(ctx, host); tn != nil {
		if conn, err := r.viaTunnel(ctx, tn, network, addr); err == nil {
			return conn, nil
		}
	}
	conn, err := r.direct(ctx, network, addr)
	if err == nil || ctx.Err() != nil || !warpWorthy(err) {
		return conn, err
	}
	r.fail(ctx, host, warpDialWeight, "соединение не установлено")
	if tn := r.routed(ctx, host); tn != nil {
		if conn, terr := r.viaTunnel(ctx, tn, network, addr); terr == nil {
			return conn, nil
		}
	}
	return nil, err
}

// Force переводит узел в туннель сразу, без накопления срывов.
func (r *warpRoute) Force(ctx context.Context, host string) {
	r.mu.Lock()
	r.host(host).until = r.now().Add(warpHostTTL)
	r.mu.Unlock()
	r.ensure(ctx)
}

// Ready сообщает, что туннель поднят и проверен.
func (r *warpRoute) Ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tunnel != nil
}

// Stall засчитывает узлу соединение, оборванное из-за молчания.
func (r *warpRoute) Stall(ctx context.Context, host string) {
	r.mu.Lock()
	h := r.host(host)
	now := r.now()
	recent := now.Sub(h.lastStall) < warpStallGap
	if !recent {
		h.lastStall = now
	}
	r.mu.Unlock()
	if !recent {
		r.fail(ctx, host, warpStallWeight, "узел молчит при любой стратегии")
	}
}

func (r *warpRoute) host(name string) *warpHost {
	h := r.hosts[name]
	if h == nil {
		if len(r.hosts) >= 512 {
			return &warpHost{}
		}
		h = &warpHost{}
		r.hosts[name] = h
	}
	return h
}

func (r *warpRoute) fail(ctx context.Context, host string, weight int, reason string) {
	r.mu.Lock()
	h := r.host(host)
	now := r.now()
	if now.Before(h.until) {
		r.mu.Unlock()
		return
	}
	kept := h.points[:0]
	total := weight
	for _, p := range h.points {
		if now.Sub(p.at) < warpFailWindow {
			kept = append(kept, p)
			total += p.weight
		}
	}
	h.points = append(kept, warpPoint{now, weight})
	if total < warpFailLimit {
		r.mu.Unlock()
		return
	}
	h.points = nil
	h.until = now.Add(warpHostTTL)
	r.mu.Unlock()
	r.log.Warn("резерв WARP: узел переводится в туннель", "узел", host, "причина", reason, "на", warpHostTTL.String())
	r.ensure(ctx)
}

// routed возвращает туннель, если узел сейчас ведётся через него и туннель поднят.
func (r *warpRoute) routed(ctx context.Context, host string) warpDialer {
	r.mu.Lock()
	h := r.hosts[host]
	if h == nil || h.until.IsZero() {
		r.mu.Unlock()
		return nil
	}
	if !r.now().Before(h.until) {
		h.until = time.Time{}
		r.mu.Unlock()
		r.log.Info("резерв WARP: узел снова пробуется напрямую", "узел", host)
		return nil
	}
	tn := r.tunnel
	r.mu.Unlock()
	if tn == nil {
		r.ensure(ctx)
	}
	return tn
}

func (r *warpRoute) viaTunnel(ctx context.Context, tn warpDialer, network, addr string) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := tn.DialContext(dctx, network, addr)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tunnel != tn {
		return conn, err
	}
	if err == nil {
		r.broken = 0
		if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil && !r.carried[host] {
			if r.carried == nil || len(r.carried) >= 1024 {
				r.carried = map[string]bool{}
			}
			r.carried[host] = true
			r.log.Info("резерв WARP: узел соединился через туннель", "узел", host)
		}
		return conn, nil
	}
	if ctx.Err() != nil {
		return nil, err
	}
	r.broken++
	r.log.Warn("резерв WARP: соединение через туннель не установлено", "адрес", addr, "err", err)
	if r.broken >= warpBrokenDials {
		r.broken = 0
		r.tunnel = nil
		r.retryAt = r.now().Add(time.Minute)
		_ = tn.Close()
		r.log.Warn("резерв WARP: туннель перестал отвечать и будет поднят заново")
	}
	return nil, err
}

// ensure поднимает туннель в фоне: соединения клиента подъёма не ждут.
func (r *warpRoute) ensure(ctx context.Context) {
	r.mu.Lock()
	if r.tunnel != nil || r.opening || r.now().Before(r.retryAt) {
		r.mu.Unlock()
		return
	}
	r.opening = true
	r.mu.Unlock()
	go func() {
		tn, err := r.open(context.WithoutCancel(ctx))
		r.mu.Lock()
		r.opening = false
		if err != nil {
			r.retryAt = r.now().Add(warpRetry)
			r.mu.Unlock()
			r.log.Error("резерв WARP: туннель не поднялся, узлы остаются на прямом пути", "err", err, "повтор_через", warpRetry.String())
			return
		}
		r.tunnel = tn
		r.mu.Unlock()
	}()
}

func (r *warpRoute) Close() {
	r.mu.Lock()
	tn := r.tunnel
	r.tunnel = nil
	r.retryAt = r.now().Add(24 * time.Hour)
	r.mu.Unlock()
	if tn != nil {
		_ = tn.Close()
	}
}

// warpWorthy отличает недоступный адрес от ошибки, которую туннель не лечит.
func warpWorthy(err error) bool {
	var dns *net.DNSError
	return !errors.As(err, &dns) && !errors.Is(err, context.Canceled)
}

// openWARP регистрирует устройство при первом обращении, подбирает порт, на
// котором провайдер пропускает WARP, и проверяет туннель настоящим соединением.
func openWARP(ctx context.Context, dir string, logger *slog.Logger) (warpDialer, error) {
	return openWARPTunnelFile(ctx, dir, warpStateFile, warpPortWait, 1, 0, false, logger)
}

func openWARPTunnelFile(ctx context.Context, dir, stateFile string, portWait time.Duration, parallelBatch, handshakeJunk int, multiHost bool, logger *slog.Logger) (*tunnel.Tunnel, error) {
	path := filepath.Join(dir, stateFile)
	acc, err := loadWARPAccount(path)
	if err != nil {
		logger.Info("резерв WARP: регистрация устройства")
		// Провайдер может резать сам узел регистрации по имени. Он входит в
		// радиус обхода, и каждый срыв сдвигает ротацию стратегий, поэтому
		// попыток несколько и каждая короткая.
		for attempt := 1; attempt <= warpRegisterTries; attempt++ {
			rctx, cancel := context.WithTimeout(ctx, warpRegisterWait)
			transport := &http.Transport{TLSHandshakeTimeout: warpRegisterWait / 2, DisableKeepAlives: true}
			acc, err = warp.Register(rctx, &http.Client{Timeout: warpRegisterWait, Transport: transport})
			cancel()
			transport.CloseIdleConnections()
			if err == nil || ctx.Err() != nil {
				break
			}
			logger.Info("резерв WARP: регистрация не прошла, повтор на другой стратегии", "попытка", attempt, "err", err)
		}
		if err != nil {
			return nil, fmt.Errorf("регистрация: %w", err)
		}
		if err = saveWARPAccount(path, acc); err != nil {
			return nil, err
		}
	}
	started := time.Now()
	quiet := slog.New(slog.DiscardHandler)
	opts := tunnel.Options{Account: acc, Logger: quiet, HandshakeJunk: handshakeJunk}
	var tn *tunnel.Tunnel
	if multiHost {
		endpoints := warpMultiHostEndpoints(acc.PeerEndpoint)
		logger.Info("резерв WARP: перебор адресов", "адресов", len(endpoints), "параллельно", max(1, parallelBatch), "мусор", handshakeJunk)
		tn, err = tunnel.OpenWithFallbackEndpoints(ctx, opts, endpoints, portWait, parallelBatch)
	} else {
		ports := warpPorts(acc.PeerEndpoint)
		logger.Info("резерв WARP: перебор портов", "портов", len(ports), "параллельно", max(1, parallelBatch), "пир", acc.PeerEndpoint)
		tn, err = tunnel.OpenWithFallbackParallel(ctx, opts, ports, portWait, parallelBatch)
	}
	if err != nil {
		return nil, fmt.Errorf("провайдер не пропускает WARP ни на одном порту: %w", err)
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, err := tn.DialContext(pctx, "tcp", warpProbeAddr)
	cancel()
	if err != nil {
		_ = tn.Close()
		return nil, fmt.Errorf("туннель поднят, но соединение через него не проходит: %w", err)
	}
	_ = conn.Close()
	// Рабочий порт запоминается: следующий подъём начнётся с него.
	if endpoint := tn.Endpoint(); endpoint != "" && endpoint != acc.PeerEndpoint {
		acc.PeerEndpoint = endpoint
		if err := saveWARPAccount(path, acc); err != nil {
			logger.Warn("резерв WARP: рабочий порт не сохранён", "err", err)
		}
	}
	logger.Info("резерв WARP: туннель готов", "пир", tn.Endpoint(), "подъём_мс", time.Since(started).Milliseconds())
	return tn, nil
}

// addWARPRegistrationHost вносит узел регистрации WARP в радиус обхода: там,
// где провайдер режет его по имени, без приёма резерв не поднять вовсе.
func addWARPRegistrationHost(cfg *config.Config) {
	for _, group := range []string{"discord_cdn", "discord"} {
		hosts, ok := cfg.Groups[group]
		if !ok {
			continue
		}
		for _, host := range hosts {
			if host == warpRegisterHost {
				return
			}
		}
		cfg.Groups[group] = append(hosts, warpRegisterHost)
		return
	}
}

// warpMultiHostEndpoints строит список кандидатов "IP:port" по нескольким
// anycast-подсетям Cloudflare WARP (162.159.192-195.* и 188.114.96-99.*),
// чередуя хосты на каждом порту: первый же батч проверяет порт 2408 сразу на
// всех подсетях, а прошлый рабочий адрес идёт самым первым.
func warpMultiHostEndpoints(savedEndpoint string) []string {
	seen := make(map[string]struct{}, len(tunnel.WARPFallbackHosts)*len(tunnel.WARPTelegramPorts)+1)
	out := make([]string, 0, len(tunnel.WARPFallbackHosts)*len(tunnel.WARPTelegramPorts)+1)
	add := func(ep string) {
		if ep == "" {
			return
		}
		if _, ok := seen[ep]; ok {
			return
		}
		seen[ep] = struct{}{}
		out = append(out, ep)
	}
	if _, _, err := net.SplitHostPort(savedEndpoint); err == nil {
		add(savedEndpoint)
	}
	for _, port := range tunnel.WARPTelegramPorts {
		for _, host := range tunnel.WARPFallbackHosts {
			add(net.JoinHostPort(host, strconv.Itoa(port)))
		}
	}
	return out
}

// warpPorts ставит первым порт, на котором туннель поднимался в прошлый раз.
func warpPorts(endpoint string) []int {
	ports := tunnel.WARPFallbackPorts
	_, text, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ports
	}
	saved, err := strconv.Atoi(text)
	if err != nil || saved == ports[0] {
		return ports
	}
	out := []int{saved}
	for _, port := range ports {
		if port != saved {
			out = append(out, port)
		}
	}
	return out
}

func loadWARPAccount(path string) (*warp.Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return warp.UnmarshalAccount(data)
}

func saveWARPAccount(path string, acc *warp.Account) error {
	data, err := acc.Marshal()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("создание каталога состояния: %w", err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("сохранение устройства WARP: %w", err)
	}
	return nil
}
