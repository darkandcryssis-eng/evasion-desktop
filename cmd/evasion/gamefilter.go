package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/enginelock"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/gamefilter"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/windivert"
)

const gameTCPFilter = "outbound and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort >= 1024) and not impostor"
const gameUDPFilter = "outbound and udp and udp.DstPort >= 1024 and udp.DstPort != 443 and udp.PayloadLength > 0 and udp.PayloadLength <= 1400 and not (udp.PayloadLength == 74 and udp.Payload16[0] == 1 and udp.Payload16[1] == 70) and not impostor"

type gameTargets []string

func (p *gameTargets) String() string     { return fmt.Sprintf("%d selected", len(*p)) }
func (p *gameTargets) Set(s string) error { *p = append(*p, s); return nil }

type gameSource struct {
	source    capture.PacketSource
	sink      capture.PacketSink
	processor *gamefilter.Processor
}

func (s *gameSource) Recv() (capture.Packet, error) {
	p, err := s.source.Recv()
	if err == nil {
		s.processor.Before(p, s.sink)
	}
	return p, err
}

type gameProvider struct {
	base           proxy.StrategyProvider
	processor      *gamefilter.Processor
	selection      proxy.Selection
	smallSelection proxy.Selection
}

func (p gameProvider) Select(meta proxy.ConnMeta) proxy.Selection {
	if meta.LocalPort == 0 || !p.processor.Options.TCP() {
		return p.base.Select(meta)
	}
	selected := p.base.Select(meta)
	if originalTCPPort(meta.Port) && selected.Strategy != nil {
		return selected
	}
	owned := p.processor.Owner.Owns("tcp", meta.LocalPort)
	if !originalTCPPort(meta.Port) && !owned {
		return proxy.Selection{}
	}
	if selected.Strategy != nil {
		return selected
	}
	ip, err := netip.ParseAddr(meta.Host)
	if !owned || err != nil || !gamefilter.Public(ip) || !meta.IsClientHello {
		return proxy.Selection{}
	}
	if !p.processor.AllowTLS(meta.LocalPort, meta.Host, meta.Port) {
		return proxy.Selection{}
	}
	if meta.PayloadLength <= 681 {
		return p.smallSelection
	}
	return p.selection
}
func originalTCPPort(port uint16) bool {
	switch port {
	case 443, 2053, 2083, 2087, 2096, 8443:
		return true
	}
	return false
}
func gameStrategy(mode string, small ...bool) (*strategy.Strategy, error) {
	action := `{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"reverse"},"left":{"kind":"send"},"right":{"kind":"send"}}`
	if mode != "gentle" && (len(small) == 0 || !small[0]) {
		action = `{"kind":"tcp_overlap","params":{"preset":"tls_cover_681"}}`
	}
	if mode == "strong" {
		action = `{"kind":"duplicate","left":{"kind":"tamper","params":{"field":"tcp_seq","mode":"add","value":4294957296},"left":{"kind":"tamper","params":{"field":"payload","mode":"replace","preset":"tls_clienthello_google"},"left":{"kind":"send"}}},"right":` + action + `}`
	}
	return strategy.Unmarshal([]byte(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":`+action+`}]}`), strategy.DefaultLimits())
}

type gameRuntime struct {
	processor *gamefilter.Processor
	owners    *gamefilter.Owners
	udp       *windivert.Handle
	done      chan struct{}
	watch     chan struct{}
	mu        sync.Mutex
	lastError string
	udpMu     sync.Mutex
	udpClosed bool
	draining  atomic.Bool
}

func startGames(ctx context.Context, o gamefilter.Options, logger *slog.Logger) (*gameRuntime, error) {
	owners := gamefilter.NewOwners(o)
	g := &gameRuntime{processor: gamefilter.New(o, owners), owners: owners, done: make(chan struct{}), watch: make(chan struct{})}
	if o.UDP() {
		h, err := windivert.Open(gameUDPFilter)
		if err != nil {
			return nil, fmt.Errorf("не удалось открыть игровой UDP-фильтр: %w", err)
		}
		g.udp = h
		go func() {
			defer close(g.done)
			defer g.closeUDP()
			for {
				pkt, err := h.Recv()
				if err != nil {
					return
				}
				if !g.draining.Load() {
					g.processor.Before(pkt, h)
				}
				if err = h.Send(pkt); err != nil {
					g.mu.Lock()
					g.lastError = "не удалось отправить игровой пакет"
					g.processor.RecordSendError()
					g.mu.Unlock()
					logger.Warn("игровой фильтр: отправка оригинала", "err", err)
					return
				}
			}
		}()
	} else {
		close(g.done)
	}
	go func() {
		defer close(g.watch)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			g.save()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	logger.Info("игровой фильтр включён", "режим", o.Mode, "протокол", o.Protocol)
	return g, nil
}
func (g *gameRuntime) save() {
	targets, errText := g.owners.Status()
	g.mu.Lock()
	if g.lastError != "" {
		errText = g.lastError
	}
	g.mu.Unlock()
	data := struct {
		PID       int                       `json:"pid"`
		At        string                    `json:"at"`
		Mode      string                    `json:"mode"`
		Protocol  string                    `json:"protocol"`
		Targets   []string                  `json:"targets"`
		Stats     gamefilter.Counters       `json:"stats"`
		Error     string                    `json:"error"`
		Adaptive  gamefilter.AdaptiveState  `json:"adaptive"`
		Processes []gamefilter.ProcessState `json:"processes"`
		Transport gamefilter.TransportState `json:"transport"`
	}{os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano), g.processor.Options.Mode, g.processor.Options.Protocol, targets, g.processor.Stats(), errText, g.processor.AdaptiveState(), g.owners.Processes(), g.processor.TransportState()}
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	path := filepath.Join(defaultStateDir, "gamefilter.json")
	_ = os.MkdirAll(defaultStateDir, 0700)
	tmp := path + fmt.Sprintf(".%d.tmp", os.Getpid())
	if os.WriteFile(tmp, b, 0600) == nil {
		if os.Rename(tmp, path) != nil {
			_ = os.Remove(tmp)
		}
	}
}

func (g *gameRuntime) closeUDP() {
	g.udpMu.Lock()
	defer g.udpMu.Unlock()
	if g.udp != nil && !g.udpClosed {
		_ = g.udp.Close()
		g.udpClosed = true
	}
}
func (g *gameRuntime) stop() {
	g.draining.Store(true)
	g.udpMu.Lock()
	if g.udp != nil && !g.udpClosed {
		if g.udp.ShutdownReceive() != nil {
			_ = g.udp.Close()
			g.udpClosed = true
		}
	}
	g.udpMu.Unlock()
	<-g.done
	g.closeUDP()
	<-g.watch
}

// Game ports and new TLS connections are captured at a separate priority.
// Strategies are selected only for verified game-owned sockets.
func runGamesOnly(ctx context.Context, o gamefilter.Options, adaptive bool, logger *slog.Logger, jsonOut bool, socksEndpoint ...string) error {
	// Keep a non-capturing handle throughout idle periods and filter replacement.
	driver, err := windivert.Open("false")
	if err != nil {
		return err
	}
	defer driver.Close()

	lock, err := enginelock.Acquire(enginelock.Options{Path: filepath.Join(defaultStateDir, "game-engine.lock"), Filter: "games"})
	if err != nil {
		return err
	}
	defer lock.Release()
	owners := gamefilter.NewOwners(o)
	p := gamefilter.New(o, owners)
	p.Standalone = true
	p.Adaptive = adaptive
	p.TLSHandled = o.TCP()
	if len(socksEndpoint) > 0 && socksEndpoint[0] != "" {
		return runGameSOCKS(ctx, o, p, owners, socksEndpoint[0], jsonOut)
	}
	flows := flow.NewTable(8192, 5*time.Minute, intercept.TLSHelloDetector)
	g := &gameRuntime{owners: owners, processor: p}
	var handle *windivert.Handle
	var done chan struct{}
	var retire func()
	current := ""
	stop := func() {
		if retire != nil {
			retire()
			retire = nil
			handle = nil
		}
	}
	defer stop()
	ticker := time.NewTicker(350 * time.Millisecond)
	defer ticker.Stop()
	announced := false
	logger.Info("игровой фильтр запущен отдельно", "adaptive", adaptive)
	for {
		filter := owners.Filter()
		if o.TCP() && owners.Active() {
			filter = gameCaptureFilter(filter, gameTLSGuard)
		}
		if filter != current {
			stop()
			current = ""
			if filter != "" {
				h, e := windivert.OpenPriority(filter, 100)
				if e != nil {
					return e
				}
				handle = h
				current = filter
				done = make(chan struct{})
				var closing atomic.Bool
				var once sync.Once
				closeHandle := func() { once.Do(func() { _ = h.Close() }) }
				finished := done
				var tlsEngine *intercept.Engine
				if o.TCP() {
					tlsEngine, e = newGameTLSInterceptor(h, p, owners, flows, logger, &closing)
					if e != nil {
						closeHandle()
						return e
					}
				}
				retire = func() {
					closing.Store(true)
					if tlsEngine != nil {
						tlsEngine.SetTransparent(true)
					}
					if h.ShutdownReceive() != nil {
						closeHandle()
					}
					select {
					case <-finished:
					case <-time.After(3 * time.Second):
						closeHandle()
						<-finished
					}
				}
				go func() {
					defer close(finished)
					defer closeHandle()
					if tlsEngine != nil {
						if err := tlsEngine.Run(context.Background()); err != nil && !closing.Load() {
							g.mu.Lock()
							g.lastError = "игровой TLS-фильтр остановился"
							g.mu.Unlock()
							logger.Warn("игровой TLS-фильтр", "err", err)
						}
						return
					}
					for {
						pkt, e := h.Recv()
						if e != nil {
							return
						}
						if !closing.Load() {
							p.Observe(pkt, h)
						}
						if e = h.Send(pkt); e != nil {
							p.RecordSendError()
							g.mu.Lock()
							g.lastError = "не удалось передать игровой пакет"
							g.mu.Unlock()
							return
						}
					}
				}()
			}
		}
		if done != nil && handle != nil {
			select {
			case <-done:
				return fmt.Errorf("игровой фильтр остановился: проверьте драйвер и повторите запуск")
			default:
			}
		}
		g.save()
		if !announced {
			if jsonOut {
				_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"filter": "selected game sockets · independent", "quic_mode": "off"})
			}
			announced = true
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-owners.Changed():
			// Let a burst of new connections settle into one filter update.
			time.Sleep(25 * time.Millisecond)
		}
	}
}
