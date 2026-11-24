package main

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/netbind"
)

// maxVoiceRoutes — потолок одновременно стоящих маршрутов к голосовым серверам.
const maxVoiceRoutes = 128

// voiceRouter выводит голос Discord из-под стороннего VPN. Голос идёт по UDP
// напрямую из клиента, локальный прокси его не видит, а VPN-туннель его часто
// не пропускает. Поэтому на каждый голосовой сервер, к которому клиент
// подключается (его сигнальное соединение проходит через прокси), ставится
// маршрут через физический адаптер: UDP к серверу уходит мимо туннеля и
// попадает под голосовой десинк.
type voiceRouter struct {
	adapter netbind.Adapter
	logger  *slog.Logger
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	add     func(netbind.HostRoute) error
	remove  func(netbind.HostRoute) error

	mu     sync.Mutex
	routes map[netip.Addr]voiceRoute
}

type voiceRoute struct {
	route netbind.HostRoute
	used  time.Time
}

func newVoiceRouter(adapter netbind.Adapter, logger *slog.Logger) *voiceRouter {
	return &voiceRouter{
		adapter: adapter,
		logger:  logger,
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		},
		add:    netbind.HostRoute.Add,
		remove: netbind.HostRoute.Delete,
		routes: make(map[netip.Addr]voiceRoute),
	}
}

// isDiscordVoiceHost — узел голосового сервера Discord (c-ams19-….discord.media).
func isDiscordVoiceHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return strings.HasSuffix(host, ".discord.media")
}

// routableVoiceAddr отсекает адреса, на которые маршрут ставить нельзя:
// частные и служебные, включая 198.18.0.0/15, которым VPN-клиенты с
// подменой DNS отвечают вместо настоящего адреса.
func routableVoiceAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	fakeIP := netip.MustParsePrefix("198.18.0.0/15")
	return addr.Is4() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !fakeIP.Contains(addr)
}

// Ensure ставит маршруты ко всем адресам голосового узла host. Вызывается до
// сигнального соединения, то есть раньше, чем клиент начнёт слать голос.
func (r *voiceRouter) Ensure(ctx context.Context, host string) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := r.resolve(ctx, host)
	if err != nil {
		r.logger.Warn("голос Discord: адрес сервера не определён, голос останется в VPN", "узел", host, "err", err)
		return
	}
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !routableVoiceAddr(addr) {
			r.logger.Warn("голос Discord: VPN подменил адрес сервера, вывести голос из туннеля нельзя", "узел", host, "адрес", addr)
			continue
		}
		r.ensureAddr(host, addr)
	}
}

func (r *voiceRouter) ensureAddr(host string, addr netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if existing, ok := r.routes[addr]; ok {
		existing.used = now
		r.routes[addr] = existing
		return
	}
	route, err := netbind.NewHostRoute(r.adapter, addr)
	if err != nil {
		r.logger.Warn("голос Discord: маршрут мимо VPN не собран", "узел", host, "err", err)
		return
	}
	if len(r.routes) >= maxVoiceRoutes {
		var oldest netip.Addr
		for candidate, entry := range r.routes {
			if !oldest.IsValid() || entry.used.Before(r.routes[oldest].used) {
				oldest = candidate
			}
		}
		_ = r.remove(r.routes[oldest].route)
		delete(r.routes, oldest)
	}
	if err := r.add(route); err != nil {
		r.logger.Warn("голос Discord: маршрут мимо VPN не поставлен, голос останется в VPN", "узел", host, "адрес", addr, "err", err)
		return
	}
	r.routes[addr] = voiceRoute{route: route, used: now}
	r.logger.Info("голос Discord выведен из VPN: маршрут через физический адаптер", "узел", host, "адрес", addr, "адаптер", r.adapter.Name)
}

// Close снимает все поставленные маршруты.
func (r *voiceRouter) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for addr, entry := range r.routes {
		if err := r.remove(entry.route); err != nil {
			r.logger.Warn("голос Discord: маршрут не снят", "адрес", addr, "err", err)
		}
		delete(r.routes, addr)
	}
}
