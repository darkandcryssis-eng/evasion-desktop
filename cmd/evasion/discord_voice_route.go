package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/netbind"
)

// maxVoiceRoutes — потолок одновременно стоящих маршрутов к голосовым серверам.
const maxVoiceRoutes = 128

// voiceRouter выводит голос Discord из-под стороннего VPN. Голос идёт по UDP
// напрямую из клиента, локальный прокси его не видит, а VPN-туннель его часто
// не пропускает. Адрес голосового сервера узнаётся по первому пакету голоса
// (IP discovery), ушедшему в туннель: на него ставится маршрут через
// физический адаптер, и повтор пакета вместе со всем голосом уходит мимо
// туннеля, под голосовой десинк.
type voiceRouter struct {
	adapter netbind.Adapter
	logger  *slog.Logger
	add     func(netbind.HostRoute) error
	remove  func(netbind.HostRoute) error

	// journal — файл со списком поставленных маршрутов. Если движок убит и не
	// снял их сам, следующий запуск снимает их по этому списку.
	journal string

	mu     sync.Mutex
	routes map[netip.Addr]voiceRoute
}

type voiceRoute struct {
	route netbind.HostRoute
	used  time.Time
}

func newVoiceRouter(adapter netbind.Adapter, logger *slog.Logger) *voiceRouter {
	r := &voiceRouter{
		adapter: adapter,
		logger:  logger,
		add:     netbind.HostRoute.Add,
		remove:  netbind.HostRoute.Delete,
		journal: filepath.Join(defaultStateDir, "voice-routes.txt"),
		routes:  make(map[netip.Addr]voiceRoute),
	}
	r.removeStale()
	return r
}

// removeStale снимает маршруты, оставшиеся от прошлого запуска.
func (r *voiceRouter) removeStale() {
	data, err := os.ReadFile(r.journal)
	if err != nil {
		return
	}
	removed := 0
	for _, line := range strings.Split(string(data), "\n") {
		var dest, gateway string
		var route netbind.HostRoute
		if n, _ := fmt.Sscanf(line, "%s %s %d %d", &dest, &gateway, &route.IfIndex, &route.Metric); n != 4 {
			continue
		}
		var errDest, errGateway error
		route.Dest, errDest = netip.ParseAddr(dest)
		route.Gateway, errGateway = netip.ParseAddr(gateway)
		if errDest != nil || errGateway != nil {
			continue
		}
		if r.remove(route) == nil {
			removed++
		}
	}
	_ = os.Remove(r.journal)
	if removed > 0 {
		r.logger.Info("голос Discord: сняты маршруты прошлого запуска", "маршрутов", removed)
	}
}

// saveJournal переписывает список стоящих маршрутов. Вызывается под r.mu.
func (r *voiceRouter) saveJournal() {
	if len(r.routes) == 0 {
		_ = os.Remove(r.journal)
		return
	}
	var b strings.Builder
	for _, entry := range r.routes {
		fmt.Fprintf(&b, "%s %s %d %d\n", entry.route.Dest, entry.route.Gateway, entry.route.IfIndex, entry.route.Metric)
	}
	if err := os.MkdirAll(filepath.Dir(r.journal), 0o755); err == nil {
		_ = os.WriteFile(r.journal, []byte(b.String()), 0o644)
	}
}

// isDiscordVoiceHost — узел голосового сервера Discord (c-ams19-….discord.media).
func isDiscordVoiceHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return strings.HasSuffix(host, ".discord.media")
}

// routableVoiceAddr отсекает адреса, на которые маршрут ставить нельзя:
// частные и служебные, включая 198.18.0.0/15, которым VPN-клиенты с
// подменой адресов отвечают вместо настоящего.
func routableVoiceAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	fakeIP := netip.MustParsePrefix("198.18.0.0/15")
	return addr.Is4() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !fakeIP.Contains(addr)
}

// Route ставит маршрут мимо VPN до голосового сервера addr. Сообщает, стоит ли
// маршрут после вызова.
func (r *voiceRouter) Route(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !routableVoiceAddr(addr) {
		r.logger.Warn("голос Discord: VPN подменил адрес сервера, вывести голос из туннеля нельзя", "адрес", addr)
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if existing, ok := r.routes[addr]; ok {
		existing.used = now
		r.routes[addr] = existing
		return true
	}
	route, err := netbind.NewHostRoute(r.adapter, addr)
	if err != nil {
		r.logger.Warn("голос Discord: маршрут мимо VPN не собран", "адрес", addr, "err", err)
		return false
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
		r.logger.Warn("голос Discord: маршрут мимо VPN не поставлен, голос останется в VPN", "адрес", addr, "err", err)
		return false
	}
	r.routes[addr] = voiceRoute{route: route, used: now}
	r.saveJournal()
	r.logger.Info("голос Discord выведен из VPN: маршрут через физический адаптер", "адрес", addr, "адаптер", r.adapter.Name)
	return true
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
	r.saveJournal()
}
