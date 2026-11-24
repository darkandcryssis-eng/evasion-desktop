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
// (IP discovery), ушедшему в туннель: на его сеть ставится маршрут через
// физический адаптер, и повтор пакета вместе со всем голосом уходит мимо
// туннеля, под голосовой десинк.
//
// Маршрут ставится на всю сеть /24 сервера, и сети запоминаются между
// запусками: голосовые серверы Discord стоят пачками в одних и тех же сетях,
// поэтому со временем маршрут уже стоит до первого пакета, и клиент не теряет
// секунду на повтор запроса.
type voiceRouter struct {
	adapter netbind.Adapter
	logger  *slog.Logger
	add     func(netbind.HostRoute) error
	remove  func(netbind.HostRoute) error

	// journal — файл со списком поставленных маршрутов. Если движок убит и не
	// снял их сам, следующий запуск снимает их по этому списку.
	journal string
	// learned — файл с сетями голосовых серверов, увиденными раньше.
	learned string

	mu     sync.Mutex
	routes map[netip.Prefix]voiceRoute
}

// voiceNetworkBits — размер сети, на которую ставится маршрут.
const voiceNetworkBits = 24

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
		learned: filepath.Join(defaultStateDir, "voice-networks.txt"),
		routes:  make(map[netip.Prefix]voiceRoute),
	}
	r.removeStale()
	return r
}

// Preload ставит маршруты на сети голосовых серверов, запомненные с прошлых
// запусков.
func (r *voiceRouter) Preload() {
	networks := r.readLearned()
	r.mu.Lock()
	defer r.mu.Unlock()
	placed := 0
	for _, network := range networks {
		if r.place(network) {
			placed++
		}
	}
	if placed > 0 {
		r.saveJournal()
		r.logger.Info("голос Discord: маршруты мимо VPN на известные сети голосовых серверов", "сетей", placed, "адаптер", r.adapter.Name)
	}
}

func (r *voiceRouter) readLearned() []netip.Prefix {
	data, err := os.ReadFile(r.learned)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, line := range strings.Fields(string(data)) {
		if network, err := netip.ParsePrefix(line); err == nil && network.Bits() == voiceNetworkBits && routableVoiceAddr(network.Addr()) {
			out = append(out, network.Masked())
		}
	}
	return out
}

// remember дописывает сеть в список известных; самые давние вытесняются.
func (r *voiceRouter) remember(network netip.Prefix) {
	networks := r.readLearned()
	kept := networks[:0]
	for _, known := range networks {
		if known != network {
			kept = append(kept, known)
		}
	}
	kept = append(kept, network)
	if len(kept) > maxVoiceRoutes/2 {
		kept = kept[len(kept)-maxVoiceRoutes/2:]
	}
	var b strings.Builder
	for _, known := range kept {
		b.WriteString(known.String() + "\n")
	}
	if err := os.MkdirAll(filepath.Dir(r.learned), 0o755); err == nil {
		_ = os.WriteFile(r.learned, []byte(b.String()), 0o644)
	}
}

// place ставит маршрут на сеть, если его ещё нет. Вызывается под r.mu.
func (r *voiceRouter) place(network netip.Prefix) bool {
	if _, ok := r.routes[network]; ok {
		return true
	}
	route, err := netbind.NewHostRoute(r.adapter, network)
	if err != nil {
		r.logger.Warn("голос Discord: маршрут мимо VPN не собран", "сеть", network, "err", err)
		return false
	}
	if len(r.routes) >= maxVoiceRoutes {
		var oldest netip.Prefix
		for candidate, entry := range r.routes {
			if !oldest.IsValid() || entry.used.Before(r.routes[oldest].used) {
				oldest = candidate
			}
		}
		_ = r.remove(r.routes[oldest].route)
		delete(r.routes, oldest)
	}
	if err := r.add(route); err != nil {
		r.logger.Warn("голос Discord: маршрут мимо VPN не поставлен, голос останется в VPN", "сеть", network, "err", err)
		return false
	}
	r.routes[network] = voiceRoute{route: route, used: time.Now()}
	return true
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
		if route.Dest, errDest = netip.ParsePrefix(dest); errDest != nil {
			// Прежний формат журнала: одиночный адрес.
			var addr netip.Addr
			if addr, errDest = netip.ParseAddr(dest); errDest == nil {
				route.Dest = netip.PrefixFrom(addr, 32)
			}
		}
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

// Route ставит маршрут мимо VPN до сети голосового сервера addr. Сообщает,
// стоит ли маршрут после вызова.
func (r *voiceRouter) Route(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !routableVoiceAddr(addr) {
		r.logger.Warn("голос Discord: VPN подменил адрес сервера, вывести голос из туннеля нельзя", "адрес", addr)
		return false
	}
	network := netip.PrefixFrom(addr, voiceNetworkBits).Masked()
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.routes[network]; ok {
		existing.used = time.Now()
		r.routes[network] = existing
		return true
	}
	if !r.place(network) {
		return false
	}
	r.saveJournal()
	r.remember(network)
	r.logger.Info("голос Discord выведен из VPN: маршрут через физический адаптер", "сеть", network, "адаптер", r.adapter.Name)
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
