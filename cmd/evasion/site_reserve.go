package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fitting-1c/evasion/internal/discordproxy"
	"github.com/fitting-1c/evasion/internal/ruguard"
	"github.com/fitting-1c/evasion/internal/youtubetune"
)

// Резерв сайтов: соединение с сайтом проходит рукопожатие и замерзает — так
// выглядит ограничение по адресу хостинга, которое приёмами на уровне пакетов
// не снимается. Такой сайт уводится в туннель WARP: движок вносит его в
// сценарий автонастройки прокси Windows, браузер приводит сайт на локальный
// прокси, прокси ведёт его через туннель. Остальные сайты идут напрямую.
const (
	siteStallWindow = 5 * time.Minute
	siteStallLimit  = 3 // зависаний сайта за окно, после которых он уходит в туннель
	// Под приёмом (широкий радиус) зависание сначала лечит ротация стратегий:
	// в туннель сайт уходит, только если не помогла и она.
	siteDesyncLimit = 8
	siteTunnelWait  = 150 * time.Second
	siteCapacity    = 256
)

// siteStallHook — куда движок перехвата сообщает о зависших соединениях.
var siteStallHook atomic.Pointer[func(sni string, desynced bool)]

func reportSiteStall(sni string, desynced bool) {
	if hook := siteStallHook.Load(); hook != nil {
		(*hook)(sni, desynced)
	}
}

type siteReserve struct {
	ctx      context.Context
	route    *warpRoute
	settings pacSettings
	prefix   string // начало адреса сценария: по нему узнаётся своя запись
	listen   string
	log      *slog.Logger
	now      func() time.Time
	wait     time.Duration

	mu        sync.Mutex
	stalls    map[string][]time.Time
	desynced  map[string]bool
	pending   map[string]bool
	sites     map[string]bool
	version   int
	installed bool
	refused   bool
	original  string
}

func newSiteReserve(ctx context.Context, route *warpRoute, settings pacSettings, listen string, logger *slog.Logger) *siteReserve {
	s := &siteReserve{ctx: ctx, route: route, settings: settings, listen: listen, prefix: "http://" + listen + "/proxy.pac",
		log: logger, now: time.Now, wait: siteTunnelWait,
		stalls: map[string][]time.Time{}, desynced: map[string]bool{}, pending: map[string]bool{}, sites: map[string]bool{}}
	// Запись, оставшаяся от аварийно завершённого запуска, снимается сразу.
	if current, err := settings.Snapshot(); err == nil && strings.HasPrefix(current.AutoConfigURL, s.prefix) {
		_ = settings.SetAutoConfigURL("")
		_ = settings.Notify()
	}
	hook := s.Stall
	siteStallHook.Store(&hook)
	return s
}

// Stall засчитывает сайту зависшее соединение. Вызывается с горячего пути
// перехвата, поэтому сам ничего не ждёт.
func (s *siteReserve) Stall(sni string, desynced bool) {
	host := strings.TrimSuffix(strings.ToLower(sni), ".")
	// Discord и YouTube ведут свои прокси и своя ротация.
	if !siteHostOK(host) || ruguard.IsRussian(host) || discordproxy.AllowedHost(host) || youtubetune.IsYouTube(host) {
		return
	}
	s.mu.Lock()
	now := s.now()
	if s.pending[host] {
		s.mu.Unlock()
		return
	}
	if _, known := s.stalls[host]; !known && len(s.stalls) >= siteCapacity {
		s.stalls = map[string][]time.Time{}
		s.desynced = map[string]bool{}
	}
	if desynced {
		s.desynced[host] = true
	}
	limit := siteStallLimit
	if s.desynced[host] {
		limit = siteDesyncLimit
	}
	kept := s.stalls[host][:0]
	for _, at := range s.stalls[host] {
		if now.Sub(at) < siteStallWindow {
			kept = append(kept, at)
		}
	}
	kept = append(kept, now)
	if len(kept) < limit || len(s.sites) >= siteCapacity {
		s.stalls[host] = kept
		s.mu.Unlock()
		return
	}
	delete(s.stalls, host)
	delete(s.desynced, host)
	s.pending[host] = true
	s.mu.Unlock()
	go s.take(host)
}

func (s *siteReserve) take(host string) {
	defer func() {
		s.mu.Lock()
		delete(s.pending, host)
		s.mu.Unlock()
	}()
	s.route.Force(s.ctx, host)
	deadline := time.Now().Add(s.wait)
	for !s.route.Ready() {
		if s.ctx.Err() != nil {
			return
		}
		if time.Now().After(deadline) {
			s.log.Warn("резерв сайтов: сайт замерзает после рукопожатия, но туннель WARP недоступен", "сайт", host)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	s.mu.Lock()
	added := !s.sites[host]
	s.sites[host] = true
	s.mu.Unlock()
	if !added {
		return
	}
	if s.publish() {
		s.log.Warn("резерв сайтов: сайт замерзает после рукопожатия и переведён в WARP", "сайт", host)
	}
}

// publish прописывает сценарий в Windows. Адрес каждый раз новый: по смене
// адреса браузер перечитывает список сайтов.
func (s *siteReserve) publish() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refused {
		return false
	}
	current, err := s.settings.Snapshot()
	if err != nil {
		s.refused = true
		s.log.Warn("резерв сайтов: настройки прокси Windows не читаются, сайты остаются на прямом пути", "err", err)
		return false
	}
	ours := strings.HasPrefix(current.AutoConfigURL, s.prefix)
	if (current.AutoConfigURL != "" && !ours) || (current.ProxyEnable != 0 && current.ProxyServer != "") {
		s.refused = true
		s.log.Warn("резерв сайтов: в Windows уже настроен свой прокси или сценарий, он не тронут; замерзающие сайты остаются на прямом пути")
		return false
	}
	s.version++
	if err = s.settings.SetAutoConfigURL(fmt.Sprintf("%s?v=%d", s.prefix, s.version)); err == nil {
		err = s.settings.Notify()
	}
	if err != nil {
		s.log.Warn("резерв сайтов: сценарий прокси не установлен", "err", err)
		return false
	}
	if !s.installed {
		s.installed = true
		s.log.Info("резерв сайтов: в Windows прописан сценарий прокси только для замерзающих сайтов; при выходе он убирается", "адрес", s.prefix)
	}
	return true
}

// PAC возвращает сценарий: сайты из списка — через локальный прокси, с прямым
// путём про запас, всё остальное — напрямую.
func (s *siteReserve) PAC() string {
	s.mu.Lock()
	hosts := make([]string, 0, len(s.sites))
	for host := range s.sites {
		hosts = append(hosts, host)
	}
	s.mu.Unlock()
	sort.Strings(hosts)
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n  host = host.toLowerCase();\n")
	if len(hosts) > 0 {
		b.WriteString("  if (shExpMatch(url, \"https://*\") && (\n")
		for i, host := range hosts {
			if i > 0 {
				b.WriteString(" ||\n")
			}
			fmt.Fprintf(&b, "      host == %q", host)
		}
		fmt.Fprintf(&b, ")) {\n    return \"PROXY %s; DIRECT\";\n  }\n", s.listen)
	}
	b.WriteString("  return \"DIRECT\";\n}\n")
	return b.String()
}

// Close убирает сценарий из Windows, если он всё ещё наш.
func (s *siteReserve) Close() {
	siteStallHook.Store(nil)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refused = true
	if !s.installed {
		return
	}
	s.installed = false
	if current, err := s.settings.Snapshot(); err == nil && strings.HasPrefix(current.AutoConfigURL, s.prefix) {
		_ = s.settings.SetAutoConfigURL("")
		_ = s.settings.Notify()
	}
}

// siteHostOK пропускает только обычные имена сайтов: имя попадает в текст
// сценария, поэтому посторонних символов в нём быть не должно.
func siteHostOK(host string) bool {
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, c := range host {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}
