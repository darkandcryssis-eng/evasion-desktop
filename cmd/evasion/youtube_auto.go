package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/vantage"
	"github.com/fitting-1c/evasion/internal/youtubetune"
)

type youtubeCheck struct {
	Target string `json:"target"`
	Stage  string `json:"stage"`
	OK     bool   `json:"ok"`
	Code   int    `json:"code"`
	MS     int64  `json:"ms"`
}
type youtubeHealth struct {
	CheckedAt     time.Time      `json:"checkedAt"`
	PID           int            `json:"pid"`
	At            time.Time      `json:"at"`
	Phase         string         `json:"phase"`
	Profile       string         `json:"profile"`
	Route         string         `json:"route,omitempty"`
	Switches      int            `json:"switches"`
	Rollbacks     int            `json:"rollbacks"`
	Failures      int            `json:"failures"`
	MediaObserved bool           `json:"mediaObserved"`
	Checks        []youtubeCheck `json:"checks"`
}
type youtubeLease struct {
	port   uint16
	host   string
	remote uint16
}

const (
	youtubeRetryDelay       = 200 * time.Millisecond
	youtubeRetryTimeout     = 1500 * time.Millisecond
	youtubeActivityInterval = 5 * time.Second
	youtubeActiveInterval   = 10 * time.Second
	youtubeWarmMaxAge       = 7 * 24 * time.Hour
	// youtubeScanWorkers — сколько профилей проверяется одновременно при
	// восстановлении. Пробы разведены по локальным портам (leases), поэтому
	// параллельность не смешивает профили; 3 вместо 2 сокращает худший перебор
	// 12 профилей на треть, не создавая шторма соединений к YouTube.
	youtubeScanWorkers = 3
)

type youtubeMux struct {
	dial        func(context.Context, string, string) (net.Conn, error)
	mu          sync.Mutex
	base        proxy.StrategyProvider
	scope       *config.DomainSet
	active      string
	choices     map[string]proxy.Selection
	leases      map[youtubeLease]string
	media       string
	lastUse     time.Time
	mediaAt     time.Time
	lastWake    time.Time
	wake        chan struct{}
	cancelRound context.CancelFunc
}

func newYouTubeMux(base proxy.StrategyProvider, scope *config.DomainSet) (*youtubeMux, error) {
	p := &youtubeMux{base: base, scope: scope, active: "current", choices: map[string]proxy.Selection{}, leases: map[youtubeLease]string{}, wake: make(chan struct{}, 1)}
	for _, name := range youtubetune.Profiles {
		if name == "current" {
			continue
		}
		s, e := youtubetune.Profile(name, nil)
		if e != nil {
			return nil, e
		}
		static, e := proxy.NewStaticProvider(s)
		if e != nil {
			return nil, e
		}
		p.choices[name] = static.Select(proxy.ConnMeta{})
	}
	return p, nil
}
func (p *youtubeMux) Select(m proxy.ConnMeta) proxy.Selection {
	if !m.IsClientHello || !youtubetune.IsYouTube(m.SNI) || !p.scope.Matches(m.Host, m.SNI) {
		return p.base.Select(m)
	}
	var cancelRound context.CancelFunc
	p.mu.Lock()
	name := p.active
	if lease, ok := p.leases[youtubeLease{m.LocalPort, m.Host, m.Port}]; ok {
		name = lease
	} else {
		now := time.Now()
		p.lastUse = now
		if validMediaHost(m.SNI) {
			host := strings.ToLower(m.SNI)
			changed := host != p.media
			if changed {
				p.media = host
				cancelRound = p.cancelRound
			}
			if changed || now.Sub(p.lastWake) >= youtubeActivityInterval {
				p.lastWake = now
				select {
				case p.wake <- struct{}{}:
				default:
				}
			}
			p.mediaAt = now
		}
	}
	if name == "active" {
		name = p.active
	}
	p.mu.Unlock()
	if cancelRound != nil {
		cancelRound()
	}
	if name == "media-sld" {
		if validMediaHost(m.SNI) {
			name = "split-sld"
		} else {
			name = "fake-sld"
		}
	}
	if name == "current" {
		return p.base.Select(m)
	}
	if m.PayloadLength > 0 && m.PayloadLength < strategy.MinOverlapPayload {
		if name == "overlap" {
			name = "split-forward"
		}
		if name == "fake-overlap" {
			name = "fake-split"
		}
	}
	return p.choices[name]
}
func (p *youtubeMux) set(name string) { p.mu.Lock(); p.active = name; p.mu.Unlock() }
func (p *youtubeMux) current() string { p.mu.Lock(); defer p.mu.Unlock(); return p.active }
func (p *youtubeMux) mediaHost() (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.media != "" {
		return p.media, true
	}
	return "redirector.googlevideo.com", false
}
func validMediaHost(host string) bool {
	host = strings.ToLower(host)
	if len(host) > 253 || host == "redirector.googlevideo.com" || !strings.HasSuffix(host, ".googlevideo.com") {
		return false
	}
	for _, r := range host {
		if r != '.' && r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

type youtubeConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *youtubeConn) Close() error { c.once.Do(c.release); return c.Conn.Close() }
func (p *youtubeMux) lease(c net.Conn, name string) net.Conn {
	l := c.LocalAddr().(*net.TCPAddr)
	r := c.RemoteAddr().(*net.TCPAddr)
	k := youtubeLease{uint16(l.Port), r.IP.String(), uint16(r.Port)}
	p.mu.Lock()
	p.leases[k] = name
	p.mu.Unlock()
	return &youtubeConn{Conn: c, release: func() { p.mu.Lock(); delete(p.leases, k); p.mu.Unlock() }}
}

// Each probe registers its connected socket before net/http sends ClientHello.
// Candidate selection is limited to that exact endpoint; user flows keep active.
func (p *youtubeMux) probe(ctx context.Context, name, target, url string, short bool) youtubeCheck {
	r := youtubeCheck{Target: target, Stage: "dns"}
	var traceMu sync.Mutex
	phase := "dns"
	stage := func(s string) { traceMu.Lock(); phase = s; traceMu.Unlock() }
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if short {
		tc.CurvePreferences = []tls.CurveID{tls.X25519}
	}
	tr := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: tc, DisableKeepAlives: true, TLSHandshakeTimeout: 4 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		dial := p.dial
		if dial == nil {
			dial = (&net.Dialer{Timeout: 3 * time.Second}).DialContext
		}
		c, e := dial(ctx, network, address)
		if e != nil {
			return nil, e
		}
		return p.lease(c, name), nil
	}}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	trace := &httptrace.ClientTrace{DNSDone: func(d httptrace.DNSDoneInfo) {
		if d.Err == nil {
			stage("tcp")
		}
	}, ConnectStart: func(string, string) { stage("tcp") }, TLSHandshakeStart: func() { stage("tls") }, TLSHandshakeDone: func(_ tls.ConnectionState, e error) {
		if e == nil {
			stage("http")
		}
	}}
	req, e := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", url, nil)
	if e != nil {
		return r
	}
	req.Header.Set("User-Agent", "Evasion-Connection-Check/2")
	req.Header.Set("Cache-Control", "no-cache")
	start := time.Now()
	response, e := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if e != nil {
		traceMu.Lock()
		r.Stage = phase
		traceMu.Unlock()
		r.MS = time.Since(start).Milliseconds()
		return r
	}
	defer response.Body.Close()
	r.Code = response.StatusCode
	r.Stage = "http"
	switch target {
	case "site":
		r.OK = r.Code == http.StatusNoContent
	case "image":
		if r.Code == http.StatusOK {
			data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
			r.OK = err == nil && len(data) > 32 && len(data) <= 65536 && data[0] == 0xff && data[1] == 0xd8
		}
	case "media_transport":
		r.OK = r.Code == http.StatusNoContent || r.Code == http.StatusNotFound
	}
	r.MS = time.Since(start).Milliseconds()
	return r
}
func (p *youtubeMux) measure(ctx context.Context, name string, short bool) []youtubeCheck {
	media, _ := p.mediaHost()
	targets := []struct{ key, url string }{{"site", "https://www.youtube.com/generate_204"}, {"image", "https://i.ytimg.com/vi/M7lc1UVf-VE/default.jpg"}, {"media_transport", "https://" + media + "/generate_204"}}
	ch := make(chan youtubeCheck, len(targets))
	for _, v := range targets {
		go func(key, url string) { ch <- p.probe(ctx, name, key, url, short) }(v.key, v.url)
	}
	checks := make([]youtubeCheck, 0, len(targets))
	for range targets {
		checks = append(checks, <-ch)
	}
	return checks
}
func youtubeHealthy(checks []youtubeCheck) bool {
	if len(checks) != 3 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range checks {
		if !v.OK || seen[v.Target] {
			return false
		}
		seen[v.Target] = true
	}
	return seen["site"] && seen["image"] && seen["media_transport"]
}

type youtubeRecovery struct {
	paused         func() bool
	route          func(bool)
	fallback       bool
	directGood     int
	nextShort      bool
	consecutive    int
	failureByShape [2]int
	checkedShape   [2]bool
	p              *youtubeMux
	state          youtubeHealth
	measure        func(context.Context, string, bool) []youtubeCheck
	tunnelMeasure  func(context.Context, bool) []youtubeCheck
	control        func(context.Context) bool
	identity       func() string
	publish        func(youtubeHealth)
	store          func(id, profile, media string)
	load           func(string) string
	network        string
	warm           string
	media          string
	lastScan       time.Time
}

// Verify both handshake shapes concurrently, retaining full probe timeouts.
func (a *youtubeRecovery) verify(ctx context.Context, name string) ([]youtubeCheck, bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		short  bool
		checks []youtubeCheck
	}
	results := make(chan result, 2)
	for _, short := range []bool{false, true} {
		go func(short bool) { results <- result{short, a.measure(ctx, name, short)} }(short)
	}
	var checks []youtubeCheck
	ok := true
	for range 2 {
		r := <-results
		if !youtubeHealthy(r.checks) {
			ok = false
			cancel()
		}
		if !r.short {
			checks = r.checks
		}
	}
	return checks, ok && ctx.Err() == nil
}

func (a *youtubeRecovery) candidates(ctx context.Context, old string) <-chan string {
	// Первым идёт профиль, который уже доказал себя в этой сети: восстановление
	// занимает одну проверку вместо перебора, и лишних переключений не бывает.
	order := []string{"fake-sld", "media-sld", "multisplit", "split-forward", "fake-multisplit", "fake-disorder", "fake-forward", "fake-split", "split", "overlap", "fake-overlap", "current"}
	jobs := make(chan string, len(order))
	if warm := a.load(a.identity()); warm != "" && warm != old {
		next := make([]string, 0, len(order))
		next = append(next, warm)
		for _, name := range order {
			if name != warm {
				next = append(next, name)
			}
		}
		order = next
	}
	for _, name := range order {
		if name != old {
			jobs <- name
		}
	}
	close(jobs)
	results := make(chan string)
	var wg sync.WaitGroup
	for range youtubeScanWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				if ctx.Err() != nil {
					return
				}
				if _, ok := a.verify(ctx, name); ok {
					select {
					case results <- name:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() { wg.Wait(); close(results) }()
	return results
}

func (a *youtubeRecovery) resetNetwork(id string, clearMedia bool) {
	a.network = id
	a.warm = a.load(id)
	a.p.mu.Lock()
	defer a.p.mu.Unlock()
	a.p.active = a.warm
	if a.p.active == "" {
		a.p.active = "current"
	}
	if clearMedia {
		a.p.media = ""
		a.p.mediaAt = time.Time{}
		a.p.lastUse = time.Time{}
		a.p.lastWake = time.Time{}
	}
}

func (a *youtubeRecovery) setFallback(enabled bool) {
	if a.route == nil || a.fallback == enabled {
		return
	}
	a.fallback = enabled
	a.directGood = 0
	a.route(enabled)
}

func (a *youtubeRecovery) enableFallback(ctx context.Context, short bool) {
	if a.fallback || a.route == nil {
		return
	}
	if a.tunnelMeasure != nil {
		probeCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		checks := a.tunnelMeasure(probeCtx, short)
		cancel()
		if ctx.Err() != nil || !youtubeHealthy(checks) {
			return
		}
	}
	a.setFallback(true)
}

func (a *youtubeRecovery) round(ctx context.Context) time.Duration {
	id := a.identity()
	networkChanged := id != a.network
	if networkChanged {
		a.resetNetwork(id, true)
	}
	ctx, cancelRound := context.WithCancel(ctx)
	a.p.mu.Lock()
	a.p.cancelRound = cancelRound
	a.p.mu.Unlock()
	defer func() {
		a.p.mu.Lock()
		a.p.cancelRound = nil
		a.p.mu.Unlock()
		cancelRound()
	}()
	media, observed := a.p.mediaHost()
	if networkChanged || media != a.media {
		a.media = media
		a.consecutive = 0
		a.directGood = 0
		a.failureByShape = [2]int{}
		a.checkedShape = [2]bool{}
		a.state.Failures = 0
		a.state.Checks = nil
		a.state.CheckedAt = time.Time{}
		a.lastScan = time.Time{}
	}
	a.state.MediaObserved = observed
	a.state.Profile = a.p.current()
	if a.paused != nil && a.paused() {
		a.state.Phase = "network_down"
		a.state.Checks = nil
		a.emit()
		return 10 * time.Second
	}
	a.state.Phase = "checking"
	a.emit()
	shape := 0
	if a.nextShort {
		shape = 1
	}
	probeCtx := ctx
	cancel := func() {}
	if a.state.Failures > 0 {
		probeCtx, cancel = context.WithTimeout(ctx, youtubeRetryTimeout)
	}
	checks := a.measure(probeCtx, "active", a.nextShort)
	cancel()
	if ctx.Err() != nil || a.identity() != id {
		return 0
	}
	if latest, _ := a.p.mediaHost(); latest != media {
		return 0
	}
	a.nextShort = !a.nextShort
	a.state.Checks = checks
	a.state.CheckedAt = time.Now().UTC()
	a.checkedShape[shape] = true
	if youtubeHealthy(checks) {
		a.consecutive = 0
		a.failureByShape[shape] = 0
		a.state.Failures = max(a.failureByShape[0], a.failureByShape[1])
		if a.state.Failures > 0 {
			a.directGood = 0
			a.state.Phase = "degraded"
			a.emit()
			return youtubeRetryDelay
		}
		if !a.checkedShape[0] || !a.checkedShape[1] {
			a.emit()
			return youtubeRetryDelay
		}
		if a.fallback {
			a.directGood++
			if a.directGood >= 3 {
				a.setFallback(false)
			}
		}
		a.state.Phase = "healthy"
		if observed {
			a.store(id, a.p.current(), media)
		} else {
			a.state.Phase = "awaiting_media"
		}
		a.emit()
		a.p.mu.Lock()
		recent := time.Since(a.p.lastUse) < 5*time.Minute
		a.p.mu.Unlock()
		if recent {
			return youtubeActiveInterval
		}
		return 3 * time.Minute
	}
	a.consecutive++
	a.directGood = 0
	a.failureByShape[shape]++
	a.state.Failures = max(a.consecutive, max(a.failureByShape[0], a.failureByShape[1]))
	a.state.Phase = "degraded"
	a.emit()
	if a.state.Failures < 2 {
		return youtubeRetryDelay
	}
	online := a.control == nil || a.control(ctx)
	if ctx.Err() != nil || a.identity() != id {
		return 0
	}
	if !online {
		a.state.Phase = "network_down"
		a.emit()
		return 30 * time.Second
	}
	a.enableFallback(ctx, a.nextShort)
	if !a.lastScan.IsZero() && time.Since(a.lastScan) < 2*time.Minute {
		a.state.Phase = "unavailable"
		a.emit()
		return 30 * time.Second
	}
	a.lastScan = time.Now()
	old := a.p.current()
	a.state.Phase = "recovering"
	a.emit()
	scanCtx, stopScan := context.WithCancel(ctx)
	candidates := a.candidates(scanCtx, old)
	defer func() {
		stopScan()
		for range candidates {
		}
	}()
	for name := range candidates {
		if ctx.Err() != nil {
			return 0
		}
		if latest, _ := a.p.mediaHost(); latest != media {
			return 0
		}
		// Check the committed production selector too; rollback on any regression.
		a.p.set(name)
		verified, ok := a.verify(ctx, "active")
		if ctx.Err() != nil {
			a.p.set(old)
			return 0
		}
		if !ok {
			a.p.set(old)
			a.state.Rollbacks++
			continue
		}
		latest, _ := a.p.mediaHost()
		if a.identity() != id || latest != media {
			a.p.set(old)
			return 0
		}
		a.state.Profile = name
		a.state.Checks = verified
		a.state.CheckedAt = time.Now().UTC()
		a.state.Switches++
		a.consecutive = 0
		a.failureByShape = [2]int{}
		a.checkedShape = [2]bool{true, true}
		a.state.Failures = 0
		a.setFallback(false)
		a.state.Phase = "recovered"
		if observed {
			a.store(id, name, media)
		} else {
			a.state.Phase = "awaiting_media"
		}
		a.emit()
		return youtubeActiveInterval
	}
	a.state.Phase = "unavailable"
	a.emit()
	return 30 * time.Second
}
func (a *youtubeRecovery) emit() {
	if a.route != nil {
		a.state.Route = "direct"
		if a.fallback {
			a.state.Route = "vless"
		}
	}
	a.state.PID = enginePID()
	a.state.At = time.Now().UTC()
	a.publish(a.state)
}
func (a *youtubeRecovery) run(ctx context.Context) {
	defer func() { a.setFallback(false); a.state.Phase = "stopped"; a.emit() }()
	for {
		d := a.round(ctx)
		if ctx.Err() != nil {
			return
		}
		if d == 0 {
			select {
			case <-a.p.wake:
			default:
			}
			continue
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-a.p.wake:
			t.Stop()
		}
	}
}

type youtubeInterfaces []vantage.Iface

func (s youtubeInterfaces) Interfaces() ([]vantage.Iface, error) { return s, nil }

func youtubeRouteInterfaces(ip net.IP, list []vantage.Iface) []vantage.Iface {
	var routed []vantage.Iface
	for _, iface := range list {
		for _, address := range iface.Addrs {
			if address.IP.Equal(ip) {
				routed = append(routed, iface)
				break
			}
		}
	}
	return routed
}

func youtubeNetworkFingerprint() string {
	list, err := vantage.SystemInterfaces().Interfaces()
	if err != nil {
		return ""
	}
	conn, err := net.Dial("udp4", "192.0.2.1:443")
	if err == nil {
		if address, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			if routed := youtubeRouteInterfaces(address.IP, list); len(routed) > 0 {
				list = routed
			}
		}
		_ = conn.Close()
	}
	fingerprint, err := vantage.Fingerprint(youtubeInterfaces(list))
	if err != nil {
		return ""
	}
	return fingerprint
}

func youtubeIdentityForFingerprint(cfg *config.Config, fingerprint string) string {
	if fingerprint == "" {
		return ""
	}
	s := cfg.Strategies["video"]
	if s == nil {
		s = cfg.Strategy
	}
	b, _ := strategy.Marshal(s)
	sum := sha256.Sum256(append([]byte(fingerprint+"|youtube-auto-v2|"), b...))
	return hex.EncodeToString(sum[:])
}

func youtubeIdentity(cfg *config.Config) string {
	return youtubeIdentityForFingerprint(cfg, youtubeNetworkFingerprint())
}
func writeYouTubeJSON(path string, v any) {
	b, e := json.Marshal(v)
	if e != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(path), 0700) != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		if os.Rename(tmp, path) != nil {
			os.Remove(tmp)
		}
	}
}

type youtubeWarmProfile struct {
	Identity string    `json:"identity"`
	Profile  string    `json:"profile"`
	At       time.Time `json:"at"`
	Media    string    `json:"media,omitempty"`
}

func youtubeProfileAllowed(s string) bool {
	if s == "media-sld" {
		return true
	}
	for _, v := range youtubetune.Profiles {
		if s == v {
			return true
		}
	}
	return false
}

func loadYouTubeWarm(path, id string, now time.Time) (youtubeWarmProfile, bool) {
	var v youtubeWarmProfile
	b, e := os.ReadFile(path)
	if e != nil || len(b) >= 4096 || json.Unmarshal(b, &v) != nil || id == "" || v.Identity != id || !youtubeProfileAllowed(v.Profile) || now.Sub(v.At) >= youtubeWarmMaxAge || v.At.After(now.Add(time.Minute)) {
		return youtubeWarmProfile{}, false
	}
	if !validMediaHost(v.Media) {
		v.Media = ""
	}
	return v, true
}

func loadYouTubeWarmProfile(path, id string, now time.Time) string {
	v, ok := loadYouTubeWarm(path, id, now)
	if !ok {
		return ""
	}
	return v.Profile
}

func newYouTubeRecovery(p *youtubeMux, cfg *config.Config, dir string) *youtubeRecovery {
	cache := filepath.Join(dir, "youtube-known-good.json")
	a := &youtubeRecovery{p: p, measure: p.measure, identity: func() string { return youtubeIdentity(cfg) }, publish: func(s youtubeHealth) { writeYouTubeJSON(filepath.Join(dir, "youtube-health.json"), s) }, store: func(id, name, media string) {
		if id != "" {
			writeYouTubeJSON(cache, youtubeWarmProfile{Identity: id, Profile: name, At: time.Now().UTC(), Media: media})
		}
	}, load: func(id string) string {
		return loadYouTubeWarmProfile(cache, id, time.Now())
	}}
	if len(cfg.ControlTargets) > 0 {
		a.control = controlTargetsHealthy(cfg.ControlTargets)
	}
	a.resetNetwork(a.identity(), false)
	if warm, ok := loadYouTubeWarm(cache, a.network, time.Now()); ok && warm.Profile == a.warm && warm.Media != "" {
		p.mu.Lock()
		if p.media == "" {
			p.media = warm.Media
			p.mediaAt = time.Now()
		}
		p.mu.Unlock()
	}
	return a
}

func (a *youtubeRecovery) startProfile(name string) bool {
	if a.warm != "" || name == "" || !youtubeProfileAllowed(name) {
		return false
	}
	a.p.set(name)
	return true
}

func prepareYouTubeAuto(cfg *config.Config, domains *config.DomainSet, groups []string) (*config.DomainSet, bool) {
	if cfg.Observe || !domains.Matches("www.youtube.com", "www.youtube.com") || youtubetune.ValidateVideoGroup(cfg) != nil {
		return domains, false
	}
	seen := map[string]bool{}
	for _, host := range cfg.Groups["video"] {
		seen[host] = true
	}
	for _, host := range youtubetune.Domains {
		if !seen[host] {
			cfg.Groups["video"] = append(cfg.Groups["video"], host)
		}
	}
	mode := config.QUICBlock
	cfg.YouTubeQUICMode = &mode
	if next, e := cfg.DomainSet(groups); e == nil {
		return next, true
	}
	return domains, false
}
