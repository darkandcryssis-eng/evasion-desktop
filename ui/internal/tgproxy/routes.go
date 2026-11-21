package tgproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var dcIPs = map[int]string{1: "149.154.175.50", 2: "149.154.167.51", 3: "149.154.175.100", 4: "149.154.167.91", 5: "149.154.171.5", 203: "91.105.192.100"}

var errDialQueue = errors.New("очередь подключений Telegram занята")

type route struct {
	id, host, address string
	tcp               bool
	tunnel            bool
	community         bool
	plain             bool
	fronting          bool
	fromPool          bool
	dc                int
	media             bool
}
type routeHealth struct {
	preferred bool
	code      string
	reason    string
	inflight  int
	checked   time.Time
	opened    bool
	failures  int
	retryAt   time.Time
	latency   time.Duration
	success   bool
}
type dialFunc func(context.Context, route) (peer, error)
type router struct {
	cache      *routeCache
	pool       *warmPool
	domains    *domainPool
	mu         sync.Mutex
	health     map[string]routeHealth
	known      map[string]route
	dial       dialFunc
	tunnel     dialFunc
	slots      chan struct{}
	background chan struct{}
	community  bool
	rotation   uint64
}

func newRouter(dial dialFunc, community ...bool) *router {
	r := &router{pool: newWarmPool(), domains: newDomainPool(), health: map[string]routeHealth{}, known: map[string]route{}, slots: make(chan struct{}, 8), background: make(chan struct{}, 3)}
	r.community = len(community) > 0 && community[0]
	if dial == nil {
		dial = newNetworkDialer(&tls.Config{MinVersion: tls.VersionTLS12, ClientSessionCache: tls.NewLRUClientSessionCache(64)})
	}
	r.dial = dial
	return r
}

func (c route) scoped() route {
	if c.media {
		c.id += fmt.Sprintf("/dc%d-media", c.dc)
	} else if c.dc == 203 && !c.tcp && !c.community {
		// DC203 shares the WSS endpoints of DC2.
		c.id += "/dc203"
	}
	return c
}

func relayRoute(dc int, media bool, domain string) route {
	return communityRoute(dc, media, domain, false)
}

func plainRelayRoute(dc int, media bool, domain string) route {
	return communityRoute(dc, media, domain, true)
}

func communityRoute(dc int, media bool, domain string, plain bool) route {
	host := fmt.Sprintf("kws%d.%s", dc, domain)
	id := "relay:" + host
	if plain {
		id = "relay80:" + host
	}
	return (route{id: id, host: host, community: true, plain: plain, dc: dc, media: media}).scoped()
}

func communityRoutes(dc int, media bool, domain string) []route {
	return []route{plainRelayRoute(dc, media, domain), relayRoute(dc, media, domain)}
}

func tcpRoute(dc int, media bool) route {
	return (route{id: fmt.Sprintf("tcp:dc%d", dc), address: net.JoinHostPort(dcIPs[dc], "443"), tcp: true, dc: dc, media: media}).scoped()
}

func tunnelRoute(dc int, media bool) route {
	return (route{id: fmt.Sprintf("vless:dc%d", dc), address: net.JoinHostPort(dcIPs[dc], "443"), tcp: true, tunnel: true, dc: dc, media: media}).scoped()
}

func routesFor(dc int, media bool) []route {
	hostDC := dc
	if dc == 203 {
		hostDC = 2
	}
	hosts := []string{fmt.Sprintf("kws%d.web.telegram.org", hostDC)}
	if media {
		hosts = append([]string{fmt.Sprintf("kws%d-1.web.telegram.org", hostDC)}, hosts...)
	}
	var candidates []route
	for _, host := range hosts {
		candidates = append(candidates, route{id: "wss:" + host, host: host, dc: dc, media: media})
		ip := dcIPs[dc]
		if dc == 2 || dc == 4 || dc == 203 {
			ip = "149.154.167.220"
		}
		address := net.JoinHostPort(ip, "443")
		candidates = append(candidates,
			route{id: "wss:" + host + "@" + ip, host: host, address: address, dc: dc, media: media},
			route{id: "front:" + host + "@" + ip, host: host, address: address, fronting: true, dc: dc, media: media},
		)
	}
	for i := range candidates {
		candidates[i] = candidates[i].scoped()
	}
	return candidates
}

func (r *router) failure(id string, cause ...error) {
	if len(cause) > 0 && errors.Is(cause[0], errDialQueue) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.health[id]
	h.code, h.reason = "channel_error", "Маршрут временно недоступен"
	if len(cause) > 0 {
		h.code, h.reason = routeFailure(cause[0])
	}
	h.failures++
	h.checked = time.Now()
	h.opened = false
	h.success = false
	h.preferred = false
	if r.cache != nil {
		r.cache.forget(id)
	}
	delay := time.Second << min(h.failures-1, 4)
	if delay > 15*time.Second {
		delay = 15 * time.Second
	}
	h.retryAt = time.Now().Add(delay)
	r.health[id] = h
}

func (r *router) success(id string, latency time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.health[id]
	h.failures = 0
	h.retryAt = time.Time{}
	h.success = true
	h.code, h.reason = "", ""
	h.checked = time.Now()
	if latency > 0 {
		if h.latency == 0 {
			h.latency = latency
		} else {
			h.latency = (h.latency*3 + latency) / 4
		}
	}
	r.health[id] = h
	candidate := r.known[id]
	if candidate.community {
		r.domains.prefer(candidate.dc, strings.TrimPrefix(candidate.host, fmt.Sprintf("kws%d.", candidate.dc)))
	}
	if r.cache != nil {
		r.cache.remember(candidate, latency)
	}
}

func (r *router) connect(ctx context.Context, dc int, media bool) (peer, route, time.Duration, error) {
	return r.connectAvoid(ctx, dc, media, "")
}

// connectAvoid — connect для страхующей попытки: маршрут avoid ещё ждёт первого
// ответа, поэтому прогретый пул пропускается (там чаще всего тот же маршрут),
// а сам avoid исключается из гонки, если есть другие маршруты.
func (r *router) connectAvoid(ctx context.Context, dc int, media bool, avoid string) (peer, route, time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return nil, route{}, 0, err
	}
	started := time.Now()
	if avoid == "" {
		if p, c, ok := r.takeWarm(ctx, dc, media); ok {
			return p, c, time.Since(started), nil
		}
	}
	var failures []string
	candidates := routesFor(dc, media)
	r.mu.Lock()
	if r.community {
		domains := r.domains.forDC(dc)
		start := int(r.rotation % uint64(len(domains)))
		r.rotation++
		var relays []route
		for pass := range 2 {
			for i := range domains {
				domain := domains[(start+i)%len(domains)]
				if pass == 0 {
					relays = append(relays, plainRelayRoute(dc, media, domain))
				} else {
					relays = append(relays, relayRoute(dc, media, domain))
				}
			}
		}
		sort.SliceStable(relays, func(i, j int) bool { return routeRank(r.health[relays[i].id]) > routeRank(r.health[relays[j].id]) })
		count := 0
		for _, candidate := range relays {
			if time.Now().Before(r.health[candidate.id].retryAt) {
				continue
			}
			candidates = append(candidates, candidate)
			count++
			if count == 8 {
				break
			}
		}
	}
	candidates = append(candidates, tcpRoute(dc, media))
	if r.tunnel != nil {
		candidates = append(candidates, tunnelRoute(dc, media))
	}
	var available []route
	for _, candidate := range candidates {
		if !time.Now().Before(r.health[candidate.id].retryAt) {
			available = append(available, candidate)
		}
	}
	sort.SliceStable(available, func(i, j int) bool {
		a, b := r.health[available[i].id], r.health[available[j].id]
		if routeRank(a) != routeRank(b) {
			return routeRank(a) > routeRank(b)
		}
		return routeRank(a) > 0 && a.latency < b.latency
	})
	if avoid != "" {
		others := available[:0:0]
		for _, candidate := range available {
			if candidate.id != avoid {
				others = append(others, candidate)
			}
		}
		if len(others) > 0 {
			available = others
		}
	}
	r.mu.Unlock()
	type result struct {
		p       peer
		route   route
		elapsed time.Duration
		err     error
	}
	results := make(chan result, len(available))
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	plainOrder, secureOrder := 0, 0
	for i, candidate := range available {
		delay := time.Duration(i) * 75 * time.Millisecond
		if candidate.community {
			if candidate.plain {
				delay = 75*time.Millisecond + time.Duration(plainOrder)*50*time.Millisecond
				plainOrder++
			} else {
				delay = 500*time.Millisecond + time.Duration(secureOrder)*75*time.Millisecond
				secureOrder++
			}
		}
		if candidate.tcp {
			delay = 300 * time.Millisecond
		}
		if candidate.tunnel {
			delay = 250 * time.Millisecond
		}
		go func(i int, candidate route, delay time.Duration) {
			r.mu.Lock()
			verified := routeRank(r.health[candidate.id]) > 0
			r.mu.Unlock()
			if verified {
				delay = time.Duration(i) * 75 * time.Millisecond
			}
			timer := time.NewTimer(delay)
			select {
			case <-raceCtx.Done():
				timer.Stop()
				results <- result{route: candidate, err: raceCtx.Err()}
				return
			case <-timer.C:
			}
			started := time.Now()
			attemptCtx, attemptCancel := context.WithTimeout(raceCtx, 4*time.Second)
			p, err := r.dialRoute(attemptCtx, candidate)
			attemptCancel()
			if err != nil && raceCtx.Err() == nil {
				r.failure(candidate.id, err)
			}
			results <- result{p: p, route: candidate, elapsed: time.Since(started), err: err}
		}(i, candidate, delay)
	}
	for remaining := len(available); remaining > 0; remaining-- {
		select {
		case <-ctx.Done():
			cancel()
			go func(n int) {
				for range n {
					v := <-results
					if v.p != nil {
						_ = v.p.Close()
					}
				}
			}(remaining)
			return nil, route{}, 0, ctx.Err()
		case v := <-results:
			if v.err == nil && v.p != nil {
				cancel()
				go func(n int) {
					for range n {
						other := <-results
						if other.p != nil {
							_ = other.p.Close()
						}
					}
				}(remaining - 1)
				return v.p, v.route, v.elapsed, nil
			}
			if v.p != nil {
				_ = v.p.Close()
			}
			if v.err != nil && !errors.Is(v.err, context.Canceled) {
				failures = append(failures, v.route.id+": "+v.err.Error())
			}
		}
	}
	if ctx.Err() != nil {
		return nil, route{}, 0, ctx.Err()
	}
	detail := strings.Join(failures, "; ")
	if len(detail) > 1800 {
		detail = detail[:1800]
	}
	return nil, route{}, 0, fmt.Errorf("маршруты Telegram недоступны; повторная проверка не позднее чем через 15 секунд: %s", detail)
}

func tuneSocket(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetReadBuffer(256 << 10)
		_ = tcp.SetWriteBuffer(256 << 10)
	}
}

func newNetworkDialer(config *tls.Config) dialFunc {
	return func(ctx context.Context, candidate route) (peer, error) {
		operationCtx := ctx
		d := net.Dialer{Timeout: 6 * time.Second, KeepAlive: 30 * time.Second}
		if candidate.tcp {
			c, err := d.DialContext(ctx, "tcp", candidate.address)
			if err == nil {
				tuneSocket(c)
				return &tcpPeer{c}, nil
			}
			return nil, err
		}
		tlsConfig := config.Clone()
		if candidate.fronting {
			// Upstream uses check_hostname=False here: SNI belongs to the masking
			// site while the certificate chain is still verified without DNSName.
			tlsConfig.ServerName = "sprinthost.ru"
			tlsConfig.InsecureSkipVerify = true
			tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return errors.New("fronting: empty certificate chain")
				}
				intermediates := x509.NewCertPool()
				for _, cert := range state.PeerCertificates[1:] {
					intermediates.AddCert(cert)
				}
				_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Intermediates: intermediates})
				return err
			}
		}
		scheme := "wss"
		if candidate.plain {
			scheme = "ws"
			tlsConfig = nil
		}
		ws := websocket.Dialer{HandshakeTimeout: 6 * time.Second, ReadBufferSize: 256 << 10, WriteBufferSize: 256 << 10, Subprotocols: []string{"binary"}, TLSClientConfig: tlsConfig}
		var stopCancel func() bool
		defer func() {
			if stopCancel != nil {
				stopCancel()
			}
		}()
		ws.NetDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if candidate.address != "" {
				address = candidate.address
			}
			c, err := d.DialContext(ctx, network, address)
			if err == nil {
				tuneSocket(c)
				// Gorilla cancels its inner handshake context after a successful dial.
				// Only watch our outer operation, or the winning socket is closed.
				stopCancel = context.AfterFunc(operationCtx, func() { _ = c.Close() })
			}
			return c, err
		}
		c, response, err := ws.DialContext(ctx, scheme+"://"+candidate.host+"/apiws", http.Header{})
		if err != nil {
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			return nil, err
		}
		return newWSPeer(c), nil
	}
}

func routeRank(h routeHealth) int {
	if h.success {
		return 2
	}
	if h.preferred {
		return 1
	}
	return 0
}

// bestCandidates возвращает до n маршрутов в порядке здоровья и латентности,
// пропуская те, что ещё отдыхают после сбоя.
func (r *router) bestCandidates(dc int, media bool, n int) []route {
	candidates := routesFor(dc, media)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.community {
		var relays []route
		for _, domain := range r.domains.forDC(dc) {
			relays = append(relays, communityRoutes(dc, media, domain)...)
		}
		candidates = append(relays, candidates...)
	}
	if r.tunnel != nil {
		candidates = append([]route{tunnelRoute(dc, media)}, candidates...)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := r.health[candidates[i].id], r.health[candidates[j].id]
		if routeRank(a) != routeRank(b) {
			return routeRank(a) > routeRank(b)
		}
		return routeRank(a) > 0 && a.latency < b.latency
	})
	var out []route
	for _, candidate := range candidates {
		if time.Now().Before(r.health[candidate.id].retryAt) {
			continue
		}
		out = append(out, candidate)
		if len(out) == n {
			break
		}
	}
	return out
}

// probeRoutes фоново проверяет лучшие маршруты полноценным MTProto-рукопожатием:
// мёртвый маршрут уходит в отдых, живой подтверждается и обновляет латентность.
func (r *router) probeRoutes(ctx context.Context, dc int, media bool, n int) {
	var wg sync.WaitGroup
	for _, candidate := range r.bestCandidates(dc, media, n) {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.probeRoute(ctx, candidate, 4*time.Second)
		}()
	}
	wg.Wait()
}

// warmBest пополняет тёплый пул по лучшему проверенному маршруту.
func (r *router) warmBest(dc int, media bool) {
	best := r.bestCandidates(dc, media, 1)
	if len(best) == 0 {
		return
	}
	r.mu.Lock()
	verified := routeRank(r.health[best[0].id]) > 0
	r.mu.Unlock()
	if !verified {
		return
	}
	r.warm(dc, media, best[0])
}

func (r *router) latencyHint(id string) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.health[id].latency
}
