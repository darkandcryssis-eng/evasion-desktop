package tgproxy

import (
	"context"
	"sync"
	"time"
)

const warmTTL = 110 * time.Second
const warmLimit = 16
const warmPerRoute = 4

type poolKey struct {
	dc    int
	media bool
}
type warmPeer struct {
	p       peer
	route   route
	created time.Time
	expiry  *time.Timer
}
type warmPool struct {
	mu      sync.Mutex
	idle    map[poolKey][]*warmPeer
	filling map[poolKey]bool
	count   int
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	workers chan struct{}
}

func newWarmPool() *warmPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &warmPool{idle: map[poolKey][]*warmPeer{}, filling: map[poolKey]bool{}, ctx: ctx, cancel: cancel, workers: make(chan struct{}, 4)}
}

func peerAlive(p peer) bool {
	if v, ok := p.(interface{ Alive() bool }); ok {
		return v.Alive()
	}
	return true
}

func (r *router) takeWarm(ctx context.Context, dc int, media bool, avoid map[string]bool) (peer, route, bool) {
	pool := r.pool
	key := poolKey{dc, media}
	for ctx.Err() == nil {
		pool.mu.Lock()
		items := pool.idle[key]
		if pool.closed || len(items) == 0 {
			pool.mu.Unlock()
			return nil, route{}, false
		}
		index := -1
		r.mu.Lock()
		now := time.Now()
		preferTLS := r.tlsFallbackActiveLocked(dc, media, now)
		for i, item := range items {
			a := item.route
			if avoid[a.id] {
				continue
			}
			if index < 0 || (media && routeBefore(a, items[index].route, r.health[a.id], r.health[items[index].route.id], preferTLS, now)) {
				index = i
			}
			if !media {
				break
			}
		}
		r.mu.Unlock()
		if index < 0 {
			pool.mu.Unlock()
			return nil, route{}, false
		}
		item := items[index]
		copy(items[index:], items[index+1:])
		items[len(items)-1] = nil
		pool.idle[key] = items[:len(items)-1]
		pool.count--
		item.expiry.Stop()
		pool.mu.Unlock()
		r.mu.Lock()
		health := r.health[item.route.id]
		r.mu.Unlock()
		if time.Since(item.created) >= warmTTL || !peerAlive(item.p) || !health.success || time.Now().Before(health.retryAt) {
			_ = item.p.Close()
			continue
		}
		candidate := item.route
		candidate.fromPool = true
		if media {
			r.warmBest(dc, media)
		} else {
			r.warm(dc, media, item.route)
		}
		return item.p, candidate, true
	}
	return nil, route{}, false
}

// Warm sockets contain no client init, auth key or user request. Each is used once.
func (r *router) warm(dc int, media bool, candidates ...route) {
	var warmable []route
	for _, candidate := range candidates {
		if !candidate.tcp {
			warmable = append(warmable, candidate)
		}
	}
	if len(warmable) == 0 {
		return
	}
	pool := r.pool
	key := poolKey{dc, media}
	pool.mu.Lock()
	if pool.closed || pool.filling[key] {
		pool.mu.Unlock()
		return
	}
	counts := make(map[string]int, len(warmable))
	for _, item := range pool.idle[key] {
		counts[item.route.id]++
	}
	var evicted []*warmPeer
	if len(pool.idle[key]) >= warmPerRoute && len(warmable) > 1 {
		missing := 0
		for _, candidate := range warmable {
			if counts[candidate.id] == 0 {
				missing++
			}
		}
		for range missing {
			victim := -1
			for i, item := range pool.idle[key] {
				if counts[item.route.id] <= 1 {
					continue
				}
				if victim < 0 || counts[item.route.id] > counts[pool.idle[key][victim].route.id] {
					victim = i
				}
			}
			if victim < 0 {
				break
			}
			item := pool.idle[key][victim]
			item.expiry.Stop()
			pool.idle[key] = append(pool.idle[key][:victim], pool.idle[key][victim+1:]...)
			pool.count--
			counts[item.route.id]--
			evicted = append(evicted, item)
		}
	}
	count := min(warmPerRoute-len(pool.idle[key]), warmLimit-pool.count)
	if count <= 0 {
		pool.mu.Unlock()
		for _, item := range evicted {
			_ = item.p.Close()
		}
		return
	}
	plan := make([]route, 0, count)
	for range count {
		best := warmable[0]
		for _, candidate := range warmable[1:] {
			if counts[candidate.id] < counts[best.id] {
				best = candidate
			}
		}
		counts[best.id]++
		plan = append(plan, best)
	}
	pool.filling[key] = true
	pool.count += count
	pool.wg.Add(1)
	pool.mu.Unlock()
	for _, item := range evicted {
		_ = item.p.Close()
	}
	go func() {
		defer pool.wg.Done()
		defer func() { pool.mu.Lock(); pool.filling[key] = false; pool.mu.Unlock() }()
		for _, candidate := range plan {
			select {
			case pool.workers <- struct{}{}:
			case <-pool.ctx.Done():
				pool.mu.Lock()
				pool.count--
				pool.mu.Unlock()
				continue
			}
			ctx, cancel := context.WithTimeout(pool.ctx, 4*time.Second)
			p, err := r.dialBackground(ctx, candidate)
			cancel()
			<-pool.workers
			pool.mu.Lock()
			if err != nil || p == nil || pool.closed || !peerAlive(p) {
				pool.count--
				pool.mu.Unlock()
				if p != nil {
					_ = p.Close()
				}
				continue
			}
			item := &warmPeer{p: p, route: candidate, created: time.Now()}
			pool.idle[key] = append(pool.idle[key], item)
			item.expiry = time.AfterFunc(warmTTL, func() { pool.expire(key, item) })
			pool.mu.Unlock()
		}
	}()
}

func (p *warmPool) expire(key poolKey, item *warmPeer) {
	p.mu.Lock()
	for i, current := range p.idle[key] {
		if current == item {
			p.idle[key] = append(p.idle[key][:i], p.idle[key][i+1:]...)
			p.count--
			p.mu.Unlock()
			_ = item.p.Close()
			return
		}
	}
	p.mu.Unlock()
}

func (p *warmPool) close() {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	var sockets []peer
	for key, items := range p.idle {
		for _, item := range items {
			item.expiry.Stop()
			sockets = append(sockets, item.p)
			p.count--
		}
		delete(p.idle, key)
	}
	p.mu.Unlock()
	for _, socket := range sockets {
		_ = socket.Close()
	}
	p.wg.Wait()
}
