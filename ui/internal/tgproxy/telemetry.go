package tgproxy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type SpeedSample struct {
	At   string  `json:"at"`
	Up   float64 `json:"up"`
	Down float64 `json:"down"`
}

type RouteStatus struct {
	Code      string `json:"code"`
	Reason    string `json:"reason"`
	ID        string `json:"id"`
	Host      string `json:"host"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
	LatencyMS int64  `json:"latencyMs"`
	Failures  int    `json:"failures"`
	CheckedAt string `json:"checkedAt"`
	RetryAt   string `json:"retryAt"`
}

func (s *Server) measure() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	last, up, down := time.Now(), s.up.Load(), s.down.Load()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			u, d := s.up.Load(), s.down.Load()
			elapsed := now.Sub(last).Seconds()
			if elapsed <= 0 {
				continue
			}
			sample := SpeedSample{At: now.Format(time.RFC3339Nano), Up: float64(u-up) / elapsed, Down: float64(d-down) / elapsed}
			s.mu.Lock()
			s.speeds = append(s.speeds, sample)
			if len(s.speeds) > 120 {
				copy(s.speeds, s.speeds[len(s.speeds)-120:])
				s.speeds = s.speeds[:120]
			}
			s.mu.Unlock()
			last, up, down = now, u, d
		}
	}
}

func (r *router) dialRoute(ctx context.Context, candidate route) (peer, error) {
	select {
	case r.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", errDialQueue, ctx.Err())
	}
	defer func() { <-r.slots }()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", errDialQueue, err)
	}
	r.mu.Lock()
	r.known[candidate.id] = candidate
	h := r.health[candidate.id]
	h.inflight++
	r.health[candidate.id] = h
	r.mu.Unlock()
	started := time.Now()
	dial := r.dial
	if candidate.tunnel {
		dial = r.tunnel
	}
	if dial == nil {
		r.mu.Lock()
		h.inflight--
		r.health[candidate.id] = h
		r.mu.Unlock()
		return nil, errors.New("локальный VLESS-канал Telegram не настроен")
	}
	p, err := dial(ctx, candidate)
	r.mu.Lock()
	h = r.health[candidate.id]
	h.inflight--
	if ctx.Err() == nil {
		h.checked = time.Now()
		if err == nil {
			h.opened = true
			h.code, h.reason = "", ""
			if !h.success {
				h.latency = time.Since(started)
			}
		}
	}
	r.health[candidate.id] = h
	r.mu.Unlock()
	return p, err
}

func (r *router) dialBackground(ctx context.Context, candidate route) (peer, error) {
	select {
	case r.background <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", errDialQueue, ctx.Err())
	}
	defer func() { <-r.background }()
	return r.dialRoute(ctx, candidate)
}

func (r *router) snapshot() []RouteStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, candidate := range routesFor(2, false) {
		r.known[candidate.id] = candidate
	}
	if r.community {
		domains := r.domains.all()
		for _, domain := range domains[:min(2, len(domains))] {
			candidate := relayRoute(2, false, domain)
			r.known[candidate.id] = candidate
		}
	}
	out := make([]RouteStatus, 0, len(r.known))
	now := time.Now()
	for id, candidate := range r.known {
		h := r.health[id]
		v := RouteStatus{Code: h.code, Reason: h.reason, ID: id, Host: candidate.host, Kind: "WSS", Status: "untested", LatencyMS: h.latency.Milliseconds(), Failures: h.failures}
		if candidate.address != "" && !candidate.tcp {
			v.Kind = "WSS · фиксированный адрес"
		}
		if candidate.fronting {
			v.Kind = "WSS · fronting"
		}
		if candidate.tcp {
			v.Kind = "TCP"
			v.Host, _, _ = strings.Cut(strings.TrimPrefix(id, "tcp:"), "/")
		}
		if candidate.tunnel {
			v.Kind = "VLESS"
			v.Host = candidate.address
		}
		if candidate.community {
			v.Kind = "Резерв WSS"
			if candidate.plain {
				v.Kind = "Резерв WS"
			}
		}
		if candidate.media {
			v.Kind += " · медиа"
		}
		switch {
		case h.inflight > 0:
			v.Status = "checking"
		case h.success:
			v.Status = "verified"
		case h.opened:
			v.Status = "opened"
		case now.Before(h.retryAt):
			v.Status = "cooldown"
		case h.failures > 0:
			v.Status = "failed"
		}
		if !h.checked.IsZero() {
			v.CheckedAt = h.checked.Format(time.RFC3339Nano)
		}
		if now.Before(h.retryAt) {
			v.RetryAt = h.retryAt.Format(time.RFC3339Nano)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Server) Routes() []RouteStatus { return s.router.snapshot() }

func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listener != nil && !s.closed
}
