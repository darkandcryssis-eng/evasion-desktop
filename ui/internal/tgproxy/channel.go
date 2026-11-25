package tgproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

type relayChannel struct {
	upstream   peer
	route      route
	latency    time.Duration
	encrypt    cipher.Stream
	decrypt    cipher.Stream
	firstReply []byte
	label      string
}

func telegramRouteLabel(candidate route, dc int) string {
	transport := "WSS"
	if candidate.fronting {
		transport = "WSS · fronting"
	}
	if candidate.tcp {
		transport = "TCP"
	}
	if candidate.tunnel {
		transport = "VLESS"
	}
	if candidate.community {
		transport = "WSS"
		if candidate.plain {
			transport = "WS"
		}
		return fmt.Sprintf("Резерв %s · DC%d · %s", transport, dc, candidate.host)
	}
	return fmt.Sprintf("%s · DC%d", transport, dc)
}

func readFirstUpstream(ctx context.Context, upstream peer, timeout time.Duration) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		buf := buffers.Get().([]byte)
		n, err := upstream.Read(buf)
		data := append([]byte(nil), buf[:n]...)
		buffers.Put(buf)
		resultCh <- result{data: data, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		if len(result.data) > 0 {
			return result.data, nil
		}
		if result.err == nil {
			result.err = io.EOF
		}
		return nil, protocolProbeError{result.err}
	case <-timer.C:
		_ = upstream.Close()
		<-resultCh
		return nil, protocolProbeError{fmt.Errorf("нет первого ответа Telegram: %w", context.DeadlineExceeded)}
	case <-ctx.Done():
		_ = upstream.Close()
		<-resultCh
		return nil, ctx.Err()
	}
}

// hedgeDelayFor — через сколько без первого ответа Telegram запускать
// страхующую попытку по другому маршруту. Раньше «чёрная дыра» держала клиента
// весь replyTimeout (≥2.5 с) и только потом начинался следующий маршрут.
func hedgeDelayFor(hint time.Duration) time.Duration {
	if hint <= 0 {
		return time.Second
	}
	return min(max(3*hint, 500*time.Millisecond), 1500*time.Millisecond)
}

var errOutrun = errors.New("обогнан страхующим маршрутом: нет первого ответа")

type channelAttempt struct {
	mu        sync.Mutex
	candidate route
	known     bool
	done      bool
	started   time.Time
}

func (a *channelAttempt) route() (route, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.candidate, a.known
}

// openChannel открывает канал к Telegram. Если выбранный маршрут не прислал
// первый ответ за hedgeDelayFor, параллельно запускается вторая попытка по
// другому маршруту; побеждает первый ответивший, проигравший закрывается. В
// полёте не больше двух попыток, отказ одной сразу заменяется новой.
func (s *Server) openChannel(ctx context.Context, h handshake, firstFrame []byte) (*relayChannel, error) {
	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan channelOutcome, 16)
	routed := make(chan *channelAttempt, 16)
	var attempts []*channelAttempt
	inflight := 0
	launch := func(avoid string) {
		a := &channelAttempt{started: time.Now()}
		attempts = append(attempts, a)
		inflight++
		go func() {
			channel, connectErr, err := s.openAttempt(attemptCtx, h, firstFrame, avoid, a, routed)
			results <- channelOutcome{attempt: a, channel: channel, err: err, connect: connectErr}
		}()
	}
	pendingRoute := func() string {
		for _, a := range attempts {
			if a.done {
				continue
			}
			if c, ok := a.route(); ok {
				return c.id
			}
		}
		return ""
	}
	launch("")
	hedge := time.NewTimer(hedgeDelayFor(0))
	hedge.Stop()
	defer hedge.Stop()
	var hedgeC <-chan time.Time
	hedged := false
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			go drainAttempts(results, inflight)
			return nil, ctx.Err()
		case a := <-routed:
			if !hedged && !a.done && inflight == 1 {
				c, _ := a.route()
				hedge.Reset(hedgeDelayFor(s.router.latencyHint(c.id)))
				hedgeC = hedge.C
			}
		case <-hedgeC:
			hedgeC = nil
			if avoid := pendingRoute(); !hedged && inflight == 1 && avoid != "" {
				hedged = true
				launch(avoid)
			}
		case o := <-results:
			inflight--
			o.attempt.done = true
			if o.err == nil {
				cancel()
				winner := o.channel.route.id
				for _, a := range attempts {
					if a.done {
						continue
					}
					if c, ok := a.route(); ok && c.id != winner && a.started.Before(o.attempt.started) {
						s.router.failure(c.id, protocolProbeError{errOutrun})
					}
				}
				go drainAttempts(results, inflight)
				s.up.Add(uint64(len(firstFrame)))
				s.router.success(winner, o.channel.latency)
				s.router.warm(h.dc, h.media, o.channel.route)
				s.log("INFO", "Есть обмен с Telegram", o.channel.label)
				return o.channel, nil
			}
			lastErr = o.err
			hedge.Stop()
			hedgeC = nil
			if ctx.Err() != nil {
				go drainAttempts(results, inflight)
				return nil, ctx.Err()
			}
			if o.connect {
				if inflight == 0 {
					return nil, lastErr
				}
				continue
			}
			launch(pendingRoute())
		}
	}
}

type channelOutcome struct {
	attempt *channelAttempt
	channel *relayChannel
	err     error
	connect bool
}

// drainAttempts дожидается попыток, оставшихся в полёте после решения, и
// закрывает каналы, успевшие открыться впустую.
func drainAttempts(results <-chan channelOutcome, inflight int) {
	for range inflight {
		if o := <-results; o.channel != nil {
			_ = o.channel.upstream.Close()
		}
	}
}

// openAttempt — одна попытка: маршрут, рукопожатие, первый кадр, первый ответ.
// connectErr сообщает, что не нашлось маршрута вовсе (повторять бессмысленно).
func (s *Server) openAttempt(ctx context.Context, h handshake, firstFrame []byte, avoid string, a *channelAttempt, routed chan<- *channelAttempt) (*relayChannel, bool, error) {
	upstream, candidate, latency, err := s.router.connectAvoid(ctx, h.dc, h.media, avoid)
	if err != nil {
		return nil, true, err
	}
	a.mu.Lock()
	a.candidate, a.known = candidate, true
	a.mu.Unlock()
	select {
	case routed <- a:
	default:
	}
	// Отмена попытки (победил другой маршрут) закрывает сокет сразу: иначе
	// проигравший WritePacket, не знающий о контексте, держал бы его до таймаута.
	stopClose := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	label := telegramRouteLabel(candidate, h.dc)
	init, tgEnc, tgDec, err := relayHandshake(h)
	if err == nil {
		err = upstream.WritePacket(bytes.NewReader(init), int64(len(init)))
	}
	if err == nil {
		encoded := append([]byte(nil), firstFrame...)
		tgEnc.XORKeyStream(encoded, encoded)
		err = upstream.WritePacket(bytes.NewReader(encoded), int64(len(encoded)))
	}
	var firstReply []byte
	if err == nil {
		firstReply, err = readFirstUpstream(ctx, upstream, replyTimeoutFor(s.firstReplyTimeout, s.router.latencyHint(candidate.id)))
	}
	if err == nil && !stopClose() {
		err = ctx.Err()
	}
	if err != nil {
		stopClose()
		_ = upstream.Close()
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			s.router.failure(candidate.id, err)
		} else {
			s.router.failure(candidate.id, protocolProbeError{err})
		}
		s.log("INFO", "Маршрут Telegram не ответил, выбираю другой", label+": "+err.Error())
		return nil, false, err
	}
	return &relayChannel{upstream: upstream, route: candidate, latency: latency, encrypt: tgEnc, decrypt: tgDec, firstReply: firstReply, label: label}, false, nil
}

// switchChannel opens a replacement upstream route after an active channel
// breaks mid-stream, avoiding the failed route. If replayFrames is non-empty,
// it replays all pending unacknowledged client frames in order and verifies
// the first reply. On an idle switch (no pending frames), it verifies that an
// unverified candidate actually answers Telegram before accepting it.
func (s *Server) switchChannel(ctx context.Context, h handshake, avoid string, replayFrames [][]byte) (*relayChannel, error) {
	const maxSwitchAttempts = 3
	switchCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	tried := map[string]bool{}
	if avoid != "" {
		tried[avoid] = true
	}
	var lastErr error
	for attempt := 0; attempt < maxSwitchAttempts && switchCtx.Err() == nil; attempt++ {
		upstream, candidate, latency, err := s.router.connectAvoidSet(switchCtx, h.dc, h.media, tried)
		if err != nil {
			lastErr = err
			break
		}
		tried[candidate.id] = true
		stopClose := context.AfterFunc(switchCtx, func() { _ = upstream.Close() })
		label := telegramRouteLabel(candidate, h.dc)
		init, tgEnc, tgDec, err := relayHandshake(h)
		if err == nil {
			err = upstream.WritePacket(bytes.NewReader(init), int64(len(init)))
		}
		var firstReply []byte
		if err == nil && len(replayFrames) > 0 {
			for _, frame := range replayFrames {
				if len(frame) == 0 {
					continue
				}
				encoded := append([]byte(nil), frame...)
				tgEnc.XORKeyStream(encoded, encoded)
				if err = upstream.WritePacket(bytes.NewReader(encoded), int64(len(encoded))); err != nil {
					break
				}
			}
			if err == nil {
				firstReply, err = readFirstUpstream(switchCtx, upstream, replyTimeoutFor(s.firstReplyTimeout, s.router.latencyHint(candidate.id)))
			}
		} else if err == nil && !s.router.isVerified(candidate.id) {
			// Idle switch onto an unverified route: confirm Telegram actually
			// responds on this route so failover never lands on a silent blackhole.
			s.router.probeRoute(switchCtx, candidate, 3*time.Second)
			if !s.router.isVerified(candidate.id) {
				err = errors.New("replacement route did not answer Telegram probe")
			}
		}
		if err == nil && !stopClose() {
			err = switchCtx.Err()
		}
		if err != nil {
			stopClose()
			_ = upstream.Close()
			if switchCtx.Err() == nil {
				s.router.failure(candidate.id, err)
			}
			lastErr = err
			continue
		}
		s.router.success(candidate.id, latency)
		s.router.warm(h.dc, h.media, candidate)
		return &relayChannel{
			upstream:   upstream,
			route:      candidate,
			latency:    latency,
			encrypt:    tgEnc,
			decrypt:    tgDec,
			firstReply: firstReply,
			label:      label,
		}, nil
	}
	if lastErr == nil {
		lastErr = switchCtx.Err()
	}
	return nil, lastErr
}
