package tgproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
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

func (s *Server) openChannel(ctx context.Context, h handshake, firstFrame []byte) (*relayChannel, error) {
	for {
		upstream, candidate, latency, err := s.router.connect(ctx, h.dc, h.media)
		if err != nil {
			return nil, err
		}
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
		if err != nil {
			_ = upstream.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
				s.router.failure(candidate.id, err)
			} else {
				s.router.failure(candidate.id, protocolProbeError{err})
			}
			s.log("INFO", "Маршрут Telegram не ответил, выбираю другой", label+": "+err.Error())
			continue
		}
		s.up.Add(uint64(len(firstFrame)))
		s.router.success(candidate.id, latency)
		s.router.warm(h.dc, h.media, candidate)
		s.log("INFO", "Есть обмен с Telegram", label)
		return &relayChannel{upstream: upstream, route: candidate, latency: latency, encrypt: tgEnc, decrypt: tgDec, firstReply: firstReply, label: label}, nil
	}
}
