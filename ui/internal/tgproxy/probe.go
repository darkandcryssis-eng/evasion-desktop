package tgproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// CheckRoutes uses an unauthenticated MTProto nonce exchange; it never logs in.
func (s *Server) CheckRoutes(ctx context.Context) []RouteStatus { return s.router.checkRoutes(ctx) }

func CheckRoutes(ctx context.Context, community bool) []RouteStatus {
	r := newRouter(nil, community)
	defer r.pool.close()
	return r.checkRoutes(ctx)
}

func (r *router) checkRoutes(ctx context.Context) []RouteStatus {
	candidates := routesFor(2, false)
	if r.community {
		domains := r.domains.forDC(2)
		for _, domain := range domains[:min(4, len(domains))] {
			candidates = append(candidates, communityRoutes(2, false, domain)...)
		}
	}
	candidates = append(candidates, tcpRoute(2, false))
	if r.tunnel != nil {
		candidates = append([]route{tunnelRoute(2, false)}, candidates...)
	}
	var wg sync.WaitGroup
	jobs := make(chan route)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for candidate := range jobs {
				r.probeRoute(ctx, candidate, 5*time.Second)
			}
		}()
	}
send:
	for _, candidate := range candidates {
		select {
		case jobs <- candidate:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	wg.Wait()
	return r.snapshot()
}

func (r *router) probeRoute(ctx context.Context, candidate route, timeout time.Duration) {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	p, err := r.dialBackground(probeCtx, candidate)
	if err == nil {
		err = probePeer(probeCtx, p, candidate)
		if err != nil {
			if probeCtx.Err() != nil {
				err = probeCtx.Err()
			}
			err = protocolProbeError{err}
		}
	}
	if p != nil {
		_ = p.Close()
	}
	if err == nil {
		r.success(candidate.id, time.Since(started))
	} else if ctx.Err() == nil {
		r.failure(candidate.id, err)
	}
}

type protocolProbeError struct{ error }

func (e protocolProbeError) Unwrap() error { return e.error }

func routeFailure(err error) (string, string) {
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var timeout net.Error
	var protocol protocolProbeError
	switch {
	case errors.As(err, &dns):
		return "dns_error", "DNS не определил адрес узла"
	case errors.As(err, &cert):
		return "tls_certificate", "Сертификат узла не прошёл проверку"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &timeout) && timeout.Timeout():
		if errors.As(err, &protocol) {
			return "mtproto_timeout", "Канал открыт, но Telegram не ответил вовремя"
		}
		return "channel_timeout", "Узел не открыл канал вовремя"
	default:
		if errors.As(err, &protocol) {
			return "mtproto_error", "Канал открыт, но ответ Telegram не подтверждён"
		}
		return "channel_error", "Не удалось открыть канал к узлу"
	}
}

func probePeer(ctx context.Context, p peer, candidate route) error {
	stop := context.AfterFunc(ctx, func() { _ = p.Close() })
	defer stop()
	init, enc, dec, err := relayHandshake(handshake{dc: candidate.dc, media: candidate.media, protocol: 0xef})
	if err != nil {
		return err
	}
	if err := p.WritePacket(bytes.NewReader(init), int64(len(init))); err != nil {
		return err
	}
	request := make([]byte, 40)
	now := time.Now()
	binary.LittleEndian.PutUint64(request[8:16], uint64(now.Unix())<<32|uint64(now.Nanosecond())&^3)
	binary.LittleEndian.PutUint32(request[16:20], 20)
	binary.LittleEndian.PutUint32(request[20:24], 0xbe7e8ef1)
	if _, err := rand.Read(request[24:40]); err != nil {
		return err
	}
	frame := append([]byte{10}, request...)
	enc.XORKeyStream(frame, frame)
	if err := p.WritePacket(bytes.NewReader(frame), int64(len(frame))); err != nil {
		return err
	}
	reader := &cipher.StreamReader{S: dec, R: p}
	_, size, err := readPacketHeader(reader, 0xef)
	if err != nil {
		return err
	}
	if size < 40 || size > 1024 {
		return errors.New("unexpected MTProto reply size")
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(reader, response); err != nil {
		return err
	}
	if !bytes.Equal(response[:8], make([]byte, 8)) || binary.LittleEndian.Uint32(response[20:24]) != 0x05162463 || !bytes.Equal(response[24:40], request[24:40]) {
		return errors.New("unexpected MTProto nonce response")
	}
	return nil
}
