package tgproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type LogLine struct {
	At    string `json:"at"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
	Attrs string `json:"attrs"`
}
type Snapshot struct {
	Speeds      []SpeedSample     `json:"speeds"`
	Running     bool              `json:"running"`
	Phase       string            `json:"phase"`
	Address     string            `json:"address"`
	Active      int64             `json:"active"`
	Connections uint64            `json:"connections"`
	BytesUp     uint64            `json:"bytesUp"`
	BytesDown   uint64            `json:"bytesDown"`
	Failures    uint64            `json:"failures"`
	Switches    uint64            `json:"switches"`
	Rejected    uint64            `json:"rejected"`
	Route       string            `json:"route"`
	DialMS      int64             `json:"dialMs"`
	LastDataAt  string            `json:"lastDataAt"`
	Error       string            `json:"error"`
	Logs        []LogLine         `json:"logs"`
	Disconnects []DisconnectEvent `json:"disconnects"`
}

type Options struct {
	CachePath         string
	JournalPath       string
	NetworkKey        string
	Community         bool
	Port              int
	Secret            []byte
	MaxClients        int
	FirstReplyTimeout time.Duration
	Dial              dialFunc
	Tunnel            dialFunc
}

type Server struct {
	mu                    sync.Mutex
	listener              net.Listener
	ctx                   context.Context
	cancel                context.CancelFunc
	closed                bool
	clients               map[net.Conn]struct{}
	wg                    sync.WaitGroup
	slots                 chan struct{}
	secret                []byte
	router                *router
	journal               *disconnectJournal
	cachePath, networkKey string
	firstReplyTimeout     time.Duration
	active                atomic.Int64
	dialing               atomic.Int64
	connections           atomic.Uint64
	up                    atomic.Uint64
	down                  atomic.Uint64
	failures              atomic.Uint64
	switches              atomic.Uint64
	rejected              atomic.Uint64
	lastData              time.Time
	lastErr               string
	lastRoute             string
	dialMS                int64
	logs                  []LogLine
	speeds                []SpeedSample
	usedKeys              map[poolKey]struct{}
	guardianSignal        chan struct{}
}

func New(opts Options) (*Server, error) {
	if len(opts.Secret) != 16 || opts.Port < 0 || opts.Port > 65535 {
		return nil, errors.New("invalid Telegram proxy settings")
	}
	if opts.MaxClients == 0 {
		opts.MaxClients = 64
	}
	if opts.MaxClients < 1 || opts.MaxClients > 256 {
		return nil, errors.New("invalid connection limit")
	}
	if opts.FirstReplyTimeout == 0 {
		opts.FirstReplyTimeout = 3 * time.Second
	}
	server := &Server{secret: append([]byte(nil), opts.Secret...), clients: map[net.Conn]struct{}{}, slots: make(chan struct{}, opts.MaxClients), router: newRouter(opts.Dial, opts.Community), journal: newDisconnectJournal(opts.JournalPath), cachePath: opts.CachePath, networkKey: opts.NetworkKey, firstReplyTimeout: opts.FirstReplyTimeout, usedKeys: map[poolKey]struct{}{}, guardianSignal: make(chan struct{}, 1)}
	server.router.tunnel = opts.Tunnel
	return server, nil
}

func (s *Server) Start(ctx context.Context, port int) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil || s.closed {
		return errors.New("Telegram proxy has already been started")
	}
	if port < 0 || port > 65535 {
		return errors.New("invalid port")
	}
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("не удалось открыть локальный порт Telegram: %w", err)
	}
	s.listener = listener
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.router.enableCache(s.cachePath, s.networkKey)
	s.wg.Add(3)
	go s.accept()
	go s.measure()
	go s.guardian()
	if s.router.community {
		s.wg.Add(1)
		go s.refreshDomains()
	}
	go func() { <-s.ctx.Done(); _ = s.Close() }()
	s.logs = append(s.logs, LogLine{At: time.Now().Format(time.RFC3339Nano), Level: "INFO", Msg: "Telegram-прокси запущен", Attrs: listener.Addr().String()})
	return nil
}

func (s *Server) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := Snapshot{Speeds: append([]SpeedSample{}, s.speeds...), Phase: "stopped", Running: s.listener != nil && !s.closed, Active: s.active.Load(), Connections: s.connections.Load(), BytesUp: s.up.Load(), BytesDown: s.down.Load(), Failures: s.failures.Load(), Switches: s.switches.Load(), Rejected: s.rejected.Load(), Route: s.lastRoute, DialMS: s.dialMS, Error: s.lastErr, Logs: append([]LogLine{}, s.logs...), Disconnects: s.journal.snapshot()}
	if s.listener != nil {
		state.Address = s.listener.Addr().String()
	}
	if !s.lastData.IsZero() {
		state.LastDataAt = s.lastData.Format(time.RFC3339Nano)
	}
	if state.Running {
		switch {
		case state.Active > 0 && !s.lastData.IsZero() && time.Since(s.lastData) < 90*time.Second:
			state.Phase = "online"
		case s.dialing.Load() > 0:
			state.Phase = "connecting"
		case s.lastErr != "":
			state.Phase = "degraded"
		default:
			state.Phase = "waiting"
		}
	}
	return state
}

func (s *Server) log(level, message, details string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, LogLine{At: time.Now().Format(time.RFC3339Nano), Level: level, Msg: message, Attrs: details})
	if len(s.logs) > 200 {
		s.logs = s.logs[len(s.logs)-200:]
	}
	if level == "ERROR" {
		s.lastErr = message
	}
}

func (s *Server) accept() {
	defer s.wg.Done()
	var backoff time.Duration
	for {
		s.mu.Lock()
		listener, closed := s.listener, s.closed
		s.mu.Unlock()
		if closed || listener == nil {
			return
		}
		client, err := listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			if backoff == 0 {
				backoff = 10 * time.Millisecond
			} else {
				backoff = min(backoff*2, time.Second)
			}
			s.log("WARN", "Восстановление локального порта Telegram", err.Error())
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
			case <-s.ctx.Done():
				timer.Stop()
				return
			}
			var temporary interface{ Temporary() bool }
			if !errors.As(err, &temporary) || !temporary.Temporary() {
				// Как и upstream listener watchdog: постоянная ошибка Accept не
				// выключает прокси — занимаем тот же loopback-адрес и продолжаем.
				s.mu.Lock()
				if s.listener == listener && !s.closed {
					_ = listener.Close()
					replacement, listenErr := net.Listen("tcp4", listener.Addr().String())
					if listenErr == nil {
						s.listener = replacement
						s.logs = append(s.logs, LogLine{At: time.Now().Format(time.RFC3339Nano), Level: "INFO", Msg: "Локальный порт Telegram восстановлен", Attrs: replacement.Addr().String()})
					}
				}
				s.mu.Unlock()
			}
			continue
		}
		backoff = 0
		tuneSocket(client)
		select {
		case s.slots <- struct{}{}:
		default:
			s.rejected.Add(1)
			_ = client.Close()
			continue
		}
		s.mu.Lock()
		if s.closed || s.ctx.Err() != nil {
			s.mu.Unlock()
			<-s.slots
			_ = client.Close()
			return
		}
		s.clients[client] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { _ = client.Close(); s.mu.Lock(); delete(s.clients, client); s.mu.Unlock(); <-s.slots }()
			s.serve(client)
		}()
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		if s.cancel != nil {
			s.cancel()
		}
		if s.listener != nil {
			_ = s.listener.Close()
		}
		for client := range s.clients {
			_ = client.Close()
		}
	}
	s.mu.Unlock()
	s.router.pool.close()
	s.wg.Wait()
	s.router.cache.close()
	return nil
}

const (
	maxSeamlessSwitches  = 5
	bufferedDownFrameMax = 256 << 10
)

type clientFrameMsg struct {
	frame []byte
	err   error
}

type upstreamChunkMsg struct {
	data     []byte
	midFrame bool
	err      error
}

func startUpstreamReader(ctx context.Context, upstream peer, firstReply []byte, dec cipher.Stream, protocol byte) (<-chan upstreamChunkMsg, <-chan struct{}) {
	ch := make(chan upstreamChunkMsg, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(ch)
		raw := io.Reader(upstream)
		if len(firstReply) > 0 {
			raw = io.MultiReader(bytes.NewReader(firstReply), upstream)
		}
		decReader := &cipher.StreamReader{S: dec, R: raw}
		for {
			header, size, err := readUpstreamPacketHeader(decReader, protocol)
			if err != nil {
				select {
				case ch <- upstreamChunkMsg{err: err}:
				case <-ctx.Done():
				}
				return
			}
			if size == 0 {
				// Standalone 4-byte quick-acknowledgment token from Telegram.
				select {
				case ch <- upstreamChunkMsg{data: header, midFrame: false}:
				case <-ctx.Done():
					return
				}
				continue
			}
			if size <= bufferedDownFrameMax {
				frame := make([]byte, len(header)+int(size))
				copy(frame, header)
				if _, err := io.ReadFull(decReader, frame[len(header):]); err != nil {
					select {
					case ch <- upstreamChunkMsg{err: err}:
					case <-ctx.Done():
					}
					return
				}
				select {
				case ch <- upstreamChunkMsg{data: frame, midFrame: false}:
				case <-ctx.Done():
					return
				}
				continue
			}
			// Large media frame: stream header then chunks while tracking midFrame.
			select {
			case ch <- upstreamChunkMsg{data: header, midFrame: true}:
			case <-ctx.Done():
				return
			}
			remaining := size
			for remaining > 0 {
				buf := make([]byte, min(remaining, 32<<10))
				n, err := decReader.Read(buf)
				if n > 0 {
					remaining -= int64(n)
					select {
					case ch <- upstreamChunkMsg{data: buf[:n], midFrame: remaining > 0}:
					case <-ctx.Done():
						return
					}
				}
				if err != nil {
					select {
					case ch <- upstreamChunkMsg{err: err, midFrame: remaining > 0}:
					case <-ctx.Done():
					}
					return
				}
			}
		}
	}()
	return ch, done
}

func writeAll(w io.Writer, b []byte) (int, error) {
	written := 0
	for len(b) > 0 {
		n, err := w.Write(b)
		written += n
		b = b[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

func (s *Server) serve(client net.Conn) {
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	h, err := readHandshake(client, s.secret)
	if err != nil {
		s.rejected.Add(1)
		return
	}
	_ = client.SetReadDeadline(time.Time{})
	s.active.Add(1)
	defer s.active.Add(-1)
	s.connections.Add(1)
	s.mu.Lock()
	s.usedKeys[poolKey{h.dc, h.media}] = struct{}{}
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	reader := &cipher.StreamReader{S: h.decrypt, R: client}
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	header, size, err := readPacketHeader(reader, h.protocol)
	var firstFrame []byte
	if err == nil {
		firstFrame = make([]byte, int(size)+len(header))
		copy(firstFrame, header)
		_, err = io.ReadFull(reader, firstFrame[len(header):])
	}
	_ = client.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	openCtx, openCancel := context.WithTimeout(ctx, 12*time.Second)
	started := time.Now()
	s.dialing.Add(1)
	channel, err := s.openChannel(openCtx, h, firstFrame)
	s.dialing.Add(-1)
	openCancel()
	if err != nil {
		if ctx.Err() == nil {
			s.failures.Add(1)
			s.journal.record(DisconnectEvent{
				DC:         h.dc,
				Media:      h.media,
				Stage:      "dial",
				Cause:      classifyDisconnect(err),
				Detail:     err.Error(),
				DurationMS: time.Since(started).Milliseconds(),
			})
			s.log("ERROR", "Маршрут Telegram недоступен", err.Error())
			s.pingGuardian()
		}
		return
	}

	upstream := channel.upstream
	candidate := channel.route
	tgEnc, tgDec := channel.encrypt, channel.decrypt
	label := channel.label
	connectedAt := time.Now()
	connUp := uint64(len(firstFrame))
	connDown := uint64(0)
	s.mu.Lock()
	s.lastRoute = label
	s.dialMS = time.Since(started).Milliseconds()
	s.mu.Unlock()

	upCtx, upCancel := context.WithCancel(ctx)
	upCh, upDone := startUpstreamReader(upCtx, upstream, channel.firstReply, tgDec, h.protocol)

	clientCh := make(chan clientFrameMsg, 1)
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		for {
			hdr, sz, rerr := readPacketHeader(reader, h.protocol)
			if rerr != nil {
				select {
				case clientCh <- clientFrameMsg{err: rerr}:
				case <-ctx.Done():
				}
				return
			}
			frame := make([]byte, len(hdr)+int(sz))
			copy(frame, hdr)
			if _, rerr = io.ReadFull(reader, frame[len(hdr):]); rerr != nil {
				select {
				case clientCh <- clientFrameMsg{err: rerr}:
				case <-ctx.Done():
				}
				return
			}
			select {
			case clientCh <- clientFrameMsg{frame: frame}:
			case <-ctx.Done():
				return
			}
		}
	}()

	closeCurrentUpstream := func() {
		upCancel()
		_ = upstream.Close()
		<-upDone
	}
	defer func() {
		cancel()
		_ = client.Close()
		closeCurrentUpstream()
		<-clientDone
	}()

	const (
		maxPendingReplayFrames = 8
		maxPendingReplayBytes  = 256 << 10
	)
	var pendingFrames [][]byte
	pendingBytes := 0
	pendingOverflow := false
	pushPending := func(frame []byte) {
		if pendingOverflow {
			return
		}
		if len(pendingFrames) >= maxPendingReplayFrames || pendingBytes+len(frame) > maxPendingReplayBytes {
			pendingFrames = nil
			pendingBytes = 0
			pendingOverflow = true
			return
		}
		pendingFrames = append(pendingFrames, frame)
		pendingBytes += len(frame)
	}
	popPending := func() {
		if pendingOverflow {
			pendingOverflow = false
			return
		}
		if len(pendingFrames) > 0 {
			pendingBytes -= len(pendingFrames[0])
			pendingFrames = pendingFrames[1:]
		}
	}

	midFrame := false
	switchesUsed := 0

	trySwitch := func(stage string, causeErr error, extraFrame []byte) bool {
		duration := time.Since(connectedAt)
		cause := classifyDisconnect(causeErr)
		cleanClose := errors.Is(causeErr, io.EOF) || websocket.IsCloseError(causeErr, websocket.CloseNormalClosure, websocket.CloseGoingAway)
		if !cleanClose || duration < 30*time.Second {
			s.router.recordDrop(candidate, duration, causeErr)
		} else {
			s.router.recordCleanSession(candidate.id, duration)
		}
		ev := DisconnectEvent{
			RouteID:    candidate.id,
			RouteLabel: label,
			Transport:  routeTransport(candidate),
			DC:         h.dc,
			Media:      h.media,
			Stage:      stage,
			Cause:      cause,
			Detail:     causeErr.Error(),
			DurationMS: duration.Milliseconds(),
			BytesUp:    connUp,
			BytesDown:  connDown,
		}
		closeCurrentUpstream()
		replay := make([][]byte, 0, len(pendingFrames)+1)
		replay = append(replay, pendingFrames...)
		if len(extraFrame) > 0 {
			replay = append(replay, extraFrame)
		}
		if !midFrame && !pendingOverflow && switchesUsed < maxSeamlessSwitches && ctx.Err() == nil {
			replacement, switchErr := s.switchChannel(ctx, h, candidate.id, replay)
			if switchErr == nil {
				switchesUsed++
				s.switches.Add(1)
				ev.Recovered = true
				ev.SwitchedTo = replacement.label
				s.journal.record(ev)
				upstream = replacement.upstream
				candidate = replacement.route
				tgEnc, tgDec = replacement.encrypt, replacement.decrypt
				label = replacement.label
				connectedAt = time.Now()
				var replayedBytes uint64
				for _, f := range replay {
					replayedBytes += uint64(len(f))
				}
				connUp = replayedBytes
				connDown = 0
				if replayedBytes > 0 {
					s.up.Add(replayedBytes)
				}
				pendingFrames = nil
				pendingBytes = 0
				pendingOverflow = false
				s.mu.Lock()
				s.lastRoute = label
				s.lastErr = ""
				s.mu.Unlock()
				s.log("INFO", "Маршрут Telegram переключён без обрыва", ev.RouteLabel+" → "+label)
				upCtx, upCancel = context.WithCancel(ctx)
				upCh, upDone = startUpstreamReader(upCtx, upstream, replacement.firstReply, tgDec, h.protocol)
				s.pingGuardian()
				return true
			}
		}
		s.journal.record(ev)
		if !cleanClose {
			s.failures.Add(1)
			s.log("ERROR", "Соединение Telegram прервано", label+": "+causeErr.Error())
			s.pingGuardian()
		} else {
			s.log("INFO", "Канал Telegram закрыт", label)
		}
		return false
	}

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-clientCh:
			if msg.err != nil {
				s.router.recordCleanSession(candidate.id, time.Since(connectedAt))
				s.log("INFO", "Канал Telegram закрыт", label)
				return
			}
			encoded := append([]byte(nil), msg.frame...)
			tgEnc.XORKeyStream(encoded, encoded)
			writeErr := upstream.WritePacket(bytes.NewReader(encoded), int64(len(encoded)))
			if writeErr != nil {
				if ctx.Err() != nil {
					return
				}
				if !trySwitch("relay_write", writeErr, msg.frame) {
					return
				}
				continue
			}
			pushPending(msg.frame)
			connUp += uint64(len(msg.frame))
			s.up.Add(uint64(len(msg.frame)))
		case msg, ok := <-upCh:
			if !ok {
				return
			}
			if len(msg.data) > 0 {
				if !msg.midFrame {
					popPending()
				}
				out := make([]byte, len(msg.data))
				h.encrypt.XORKeyStream(out, msg.data)
				_ = client.SetWriteDeadline(time.Now().Add(30 * time.Second))
				written, writeErr := writeAll(client, out)
				connDown += uint64(written)
				s.mu.Lock()
				s.down.Add(uint64(written))
				if written > 0 {
					s.lastData = time.Now()
					s.lastErr = ""
				}
				s.mu.Unlock()
				if writeErr != nil {
					s.router.recordCleanSession(candidate.id, time.Since(connectedAt))
					return
				}
				midFrame = msg.midFrame
			}
			if msg.err != nil {
				if ctx.Err() != nil {
					return
				}
				if !trySwitch("relay_read", msg.err, nil) {
					return
				}
			}
		}
	}
}
