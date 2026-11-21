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
	Speeds      []SpeedSample `json:"speeds"`
	Running     bool          `json:"running"`
	Phase       string        `json:"phase"`
	Address     string        `json:"address"`
	Active      int64         `json:"active"`
	Connections uint64        `json:"connections"`
	BytesUp     uint64        `json:"bytesUp"`
	BytesDown   uint64        `json:"bytesDown"`
	Failures    uint64        `json:"failures"`
	Rejected    uint64        `json:"rejected"`
	Route       string        `json:"route"`
	DialMS      int64         `json:"dialMs"`
	LastDataAt  string        `json:"lastDataAt"`
	Error       string        `json:"error"`
	Logs        []LogLine     `json:"logs"`
}

type Options struct {
	CachePath         string
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
	cachePath, networkKey string
	firstReplyTimeout     time.Duration
	active                atomic.Int64
	dialing               atomic.Int64
	connections           atomic.Uint64
	up                    atomic.Uint64
	down                  atomic.Uint64
	failures              atomic.Uint64
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
	server := &Server{secret: append([]byte(nil), opts.Secret...), clients: map[net.Conn]struct{}{}, slots: make(chan struct{}, opts.MaxClients), router: newRouter(opts.Dial, opts.Community), cachePath: opts.CachePath, networkKey: opts.NetworkKey, firstReplyTimeout: opts.FirstReplyTimeout, usedKeys: map[poolKey]struct{}{}, guardianSignal: make(chan struct{}, 1)}
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
	state := Snapshot{Speeds: append([]SpeedSample{}, s.speeds...), Phase: "stopped", Running: s.listener != nil && !s.closed, Active: s.active.Load(), Connections: s.connections.Load(), BytesUp: s.up.Load(), BytesDown: s.down.Load(), Failures: s.failures.Load(), Rejected: s.rejected.Load(), Route: s.lastRoute, DialMS: s.dialMS, Error: s.lastErr, Logs: append([]LogLine{}, s.logs...)}
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

type relayResult struct {
	err      error
	upstream bool
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
			s.log("ERROR", "Маршрут Telegram недоступен", err.Error())
			s.pingGuardian()
		}
		return
	}
	upstream := channel.upstream
	candidate := channel.route
	tgEnc, tgDec := channel.encrypt, channel.decrypt
	label := channel.label
	defer upstream.Close()
	s.mu.Lock()
	s.lastRoute = label
	s.dialMS = time.Since(started).Milliseconds()
	s.mu.Unlock()
	results := make(chan relayResult, 2)
	go func() {
		for {
			header, size, err := readPacketHeader(reader, h.protocol)
			if err != nil {
				results <- relayResult{err: err}
				return
			}
			encoded := &cipher.StreamReader{S: tgEnc, R: io.MultiReader(bytes.NewReader(header), io.LimitReader(reader, size))}
			err = upstream.WritePacket(encoded, size+int64(len(header)))
			if err != nil {
				results <- relayResult{err: err, upstream: !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF)}
				return
			}
			s.up.Add(uint64(size) + uint64(len(header)))
		}
	}()
	go func() {
		buf := buffers.Get().([]byte)
		defer buffers.Put(buf)
		upstreamReader := io.MultiReader(bytes.NewReader(channel.firstReply), upstream)
		for {
			n, err := upstreamReader.Read(buf)
			if n > 0 {
				tgDec.XORKeyStream(buf[:n], buf[:n])
				h.encrypt.XORKeyStream(buf[:n], buf[:n])
				_ = client.SetWriteDeadline(time.Now().Add(30 * time.Second))
				written, writeErr := writeAll(client, buf[:n])
				s.mu.Lock()
				s.down.Add(uint64(written))
				if written > 0 {
					s.lastData = time.Now()
					s.lastErr = ""
				}
				s.mu.Unlock()
				if writeErr != nil {
					results <- relayResult{err: writeErr}
					return
				}
			}
			if err != nil {
				results <- relayResult{err: err, upstream: true}
				return
			}
		}
	}()
	var selected relayResult
	consumed := 0
	select {
	case selected = <-results:
		consumed = 1
	case <-ctx.Done():
	}
	cancel()
	_ = client.Close()
	_ = upstream.Close()
	for consumed < 2 {
		<-results
		consumed++
	}
	if selected.upstream && s.ctx.Err() == nil && selected.err != nil && !errors.Is(selected.err, io.EOF) && !websocket.IsCloseError(selected.err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
		s.router.failure(candidate.id, selected.err)
		s.failures.Add(1)
		s.log("ERROR", "Соединение Telegram прервано", label+": "+selected.err.Error())
		// Будим стража: немедленно перепроверить маршруты и наполнить
		// тёплый пул, чтобы переподключение Telegram было мгновенным.
		s.pingGuardian()
	} else {
		s.log("INFO", "Канал Telegram закрыт", label)
	}
}
