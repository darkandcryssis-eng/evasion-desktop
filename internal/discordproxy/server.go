package discordproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type DialContextFunc func(context.Context, string, string) (net.Conn, error)

type Server struct {
	Dial DialContextFunc
	// Passthrough, если задан, обслуживает адреса вне Discord (порт 443)
	// вместо отказа. Нужен, когда клиент Discord целиком заведён на прокси:
	// сторонние узлы (капча, вложения, встраиваемые плееры) идут обычным
	// маршрутом, а не обрываются.
	Passthrough DialContextFunc
	// Reroute, если задан и вернул true, ведёт узел Discord через Passthrough:
	// так вызывающий переводит узел на другой маршрут, когда прямой не работает.
	Reroute func(host string) bool
	// NoReply, если больше нуля, обрывает соединение, на которое клиент уже
	// отправил данные, а узел за это время не ответил ни байтом. Клиент
	// подключается заново сразу, а не через свой долгий тайм-аут, и движок
	// успевает сменить стратегию.
	NoReply time.Duration
	// OnStall вызывается для каждого соединения, оборванного по NoReply.
	OnStall func(host string)
	Logger  *slog.Logger
	wg      sync.WaitGroup

	connMu sync.Mutex
	conns  map[net.Conn]activeConn

	statsMu sync.Mutex
	stats   map[string]*hostStats
	dirty   bool
}

// hostStats — что реально происходило с соединениями клиента к одному узлу.
type hostStats struct {
	opened, active, silent int
	up, down               atomic.Int64
	lastDown               atomic.Int64 // UnixNano последнего входящего блока
}

func (s *Server) track(host string, fn func(*hostStats)) *hostStats {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	if s.stats == nil {
		s.stats = make(map[string]*hostStats)
	}
	st := s.stats[host]
	if st == nil {
		if len(s.stats) >= 256 {
			return &hostStats{}
		}
		st = &hostStats{}
		s.stats[host] = st
	}
	fn(st)
	s.dirty = true
	return st
}

// Summary возвращает сводку по узлам и сбрасывает признак изменений.
// Пустая строка — с прошлого вызова ничего не менялось.
func (s *Server) Summary() string {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	active := false
	for _, st := range s.stats {
		active = active || st.active > 0
	}
	if !s.dirty && !active {
		return ""
	}
	s.dirty = false
	now := time.Now()
	hosts := make([]string, 0, len(s.stats))
	for host := range s.stats {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	var b strings.Builder
	for _, host := range hosts {
		st := s.stats[host]
		fmt.Fprintf(&b, "%s: соединений %d, открыто %d, без ответа %d, отправлено %d Б, получено %d Б",
			host, st.opened, st.active, st.silent, st.up.Load(), st.down.Load())
		if last := st.lastDown.Load(); last != 0 && st.active > 0 {
			fmt.Fprintf(&b, ", тишина %d с", int(now.Sub(time.Unix(0, last)).Seconds()))
		}
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

func (s *Server) reportLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if summary := s.Summary(); summary != "" && s.Logger != nil {
				s.Logger.Info("прокси Discord: соединения клиента", "узлы", summary)
			}
		}
	}
}

type activeConn struct {
	host     string
	upstream net.Conn
}

func (s *Server) register(host string, client, upstream net.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.conns == nil {
		s.conns = make(map[net.Conn]activeConn)
	}
	s.conns[client] = activeConn{host: host, upstream: upstream}
}

func (s *Server) unregister(client net.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	delete(s.conns, client)
}

// Drop обрывает открытые соединения к узлам, для которых match вернул true, и
// возвращает их число. Клиент при этом сам подключается заново.
func (s *Server) Drop(match func(host string) bool) int {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	dropped := 0
	for client, conn := range s.conns {
		if match(conn.host) {
			_ = client.Close()
			_ = conn.upstream.Close()
			dropped++
		}
	}
	return dropped
}

type countingWriter struct {
	w     io.Writer
	n     *atomic.Int64 // по соединению
	total *atomic.Int64 // по узлу
	stamp *atomic.Int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	c.total.Add(int64(n))
	if c.stamp != nil && n > 0 {
		c.stamp.Store(time.Now().UnixNano())
	}
	return n, err
}

func AllowedHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, domain := range []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discord.co", "discordstatus.com"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func allowedTarget(address string) (string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || !AllowedHost(host) {
		return "", fmt.Errorf("адрес не относится к Discord")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", fmt.Errorf("некорректный порт")
	}
	switch port {
	case 443, 2053, 2083, 2087, 2096, 8443:
	default:
		return "", fmt.Errorf("порт запрещён")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-closed:
		}
	}()
	defer close(closed)
	go s.reportLoop(ctx)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return ctx.Err()
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	stopClient := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stopClient()

	reader := bufio.NewReader(client)
	req, err := http.ReadRequest(reader)
	if err != nil {
		writeError(client, http.StatusBadRequest)
		return
	}
	if req.Method != http.MethodConnect {
		writeError(client, http.StatusMethodNotAllowed)
		return
	}
	dial := s.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	target, err := allowedTarget(req.Host)
	if err != nil {
		target, err = passthroughTarget(req.Host)
		if err != nil || s.Passthrough == nil {
			s.warn("прокси Discord: адрес отклонён", "адрес", req.Host)
			writeError(client, http.StatusForbidden)
			return
		}
		dial = s.Passthrough
	} else if host, _, _ := net.SplitHostPort(target); s.Reroute != nil && s.Passthrough != nil && s.Reroute(host) {
		dial = s.Passthrough
	}
	upstream, err := dial(ctx, "tcp", target)
	if err != nil {
		s.warn("прокси Discord: соединение не установлено", "адрес", target, "err", err)
		writeError(client, http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stopUpstream()
	if _, err = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	host, _, _ := net.SplitHostPort(target)
	s.register(host, client, upstream)
	defer s.unregister(client)
	var up, down atomic.Int64
	stats := s.track(host, func(st *hostStats) { st.opened++; st.active++ })
	defer func() {
		s.track(host, func(st *hostStats) {
			st.active--
			if up.Load() > 0 && down.Load() == 0 {
				st.silent++
			}
		})
	}()

	var lastUp, connDown, discard atomic.Int64
	var finished atomic.Bool // клиент отправил первую запись с данными приложения
	var flight atomic.Int64  // сколько узел прислал к моменту, когда клиент завершил рукопожатие
	records := &tlsRecords{done: &finished, down: &down, flight: &flight}
	if s.NoReply > 0 {
		watchCtx, stopWatch := context.WithCancel(ctx)
		defer stopWatch()
		go s.watch(watchCtx, host, &up, &down, &lastUp, &connDown, &flight, &finished, func() {
			_ = upstream.Close()
			_ = client.Close()
		})
	}

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(clientReply{countingWriter{upstream, &up, &stats.up, &lastUp}, records}, reader)
		_ = upstream.Close()
		_ = client.Close()
		close(done)
	}()
	_, _ = io.Copy(countingWriter{countingWriter{client, &down, &stats.down, &stats.lastDown}, &discard, &discard, &connDown}, upstream)
	_ = upstream.Close()
	_ = client.Close()
	<-done
}

// tlsRecords следит за границами записей TLS в потоке клиента и отмечает
// первую запись с данными приложения (тип 23). В TLS 1.3 ею уходит уже
// зашифрованное завершение рукопожатия, в TLS 1.2 — первый запрос: в обоих
// случаях рукопожатие со стороны клиента пройдено.
type tlsRecords struct {
	done   *atomic.Bool
	down   *atomic.Int64
	flight *atomic.Int64
	header [5]byte
	have   int
	skip   int
	broken bool
}

func (t *tlsRecords) feed(p []byte) {
	for len(p) > 0 && !t.broken && !t.done.Load() {
		if t.skip > 0 {
			n := min(t.skip, len(p))
			t.skip -= n
			p = p[n:]
			continue
		}
		n := copy(t.header[t.have:], p)
		t.have += n
		p = p[n:]
		if t.have < len(t.header) {
			return
		}
		t.have = 0
		switch t.header[0] {
		case 23:
			t.flight.Store(t.down.Load())
			t.done.Store(true)
		case 20, 21, 22:
			t.skip = int(t.header[3])<<8 | int(t.header[4])
		default:
			// Не TLS: судить о рукопожатии не по чему, наблюдение снимается.
			t.broken = true
		}
	}
}

type clientReply struct {
	countingWriter
	records *tlsRecords
}

func (c clientReply) Write(p []byte) (int, error) {
	c.records.feed(p)
	return c.countingWriter.Write(p)
}

// stallChecks — сколько интервалов NoReply соединение наблюдается: начало
// обмена либо проходит за это время, либо уже не пройдёт.
const stallChecks = 6

// watch обрывает соединение, застрявшее в начале обмена TLS:
//   - узел не ответил на приветствие клиента;
//   - узел начал отвечать и замолчал, не дав клиенту завершить рукопожатие;
//   - клиент завершил рукопожатие, а узел после этого не прислал ни байта.
//
// Живой узел присылает свою часть рукопожатия разом, а на его завершение
// сразу отвечает билетами сеанса и настройками HTTP/2, поэтому тишина в любой
// из этих точек означает обмен, замороженный по дороге.
func (s *Server) watch(ctx context.Context, host string, up, down, lastUp, lastDown, flight *atomic.Int64, finished *atomic.Bool, drop func()) {
	ticker := time.NewTicker(s.NoReply / 2)
	defer ticker.Stop()
	for range stallChecks * 2 {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		sent, got := up.Load(), down.Load()
		if sent == 0 || time.Since(time.Unix(0, lastUp.Load())) < s.NoReply {
			continue
		}
		reason := ""
		switch {
		case got == 0:
			reason = "узел не ответил"
		case finished.Load():
			if got > flight.Load() {
				return
			}
			reason = "узел молчит после рукопожатия"
		case time.Since(time.Unix(0, lastDown.Load())) >= s.NoReply:
			reason = "ответ узла оборвался посреди рукопожатия"
		default:
			continue
		}
		s.warn("прокси Discord: соединение оборвано для повтора", "узел", host, "причина", reason, "отправлено", sent, "получено", got)
		if s.OnStall != nil {
			s.OnStall(host)
		}
		drop()
		return
	}
}

func (s *Server) warn(msg string, args ...any) {
	if s.Logger != nil {
		s.Logger.Warn(msg, args...)
	}
}

// passthroughTarget допускает любой узел, но только по HTTPS-порту.
func passthroughTarget(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port != "443" {
		return "", fmt.Errorf("адрес не подходит для сквозного соединения")
	}
	return net.JoinHostPort(host, port), nil
}

func writeError(w io.Writer, status int) {
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
}
