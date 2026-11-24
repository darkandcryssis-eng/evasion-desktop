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

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(countingWriter{upstream, &up, &stats.up, nil}, reader)
		_ = upstream.Close()
		_ = client.Close()
		close(done)
	}()
	_, _ = io.Copy(countingWriter{client, &down, &stats.down, &stats.lastDown}, upstream)
	_ = upstream.Close()
	_ = client.Close()
	<-done
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
