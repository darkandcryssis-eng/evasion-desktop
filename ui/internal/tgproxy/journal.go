package tgproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	journalMaxMemory = 200
	journalMaxFile   = 256 << 10
)

// DisconnectEvent records a single Telegram upstream break or failure for
// diagnostics, stability scoring, and user visibility.
type DisconnectEvent struct {
	At         string `json:"at"`
	RouteID    string `json:"routeId"`
	RouteLabel string `json:"routeLabel"`
	Transport  string `json:"transport"`
	DC         int    `json:"dc"`
	Media      bool   `json:"media,omitempty"`
	Stage      string `json:"stage"`
	Cause      string `json:"cause"`
	Detail     string `json:"detail,omitempty"`
	DurationMS int64  `json:"durationMs"`
	BytesUp    uint64 `json:"bytesUp"`
	BytesDown  uint64 `json:"bytesDown"`
	Recovered  bool   `json:"recovered,omitempty"`
	SwitchedTo string `json:"switchedTo,omitempty"`
}

func routeTransport(c route) string {
	switch {
	case c.tunnel:
		return "vless"
	case c.tcp:
		return "tcp"
	case c.community && c.plain:
		return "relay_ws"
	case c.community:
		return "relay_wss"
	case c.fronting:
		return "fronting"
	case c.address != "":
		return "wss_ip"
	default:
		return "wss"
	}
}

func classifyDisconnect(err error) string {
	if err == nil {
		return "channel_error"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns_error"
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "tls_error"
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		return "ws_close"
	}
	var protocol protocolProbeError
	isProtocol := errors.As(err, &protocol)
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		if isProtocol {
			return "mtproto_timeout"
		}
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) {
		return "reset"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "reset by peer"),
		strings.Contains(msg, "forcibly closed"),
		strings.Contains(msg, "connection aborted"),
		strings.Contains(msg, "broken pipe"):
		return "reset"
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "deadline exceeded"):
		if isProtocol {
			return "mtproto_timeout"
		}
		return "timeout"
	case strings.Contains(msg, "tls:"), strings.Contains(msg, "x509:"), strings.Contains(msg, "handshake failure"):
		return "tls_error"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case isProtocol:
		return "mtproto_error"
	default:
		return "channel_error"
	}
}

type disconnectJournal struct {
	mu     sync.Mutex
	path   string
	events []DisconnectEvent
}

func newDisconnectJournal(path string) *disconnectJournal {
	j := &disconnectJournal{path: path}
	if path != "" {
		j.load()
	}
	return j
}

func (j *disconnectJournal) load() {
	f, err := os.Open(j.path)
	if err != nil {
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > 2*journalMaxFile {
		return
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), 32<<10)
	var loaded []DisconnectEvent
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev DisconnectEvent
		if json.Unmarshal([]byte(line), &ev) == nil && ev.At != "" && ev.Cause != "" {
			loaded = append(loaded, ev)
		}
	}
	if len(loaded) > journalMaxMemory {
		loaded = loaded[len(loaded)-journalMaxMemory:]
	}
	j.events = loaded
}

func (j *disconnectJournal) record(ev DisconnectEvent) {
	if ev.At == "" {
		ev.At = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if len(ev.Detail) > 240 {
		ev.Detail = ev.Detail[:240]
	}
	if ev.DurationMS < 0 {
		ev.DurationMS = 0
	}
	j.mu.Lock()
	j.events = append(j.events, ev)
	if len(j.events) > journalMaxMemory {
		copy(j.events, j.events[len(j.events)-journalMaxMemory:])
		j.events = j.events[:journalMaxMemory]
	}
	path := j.path
	var snapshot []DisconnectEvent
	if path != "" {
		snapshot = append([]DisconnectEvent(nil), j.events...)
	}
	j.mu.Unlock()
	if path != "" {
		j.persist(path, ev, snapshot)
	}
}

func (j *disconnectJournal) persist(path string, ev DisconnectEvent, snapshot []DisconnectEvent) {
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	if info, err := os.Stat(path); err == nil && info.Size() >= journalMaxFile {
		j.compact(path, snapshot)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(line, '\n'))
	_ = f.Close()
}

func (j *disconnectJournal) compact(path string, events []DisconnectEvent) {
	var b strings.Builder
	for _, ev := range events {
		line, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	_ = saveCacheFile(path, []byte(b.String()))
}

func (j *disconnectJournal) snapshot() []DisconnectEvent {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.events) == 0 {
		return nil
	}
	return append([]DisconnectEvent(nil), j.events...)
}
