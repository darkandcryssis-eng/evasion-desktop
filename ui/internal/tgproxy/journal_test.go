package tgproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/gorilla/websocket"
)

func TestClassifyDisconnect(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"econnreset", syscall.ECONNRESET, "reset"},
		{"windows_reset", errors.New("wsarecv: An existing connection was forcibly closed by the remote host."), "reset"},
		{"deadline", context.DeadlineExceeded, "timeout"},
		{"mtproto_timeout", protocolProbeError{context.DeadlineExceeded}, "mtproto_timeout"},
		{"mtproto_error", protocolProbeError{errors.New("bad nonce")}, "mtproto_error"},
		{"eof", io.EOF, "eof"},
		{"unexpected_eof", io.ErrUnexpectedEOF, "eof"},
		{"ws_close", &websocket.CloseError{Code: websocket.CloseAbnormalClosure}, "ws_close"},
		{"dns", &net.DNSError{Err: "no such host", Name: "kws2.web.telegram.org"}, "dns_error"},
		{"tls_cert", &tls.CertificateVerificationError{}, "tls_error"},
		{"tls_msg", errors.New("remote error: tls: handshake failure"), "tls_error"},
		{"generic", errors.New("something else"), "channel_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyDisconnect(tc.err); got != tc.want {
				t.Fatalf("classifyDisconnect(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestDisconnectJournalPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telegram-disconnects.jsonl")
	j := newDisconnectJournal(path)
	j.record(DisconnectEvent{
		RouteID:    "tcp:dc2",
		RouteLabel: "TCP · DC2",
		Transport:  "tcp",
		DC:         2,
		Stage:      "relay_read",
		Cause:      "reset",
		Detail:     "connection reset by peer",
		DurationMS: 14500,
		BytesUp:    1200,
		BytesDown:  4800,
		Recovered:  true,
		SwitchedTo: "WSS · DC2",
	})
	reloaded := newDisconnectJournal(path)
	events := reloaded.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 persisted event, got %d", len(events))
	}
	ev := events[0]
	if ev.RouteID != "tcp:dc2" || ev.Cause != "reset" || !ev.Recovered || ev.SwitchedTo != "WSS · DC2" {
		t.Fatalf("unexpected reloaded event: %+v", ev)
	}
}
