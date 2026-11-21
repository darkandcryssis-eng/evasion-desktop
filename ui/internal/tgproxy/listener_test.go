package tgproxy

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary test listener error" }
func (temporaryAcceptError) Temporary() bool { return true }

type retryListener struct {
	calls atomic.Int32
	done  chan struct{}
	once  sync.Once
}

func (l *retryListener) Accept() (net.Conn, error) {
	if l.calls.Add(1) == 1 {
		return nil, temporaryAcceptError{}
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *retryListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (*retryListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestTemporaryAcceptErrorDoesNotSilentlyStopProxy(t *testing.T) {
	s, err := New(Options{Secret: make([]byte, 16)})
	if err != nil {
		t.Fatal(err)
	}
	l := &retryListener{done: make(chan struct{})}
	s.listener = l
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.accept()
	defer s.Close()
	deadline := time.Now().Add(time.Second)
	for l.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if l.calls.Load() < 2 || !s.Running() {
		t.Fatal("temporary accept error stopped the proxy")
	}
}
