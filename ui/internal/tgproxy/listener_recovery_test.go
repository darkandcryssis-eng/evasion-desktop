package tgproxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type brokenListener struct {
	done chan struct{}
	once sync.Once
}

func (l *brokenListener) Accept() (net.Conn, error) {
	return nil, errors.New("permanent accept failure")
}
func (l *brokenListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (*brokenListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0} }

func TestPermanentAcceptErrorReopensListener(t *testing.T) {
	s, err := New(Options{Secret: make([]byte, 16)})
	if err != nil {
		t.Fatal(err)
	}
	broken := &brokenListener{done: make(chan struct{})}
	s.listener = broken
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.accept()
	defer s.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		replaced := s.listener != broken && s.listener != nil
		s.mu.Unlock()
		if replaced && s.Running() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("listener was not reopened")
}
