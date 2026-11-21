package tgproxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type peer interface {
	io.Reader
	WritePacket(io.Reader, int64) error
	Close() error
}

var buffers = sync.Pool{New: func() any { return make([]byte, 32<<10) }}

type wsPeer struct {
	ws          *websocket.Conn
	chunks      chan []byte
	done        chan struct{}
	once        sync.Once
	current     []byte
	currentBase []byte
	mu          sync.Mutex
	err         error
	idleTimeout time.Duration
}

func newWSPeer(ws *websocket.Conn) *wsPeer {
	return newWSPeerWithTiming(ws, 75*time.Second, 20*time.Second)
}

func newWSPeerWithTiming(ws *websocket.Conn, idle, ping time.Duration) *wsPeer {
	p := &wsPeer{ws: ws, idleTimeout: idle, chunks: make(chan []byte, 2), done: make(chan struct{})}
	ws.SetReadLimit(maxPacket + 4)
	_ = ws.SetReadDeadline(time.Now().Add(idle))
	ws.SetPongHandler(func(string) error { return ws.SetReadDeadline(time.Now().Add(idle)) })
	go p.readPump()
	go p.heartbeat(ping)
	return p
}

func (p *wsPeer) heartbeat(interval time.Duration) {
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-timer.C:
			if err := p.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				_ = p.Close()
				return
			}
		}
	}
}

func (p *wsPeer) readPump() {
	defer close(p.chunks)
	defer p.Close()
	lastDeadline := time.Now()
	for {
		kind, r, err := p.ws.NextReader()
		if err != nil {
			p.mu.Lock()
			p.err = err
			p.mu.Unlock()
			return
		}
		if kind != websocket.BinaryMessage {
			p.mu.Lock()
			p.err = errors.New("unexpected Telegram WebSocket message")
			p.mu.Unlock()
			return
		}
		for {
			buf := buffers.Get().([]byte)
			n, err := r.Read(buf)
			if n > 0 {
				// Payload traffic also proves liveness when a relay suppresses Pong.
				if time.Since(lastDeadline) >= p.idleTimeout/3 {
					lastDeadline = time.Now()
					_ = p.ws.SetReadDeadline(lastDeadline.Add(p.idleTimeout))
				}
				select {
				case p.chunks <- buf[:n]:
				case <-p.done:
					buffers.Put(buf)
					return
				}
			} else {
				buffers.Put(buf)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				p.mu.Lock()
				p.err = err
				p.mu.Unlock()
				return
			}
		}
	}
}

func (p *wsPeer) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(p.current) == 0 {
		part, ok := <-p.chunks
		if !ok {
			p.mu.Lock()
			err := p.err
			p.mu.Unlock()
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}
		p.current = part
		p.currentBase = part[:cap(part)]
	}
	n := copy(b, p.current)
	p.current = p.current[n:]
	if len(p.current) == 0 {
		buffers.Put(p.currentBase)
		p.currentBase = nil
	}
	return n, nil
}

func (p *wsPeer) WritePacket(r io.Reader, size int64) error {
	if err := p.ws.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	w, err := p.ws.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return err
	}
	buf := buffers.Get().([]byte)
	defer buffers.Put(buf)
	n, err := io.CopyBuffer(w, io.LimitReader(r, size), buf)
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}

func (p *wsPeer) Close() error {
	var err error
	p.once.Do(func() { close(p.done); err = p.ws.Close() })
	return err
}

func (p *wsPeer) Alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

type tcpPeer struct{ net.Conn }

func (p *tcpPeer) WritePacket(r io.Reader, size int64) error {
	_ = p.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := io.CopyN(p.Conn, r, size)
	return err
}
