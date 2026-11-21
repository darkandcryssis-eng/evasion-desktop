//go:build windows

package gameproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/gamefilter"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/windivert"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type Owner interface {
	Owns(string, uint16) bool
	OwnsCurrent(string, uint16) bool
}
type Options struct {
	Proxy    string
	TCP, UDP bool
	Owner    Owner
	Observe  func(capture.Packet)
	Opened   func(bool)
	Error    func()
}
type key struct {
	local, remote netip.AddrPort
	tcp           bool
}
type binding struct {
	address windivert.Address
	last    time.Time
	seq     uint32
	conn    net.Conn
	closed  bool
}
type Bridge struct {
	ctx              context.Context
	cancel           context.CancelFunc
	o                Options
	h                *windivert.Handle
	stack            *stack.Stack
	link             *channel.Endpoint
	mu, sendMu       sync.Mutex
	flows            map[key]*binding
	udpChecks        map[netip.AddrPort]time.Time
	connections      map[net.Conn]bool
	wg               sync.WaitGroup
	done, outputDone chan struct{}
	err              error
}

func Start(ctx context.Context, o Options) (*Bridge, error) {
	if !loopbackProxy(o.Proxy) || o.Owner == nil {
		return nil, errors.New("некорректный локальный игровой канал")
	}
	ctx, cancel := context.WithCancel(ctx)
	b := &Bridge{ctx: ctx, cancel: cancel, o: o, flows: map[key]*binding{}, connections: map[net.Conn]bool{}, done: make(chan struct{}), outputDone: make(chan struct{}), link: channel.New(1024, 1500, "")}
	b.stack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	tf := tcp.NewForwarder(b.stack, 0, 1024, func(r *tcp.ForwarderRequest) {
		if !b.worker() {
			r.Complete(true)
			return
		}
		go b.tcp(r)
	})
	uf := udp.NewForwarder(b.stack, func(r *udp.ForwarderRequest) {
		if !b.worker() {
			return
		}
		go b.udp(r)
	})
	b.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	b.stack.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)
	if e := b.stack.CreateNIC(1, b.link); e != nil {
		cancel()
		b.stack.Close()
		return nil, errors.New("не удалось создать игровой сетевой контур")
	}
	b.stack.SetPromiscuousMode(1, true)
	b.stack.SetSpoofing(1, true)
	b.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	var err error
	b.h, err = windivert.OpenPriority("outbound and not loopback and not impostor and (tcp or udp)", 200)
	if err != nil {
		cancel()
		b.stack.Close()
		return nil, err
	}
	go b.output()
	go b.receive()
	return b, nil
}

func (b *Bridge) Done() <-chan struct{} { return b.done }
func (b *Bridge) Err() error            { return b.err }
func (b *Bridge) fail() {
	if b.ctx.Err() == nil && b.o.Error != nil {
		b.o.Error()
	}
}
func (b *Bridge) observe(p capture.Packet) {
	if b.o.Observe != nil {
		b.o.Observe(p)
	}
}
func (b *Bridge) send(p capture.Packet) {
	b.sendMu.Lock()
	err := b.h.Send(p)
	b.sendMu.Unlock()
	if err != nil {
		b.fail()
	}
}
func (b *Bridge) worker() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx.Err() != nil {
		return false
	}
	b.wg.Add(1)
	return true
}
func (b *Bridge) track(c net.Conn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx.Err() != nil {
		c.Close()
		return false
	}
	b.connections[c] = true
	return true
}
func (b *Bridge) untrack(c net.Conn) { c.Close(); b.mu.Lock(); delete(b.connections, c); b.mu.Unlock() }

func packetKey(d packet.Dissection, data []byte) key {
	var a, z netip.Addr
	if h, ok := d.IPv4(data); ok {
		a, _ = netip.AddrFromSlice(h.Src())
		z, _ = netip.AddrFromSlice(h.Dst())
	} else if h, ok := d.IPv6(data); ok {
		a, _ = netip.AddrFromSlice(h.Src())
		z, _ = netip.AddrFromSlice(h.Dst())
	}
	return key{netip.AddrPortFrom(a.Unmap(), binary.BigEndian.Uint16(data[d.L4Off:])), netip.AddrPortFrom(z.Unmap(), binary.BigEndian.Uint16(data[d.L4Off+2:])), d.Protocol == packet.ProtoTCP}
}
func endpointKey(id stack.TransportEndpointID, tcp bool) key {
	a, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	z, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	return key{netip.AddrPortFrom(a.Unmap(), id.RemotePort), netip.AddrPortFrom(z.Unmap(), id.LocalPort), tcp}
}

func (b *Bridge) receive() {
	defer close(b.done)
	for {
		p, err := b.h.Recv()
		if err != nil {
			if b.ctx.Err() == nil {
				b.err = errors.New("игровой сетевой контур остановился")
			}
			return
		}
		d, err := packet.Dissect(p.Data)
		if err != nil || d.Fragment || d.Truncated || (d.Protocol != packet.ProtoTCP && d.Protocol != packet.ProtoUDP) {
			b.send(p)
			continue
		}
		k := packetKey(d, p.Data)
		b.mu.Lock()
		v := b.flows[k]
		b.mu.Unlock()
		eligible := false
		if k.tcp {
			h, _ := d.TCP(p.Data)
			if h.Flags()&(packet.FlagSYN|packet.FlagACK) == packet.FlagSYN {
				eligible = b.o.TCP && gamefilter.Public(k.remote.Addr()) && b.o.Owner.OwnsCurrent("tcp", k.local.Port())
				if v != nil && (!eligible || h.Seq() != v.seq) {
					b.mu.Lock()
					delete(b.flows, k)
					previousConn := v.conn
					b.mu.Unlock()
					if previousConn != nil {
						previousConn.Close()
					}
					v = nil
				}
			} else {
				eligible = v != nil
			}
		} else if b.o.UDP && gamefilter.Public(k.remote.Addr()) {
			eligible = b.o.Owner.Owns("udp", k.local.Port())
			if !eligible && v == nil {
				if b.udpChecks == nil {
					b.udpChecks = map[netip.AddrPort]time.Time{}
				}
				if last, seen := b.udpChecks[k.local]; !seen || time.Since(last) >= 100*time.Millisecond {
					if len(b.udpChecks) >= 4096 {
						for port, at := range b.udpChecks {
							if time.Since(at) > time.Second {
								delete(b.udpChecks, port)
							}
						}
					}
					if len(b.udpChecks) < 4096 {
						b.udpChecks[k.local] = time.Now()
						eligible = b.o.Owner.OwnsCurrent("udp", k.local.Port())
					}
				}
			}
		}
		if !eligible {
			b.send(p)
			continue
		}
		if b.ctx.Err() != nil {
			continue
		}
		b.mu.Lock()
		if v == nil {
			for key, old := range b.flows {
				if (old.closed || old.conn == nil) && time.Since(old.last) > time.Minute {
					delete(b.flows, key)
				}
			}
			if len(b.flows) >= 4096 {
				b.mu.Unlock()
				b.fail()
				continue
			}
			v = &binding{address: p.Reinject.(windivert.Address)}
			if k.tcp {
				h, _ := d.TCP(p.Data)
				v.seq = h.Seq()
			}
			b.flows[k] = v
			if b.o.Opened != nil {
				b.o.Opened(k.tcp)
			}
		}
		v.last = time.Now()
		b.mu.Unlock()
		b.observe(p)
		data := append([]byte(nil), p.Data...)
		d.RecomputeChecksums(data)
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		proto := ipv4.ProtocolNumber
		if d.Version == packet.Version6 {
			proto = ipv6.ProtocolNumber
		}
		b.link.InjectInbound(proto, pb)
		pb.DecRef()
	}
}

func (b *Bridge) output() {
	defer close(b.outputDone)
	for {
		pb := b.link.ReadContext(b.ctx)
		if pb == nil {
			return
		}
		view := pb.ToView()
		data := append([]byte(nil), view.AsSlice()...)
		view.Release()
		pb.DecRef()
		d, err := packet.Dissect(data)
		if err != nil || (d.Protocol != packet.ProtoTCP && d.Protocol != packet.ProtoUDP) {
			continue
		}
		reverse := packetKey(d, data)
		k := key{reverse.remote, reverse.local, reverse.tcp}
		b.mu.Lock()
		v := b.flows[k]
		var address windivert.Address
		if v != nil {
			address = v.address
			v.last = time.Now()
		}
		b.mu.Unlock()
		if v == nil {
			continue
		}
		address[10] &^= 2
		address[10] |= (1 << 5) | (1 << 6) | (1 << 7)
		d.RecomputeChecksums(data)
		p := capture.Packet{Data: data, Dir: core.DirectionInbound, Reinject: address}
		b.observe(p)
		b.send(p)
	}
}

func (b *Bridge) bind(k key, c net.Conn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.flows[k]
	if v == nil || b.ctx.Err() != nil {
		c.Close()
		return false
	}
	v.conn = c
	return true
}
func (b *Bridge) finished(k key, c net.Conn) {
	b.mu.Lock()
	if v := b.flows[k]; v != nil && v.conn == c {
		v.closed = true
		v.last = time.Now()
	}
	b.mu.Unlock()
}

func (b *Bridge) tcp(r *tcp.ForwarderRequest) {
	defer b.wg.Done()
	k := endpointKey(r.ID(), true)
	var wq waiter.Queue
	ep, e := r.CreateEndpoint(&wq)
	if e != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	c := gonet.NewTCPConn(&wq, ep)
	if !b.bind(k, c) || !b.track(c) {
		return
	}
	defer b.untrack(c)
	defer b.finished(k, c)
	up, _, err := socks(b.ctx, b.o.Proxy, 1, k.remote)
	if err != nil {
		b.fail()
		return
	}
	if !b.track(up) {
		return
	}
	defer b.untrack(up)
	finished := make(chan struct{})
	go func() {
		io.Copy(up, c)
		if x, ok := up.(*net.TCPConn); ok {
			x.CloseWrite()
		}
		close(finished)
	}()
	io.Copy(c, up)
	c.CloseWrite()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	up.SetWriteDeadline(time.Now().Add(2 * time.Second))
	<-finished
}

func (b *Bridge) udp(r *udp.ForwarderRequest) {
	defer b.wg.Done()
	k := endpointKey(r.ID(), false)
	var wq waiter.Queue
	ep, e := r.CreateEndpoint(&wq)
	if e != nil {
		return
	}
	c := gonet.NewUDPConn(&wq, ep)
	if !b.bind(k, c) || !b.track(c) {
		return
	}
	defer b.untrack(c)
	defer b.finished(k, c)
	control, relay, err := socks(b.ctx, b.o.Proxy, 3, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		b.fail()
		return
	}
	if !b.track(control) {
		return
	}
	defer b.untrack(control)
	up, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		b.fail()
		return
	}
	if !b.track(up) {
		return
	}
	defer b.untrack(up)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer c.Close()
		buf := make([]byte, 65535)
		for {
			up.SetReadDeadline(time.Now().Add(45 * time.Second))
			n, e := up.Read(buf)
			if e != nil {
				return
			}
			peer, data, ok := decodeDatagram(buf[:n])
			if !ok || peer != k.remote {
				continue
			}
			if _, e = c.Write(data); e != nil {
				return
			}
		}
	}()
	buf := make([]byte, 65507)
	for {
		c.SetReadDeadline(time.Now().Add(45 * time.Second))
		n, e := c.Read(buf)
		if e != nil {
			break
		}
		data := append(append([]byte{0, 0, 0}, encodeAddress(k.remote)...), buf[:n]...)
		up.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if _, e = up.Write(data); e != nil {
			b.fail()
			break
		}
	}
	up.Close()
	<-finished
}

func (b *Bridge) Close() {
	b.cancel()
	closed := false
	if b.h.ShutdownReceive() != nil {
		b.h.Close()
		closed = true
	}
	select {
	case <-b.done:
	case <-time.After(3 * time.Second):
		if !closed {
			b.h.Close()
			closed = true
		}
		<-b.done
	}
	b.stack.Close()
	b.mu.Lock()
	connections := make([]net.Conn, 0, len(b.connections))
	for c := range b.connections {
		connections = append(connections, c)
	}
	b.mu.Unlock()
	for _, c := range connections {
		c.Close()
	}
	b.wg.Wait()
	<-b.outputDone
	b.link.Close()
	if !closed {
		b.h.Close()
	}
}
