package gameproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

func socks(ctx context.Context, proxy string, command byte, target netip.AddrPort) (net.Conn, netip.AddrPort, error) {
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, netip.AddrPort{}, errors.New("локальный канал недоступен")
	}
	fail := func() (net.Conn, netip.AddrPort, error) {
		c.Close()
		return nil, netip.AddrPort{}, errors.New("ошибка согласования игрового канала")
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		return fail()
	}
	var reply [4]byte
	if _, err = io.ReadFull(c, reply[:2]); err != nil || reply[0] != 5 || reply[1] != 0 {
		return fail()
	}
	request := append([]byte{5, command, 0}, encodeAddress(target)...)
	if _, err = c.Write(request); err != nil {
		return fail()
	}
	if _, err = io.ReadFull(c, reply[:]); err != nil || reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return fail()
	}
	var host string
	switch reply[3] {
	case 1, 4:
		n := 4
		if reply[3] == 4 {
			n = 16
		}
		b := make([]byte, n)
		if _, err = io.ReadFull(c, b); err != nil {
			return fail()
		}
		ip, _ := netip.AddrFromSlice(b)
		host = ip.Unmap().String()
	case 3:
		var n [1]byte
		if _, err = io.ReadFull(c, n[:]); err != nil || n[0] == 0 {
			return fail()
		}
		b := make([]byte, int(n[0]))
		if _, err = io.ReadFull(c, b); err != nil {
			return fail()
		}
		host = string(b)
	default:
		return fail()
	}
	var port [2]byte
	if _, err = io.ReadFull(c, port[:]); err != nil {
		return fail()
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		a, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil || len(a) == 0 {
			return fail()
		}
		ip = a[0]
	}
	if ip.IsUnspecified() {
		p, _, _ := net.SplitHostPort(proxy)
		ip, err = netip.ParseAddr(p)
		if err != nil {
			return fail()
		}
	}
	c.SetDeadline(time.Time{})
	return c, netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(port[:])), nil
}

func encodeAddress(target netip.AddrPort) []byte {
	ip := target.Addr().Unmap()
	kind := byte(4)
	if ip.Is4() {
		kind = 1
	}
	b := append([]byte{kind}, ip.AsSlice()...)
	return binary.BigEndian.AppendUint16(b, target.Port())
}

func decodeDatagram(b []byte) (netip.AddrPort, []byte, bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return netip.AddrPort{}, nil, false
	}
	n := 4
	if b[3] == 4 {
		n = 16
	} else if b[3] != 1 {
		return netip.AddrPort{}, nil, false
	}
	if len(b) < 4+n+2 {
		return netip.AddrPort{}, nil, false
	}
	ip, _ := netip.AddrFromSlice(b[4 : 4+n])
	port := binary.BigEndian.Uint16(b[4+n : 6+n])
	return netip.AddrPortFrom(ip.Unmap(), port), b[6+n:], true
}

func loopbackProxy(s string) bool {
	host, port, e := net.SplitHostPort(s)
	if e != nil {
		return false
	}
	ip, e := netip.ParseAddr(host)
	n, e2 := strconv.Atoi(port)
	return e == nil && ip.IsLoopback() && e2 == nil && n > 0 && n <= 65535
}
