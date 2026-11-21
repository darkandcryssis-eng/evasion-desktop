package gameproxy

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
)

func TestSOCKSConnectValidatesNegotiation(t *testing.T) {
	for _, ok := range []bool{true, false} {
		t.Run(map[bool]string{true: "valid", false: "unexpected_auth"}[ok], func(t *testing.T) {
			l, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan bool, 1)
			go func() {
				c, e := l.Accept()
				if e != nil {
					done <- false
					return
				}
				defer c.Close()
				var hello [3]byte
				if _, e = io.ReadFull(c, hello[:]); e != nil {
					done <- false
					return
				}
				if !ok {
					c.Write([]byte{5, 2})
					done <- true
					return
				}
				c.Write([]byte{5, 0})
				var request [10]byte
				_, e = io.ReadFull(c, request[:])
				valid := e == nil && request[0] == 5 && request[1] == 1 && request[3] == 1 && request[4] == 1 && request[8] == 1 && request[9] == 187
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				done <- valid
			}()
			c, _, err := socks(context.Background(), l.Addr().String(), 1, netip.MustParseAddrPort("1.1.1.1:443"))
			if c != nil {
				c.Close()
			}
			if (err == nil) != ok {
				t.Fatal("invalid negotiation result", err)
			}
			if !<-done {
				t.Fatal("incorrect SOCKS request")
			}
		})
	}
}

func TestSOCKSUDPFramesAndMalformedReplies(t *testing.T) {
	for _, target := range []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"} {
		a := netip.MustParseAddrPort(target)
		b := append(append([]byte{0, 0, 0}, encodeAddress(a)...), 1, 2, 3)
		peer, data, ok := decodeDatagram(b)
		if !ok || peer != a || len(data) != 3 {
			t.Fatal("UDP frame round trip failed")
		}
		for i := 0; i < len(b)-3; i++ {
			if _, _, ok = decodeDatagram(b[:i]); ok {
				t.Fatal("truncated frame accepted")
			}
		}
		b[2] = 1
		if _, _, ok = decodeDatagram(b); ok {
			t.Fatal("fragmented frame accepted")
		}
	}
	for _, proxy := range []string{"0.0.0.0:1080", "example.com:1080", "127.0.0.1:0", "[::1]:99999"} {
		if loopbackProxy(proxy) {
			t.Fatal("non-private endpoint accepted")
		}
	}
	if !loopbackProxy("127.0.0.1:1080") || !loopbackProxy("[::1]:1080") {
		t.Fatal("loopback endpoint rejected")
	}
}
