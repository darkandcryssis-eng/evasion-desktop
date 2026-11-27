//go:build windows

package main

import (
	"net/netip"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestTelegramCallTunnelFilterRejectsInvalidPeers(t *testing.T) {
	for _, peer := range []string{"", "warp.example:2408", "192.0.2.1:0", "[fe80::1%test]:2408", "[::]:2408"} {
		if _, err := telegramCallTunnelFilterForPeer(peer); err == nil {
			t.Errorf("filter accepted invalid peer %q", peer)
		}
	}
}

func TestNativeTelegramCallTunnelFilterLeavesPeerOutsideCapture(t *testing.T) {
	path := os.Getenv("EVASION_WINDIVERT_TEST_DLL")
	if path == "" {
		t.Skip("set EVASION_WINDIVERT_TEST_DLL to exercise native filtering")
	}
	dll := windows.NewLazyDLL(path)
	if err := dll.Load(); err != nil {
		t.Fatal(err)
	}
	compile, eval := dll.NewProc("WinDivertHelperCompileFilter"), dll.NewProc("WinDivertHelperEvalFilter")
	for _, tc := range []struct {
		peer, source, otherHost, otherFamily string
	}{
		{"192.0.2.1:2408", "203.0.113.9:51000", "192.0.2.2:2408", "[2001:db8::1]:2408"},
		{"[::ffff:192.0.2.1]:2408", "203.0.113.9:51000", "192.0.2.2:2408", "[2001:db8::1]:2408"},
		{"[2001:db8::1]:2408", "[2001:db8::9]:51000", "[2001:db8::2]:2408", "192.0.2.1:2408"},
	} {
		t.Run(tc.peer, func(t *testing.T) {
			filter, err := telegramCallTunnelFilterForPeer(tc.peer)
			if err != nil {
				t.Fatal(err)
			}
			native, err := windows.BytePtrFromString(filter)
			if err != nil {
				t.Fatal(err)
			}
			if ok, _, callErr := compile.Call(uintptr(unsafe.Pointer(native)), 0, 0, 0, 0, 0); ok == 0 {
				t.Fatalf("filter does not compile: %s: %v", filter, callErr)
			}
			peer := netip.MustParseAddrPort(tc.peer)
			source := netip.MustParseAddrPort(tc.source)
			foreign := netip.MustParseAddrPort(tc.otherFamily)
			foreignSource := netip.MustParseAddrPort("[2001:db8::9]:51000")
			if foreign.Addr().Is4() {
				foreignSource = netip.MustParseAddrPort("203.0.113.9:51000")
			}
			for _, sample := range []struct {
				src, dst netip.AddrPort
				want     bool
			}{
				{source, peer, false},
				{source, netip.AddrPortFrom(peer.Addr(), 2409), true},
				{source, netip.MustParseAddrPort(tc.otherHost), true},
				{foreignSource, foreign, true},
				{source, netip.AddrPortFrom(peer.Addr(), 53), false},
				{source, netip.AddrPortFrom(peer.Addr(), 443), false},
			} {
				raw, ok := buildInboundUDPPacket(sample.src, sample.dst, []byte("udp"))
				if !ok {
					t.Fatalf("invalid packet fixture: %s to %s", sample.src, sample.dst)
				}
				var addr [80]byte
				addr[10] = 2 // Outbound
				if sample.dst.Addr().Unmap().Is6() {
					addr[10] |= 16
				}
				matched, _, _ := eval.Call(uintptr(unsafe.Pointer(native)), uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&addr[0])))
				if (matched != 0) != sample.want {
					t.Errorf("packet %s to %s matched=%t, want %t", sample.src, sample.dst, matched != 0, sample.want)
				}
			}
		})
	}
}
