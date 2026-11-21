//go:build windows

package main

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"net/netip"
	"os"
	"testing"
	"unsafe"
)

func TestNativeGameTLSGuardScope(t *testing.T) {
	path := os.Getenv("EVASION_WINDIVERT_TEST_DLL")
	if path == "" {
		t.Skip("native filter helper required")
	}
	dll := windows.NewLazyDLL(path)
	if e := dll.Load(); e != nil {
		t.Fatal(e)
	}
	compile, eval := dll.NewProc("WinDivertHelperCompileFilter"), dll.NewProc("WinDivertHelperEvalFilter")
	filter := gameTLSGuard([]netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("127.0.0.1")})
	fp, _ := windows.BytePtrFromString(filter)
	if ok, _, e := compile.Call(uintptr(unsafe.Pointer(fp)), 0, 0, 0, 0, 0); ok == 0 {
		t.Fatal(filter, e)
	}
	for _, v6 := range []bool{false, true} {
		for _, out := range []bool{false, true} {
			for _, selected := range []bool{false, true} {
				for _, port := range []uint16{443, 80} {
					iplen := 20
					if v6 {
						iplen = 40
					}
					b := make([]byte, iplen+20)
					var addr [80]byte
					peer := []byte{1, 1, 1, 1}
					local := []byte{192, 0, 2, 1}
					if !selected {
						peer = []byte{8, 8, 8, 8}
					}
					if v6 {
						addr[10] |= 16
						b[0] = 0x60
						binary.BigEndian.PutUint16(b[4:6], 20)
						b[6] = 6
						b[7] = 64
						peer = netip.MustParseAddr("2606:4700:4700::1111").AsSlice()
						if !selected {
							peer = netip.MustParseAddr("2001:4860:4860::8888").AsSlice()
						}
						local = netip.MustParseAddr("2001:db8::1").AsSlice()
						if out {
							copy(b[8:24], local)
							copy(b[24:40], peer)
						} else {
							copy(b[8:24], peer)
							copy(b[24:40], local)
						}
					} else {
						b[0] = 0x45
						binary.BigEndian.PutUint16(b[2:4], 40)
						b[8] = 64
						b[9] = 6
						if out {
							copy(b[12:16], local)
							copy(b[16:20], peer)
						} else {
							copy(b[12:16], peer)
							copy(b[16:20], local)
						}
					}
					b[iplen+12] = 0x50
					if out {
						addr[10] |= 2
						binary.BigEndian.PutUint16(b[iplen:iplen+2], 45000)
						binary.BigEndian.PutUint16(b[iplen+2:iplen+4], port)
					} else {
						binary.BigEndian.PutUint16(b[iplen:iplen+2], port)
						binary.BigEndian.PutUint16(b[iplen+2:iplen+4], 45000)
					}
					ok, _, _ := eval.Call(uintptr(unsafe.Pointer(fp)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&addr[0])))
					if (ok != 0) != (selected && port == 443) {
						t.Fatalf("guard scope mismatch v6=%v outbound=%v selected=%v port=%v", v6, out, selected, port)
					}
				}
			}
		}
	}
}
