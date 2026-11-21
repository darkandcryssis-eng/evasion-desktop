//go:build windows

package gamefilter

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"time"
	"unsafe"
)

func TestNativeDynamicFilterScope(t *testing.T) {
	path := os.Getenv("EVASION_WINDIVERT_TEST_DLL")
	if path == "" {
		t.Skip("native filter helper required")
	}
	dll := windows.NewLazyDLL(path)
	if err := dll.Load(); err != nil {
		t.Fatal(err)
	}
	compile, eval := dll.NewProc("WinDivertHelperCompileFilter"), dll.NewProc("WinDivertHelperEvalFilter")
	o := Default()
	o.Mode = "balanced"
	owners := NewOwners(o)
	owners.last = time.Now()
	owners.ports = map[string]owner{"tcp:45000": {pid: 1, selected: true}, "udp:45000": {pid: 1, selected: true}, "tcp:45001": {pid: 2}, "udp:45002": {pid: 1, ambiguous: true}}
	filter := owners.Filter()
	fp, _ := windows.BytePtrFromString(filter)
	if ok, _, e := compile.Call(uintptr(unsafe.Pointer(fp)), 0, 0, 0, 0, 0); ok == 0 {
		t.Fatal(filter, e)
	}
	for _, tcp := range []bool{false, true} {
		for _, v6 := range []bool{false, true} {
			for _, outbound := range []bool{false, true} {
				for _, port := range []uint16{45000, 45001, 45002, 45003} {
					pkt := testPacket(t, tcp, v6)
					b := pkt.Data
					ip := 20
					if v6 {
						ip = 40
					}
					binary.BigEndian.PutUint16(b[ip:ip+2], port)
					if !outbound {
						binary.BigEndian.PutUint16(b[ip:ip+2], 5055)
						binary.BigEndian.PutUint16(b[ip+2:ip+4], port)
					}
					var addr [80]byte
					if outbound {
						addr[10] |= 2
					}
					if v6 {
						addr[10] |= 16
					}
					ok, _, _ := eval.Call(uintptr(unsafe.Pointer(fp)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&addr[0])))
					if (ok != 0) != (port == 45000) {
						t.Fatalf("scope leak tcp=%v v6=%v out=%v port=%d", tcp, v6, outbound, port)
					}
				}
			}
		}
	}
	owners.ports = map[string]owner{}
	if owners.Filter() != "" {
		t.Fatal("idle filter captures system")
	}
}
