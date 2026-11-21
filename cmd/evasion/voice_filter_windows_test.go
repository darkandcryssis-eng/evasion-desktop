//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNativeVoiceFilterSelectsOnlyDiscovery(t *testing.T) {
	path := os.Getenv("EVASION_WINDIVERT_TEST_DLL")
	if path == "" {
		t.Skip("set EVASION_WINDIVERT_TEST_DLL to exercise native filtering")
	}
	dll := windows.NewLazyDLL(path)
	if err := dll.Load(); err != nil {
		t.Fatal(err)
	}
	compile, eval := dll.NewProc("WinDivertHelperCompileFilter"), dll.NewProc("WinDivertHelperEvalFilter")
	filter, err := windows.BytePtrFromString(voiceFilter)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, callErr := compile.Call(uintptr(unsafe.Pointer(filter)), 0, 0, 0, 0, 0); ok == 0 {
		t.Fatal("filter does not compile", callErr)
	}
	for _, ipv6 := range []bool{false, true} {
		for _, tc := range []struct {
			name                     string
			port                     uint16
			size                     int
			kind, body               uint16
			outbound, impostor, want bool
			stun                     bool
		}{
			{"discovery-low", 19327, 74, 1, 70, true, false, true, false},
			{"discovery-high", 65534, 74, 1, 70, true, false, true, false},
			{"discovery-other-port", 12345, 74, 1, 70, true, false, true, false},
			{"quic-excluded", 443, 74, 1, 70, true, false, false, false},
			{"voice-data", 50010, 160, 1, 70, true, false, false, false},
			{"dns", 53, 74, 0x1234, 70, true, false, false, false},
			{"response", 50010, 74, 2, 70, true, false, false, false},
			{"wrong-body-length", 50010, 74, 1, 69, true, false, false, false},
			{"truncated", 50010, 73, 1, 70, true, false, false, false},
			{"incoming", 50010, 74, 1, 70, false, false, false, false},
			{"reinjected", 50010, 74, 1, 70, true, true, false, false},
			{"stun-high", 50010, 100, 1, 80, true, false, true, true},
			{"stun-low", 19300, 20, 1, 0, true, false, true, true},
			{"stun-foreign-port", 3478, 100, 1, 80, true, false, false, true},
			{"stun-google", 19302, 100, 1, 80, true, false, false, true},
			{"discovery-19302", 19302, 74, 1, 70, true, false, true, false},
			{"stun-incoming", 50010, 100, 1, 80, false, false, false, true},
			{"stun-response", 50010, 100, 0x0101, 80, true, false, false, true},
		} {
			t.Run(fmt.Sprintf("%s/ipv6=%v", tc.name, ipv6), func(t *testing.T) {
				header := 20
				if ipv6 {
					header = 40
				}
				b := make([]byte, header+8+tc.size)
				if ipv6 {
					b[0] = 0x60
					binary.BigEndian.PutUint16(b[4:6], uint16(8+tc.size))
					b[6] = 17
					b[7] = 64
					b[23] = 1
					b[39] = 2
				} else {
					b[0] = 0x45
					binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
					b[8] = 64
					b[9] = 17
					b[15] = 1
					b[19] = 2
				}
				binary.BigEndian.PutUint16(b[header:header+2], 51000)
				binary.BigEndian.PutUint16(b[header+2:header+4], tc.port)
				binary.BigEndian.PutUint16(b[header+4:header+6], uint16(8+tc.size))
				binary.BigEndian.PutUint16(b[header+8:header+10], tc.kind)
				binary.BigEndian.PutUint16(b[header+10:header+12], tc.body)
				if tc.stun {
					binary.BigEndian.PutUint32(b[header+12:header+16], 0x2112A442)
				}
				var addr [80]byte
				if tc.outbound {
					addr[10] |= 2
				}
				if tc.impostor {
					addr[10] |= 8
				}
				if ipv6 {
					addr[10] |= 16
				}
				ok, _, _ := eval.Call(uintptr(unsafe.Pointer(filter)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&addr[0])))
				if (ok != 0) != tc.want {
					t.Fatalf("native filter match=%v want=%v", ok != 0, tc.want)
				}
			})
		}
	}
}
