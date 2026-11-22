//go:build windows

package main

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
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
	filter := gameTLSGuard
	fp, _ := windows.BytePtrFromString(filter)
	if ok, _, e := compile.Call(uintptr(unsafe.Pointer(fp)), 0, 0, 0, 0, 0); ok == 0 {
		t.Fatal(filter, e)
	}
	for _, c := range []struct {
		name          string
		out           bool
		port          uint16
		flags         byte
		payload, want bool
	}{
		{"new connection", true, 443, 0x02, false, true},
		{"client data", true, 443, 0x18, true, true},
		{"bare acknowledgement", true, 443, 0x10, false, false},
		{"other port", true, 80, 0x02, false, false},
		{"reply", false, 443, 0x18, true, false},
	} {
		size := 40
		if c.payload {
			size += 8
		}
		b := make([]byte, size)
		var addr [80]byte
		b[0] = 0x45
		binary.BigEndian.PutUint16(b[2:4], uint16(size))
		b[8] = 64
		b[9] = 6
		b[32] = 0x50
		b[33] = c.flags
		local, peer := []byte{192, 0, 2, 1}, []byte{1, 1, 1, 1}
		if c.out {
			addr[10] |= 2
			copy(b[12:16], local)
			copy(b[16:20], peer)
			binary.BigEndian.PutUint16(b[20:22], 45000)
			binary.BigEndian.PutUint16(b[22:24], c.port)
		} else {
			copy(b[12:16], peer)
			copy(b[16:20], local)
			binary.BigEndian.PutUint16(b[20:22], c.port)
			binary.BigEndian.PutUint16(b[22:24], 45000)
		}
		ok, _, _ := eval.Call(uintptr(unsafe.Pointer(fp)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&addr[0])))
		if (ok != 0) != c.want {
			t.Fatalf("guard scope mismatch: %s", c.name)
		}
	}
}
