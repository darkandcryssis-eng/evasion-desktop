//go:build windows

package packetexec

import (
	"context"
	"os"
	"testing"
	"unsafe"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/windivert"
	"golang.org/x/sys/windows"
)

func TestWinDivertNativeHelperPreservesFinalFakeChecksum(t *testing.T) {
	path := os.Getenv("EVASION_WINDIVERT_DLL")
	if path == "" {
		t.Skip("opt-in checksum helper test; no driver handle or traffic injection")
	}
	helper := windows.NewLazyDLL(path).NewProc("WinDivertHelperCalcChecksums")
	if err := helper.Find(); err != nil {
		t.Fatal(err)
	}
	sink := &capture.SyntheticSink{}
	var address windivert.Address
	address[10] = 1 << 1
	conn := newConn(t, sink, address)
	s := helloRule(dup(tamper(strategy.TamperParams{Field: strategy.FieldTCPChecksum, Mode: strategy.TamperCorrupt}, send()), send()))
	if err := New().Execute(context.Background(), s, conn); err != nil {
		t.Fatal(err)
	}
	for i, p := range sink.Sent() {
		a := p.Reinject.(windivert.Address)
		data := append([]byte(nil), p.Data...)
		// Same offload-repair flags as WinDivert 2.2.2 windivert_write.
		flags := uintptr(2 | 4)
		if a[10]&(1<<5) != 0 {
			flags |= 1
		}
		if a[10]&(1<<6) != 0 {
			flags |= 8
		}
		if a[10]&(1<<7) != 0 {
			flags |= 16
		}
		r, _, err := helper.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0, flags)
		if r == 0 {
			t.Fatal("native checksum helper:", err)
		}
		d, _, _ := dissect(t, p)
		if i == 0 && d.VerifyChecksums(data) {
			t.Fatal("native WinDivert helper repaired the fake")
		}
		if i == 1 && !d.VerifyChecksums(data) {
			t.Fatal("native helper invalidated real packet")
		}
	}
}
