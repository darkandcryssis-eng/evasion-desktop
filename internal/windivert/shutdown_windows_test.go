//go:build windows

package windivert

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestNativeReceiveShutdownUnblocks(t *testing.T) {
	path := os.Getenv("EVASION_WINDIVERT_TEST_DLL")
	if path == "" {
		t.Skip("native driver test")
	}
	previous := dll
	dll = windows.NewLazyDLL(path)
	defer func() { dll = previous }()
	h, err := Open("false")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	done := make(chan error, 1)
	go func() { _, err := h.Recv(); done <- err }()
	if err = h.ShutdownReceive(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("shutdown produced a packet")
		}
	case <-time.After(time.Second):
		t.Fatal("receive stayed blocked")
	}
}
