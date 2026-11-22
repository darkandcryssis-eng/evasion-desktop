package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withTelegramPortHooks(t *testing.T, holder func(int) (portHolder, bool), retire func(uint32)) {
	t.Helper()
	oldHolder, oldRetire, oldWait, oldStep := telegramPortHolder, retireEvasionCopy, telegramPortWait, telegramPortStep
	telegramPortHolder, retireEvasionCopy, telegramPortWait, telegramPortStep = holder, retire, 200*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() {
		telegramPortHolder, retireEvasionCopy, telegramPortWait, telegramPortStep = oldHolder, oldRetire, oldWait, oldStep
	})
}

func busyErr() error {
	return fmt.Errorf("не удалось открыть локальный порт Telegram: %w", &net.OpError{Op: "listen", Net: "tcp4", Err: os.NewSyscallError("bind", busyErrno())})
}

func TestTelegramPortRetiresLeftoverEvasion(t *testing.T) {
	exe, err := currentExecutable()
	if err != nil {
		t.Skip(err)
	}
	retired := []uint32{}
	withTelegramPortHooks(t, func(int) (portHolder, bool) { return portHolder{PID: 4242, Image: exe + ".old"}, true }, func(pid uint32) { retired = append(retired, pid) })
	calls := 0
	err = startOnTelegramPort(17655, func() error {
		calls++
		if len(retired) == 0 {
			return busyErr()
		}
		return nil
	})
	if err != nil || calls != 2 || len(retired) != 1 || retired[0] != 4242 {
		t.Fatalf("err=%v calls=%d retired=%v", err, calls, retired)
	}
}

func TestTelegramPortNamesForeignHolder(t *testing.T) {
	withTelegramPortHooks(t, func(int) (portHolder, bool) {
		return portHolder{PID: 77, Image: filepath.Join("C:", "Tools", "TgWsProxy.exe")}, true
	}, func(uint32) { t.Fatal("foreign process must not be closed") })
	err := startOnTelegramPort(17655, func() error { return busyErr() })
	if err == nil || !strings.Contains(err.Error(), "TgWsProxy.exe (PID 77)") || !strings.Contains(err.Error(), "17655") {
		t.Fatalf("err=%v", err)
	}
}

func TestTelegramPortWaitsForReleasedPort(t *testing.T) {
	withTelegramPortHooks(t, func(int) (portHolder, bool) { return portHolder{}, false }, func(uint32) {})
	calls := 0
	err := startOnTelegramPort(17655, func() error {
		calls++
		if calls < 3 {
			return busyErr()
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestTelegramPortOtherErrorsAreNotRetried(t *testing.T) {
	withTelegramPortHooks(t, func(int) (portHolder, bool) { t.Fatal("no lookup expected"); return portHolder{}, false }, func(uint32) {})
	want := errors.New("boom")
	calls := 0
	if err := startOnTelegramPort(17655, func() error { calls++; return want }); err != want || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestTelegramPortRealListenerConflict(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	withTelegramPortHooks(t, func(int) (portHolder, bool) { return portHolder{}, false }, func(uint32) {})
	go func() { time.Sleep(30 * time.Millisecond); _ = ln.Close() }()
	var second net.Listener
	err = startOnTelegramPort(port, func() error {
		l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		second = l
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
}

func TestDecodeTCPListeners(t *testing.T) {
	buf := make([]byte, 4+2*24)
	buf[0] = 2
	row := func(i int, addr [4]byte, port int, pid uint32) {
		r := buf[4+i*24:]
		r[0] = 2
		copy(r[4:8], addr[:])
		r[8], r[9] = byte(port>>8), byte(port)
		r[20], r[21], r[22], r[23] = byte(pid), byte(pid>>8), byte(pid>>16), byte(pid>>24)
	}
	row(0, [4]byte{192, 168, 1, 2}, 17655, 1)
	row(1, [4]byte{127, 0, 0, 1}, 17655, 9001)
	rows, err := decodeTCPListeners(buf)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if pid, ok := loopbackHolder(rows, 17655); !ok || pid != 9001 {
		t.Fatalf("pid=%d ok=%v", pid, ok)
	}
	if _, ok := loopbackHolder(rows, 17656); ok {
		t.Fatal("unexpected holder")
	}
	if _, err := decodeTCPListeners([]byte{5, 0, 0, 0}); err == nil {
		t.Fatal("truncated table accepted")
	}
}

func TestIsEvasionImage(t *testing.T) {
	data := dataDir()
	for image, want := range map[string]bool{
		filepath.Join(data, "runtime", "evasion.exe"):       false,
		filepath.Join("D:", "Downloads", "Evasion.exe"):     true,
		filepath.Join("D:", "Downloads", "Evasion.exe.old"): true,
		filepath.Join("C:", "Tools", "TgWsProxy.exe"):       false,
		"": false,
	} {
		if got := isEvasionImage(image); got != want {
			t.Errorf("%q: got %v want %v", image, got, want)
		}
	}
}
