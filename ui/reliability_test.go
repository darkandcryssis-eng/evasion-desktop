package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

func TestCrashOutputCapturesUnhandledPanic(t *testing.T) {
	if dir := os.Getenv("EVASION_CRASH_TEST_DIR"); dir != "" {
		f, err := openCrashLog(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := debug.SetCrashOutput(f, debug.CrashOptions{}); err != nil {
			t.Fatal(err)
		}
		f.Close()
		panic("isolated Evasion crash capture test")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashOutputCapturesUnhandledPanic$")
	cmd.Env = append(os.Environ(), "EVASION_CRASH_TEST_DIR="+dir)
	hideConsole(cmd)
	if err := cmd.Run(); err == nil {
		t.Fatal("test child did not crash")
	}
	b, err := os.ReadFile(filepath.Join(dir, "crash.log"))
	if err != nil || !strings.Contains(string(b), "isolated Evasion crash capture test") {
		t.Fatalf("panic trace not captured: %v", err)
	}
}

func TestClosingWindowKeepsServicesAliveButExplicitExitQuits(t *testing.T) {
	a := NewApp()
	a.trayAvailable.Store(true)
	if !a.beforeClose(context.Background()) {
		t.Fatal("window close would terminate the app")
	}
	a.ExitApplication()
	if a.beforeClose(context.Background()) {
		t.Fatal("explicit Exit was blocked")
	}
	b := NewApp()
	if b.beforeClose(context.Background()) {
		t.Fatal("window hidden without a usable tray")
	}
}

func TestSessionMarkerAndCrashLogRotation(t *testing.T) {
	dir := t.TempDir()
	session := filepath.Join(dir, "session.json")
	if sessionWasUnclean(session) {
		t.Fatal("new installation marked as crashed")
	}
	if err := markSession(session, false); err != nil {
		t.Fatal(err)
	}
	if !sessionWasUnclean(session) {
		t.Fatal("unexpected exit would be missed")
	}
	if err := markSession(session, true); err != nil {
		t.Fatal(err)
	}
	if sessionWasUnclean(session) {
		t.Fatal("normal exit marked as crashed")
	}
	for _, value := range []string{"old crash", "new crash"} {
		f, err := openCrashLog(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.WriteString(value); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	b, err := os.ReadFile(filepath.Join(dir, "crash.previous.log"))
	if err != nil || string(b) != "old crash" {
		t.Fatalf("old crash not preserved: %q %v", b, err)
	}
}
