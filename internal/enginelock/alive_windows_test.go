//go:build windows

package enginelock

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestMain позволяет тестовому бинарнику сыграть роль «движка»: с переменной
// ENGINELOCK_TEST_SLEEP он просто висит, пока его не убьют.
func TestMain(m *testing.M) {
	if os.Getenv("ENGINELOCK_TEST_SLEEP") == "1" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Убитый движок, на который ещё держат handle (здесь его держит os/exec до
// Wait), не должен блокировать следующий запуск: именно так lock «залипал»
// после запуска из окна PowerShell.
func TestDeadEngineWithOpenHandleDoesNotBlock(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "ENGINELOCK_TEST_SLEEP=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("старт дочернего процесса: %v", err)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()

	path := filepath.Join(t.TempDir(), "engine.lock")
	stale := Entry{PID: cmd.Process.Pid, Filter: "tcp 443", StartedAt: time.Now().UTC()}
	if err := saveEntries(path, []Entry{stale}); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(Options{Path: path, Filter: "tcp 443"}); err == nil {
		t.Fatal("живой процесс с тем же фильтром должен давать ErrConflict")
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill: %v", err)
	}
	// Wait не вызываем: handle процесса остаётся открытым, объект процесса
	// существует, OpenProcess по его PID успешен.
	deadline := time.Now().Add(10 * time.Second)
	for defaultAlive(stale) {
		if time.Now().After(deadline) {
			t.Fatal("завершённый процесс с открытым handle считается живым")
		}
		time.Sleep(20 * time.Millisecond)
	}

	l, err := Acquire(Options{Path: path, Filter: "tcp 443"})
	if err != nil {
		t.Fatalf("Acquire после смерти прежнего движка: %v", err)
	}
	defer l.Release()
	live, err := ListLive(path, nil)
	if err != nil || len(live) != 1 || live[0].PID != os.Getpid() {
		t.Fatalf("в lock-файле должна остаться только наша запись: %+v, %v", live, err)
	}
}

// PID умершего движка достался другому процессу: запись старше процесса,
// значит это не тот движок.
func TestReusedPIDIsNotAlive(t *testing.T) {
	self := os.Getpid()
	if !defaultAlive(Entry{PID: self, StartedAt: time.Now().UTC()}) {
		t.Fatal("собственный процесс должен считаться живым")
	}
	if defaultAlive(Entry{PID: self, StartedAt: time.Now().UTC().Add(-24 * time.Hour)}) {
		t.Fatal("процесс, созданный позже записи, не должен считаться её владельцем")
	}
}
