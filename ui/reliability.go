package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	wr "github.com/wailsapp/wails/v2/pkg/runtime"
)

type sessionRecord struct {
	Clean bool   `json:"clean"`
	At    string `json:"at"`
}

func sessionWasUnclean(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var s sessionRecord
	return json.Unmarshal(b, &s) == nil && !s.Clean
}

func markSession(path string, clean bool) error {
	b, err := json.Marshal(sessionRecord{Clean: clean, At: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	return writeAtomic(path, b)
}

func openCrashLog(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "crash.log")
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		// Keep one previous crash; never include crash text in exported diagnostics.
		if err := os.Rename(path, filepath.Join(dir, "crash.previous.log")); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

func (a *App) startReliabilityLog() {
	dir := dataDir()
	a.previousUnclean = sessionWasUnclean(filepath.Join(dir, "session.json"))
	a.sessionPath = filepath.Join(dir, "session.json")
	if f, err := openCrashLog(dir); err == nil {
		_ = debug.SetCrashOutput(f, debug.CrashOptions{})
		_ = f.Close()
	}
	_ = markSession(a.sessionPath, false)
}

// Closing a window must not silently disconnect Telegram. Explicit Exit still quits.
func (a *App) beforeClose(context.Context) bool {
	if a.quitRequested.Load() || !a.trayAvailable.Load() {
		return false
	}
	a.MinimiseToTray()
	return true
}

func (a *App) ExitApplication() {
	a.quitRequested.Store(true)
	if a.ctx != nil {
		wr.Quit(a.ctx)
	}
}
