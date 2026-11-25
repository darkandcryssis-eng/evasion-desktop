//go:build !windows && !darwin

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// Оболочка рассчитана на Windows (WinDivert). Заглушки нужны, чтобы модуль
// собирался и проверялся `go vet` на любой ОС.

var errWindowsOnly = errors.New("движок перехвата работает только в Windows")

func hideConsole(*exec.Cmd)          {}
func isElevated() (bool, bool)       { return false, false }
func pidAlive(int) bool              { return false }
func beforeEngineStart()             {}
func killStrayEngine(string)         {}
func clearConflicts() conflictReport { return conflictReport{} }
func restartDiscord(string, bool) (discordStartResult, error) {
	return discordStartResult{}, errWindowsOnly
}
func hostsFilePath() string { return "/etc/hosts" }

func dataDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "Evasion")
	}
	return filepath.Join(os.TempDir(), "Evasion")
}

func openPath(path string) error {
	return exec.Command("xdg-open", path).Start()
}

func prepareEngine(layout) error { return nil }
