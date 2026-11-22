//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// На macOS движок перехватывает трафик через pf, utun и BPF — всё это требует
// root. Оболочка работает от пользователя, а движку один раз (и после каждого
// обновления) выдаётся setuid-root по паролю администратора.

var errWindowsOnly = errors.New("эта функция доступна только в Windows")

func hideConsole(*exec.Cmd)          {}
func isElevated() (bool, bool)       { return true, true }
func beforeEngineStart()             {}
func killStrayEngines()              {}
func clearConflicts() conflictReport { return conflictReport{} }
func restartDiscord(string) (discordStartResult, error) {
	return discordStartResult{}, errWindowsOnly
}
func hostsFilePath() string { return "/etc/hosts" }

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func dataDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "Evasion")
	}
	return filepath.Join(os.TempDir(), "Evasion")
}

func openPath(path string) error {
	return exec.Command("/usr/bin/open", path).Start()
}

func enginePrivileged(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && info.Mode()&os.ModeSetuid != 0
}

func prepareEngine(l layout) error {
	if enginePrivileged(l.Engine) {
		return nil
	}
	quoted := "'" + strings.ReplaceAll(l.Engine, "'", `'\''`) + "'"
	shell := "/usr/sbin/chown root " + quoted + " && /bin/chmod 4755 " + quoted
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace
	script := fmt.Sprintf(`do shell script "%s" with prompt "%s" with administrator privileges`,
		esc(shell), esc("Evasion нужны права администратора, чтобы включить обход."))
	if out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "-128") {
			return errors.New("без пароля администратора обход на macOS не включить")
		}
		return fmt.Errorf("не удалось выдать движку права администратора: %s", strings.TrimSpace(string(out)))
	}
	if !enginePrivileged(l.Engine) {
		return errors.New("не удалось выдать движку права администратора")
	}
	return nil
}
