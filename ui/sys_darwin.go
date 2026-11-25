//go:build darwin

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	brokerDir    = "/var/run/evasion-broker"
	brokerEngine = brokerDir + "/evasion"
)

// На macOS движок перехватывает трафик через pf, utun и BPF — всё это требует
// root. Оболочка работает от пользователя; при первом включении обхода после
// запуска она по паролю администратора поднимает посредника, который запускает
// движок от root только для неё и завершается вместе с ней.

var errWindowsOnly = errors.New("эта функция доступна только в Windows")

func hideConsole(*exec.Cmd)          {}
func isElevated() (bool, bool)       { return true, true }
func beforeEngineStart()             {}
func killStrayEngine(string)         {}
func clearConflicts() conflictReport { return conflictReport{} }
func restartDiscord(string, bool) (discordStartResult, error) {
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

// brokerReady — отвечает ли посредник, поднятый для этого процесса оболочки.
func brokerReady() bool {
	out, err := exec.Command("/bin/ps", "-axo", "uid=,command=").Output()
	if err != nil {
		return false
	}
	want := fmt.Sprintf("%s broker --pid %d ", brokerEngine, os.Getpid())
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.SplitN(strings.TrimSpace(line), " ", 2)
		if len(f) == 2 && f[0] == "0" && strings.HasPrefix(strings.TrimSpace(f[1])+" ", want) {
			if c, err := net.Dial("unix", brokerDir+"/sock"); err == nil {
				_ = c.Close()
				return true
			}
		}
	}
	return false
}

// prepareEngine по паролю администратора копирует движок в каталог root и
// поднимает из копии посредника, привязанного к этому процессу оболочки.
func prepareEngine(l layout) error {
	if brokerReady() {
		return nil
	}
	quoted := "'" + strings.ReplaceAll(l.Engine, "'", `'\''`) + "'"
	shell := fmt.Sprintf("/bin/rm -rf %[1]s && /bin/mkdir -m 755 %[1]s && /bin/cp %[2]s %[3]s && "+
		"/usr/sbin/chown root:wheel %[3]s && /bin/chmod 755 %[3]s && "+
		"(%[3]s broker --pid %[4]d --uid %[5]d --gid %[6]d </dev/null >/dev/null 2>&1 &)",
		brokerDir, quoted, brokerEngine, os.Getpid(), os.Getuid(), os.Getgid())
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace
	script := fmt.Sprintf(`do shell script "%s" with prompt "%s" with administrator privileges`,
		esc(shell), esc("Evasion нужны права администратора, чтобы включить обход."))
	if out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "-128") {
			return errors.New("без пароля администратора обход на macOS не включить")
		}
		return fmt.Errorf("не удалось получить права администратора: %s", strings.TrimSpace(string(out)))
	}
	for i := 0; i < 50; i++ {
		if brokerReady() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("не удалось получить права администратора")
}
