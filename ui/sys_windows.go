//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hideConsole запускает консольный evasion.exe без окна консоли: оболочка —
// GUI-приложение, вывод движка она читает через пайпы.
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
}

// isElevated — запущена ли оболочка с правами администратора. Манифест
// требует их (requireAdministrator), но в режиме `wails dev` их может не быть.
func isElevated() (elevated bool, checked bool) {
	return windows.GetCurrentProcessToken().IsElevated(), true
}

func pidAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259
	return code == stillActive
}

func runHidden(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	hideConsole(cmd)
	return cmd.Run()
}

// beforeEngineStart повторяет подготовку scripts\start-discord.bat: снимает
// оставшееся от старых экспериментов правило брандмауэра на RTC-порты.
func beforeEngineStart() {
	_ = runHidden("netsh", "advfirewall", "firewall", "delete", "rule", "name=movok-discord-bad-rtc")
}

func processRunning(image string) bool {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), image) {
			return true
		}
	}
	return false
}

// Only retire an orphan of this installation's embedded engine.
func killStrayEngines() {
	l, err := resolveLayout()
	if err != nil {
		return
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if entry.ProcessID == uint32(os.Getpid()) || !strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), payloadEngine) {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, entry.ProcessID)
		if err != nil {
			continue
		}
		var buffer [32768]uint16
		size := uint32(len(buffer))
		if windows.QueryFullProcessImageName(h, 0, &buffer[0], &size) == nil && sameEngineImage(windows.UTF16ToString(buffer[:size]), l.Engine) {
			if windows.TerminateProcess(h, 0) == nil {
				_, _ = windows.WaitForSingleObject(h, 1000)
			}
		}
		windows.CloseHandle(h)
	}
}

func sameEngineImage(actual, expected string) bool {
	a, err := os.Stat(actual)
	if err != nil {
		return false
	}
	b, err := os.Stat(expected)
	if err != nil {
		return false
	}
	return !a.IsDir() && !b.IsDir() && os.SameFile(a, b)
}

// restartDiscord закрывает Discord и запускает последнюю установленную версию
// с выключенным DoH. Резервный прокси используется только при нерабочем прямом API.
func restartDiscord(proxyAddress string) (discordStartResult, error) {
	root := filepath.Join(os.Getenv("LOCALAPPDATA"), "Discord")
	dirs, _ := filepath.Glob(filepath.Join(root, "app-*"))
	var candidates []string
	for _, d := range dirs {
		if st, err := os.Stat(filepath.Join(d, "Discord.exe")); err == nil && !st.IsDir() {
			candidates = append(candidates, d)
		}
	}
	if len(candidates) == 0 {
		return discordStartResult{}, fmt.Errorf("Discord.exe не найден в %s\\app-*", root)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return versionLess(filepath.Base(candidates[j]), filepath.Base(candidates[i]))
	})
	dir := candidates[0]
	useTunnel := proxyAddress != "" && !discordDirectHealthy()
	args := []string{"--disable-features=DnsOverHttps"}
	if useTunnel {
		args = append(args, "--proxy-server=http://"+proxyAddress)
	}

	_ = runHidden("taskkill", "/F", "/IM", "Discord.exe", "/T")
	// Новый экземпляр уступит старому, пока тот жив: ждём выхода, но не дольше секунды.
	for deadline := time.Now().Add(time.Second); processRunning("Discord.exe") && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
	}

	cmd := exec.Command(filepath.Join(dir, "Discord.exe"), args...)
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		return discordStartResult{}, fmt.Errorf("не удалось запустить Discord: %w", err)
	}
	_ = cmd.Process.Release()
	return discordStartResult{Version: filepath.Base(dir), Tunnel: useTunnel}, nil
}

func discordDirectHealthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://discord.com/api/v10/gateway", nil)
	if err != nil {
		return false
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	response, err := client.Do(req)
	if err != nil {
		return false
	}
	response.Body.Close()
	return response.StatusCode == http.StatusOK
}

// versionLess сравнивает имена вида app-1.0.9213 по числам, а не по строке.
func versionLess(a, b string) bool {
	pa := strings.Split(strings.TrimPrefix(a, "app-"), ".")
	pb := strings.Split(strings.TrimPrefix(b, "app-"), ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, ex := strconv.Atoi(pa[i])
		y, ey := strconv.Atoi(pb[i])
		if ex != nil || ey != nil {
			if pa[i] != pb[i] {
				return pa[i] < pb[i]
			}
			continue
		}
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

func hostsFilePath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers", "etc", "hosts")
}

// dataDir — папка данных приложения в профиле пользователя:
// %LOCALAPPDATA%\Evasion (напр. C:\Users\Admin\AppData\Local\Evasion). Не на
// рабочем столе и не рядом с exe.
func dataDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
	}
	return filepath.Join(base, "Evasion")
}

// openPath открывает папку в Проводнике. explorer на успехе возвращает код 1 —
// не считаем это ошибкой.
func openPath(path string) error {
	_ = exec.Command("explorer", path).Start()
	return nil
}
