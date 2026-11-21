//go:build !windows

package enginelock

import "syscall"

// defaultAlive на не-Windows: `kill(pid, 0)` — безопасный способ узнать,
// существует ли процесс. Signal 0 не отправляет сигнал, только проверяет
// право и наличие.
//
// В реальной работе движок на не-Windows не живёт (ему нужен WinDivert), но
// Acquire/Release тестируются на всех платформах CI — поэтому ядро пакета
// обязано собираться и работать здесь.
func defaultAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	// nil — процесс существует и мы вправе отправить ему сигнал.
	// EPERM — процесс существует, но мы не владеем. Это тоже «жив».
	// ESRCH — такого процесса нет.
	if err == nil {
		return true
	}
	if err == syscall.EPERM {
		return true
	}
	return false
}
