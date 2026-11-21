//go:build windows

package enginelock

import "golang.org/x/sys/windows"

// defaultAlive на Windows: OpenProcess с SYNCHRONIZE правом; если handle
// получен — процесс существует. SYNCHRONIZE требует меньше прав, чем
// QUERY_INFORMATION, и доступен нам, работающим от администратора, на любой
// запущенный процесс.
//
// Процесс может быть зомби (вышел, но handle ещё не закрыт родителем). Это
// нам не мешает: зомби не делает перехватов, и наш алгоритм выбрасывает его
// при следующем запуске естественным образом.
func defaultAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	_ = windows.CloseHandle(h)
	return true
}
