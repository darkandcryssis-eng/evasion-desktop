//go:build windows

package enginelock

import (
	"time"

	"golang.org/x/sys/windows"
)

// startSlack — допуск между временем создания процесса и StartedAt записи:
// запись пишется уже после старта процесса, поэтому «свой» процесс всегда
// создан раньше StartedAt. Допуск покрывает только округление часов.
const startSlack = 2 * time.Second

// defaultAlive на Windows отвечает «жив ли именно тот движок, что оставил
// запись», а не «существует ли объект процесса с таким PID».
//
// Одного успешного OpenProcess мало: объект процесса живёт, пока на него
// открыт хотя бы один handle (окно PowerShell, запустившее движок через
// Start-Process, оболочка приложения, диспетчер задач), и его PID в это время
// не переиспользуется. Такой вышедший процесс раньше считался живым, и
// следующий запуск отказывал с ErrConflict, пока lock-файл не удаляли руками.
//
// Поэтому проверяем два условия:
//  1. процесс ещё не завершился — WaitForSingleObject с нулевым таймаутом
//     возвращает WAIT_TIMEOUT только для работающего процесса;
//  2. процесс создан не позже записи — иначе PID после смерти движка достался
//     постороннему процессу.
func defaultAlive(e Entry) bool {
	if e.PID <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(e.PID))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)

	if ev, err := windows.WaitForSingleObject(h, 0); err == nil && ev == windows.WAIT_OBJECT_0 {
		return false
	}
	if e.StartedAt.IsZero() {
		return true
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return true
	}
	created := time.Unix(0, creation.Nanoseconds())
	return !created.After(e.StartedAt.Add(startSlack))
}
