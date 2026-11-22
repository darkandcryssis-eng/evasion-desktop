package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/fitting-1c/evasion/internal/enginelock"
)

// acquireEngineLock захватывает lock-файл для одного экземпляра перехвата.
// filter попадает в запись как идентификатор запущенного контура, по которому
// проверяется конфликт.
//
// Возвращает *enginelock.Lock, который вызывающий обязан Release через defer.
// На конфликте — ошибка с указанием, какой PID уже держит фильтр, и подсказкой
// про `evasion cleanup`.
func acquireEngineLock(filter string) (*enginelock.Lock, error) {
	path := filepath.Join(defaultStateDir, "engine.lock")
	lock, err := enginelock.Acquire(enginelock.Options{
		Path:    path,
		Filter:  filter,
		SelfPID: enginePID(),
	})
	if err != nil {
		if errors.Is(err, enginelock.ErrConflict) {
			return nil, fmt.Errorf(
				"%w\nЕсли уверен, что другой экземпляр мёртв: evasion cleanup, затем повтори запуск.\n"+
					"Если старый процесс не выключается: taskkill /F /IM evasion.exe, затем повтори.",
				err)
		}
		return nil, err
	}
	return lock, nil
}

// enginePID — PID, под которым движок виден оболочке. На macOS оболочка
// запускает движок через посредника и знает PID своего дочернего процесса,
// а не движка: посредник передаёт его в EVASION_PID.
func enginePID() int {
	if runtime.GOOS == "darwin" {
		if pid, err := strconv.Atoi(os.Getenv("EVASION_PID")); err == nil && pid > 1 {
			return pid
		}
	}
	return os.Getpid()
}
