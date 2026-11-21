package main

import (
	"errors"
	"fmt"
	"path/filepath"

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
		Path:   path,
		Filter: filter,
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
