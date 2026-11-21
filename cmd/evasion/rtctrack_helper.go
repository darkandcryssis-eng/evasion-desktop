package main

import (
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fitting-1c/evasion/internal/rtctrack"
)

// rtcSaveInterval — как часто пишется state/rtctrack.json. Минута: статистика
// меняется плавно, а слишком частая запись в state/ бесполезно изнашивает
// диск.
const rtcSaveInterval = time.Minute

// rtcSnapshotName — имя файла снимка в state-каталоге.
const rtcSnapshotName = "rtctrack.json"

// openRTCTracker поднимает трекер живучести RTC-пар с восстановлением из
// state/rtctrack.json (если файл есть) и фоновым автосохранением раз в минуту.
//
// Отказ Load (несовместимая версия, сломанный JSON) ведёт к ЧИСТОМУ старту с
// предупреждением в журнал: лучше потерять историю, чем сорвать запуск движка.
// Отсутствие файла — не ошибка (первый запуск).
//
// Возвращает (tracker, autosaver). У autosaver нужно вызвать Stop() на выходе
// — он синхронно запишет финальный снимок, чтобы знания последней минуты не
// потерялись.
func openRTCTracker(log *slog.Logger) (*rtctrack.Tracker, *rtctrack.AutoSaver) {
	path := filepath.Join(defaultStateDir, rtcSnapshotName)
	tracker, err := rtctrack.Load(path, nil)
	switch {
	case err == nil:
		if n := tracker.Len(); n > 0 {
			log.Info("rtctrack: восстановлен из снимка", "путь", path, "пар", n)
		}
	default:
		log.Warn("rtctrack: снимок не загружен, старт пустой",
			"путь", path, "ошибка", err)
		tracker = rtctrack.NewTracker(nil)
	}
	saver := rtctrack.StartAutoSaver(tracker, path, rtcSaveInterval)
	return tracker, saver
}
