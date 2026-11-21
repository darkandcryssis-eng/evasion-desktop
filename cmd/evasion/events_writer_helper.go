package main

import (
	"log/slog"
	"path/filepath"

	"github.com/fitting-1c/evasion/internal/events"
)

// openEventsWriter поднимает приёмник событий жизненного цикла (state/events.jsonl).
//
// Возвращает nil Writer на ошибке — поведение движка не меняется, журнал
// просто не ведётся. Это осознанный компромисс: наблюдаемость желательна, но
// её отказ не должен ронять перехват. Ошибка идёт в журнал slog как
// предупреждение.
func openEventsWriter(log *slog.Logger) (*events.Writer, error) {
	path := filepath.Join(defaultStateDir, "events.jsonl")
	w, err := events.Open(events.Config{Path: path})
	if err != nil {
		log.Warn("журнал событий не поднялся, работаем без него", "путь", path, "ошибка", err)
		return nil, err
	}
	log.Info("журнал событий поднят", "путь", path)
	return w, nil
}

// closeEventsWriter — помощник для defer: закрывает writer, если он не nil.
// Ошибка закрытия идёт в журнал, но не наверх — это уже остановка процесса,
// и реагировать на неё нечем.
func closeEventsWriter(w *events.Writer, log *slog.Logger) {
	if w == nil {
		return
	}
	if err := w.Close(); err != nil {
		log.Warn("журнал событий закрыт с ошибкой", "ошибка", err)
	}
}
