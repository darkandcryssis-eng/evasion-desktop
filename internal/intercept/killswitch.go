package intercept

import (
	"context"
	"time"
)

// HealthCheck сообщает, жива ли связность с контрольными целями.
//
// Инъектируется, чтобы killswitch проверялся без сети. Настоящая проверка —
// рукопожатие TCP к контрольным целям (её соберёт команда запуска из того же
// материала, что doctor).
type HealthCheck func(ctx context.Context) bool

// Guard — killswitch: следит за связностью и переключает прозрачный режим (1.6).
//
// При потере связности (подряд failThreshold неудачных проверок) поднимает
// прозрачный режим и бьёт тревогу; при восстановлении снимает его. Порог нужен,
// чтобы единичный сбой проверки не ронял перехват дребезгом — тот же довод, что
// у срыва по провалам в автопилоте (5.7).
//
// Блокирует до отмены контекста; запускается отдельной горутиной рядом с Run.
// Переключение сделано через atomic.Swap, чтобы тревога и сообщение о
// восстановлении печатались ровно на переходе, а не на каждой проверке.
func (e *Engine) Guard(ctx context.Context, check HealthCheck, interval time.Duration, failThreshold int) {
	if failThreshold < 1 {
		failThreshold = 1
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	fails := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if check(ctx) {
				// Восстановление: снимаем прозрачный режим, если он стоял.
				if e.transparent.Swap(false) {
					e.log.Warn("связность восстановлена, перехват возобновлён")
				}
				fails = 0
				continue
			}
			if fails < failThreshold {
				fails++
			}
			// Потеря: поднимаем прозрачный режим на переходе false→true.
			if fails >= failThreshold && !e.transparent.Swap(true) {
				e.log.Error("ТРЕВОГА: связность потеряна, killswitch включил прозрачный режим")
			}
		}
	}
}
