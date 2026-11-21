package main

import (
	"context"
	"fmt"
	"time"
)

// Сторож движка: если evasion.exe внезапно завершился во время работы (не по
// просьбе пользователя), оболочка поднимает его заново с теми же параметрами.
// Discord при этом не перезапускается. Чтобы не зациклиться на неисправимой
// ошибке, действует предел: reviveLimit подъёмов за reviveWindow.

const (
	reviveLimit  = 3
	reviveWindow = 10 * time.Minute
	reviveDelay  = 3 * time.Second
	reviveTick   = 2 * time.Second
)

// reviveDecision — чистое решение сторожа. history — моменты прошлых подъёмов.
// wait=true — рано (движку дают reviveDelay отпустить драйвер).
func reviveDecision(now, crashedAt time.Time, history []time.Time) (revive, wait bool, recent []time.Time) {
	for _, t := range history {
		if now.Sub(t) < reviveWindow {
			recent = append(recent, t)
		}
	}
	if len(recent) >= reviveLimit {
		return false, false, recent
	}
	if now.Sub(crashedAt) < reviveDelay {
		return false, true, recent
	}
	return true, false, recent
}

func (a *App) superviseEngine(ctx context.Context) {
	ticker := time.NewTicker(reviveTick)
	defer ticker.Stop()
	var history []time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		crashedAt, opts, ok := a.engine.crashInfo()
		if !ok {
			continue
		}
		revive, wait, recent := reviveDecision(time.Now(), crashedAt, history)
		history = recent
		if wait {
			continue
		}
		if !revive {
			a.engine.giveUp(fmt.Sprintf("Движок падал %d раза за 10 минут — автоподъём приостановлен. Откройте диагностику.", reviveLimit))
			continue
		}
		a.lifecycle.Lock()
		if _, _, still := a.engine.crashInfo(); !still || a.shuttingDown {
			a.lifecycle.Unlock()
			continue
		}
		history = append(history, time.Now())
		err := a.startEngineLocked(opts, true)
		a.lifecycle.Unlock()
		if err != nil {
			a.engine.giveUp("Автоподъём не удался: " + err.Error())
			continue
		}
		a.engine.noteRevived()
	}
}
