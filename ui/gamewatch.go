package main

import (
	"context"
	"path/filepath"
	"strings"
	"time"
)

// Игровой фильтр «по требованию». Пока ни одна выбранная игра не запущена,
// игровой движок не работает вовсе: перехвата UDP/TCP нет, остальные игры и
// программы не замечают Evasion. Сторож включает фильтр при появлении процесса
// выбранной игры и снимает его через gameLinger после выхода.

const (
	gameWatchTick = 3 * time.Second
	gameLinger    = 20 * time.Second
)

// gameProcessNames — имена процессов (в нижнем регистре), ради которых фильтр
// должен работать при данных настройках.
func gameProcessNames(s GameFilterSettings) map[string]bool {
	names := map[string]bool{}
	for _, p := range s.Executables {
		if base := strings.ToLower(filepath.Base(strings.ReplaceAll(p, "\\", "/"))); base != "" && base != "." {
			names[base] = true
		}
	}
	return names
}

func anyGameRunning(s GameFilterSettings, running []string) bool {
	want := gameProcessNames(s)
	for _, n := range running {
		if want[strings.ToLower(n)] {
			return true
		}
	}
	return false
}

// gameWatchStep — чистое решение сторожа: start — поднять фильтр, stop — снять.
// lastSeen — когда игру видели в последний раз.
func gameWatchStep(now time.Time, armed, present, engineUp bool, lastSeen time.Time) (start, stop bool) {
	if !armed {
		return false, false
	}
	if present {
		return !engineUp, false
	}
	return false, engineUp && now.Sub(lastSeen) >= gameLinger
}

func (a *App) watchGames(ctx context.Context) {
	ticker := time.NewTicker(gameWatchTick)
	defer ticker.Stop()
	var lastSeen time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !a.gameArmed.Load() {
			continue
		}
		l, err := resolveLayout()
		if err != nil {
			continue
		}
		a.gameMu.Lock()
		settings, err := readGameSettings(l.Base)
		a.gameMu.Unlock()
		if err != nil || settings.Mode == "off" || !settings.OnDemand {
			continue
		}
		names, err := runningProcessNames()
		if err != nil {
			continue
		}
		now := time.Now()
		present := anyGameRunning(settings, names)
		if present {
			lastSeen = now
		}
		phase := a.games.snapshot().Phase
		// A game started by an added launcher keeps the filter on after the
		// launcher itself has exited.
		if !present && phase == phaseRunning && len(a.GetGameFilter().Targets) > 0 {
			present = true
			lastSeen = now
		}
		if phase == phaseStarting || phase == phaseStopping {
			continue
		}
		start, stop := gameWatchStep(now, true, present, phase == phaseRunning, lastSeen)
		if !start && !stop {
			continue
		}
		a.lifecycle.Lock()
		if a.gameArmed.Load() && !a.shuttingDown {
			if start {
				_ = a.startGameFilterLocked()
			} else {
				_ = a.games.stop()
			}
		}
		a.lifecycle.Unlock()
	}
}
