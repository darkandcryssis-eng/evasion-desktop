package main

import (
	"testing"
	"time"
)

func TestGameProcessNamesFollowSelection(t *testing.T) {
	s := GameFilterSettings{Albion: true, Executables: []string{`C:\Games\Warframe\Warframe.x64.exe`}}
	if !anyGameRunning(s, []string{"explorer.exe", "Albion-Online.exe"}) {
		t.Fatal("клиент Albion должен распознаваться без учёта регистра")
	}
	if !anyGameRunning(s, []string{"WARFRAME.X64.EXE"}) {
		t.Fatal("добавленная игра должна распознаваться по имени файла")
	}
	if anyGameRunning(s, []string{"upc.exe", "cs2.exe", "steam.exe"}) {
		t.Fatal("невыбранные игры и лаунчеры не должны включать фильтр")
	}
	if anyGameRunning(GameFilterSettings{}, []string{"albion-online.exe"}) {
		t.Fatal("без выбранных игр фильтр не нужен")
	}
}

func TestGameWatchStep(t *testing.T) {
	now := time.Unix(1000, 0)
	cases := []struct {
		name                     string
		armed, present, engineUp bool
		seenAgo                  time.Duration
		start, stop              bool
	}{
		{"не взведён", false, true, false, 0, false, false},
		{"игра появилась", true, true, false, 0, true, false},
		{"игра идёт", true, true, true, 0, false, false},
		{"только что вышли", true, false, true, 5 * time.Second, false, false},
		{"давно вышли", true, false, true, gameLinger, false, true},
		{"ждём игру", true, false, false, time.Hour, false, false},
	}
	for _, c := range cases {
		start, stop := gameWatchStep(now, c.armed, c.present, c.engineUp, now.Add(-c.seenAgo))
		if start != c.start || stop != c.stop {
			t.Errorf("%s: start=%v stop=%v", c.name, start, stop)
		}
	}
}
