package rtctrack

import (
	"sync"
	"testing"
	"time"
)

// Фиксированный «now» для детерминированных тестов.
func fixedNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestObserveSettledResetCounters(t *testing.T) {
	tr := NewTracker(fixedNow(time.Unix(1000, 0)))
	p := Pair{SNI: "a.discord.media", Port: 443}
	tr.Observe(p)
	tr.Observe(p)
	tr.Settled(p)
	tr.Reset(p)

	snap := tr.Snapshot()
	s := snap[p]
	if s.Observed != 2 || s.Settled != 1 || s.Reset != 1 {
		t.Fatalf("ожидали Observed=2, Settled=1, Reset=1, получили %+v", s)
	}
	if s.LastAt.Unix() != 1000 {
		t.Fatalf("LastAt = %v, ожидали 1000", s.LastAt)
	}
}

func TestAvgDwell(t *testing.T) {
	tr := NewTracker(nil)
	p := Pair{SNI: "b.discord.media", Port: 2096}
	tr.Elapsed(p, 10*time.Second)
	tr.Elapsed(p, 20*time.Second)
	tr.Elapsed(p, 30*time.Second)
	snap := tr.Snapshot()
	s := snap[p]
	if s.AvgDwell() != 20*time.Second {
		t.Fatalf("AvgDwell = %v, ожидали 20с", s.AvgDwell())
	}
}

func TestSuccessRatePermille(t *testing.T) {
	tr := NewTracker(nil)
	p := Pair{SNI: "c.discord.media", Port: 443}
	for i := 0; i < 10; i++ {
		tr.Observe(p)
	}
	tr.Settled(p)
	tr.Settled(p)
	tr.Settled(p)
	s := tr.Snapshot()[p]
	if s.SuccessRate() != 300 { // 3/10 = 300 permille
		t.Fatalf("SuccessRate = %d, ожидали 300", s.SuccessRate())
	}
}

func TestLivenessScoreCombinesBothSignals(t *testing.T) {
	tr := NewTracker(nil)
	strong := Pair{SNI: "strong.discord.media", Port: 443}
	weak := Pair{SNI: "weak.discord.media", Port: 2053}

	// strong: 10/10 успехов, 600с dwell (максимум).
	for i := 0; i < 10; i++ {
		tr.Observe(strong)
		tr.Settled(strong)
		tr.Elapsed(strong, 10*time.Minute)
	}
	// weak: 1/10 успехов, 10с dwell.
	for i := 0; i < 10; i++ {
		tr.Observe(weak)
	}
	tr.Settled(weak)
	tr.Elapsed(weak, 10*time.Second)

	snap := tr.Snapshot()
	strongScore := snap[strong].LivenessScore()
	weakScore := snap[weak].LivenessScore()

	if strongScore <= weakScore {
		t.Fatalf("strongScore %d должен быть больше weakScore %d", strongScore, weakScore)
	}
	// strong должна быть близка к 1000, weak — к 100.
	if strongScore < 900 {
		t.Fatalf("strongScore %d слишком низок (ожидали ~1000)", strongScore)
	}
}

func TestRankOrdersByScore(t *testing.T) {
	tr := NewTracker(nil)
	good := Pair{SNI: "good.discord.media", Port: 443}
	bad := Pair{SNI: "bad.discord.media", Port: 2053}
	// good: 5 попыток, все settled → 1000‰
	for i := 0; i < 5; i++ {
		tr.Observe(good)
		tr.Settled(good)
	}
	// bad: 5 попыток, 4 из них с retransmit (Reset) → 1 из 5 без явного срыва
	for i := 0; i < 5; i++ {
		tr.Observe(bad)
	}
	for i := 0; i < 4; i++ {
		tr.Reset(bad)
	}
	entries := tr.Rank(10, 1)
	if len(entries) != 2 {
		t.Fatalf("Rank вернул %d, ожидали 2", len(entries))
	}
	if entries[0].Pair != good {
		t.Fatalf("первой должна быть good (score %d), получили %v (score %d)",
			entries[0].Score, entries[1].Pair, entries[1].Score)
	}
	if entries[1].Pair != bad {
		t.Fatalf("второй должна быть bad, получили %v", entries[1].Pair)
	}
}

func TestRankSkipsBelowMinObserved(t *testing.T) {
	tr := NewTracker(nil)
	skinny := Pair{SNI: "skinny.discord.media", Port: 443}
	fat := Pair{SNI: "fat.discord.media", Port: 443}
	tr.Observe(skinny)
	tr.Settled(skinny)
	for i := 0; i < 10; i++ {
		tr.Observe(fat)
	}
	entries := tr.Rank(10, 3)
	for _, e := range entries {
		if e.Pair == skinny {
			t.Fatal("пара с 1 наблюдением должна быть исключена")
		}
	}
}

func TestPruneRemovesStale(t *testing.T) {
	tr := NewTracker(fixedNow(time.Unix(1000, 0)))
	stale := Pair{SNI: "stale.discord.media", Port: 443}
	fresh := Pair{SNI: "fresh.discord.media", Port: 443}
	tr.Observe(stale)
	// Теперь двигаем «now» вперёд.
	tr = NewTracker(fixedNow(time.Unix(2000, 0)))
	tr.Observe(stale) // но заново добавим stale с 1000 через manual
	tr.Observe(fresh)

	// Форсим stale в прошлое через прямую правку (внутренняя кухня).
	tr.stats[stale].LastAt = time.Unix(100, 0)
	removed := tr.Prune(600 * time.Second) // всё старше 600с - вон
	if removed != 1 {
		t.Fatalf("Prune удалил %d, ожидали 1", removed)
	}
	if _, ok := tr.Snapshot()[stale]; ok {
		t.Fatal("stale запись осталась после Prune")
	}
	if _, ok := tr.Snapshot()[fresh]; !ok {
		t.Fatal("fresh запись пропала после Prune")
	}
}

func TestConcurrentAccess(t *testing.T) {
	tr := NewTracker(nil)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		p := Pair{SNI: "x.discord.media", Port: uint16(1000 + i)}
		wg.Add(3)
		go func() {
			defer wg.Done()
			for k := 0; k < 100; k++ {
				tr.Observe(p)
			}
		}()
		go func() {
			defer wg.Done()
			for k := 0; k < 100; k++ {
				tr.Settled(p)
			}
		}()
		go func() {
			defer wg.Done()
			for k := 0; k < 100; k++ {
				_ = tr.Snapshot()
			}
		}()
	}
	wg.Wait()
	// Главное — не упало под -race.
	if tr.Len() == 0 {
		t.Fatal("Len == 0 после параллельной записи")
	}
}

func TestSnapshotIsCopy(t *testing.T) {
	tr := NewTracker(nil)
	p := Pair{SNI: "x", Port: 443}
	tr.Observe(p)
	snap := tr.Snapshot()
	s := snap[p]
	s.Observed = 999
	// Внутренняя статистика не должна была испортиться.
	if tr.Snapshot()[p].Observed == 999 {
		t.Fatal("Snapshot отдал ссылку, внутренние данные испорчены")
	}
}
