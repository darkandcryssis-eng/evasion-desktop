package main

import (
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/rtctrack"
)

func TestBlocklistEmptyInitially(t *testing.T) {
	b := &rtcBlocklist{}
	if b.Contains("x.discord.media") {
		t.Fatal("пустой blocklist не должен содержать ничего")
	}
}

func TestBlocklistRebuildBelowMinObservedIgnored(t *testing.T) {
	tr := rtctrack.NewTracker(nil)
	p := rtctrack.Pair{SNI: "weak.discord.media", Port: 0}
	// Всего 2 попытки — ниже minObserved=3, даже если все провальные.
	tr.Observe(p)
	tr.Observe(p)
	tr.Reset(p)
	tr.Reset(p)

	b := &rtcBlocklist{}
	n := b.Rebuild(tr, 3, 500)
	if n != 0 {
		t.Fatalf("ожидали 0 в блоке (2 попытки меньше minObserved=3), получили %d", n)
	}
	if b.Contains("weak.discord.media") {
		t.Fatal("SNI с 2 попытками не должен быть в блоке")
	}
}

func TestBlocklistBadSNIBlocked(t *testing.T) {
	tr := rtctrack.NewTracker(nil)
	bad := rtctrack.Pair{SNI: "bad.discord.media", Port: 0}
	// 5 попыток, 4 с Reset → SuccessRate = 200‰
	for i := 0; i < 5; i++ {
		tr.Observe(bad)
	}
	for i := 0; i < 4; i++ {
		tr.Reset(bad)
	}

	b := &rtcBlocklist{}
	n := b.Rebuild(tr, 3, 500)
	if n != 1 {
		t.Fatalf("ожидали 1 в блоке, получили %d", n)
	}
	if !b.Contains("bad.discord.media") {
		t.Fatal("плохой SNI не попал в блок")
	}
}

func TestBlocklistGoodSNINotBlocked(t *testing.T) {
	tr := rtctrack.NewTracker(nil)
	good := rtctrack.Pair{SNI: "good.discord.media", Port: 0}
	for i := 0; i < 10; i++ {
		tr.Observe(good)
	}
	// 1 Reset из 10 → 900‰ > 500 → не блокировать
	tr.Reset(good)

	b := &rtcBlocklist{}
	n := b.Rebuild(tr, 3, 500)
	if n != 0 {
		t.Fatalf("хороший SNI (SuccessRate 900‰) не должен быть в блоке, но было %d", n)
	}
}

func TestBlocklistAtomicRebuildDoesNotPanic(t *testing.T) {
	tr := rtctrack.NewTracker(nil)
	b := &rtcBlocklist{}

	// Параллельно: пересборка + чтение. Главное — не упасть под -race.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			p := rtctrack.Pair{SNI: "x.discord.media", Port: uint16(i)}
			tr.Observe(p)
			tr.Reset(p)
			b.Rebuild(tr, 1, 1000)
		}
	}()
	for i := 0; i < 1000; i++ {
		_ = b.Contains("x.discord.media")
	}
	<-done
}

func TestBlocklistExistingSNIClearedOnRebuild(t *testing.T) {
	tr := rtctrack.NewTracker(nil)
	bad := rtctrack.Pair{SNI: "bad.discord.media", Port: 0}
	// Сначала плохой.
	for i := 0; i < 5; i++ {
		tr.Observe(bad)
	}
	for i := 0; i < 4; i++ {
		tr.Reset(bad)
	}
	b := &rtcBlocklist{}
	_ = b.Rebuild(tr, 3, 500)
	if !b.Contains("bad.discord.media") {
		t.Fatal("прежняя проверка: SNI должен быть в блоке")
	}

	// Теперь компенсируем Settled'ами (симулируем «он снова работает»).
	for i := 0; i < 10; i++ {
		tr.Observe(bad)
		tr.Settled(bad)
	}
	_ = b.Rebuild(tr, 3, 500)
	if b.Contains("bad.discord.media") {
		t.Fatal("SNI не должен оставаться в блоке после восстановления успехов")
	}
}

func TestBlocklistRebuildTimingSanity(t *testing.T) {
	// Сам Rebuild — быстрый (не измеряем точно, лишь что он возвращается).
	tr := rtctrack.NewTracker(nil)
	for i := 0; i < 100; i++ {
		p := rtctrack.Pair{SNI: "x", Port: uint16(i)}
		tr.Observe(p)
		if i%3 == 0 {
			tr.Reset(p)
		}
	}
	b := &rtcBlocklist{}
	start := time.Now()
	_ = b.Rebuild(tr, 1, 500)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("Rebuild на 100 парах заняла %v, слишком долго", elapsed)
	}
}

// TestBlocklistDropsStaleEntries — блок не вечен: без новых событий SNI
// возвращается под десинк.
func TestBlocklistDropsStaleEntries(t *testing.T) {
	now := time.Now()
	tr := rtctrack.NewTracker(func() time.Time { return now.Add(-blocklistMaxAge - time.Minute) })
	p := rtctrack.Pair{SNI: "c-arn08-da88e905.discord.media"}
	for i := 0; i < 4; i++ {
		tr.Observe(p)
		tr.Reset(p)
	}
	b := &rtcBlocklist{}
	if n := b.Rebuild(tr, 3, 500); n != 0 || b.Contains(p.SNI) {
		t.Fatalf("устаревшая запись не должна блокировать SNI, n=%d", n)
	}
}
