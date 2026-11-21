package main

import (
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/store"
)

// TestToControlObservationsMarksBaseline: перевод записей журнала в наблюдения
// контура распознаёт базовую линию по пустой стратегии. Это важно: контур
// отвергает наблюдение без стратегии, если оно не помечено базовым, и ошибка
// здесь молча выбросила бы весь базовый прогрев.
func TestToControlObservationsMarksBaseline(t *testing.T) {
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	src := []store.Observation{
		{
			At: at, StrategyID: "s1", Target: "youtube.com",
			VantageID: "v1", Outcome: core.OutcomeOK, Source: store.SourceProbe,
		},
		{
			At: at, StrategyID: "", Target: "youtube.com",
			VantageID: "v1", Outcome: core.OutcomeFail, Source: store.SourceProbe,
		},
	}

	got := toControlObservations(src)
	if len(got) != 2 {
		t.Fatalf("переведено %d наблюдений, ожидалось 2", len(got))
	}
	if got[0].Baseline {
		t.Error("наблюдение со стратегией не должно быть базовой линией")
	}
	if !got[1].Baseline {
		t.Error("наблюдение без стратегии должно быть базовой линией")
	}
	// Поля ключа сохраняются: без них наблюдение неотносимо.
	if got[0].StrategyID != "s1" || got[0].Target != "youtube.com" ||
		got[0].Outcome != core.OutcomeOK || got[0].Source != store.SourceProbe || !got[0].At.Equal(at) {
		t.Errorf("поля наблюдения искажены при переводе: %+v", got[0])
	}
}

// TestWarmupNilArchiveIsSafe: прогрев по отсутствующему журналу не падает и
// возвращает пустоту — движок обязан работать и с нуля.
func TestWarmupNilArchiveIsSafe(t *testing.T) {
	var a *archive
	if got := a.warmup(t.Context(), "v1", time.Hour, newLogger(nil, false)); got != nil {
		t.Fatalf("прогрев по nil-журналу должен быть пустым, получено %d", len(got))
	}
}
