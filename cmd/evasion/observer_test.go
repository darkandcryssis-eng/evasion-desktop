package main

import (
	"log/slog"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/control"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/probe"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/store"
)

// discardLogger — журнал в никуда: приёмник проб обязан иметь журнал, но его
// содержимое здесь не проверяется.
func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// recordingSink запоминает наблюдения вместо их учёта.
type recordingSink struct {
	got []control.Observation
}

func (s *recordingSink) Observe(o control.Observation) bool {
	s.got = append(s.got, o)
	return true
}

var at = time.Date(2026, 10, 17, 3, 50, 0, 0, time.UTC)

// TestObserverTranslatesOutcome проверяет сам перевод: что из исхода
// соединения попадает в наблюдение и с каким весом.
func TestObserverTranslatesOutcome(t *testing.T) {
	sink := &recordingSink{}
	obs := &outcomeObserver{sink: sink}

	obs.ConnOutcome(proxy.ConnOutcome{
		Target:          "youtube.com",
		Host:            "www.youtube.com",
		SNI:             "www.youtube.com",
		StrategyID:      core.StrategyID("aaaa"),
		Trial:           true,
		StrategyApplied: true,
		Outcome:         core.OutcomeOK,
		Reason:          core.ReasonHandshakeDone,
		At:              at,
	})

	if len(sink.got) != 1 {
		t.Fatalf("наблюдений = %d, ожидалось 1", len(sink.got))
	}
	o := sink.got[0]
	if o.StrategyID != "aaaa" {
		t.Fatalf("стратегия = %q", o.StrategyID)
	}
	// Цель — из выбора, а не имя соединения: иначе наблюдение попало бы в
	// оценку другой четвёрки (6.1), и решения по цели его не увидели бы.
	if o.Target != "youtube.com" {
		t.Fatalf("цель = %q, ожидалась youtube.com, а не имя соединения", o.Target)
	}
	if o.Outcome != core.OutcomeOK {
		t.Fatalf("исход = %v", o.Outcome)
	}
	if o.Source != store.SourceLiveTraffic {
		t.Fatalf("источник = %v, ожидался живой трафик: условия известны, стратегию выбирали мы", o.Source)
	}
	if !o.Trial {
		t.Fatal("признак проверочной ветви потерян: проверочные соединения смешались бы с рабочими")
	}
	if !o.At.Equal(at) {
		t.Fatalf("время = %v, ожидалось %v", o.At, at)
	}
}

// TestObserverPassesInconclusive: «не определено» передаётся наравне с
// остальными. Вес у него нулевой (5.7), но доля таких исходов поднимает
// требуемый объём наблюдений (5.5) — выбросив их, движок скрыл бы от себя, что
// измерению верить нельзя.
func TestObserverPassesInconclusive(t *testing.T) {
	sink := &recordingSink{}
	obs := &outcomeObserver{sink: sink}

	obs.ConnOutcome(proxy.ConnOutcome{
		Target:          "youtube.com",
		StrategyID:      core.StrategyID("aaaa"),
		StrategyApplied: false,
		Outcome:         core.OutcomeInconclusive,
		Reason:          core.ReasonStrategyNotApplied,
		At:              at,
	})

	if len(sink.got) != 1 {
		t.Fatalf("наблюдений = %d, ожидалось 1: неопределённые исходы тоже считаются", len(sink.got))
	}
	if sink.got[0].Outcome != core.OutcomeInconclusive {
		t.Fatalf("исход = %v, ожидался inconclusive", sink.got[0].Outcome)
	}
}

// TestObserverSkipsConnectionsWithoutStrategy: вне радиуса стратегия не
// выбиралась, относить исход не к чему. Это не потеря данных, поэтому и
// непригодным наблюдением такое соединение называть нельзя.
func TestObserverSkipsConnectionsWithoutStrategy(t *testing.T) {
	sink := &recordingSink{}
	obs := &outcomeObserver{sink: sink}

	obs.ConnOutcome(proxy.ConnOutcome{
		Host:    "example.org",
		Outcome: core.OutcomeInconclusive,
		Reason:  core.ReasonStrategyNotApplied,
		At:      at,
	})

	if len(sink.got) != 0 {
		t.Fatalf("наблюдений = %d, ожидалось 0: вне радиуса относить исход не к чему", len(sink.got))
	}
}

// TestObserverForwardsUnattributableOutcome: стратегия выбрана, а цели нет —
// это дефект контура выбора. Наблюдение всё равно уходит контуру, чтобы тот
// посчитал его непригодным и дефект стал виден в status, а не растворился.
func TestObserverForwardsUnattributableOutcome(t *testing.T) {
	sink := &recordingSink{}
	obs := &outcomeObserver{sink: sink}

	obs.ConnOutcome(proxy.ConnOutcome{
		StrategyID: core.StrategyID("aaaa"),
		Outcome:    core.OutcomeOK,
		At:         at,
	})

	if len(sink.got) != 1 {
		t.Fatalf("наблюдений = %d, ожидалось 1", len(sink.got))
	}
	if sink.got[0].Target != "" {
		t.Fatal("цель не должна выдумываться")
	}
}

// TestObserverSatisfiesProxySink — наблюдатель обязан годиться прокси как
// приёмник исходов, а контур — наблюдателю как приёмник наблюдений.
func TestObserverSatisfiesProxySink(t *testing.T) {
	var _ proxy.OutcomeSink = (*outcomeObserver)(nil)
	var _ observationSink = (*control.Engine)(nil)
}

// recordingArchive запоминает наблюдения, которые ушли бы в журнал.
type recordingArchive struct {
	got []store.Observation
}

func (a *recordingArchive) Enqueue(o store.Observation) bool {
	a.got = append(a.got, o)
	return true
}

// TestProbeSinkPassesBaselineThrough — результат базовой пробы доходит до
// контура и до журнала, а не отбрасывается как наблюдение без стратегии.
//
// Шов этот был закрыт предохранителем «такого не бывает»: приёмник отвергал
// пустой идентификатор стратегии и писал предупреждение. Теперь базовая проба
// — осознанный случай, и предохранитель обязан пропускать именно её, оставаясь
// закрытым для настоящего дефекта (наблюдение, потерявшее стратегию).
func TestProbeSinkPassesBaselineThrough(t *testing.T) {
	engine := &recordingSink{}
	arch := &recordingArchive{}
	sink := &probeSink{
		engine:  engine,
		archive: arch,
		vantage: core.VantageID("v1"),
		log:     discardLogger(),
	}

	sink.ProbeDone(
		probe.PlanItem{Target: "discord.gg", Host: "discord.gg", Baseline: true},
		probe.Result{
			Phase:   core.PhaseFast,
			Outcome: core.OutcomeOK,
			Reason:  core.ReasonHandshakeDone,
			Started: at,
		})

	if len(engine.got) != 1 {
		t.Fatalf("контур получил %d наблюдений, ожидалось одно", len(engine.got))
	}
	o := engine.got[0]
	if !o.Baseline {
		t.Fatal("признак базовой линии потерян: контур примет наблюдение за проверку стратегии")
	}
	if o.StrategyID != "" {
		t.Fatalf("базовое наблюдение несёт стратегию %q", o.StrategyID)
	}
	if o.Target != "discord.gg" || o.Outcome != core.OutcomeOK {
		t.Fatalf("наблюдение = %+v", o)
	}
	// Источник полного веса: соединение инициировал движок, условия известны.
	if o.Source != store.SourceProbe {
		t.Fatalf("источник %v, ожидалась активная проба", o.Source)
	}

	// Базовая линия обязана переживать перезапуск так же, как остальные
	// наблюдения: иначе после перезапуска движок снова не знал бы, блокируется
	// ли цель, и снова не повышал бы никого (6.4).
	if len(arch.got) != 1 {
		t.Fatalf("журнал получил %d наблюдений, ожидалось одно", len(arch.got))
	}
	if arch.got[0].StrategyID != "" || arch.got[0].Target != "discord.gg" {
		t.Fatalf("запись журнала = %+v", arch.got[0])
	}
	if err := store.ValidateObservation(arch.got[0]); err != nil {
		t.Fatalf("запись журнала непригодна: %v", err)
	}
}

// TestProbeSinkRejectsInconsistentPlan — противоречивые записи плана
// отвергаются, а не проходят как базовая линия.
//
// Это вторая половина свойства выше, и без неё первая была бы опасной: признав
// пустую стратегию базовой линией безусловно, движок принял бы в эталон цели
// исходы чужих стратегий, и кредит перестали бы получать все сразу.
func TestProbeSinkRejectsInconsistentPlan(t *testing.T) {
	cases := []struct {
		name string
		item probe.PlanItem
	}{
		{
			name: "базовая проба со стратегией",
			item: probe.PlanItem{Target: "discord.gg", Baseline: true, StrategyID: core.StrategyID("aaaa")},
		},
		{
			name: "проба без стратегии и без признака базовой",
			item: probe.PlanItem{Target: "discord.gg"},
		},
		{
			name: "проба без цели",
			item: probe.PlanItem{Baseline: true},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			engine := &recordingSink{}
			sink := &probeSink{engine: engine, vantage: core.VantageID("v1"), log: discardLogger()}

			sink.ProbeDone(c.item, probe.Result{Outcome: core.OutcomeOK, Started: at})

			if len(engine.got) != 0 {
				t.Fatalf("принято наблюдение %+v: противоречивый план обязан отвергаться", engine.got[0])
			}
		})
	}
}
