package policy

import (
	"strings"
	"testing"

	"github.com/fitting-1c/evasion/internal/proxy"
)

// TestTrialSplitsTrafficByShare проверяет главное свойство ступенчатого
// допущения (5.1): проверяемая стратегия получает заданную долю соединений, а
// не заданную долю хостов.
//
// Проверка статистическая, границы широкие: при 20 000 жребиев и доле 50%
// отклонение в 1000 соединений — больше десяти стандартных отклонений, то
// есть случайно такое не выпадает. Узкие границы сделали бы тест капризным, а
// капризный тест в чужом прогоне выглядит поломкой окружения.
func TestTrialSplitsTrafficByShare(t *testing.T) {
	active := splitStrategy(5)
	trial := splitStrategy(77)

	snap := mustSnapshot(t, Entry{
		Domain:        "youtube.com",
		Strategy:      active,
		Trial:         trial,
		TrialPermille: 500,
	})

	const runs = 20000
	var trials, actives int
	for range runs {
		sel, ok := snap.Lookup("www.youtube.com", "")
		if !ok {
			t.Fatal("имя должно попадать в радиус")
		}
		switch sel.Strategy {
		case trial:
			if !sel.Trial {
				t.Fatal("выбор проверяемой стратегии обязан быть помечен как проверочный")
			}
			trials++
		case active:
			if sel.Trial {
				t.Fatal("выбор действующей стратегии не должен быть помечен проверочным")
			}
			actives++
		default:
			t.Fatalf("незнакомая стратегия в выборе: %v", sel.ID)
		}
	}

	if trials+actives != runs {
		t.Fatalf("учтено %d решений из %d", trials+actives, runs)
	}
	if trials < runs/2-1000 || trials > runs/2+1000 {
		t.Fatalf("доля проверочных решений = %d из %d, ожидалась около половины", trials, runs)
	}
}

// TestTrialShareBoundaries: полная доля отдаёт всё проверяемой, отсутствие
// доли — ничего. Эти два случая точные, а не статистические.
func TestTrialShareBoundaries(t *testing.T) {
	active := splitStrategy(5)
	trial := splitStrategy(77)

	t.Run("доля 1000 промилле", func(t *testing.T) {
		snap := mustSnapshot(t, Entry{
			Domain: "youtube.com", Strategy: active, Trial: trial, TrialPermille: 1000,
		})
		for range 100 {
			sel, _ := snap.Lookup("youtube.com", "")
			if sel.Strategy != trial || !sel.Trial {
				t.Fatal("при полной доле все соединения должны идти под проверяемую стратегию")
			}
		}
	})

	t.Run("проверки нет", func(t *testing.T) {
		snap := mustSnapshot(t, Entry{Domain: "youtube.com", Strategy: active})
		for range 100 {
			sel, _ := snap.Lookup("youtube.com", "")
			if sel.Strategy != active || sel.Trial {
				t.Fatal("без проверяемой стратегии все соединения идут под действующую")
			}
		}
	})
}

// TestTrialWithoutActiveStrategy — обычное состояние цели, на которой рабочей
// стратегии ещё нет, а кандидат уже проверяется: доля идёт под кандидата,
// остальное — прозрачным пропуском.
func TestTrialWithoutActiveStrategy(t *testing.T) {
	trial := splitStrategy(77)
	snap := mustSnapshot(t, Entry{Domain: "youtube.com", Trial: trial, TrialPermille: 1000})

	sel, ok := snap.Lookup("youtube.com", "")
	if !ok {
		t.Fatal("запись обязана считаться попаданием")
	}
	if sel.Strategy != trial || !sel.Trial {
		t.Fatal("при полной доле соединение должно идти под проверяемую стратегию")
	}

	// И обратный случай: доля нулевая — значит запись-исключение.
	none := mustSnapshot(t, Entry{Domain: "youtube.com"})
	if sel, ok := none.Lookup("youtube.com", ""); !ok || sel.Strategy != nil {
		t.Fatal("без стратегий запись должна быть исключением")
	}
}

// TestTrialInconsistentRejected: молча бездействующая настройка запрещена —
// доля без стратегии ничего не проверяет, стратегия без доли не получает ни
// одного соединения.
func TestTrialInconsistentRejected(t *testing.T) {
	s := splitStrategy(5)
	trial := splitStrategy(77)

	for _, tc := range []struct {
		name  string
		entry Entry
	}{
		{"доля без стратегии", Entry{Domain: "a.com", Strategy: s, TrialPermille: 50}},
		{"стратегия без доли", Entry{Domain: "a.com", Strategy: s, Trial: trial}},
		{"нулевая доля при стратегии", Entry{Domain: "a.com", Strategy: s, Trial: trial, TrialPermille: 0}},
		{"отрицательная доля", Entry{Domain: "a.com", Strategy: s, Trial: trial, TrialPermille: -1}},
		{"доля больше 1000", Entry{Domain: "a.com", Strategy: s, Trial: trial, TrialPermille: 1001}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSnapshot(testVantage, 1, []Entry{tc.entry}); err == nil {
				t.Fatal("несогласованная ступень проверки должна быть отвергнута")
			}
		})
	}
}

// TestTrialSameAsActiveRejected: делить трафик между стратегией и ею же
// бессмысленно, и такая запись означает дефект в контуре управления.
func TestTrialSameAsActiveRejected(t *testing.T) {
	s := splitStrategy(5)
	// Разные указатели, одно содержимое — идентификатор у них один и тот же.
	same := splitStrategy(5)

	_, err := NewSnapshot(testVantage, 1, []Entry{{
		Domain: "youtube.com", Strategy: s, Trial: same, TrialPermille: 50,
	}})
	if err == nil {
		t.Fatal("совпадение проверяемой и действующей стратегии должно быть отвергнуто")
	}
	if !strings.Contains(err.Error(), "совпадает") {
		t.Fatalf("ошибка должна называть причину, получено: %v", err)
	}
}

// TestTrialSelectionCarriesOwnID: телеметрия обязана получить идентификатор
// именно той стратегии, которая применилась, иначе исход проверочного
// соединения приписался бы действующей.
func TestTrialSelectionCarriesOwnID(t *testing.T) {
	active := splitStrategy(5)
	trial := splitStrategy(77)
	snap := mustSnapshot(t, Entry{
		Domain: "youtube.com", Strategy: active, Trial: trial, TrialPermille: 1000,
	})

	sel, _ := snap.Lookup("youtube.com", "")
	activeID := mustSnapshot(t, Entry{Domain: "x.com", Strategy: active}).Records()[0].Active
	if sel.ID == activeID {
		t.Fatal("проверочное соединение получило идентификатор действующей стратегии")
	}
}

func TestSnapshotRecordsReportTrial(t *testing.T) {
	active := splitStrategy(5)
	trial := splitStrategy(77)
	snap := mustSnapshot(t,
		Entry{Domain: "youtube.com", Strategy: active, Trial: trial, TrialPermille: 50},
		Entry{Domain: "discord.com", Strategy: active},
	)

	recs := snap.Records()
	if len(recs) != 2 {
		t.Fatalf("записей = %d, ожидалось 2", len(recs))
	}
	// Порядок отсортирован: discord.com первым.
	if recs[0].Domain != "discord.com" || recs[1].Domain != "youtube.com" {
		t.Fatalf("порядок = %q, %q, ожидался отсортированный", recs[0].Domain, recs[1].Domain)
	}
	if recs[0].Trial != "" || recs[0].TrialPermille != 0 {
		t.Fatal("у записи без проверки не должно быть ни проверяемой стратегии, ни доли")
	}
	if recs[1].Trial == "" || recs[1].TrialPermille != 50 {
		t.Fatalf("запись с проверкой = %+v, ожидались непустой trial и доля 50", recs[1])
	}
	if recs[1].Active == recs[1].Trial {
		t.Fatal("действующая и проверяемая стратегии не должны совпадать")
	}
}

// TestTrialTableSelectZeroAllocations: жребий не должен стоить аллокаций —
// он выполняется на каждом соединении (4.2, правило 1).
func TestTrialTableSelectZeroAllocations(t *testing.T) {
	snap := mustSnapshot(t, Entry{
		Domain:        "youtube.com",
		Strategy:      splitStrategy(5),
		Trial:         splitStrategy(77),
		TrialPermille: 500,
	})
	tab := NewTable()
	tab.Install(snap)
	meta := proxy.ConnMeta{Host: "www.youtube.com", SNI: "www.youtube.com", Port: 443, IsClientHello: true}

	avg := testing.AllocsPerRun(1000, func() {
		if sel := tab.Select(meta); sel.Strategy == nil {
			t.Fatal("ожидалось попадание")
		}
	})
	if avg != 0 {
		t.Fatalf("аллокаций на решение с жребием = %v, требуется 0", avg)
	}
}

func BenchmarkSelectWithTrial(b *testing.B) {
	snap, err := NewSnapshot(testVantage, 1, []Entry{{
		Domain:        "youtube.com",
		Strategy:      splitStrategy(5),
		Trial:         splitStrategy(77),
		TrialPermille: 50,
	}})
	if err != nil {
		b.Fatalf("NewSnapshot: %v", err)
	}
	tab := NewTable()
	tab.Install(snap)
	meta := proxy.ConnMeta{Host: "www.youtube.com", SNI: "www.youtube.com", Port: 443, IsClientHello: true}
	for b.Loop() {
		if sel := tab.Select(meta); sel.Strategy == nil {
			b.Fatal("ожидалось попадание")
		}
	}
}

// TestSelectionCarriesRadiusTarget закрепляет связку policy с учётом исходов:
// выбор обязан называть цель радиуса, а не имя соединения.
//
// Без этого исход соединения к "www.youtube.com" пришлось бы относить к
// "www.youtube.com", то есть к другой четвёрке «стратегия × цель × точка
// наблюдения × время» (6.1). Решения принимаются по цели радиуса
// ("youtube.com"), и такие наблюдения они бы просто не увидели: автопилот
// учился бы вечно и ничего не узнавал.
func TestSelectionCarriesRadiusTarget(t *testing.T) {
	active := splitStrategy(5)
	trial := splitStrategy(77)

	snap := mustSnapshot(t,
		Entry{Domain: "youtube.com", Strategy: active, Trial: trial, TrialPermille: 1000},
		Entry{Domain: "discord.com", Strategy: active},
		Entry{Domain: "api.youtube.com"},
	)

	for _, tc := range []struct {
		name   string
		host   string
		sni    string
		target string
	}{
		{"поддомен относится к записи радиуса", "www.youtube.com", "", "youtube.com"},
		{"сама цель", "youtube.com", "", "youtube.com"},
		{"глубокий поддомен", "a.b.www.youtube.com", "", "youtube.com"},
		{"совпадение по SNI", "front.example.net", "m.youtube.com", "youtube.com"},
		{"другая цель радиуса", "gw.discord.com", "", "discord.com"},
		{"более точная запись", "api.youtube.com", "", "api.youtube.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sel, ok := snap.Lookup(tc.host, tc.sni)
			if !ok {
				t.Fatalf("имя %q должно попадать в радиус", tc.host)
			}
			if sel.Target != tc.target {
				t.Fatalf("цель выбора = %q, ожидалась %q", sel.Target, tc.target)
			}
		})
	}

	// Пустому выбору цель тоже нужна: «к этой цели не применялось ничего» —
	// наблюдение, и отнести его надо к цели.
	sel, ok := snap.Lookup("api.youtube.com", "")
	if !ok || sel.Strategy != nil {
		t.Fatal("ожидалась запись-исключение")
	}
	if sel.Target != "api.youtube.com" {
		t.Fatalf("цель пустого выбора = %q, ожидалась api.youtube.com", sel.Target)
	}

	// Промах цели не даёт: относить наблюдение некуда, и выдумывать нельзя.
	if sel, ok := snap.Lookup("example.org", ""); ok || sel.Target != "" {
		t.Fatalf("промах не должен называть цель, получено %q", sel.Target)
	}
}
