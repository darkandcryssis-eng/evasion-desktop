package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/scoring"
	"github.com/fitting-1c/evasion/internal/store"
)

// TestProbeItemsAlwaysIncludeBaseline — план проб обязан содержать ровно одну
// базовую пробу на каждую цель радиуса.
//
// Без неё исходы остальных проб этой цели нельзя истолковать: движок не
// отличает «стратегия обошла DPI» от «цель и так не блокировалась». Проверяется
// «ровно одна», а не «хотя бы одна»: лишние базовые пробы жгут бюджет живых
// прогонов и отдают DPI сведения о поведении машины (5.8).
func TestProbeItemsAlwaysIncludeBaseline(t *testing.T) {
	s := splitStrategy(5)
	id := mustID(t, s)

	f := startEngine(t, Options{
		Targets:   []string{"youtube.com", "discord.gg"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusCandidate}},
	})

	items, err := f.engine.ProbeItems(ctxt(t))
	if err != nil {
		t.Fatalf("ProbeItems: %v", err)
	}

	baselines := make(map[string]int)
	for _, it := range items {
		if !it.Baseline {
			continue
		}
		baselines[it.Target]++

		// Базовая проба обязана быть пустой по стратегии со всех сторон:
		// частично заполненная запись исполнилась бы как проверка стратегии,
		// и в эталон цели попал бы исход десинка.
		if it.StrategyID != "" || it.Strategy != nil {
			t.Fatalf("базовая проба несёт стратегию: %+v", it)
		}
		if it.Reason != ProbeReasonBaseline {
			t.Fatalf("причина базовой пробы %q, ожидалась %q", it.Reason, ProbeReasonBaseline)
		}
	}

	for _, target := range []string{"youtube.com", "discord.gg"} {
		if baselines[target] != 1 {
			t.Fatalf("базовых проб по цели %s: %d, ожидалась ровно одна (план: %+v)",
				target, baselines[target], items)
		}
	}
}

// TestProbeItemsBaselineSurvivesEmptyPortfolio — базовая проба нужна и тогда,
// когда проверять больше нечего.
//
// Это не крайний случай, а нынешнее состояние проекта: рабочей стратегии у
// владельца нет вовсе. Без базовой пробы движок при пустом портфеле не ходил бы
// в сеть совсем и не узнал бы, что цель ожила сама, — то есть не отличил бы
// «обход не работает» от «блокировка снята».
func TestProbeItemsBaselineSurvivesEmptyPortfolio(t *testing.T) {
	f := startEngine(t, Options{Targets: []string{"youtube.com"}})

	items, err := f.engine.ProbeItems(ctxt(t))
	if err != nil {
		t.Fatalf("ProbeItems: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("план = %+v, при пустом портфеле ожидалась одна базовая проба", items)
	}
	if !items[0].Baseline || items[0].Target != "youtube.com" {
		t.Fatalf("запись = %+v, ожидалась базовая проба по youtube.com", items[0])
	}
}

// TestBaselineObservationValidation — пустая стратегия допустима только вместе
// с признаком Baseline.
//
// Смысл проверки не формальный. Наблюдение, потерявшее стратегию по дороге, —
// настоящий дефект, он в этом проекте уже случался с целью наблюдения. Если
// пустой идентификатор сам по себе признать базовой линией, такой дефект осел
// бы в эталоне: цель выглядела бы доступной по исходам чужих стратегий, и
// кредит перестали бы получать все стратегии сразу. Поэтому базовая линия
// заявляется явно, а несогласованное наблюдение отвергается и видно в status.
func TestBaselineObservationValidation(t *testing.T) {
	cases := []struct {
		name string
		obs  Observation
		ok   bool
	}{
		{
			name: "базовое наблюдение без стратегии принимается",
			obs:  Observation{Baseline: true, Target: target, Outcome: core.OutcomeFail, Source: store.SourceProbe, At: base},
			ok:   true,
		},
		{
			name: "базовое наблюдение со стратегией отвергается",
			obs:  Observation{Baseline: true, StrategyID: idA, Target: target, Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base},
			ok:   false,
		},
		{
			name: "обычное наблюдение без стратегии отвергается",
			obs:  Observation{Target: target, Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base},
			ok:   false,
		},
		{
			name: "базовое наблюдение без цели отвергается",
			obs:  Observation{Baseline: true, Outcome: core.OutcomeFail, Source: store.SourceProbe, At: base},
			ok:   false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.obs.validate(); (err == nil) != c.ok {
				t.Fatalf("validate = %v, ожидалась пригодность %v", err, c.ok)
			}
		})
	}
}

// TestEngineWithholdsCreditOnAvailableTarget — сквозной случай discord.gg.
//
// Самый важный тест этой правки, и написан он по настоящему измерению.
// Первая проба движка прошла рукопожатие к discord.gg со стратегией, и это
// выглядело первым положительным исходом в проекте. Но эта цель отвечает и без
// стратегии. Контур обязан не применять стратегию в таком случае: кредит
// принадлежит цели, а не десинку.
//
// Проверяются обе стороны одной обстановки, иначе тест был бы декоративным:
// на доступной цели стратегия не применяется, на заблокированной — применяется.
// Прогон при одной лишь первой половине прошёл бы и с движком, который не
// применяет ничего никогда.
func TestEngineWithholdsCreditOnAvailableTarget(t *testing.T) {
	s := splitStrategy(5)
	id := mustID(t, s)

	// Обе цели одинаковы во всём, кроме базовой линии: по одной цель отвечает
	// сама, по другой молчит. Так различие приписывается именно базовой линии,
	// а не какому-то другому предохранителю.
	const available, blocked = "discord.gg", "youtube.com"

	f := startEngine(t, Options{
		Targets:   []string{available, blocked},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusTesting}},
	})
	ctx := ctxt(t)

	for _, target := range []string{available, blocked} {
		for range 25 {
			f.engine.Observe(Observation{
				StrategyID: id, Target: target,
				Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base,
			})
		}
	}
	// Базовые пробы: discord.gg отвечает без стратегии, youtube.com — нет.
	for range 10 {
		f.engine.Observe(Observation{
			Baseline: true, Target: available,
			Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base,
		})
		f.engine.Observe(Observation{
			Baseline: true, Target: blocked,
			Outcome: core.OutcomeFail, Source: store.SourceProbe, At: base,
		})
	}

	if err := f.engine.Replan(ctx); err != nil {
		t.Fatalf("Replan: %v", err)
	}
	st, err := f.engine.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	byTarget := make(map[string]TargetStatus, len(st.Targets))
	for _, ts := range st.Targets {
		byTarget[ts.Target] = ts
	}

	// Доступная цель: стратегия не применена, и причина названа.
	if got := byTarget[available]; got.Active != "" {
		t.Fatalf("на доступной цели применена %q: успех принадлежит цели, а не стратегии", got.Active)
	}
	// Заблокированная цель: та же стратегия с теми же наблюдениями применена.
	if got := byTarget[blocked]; got.Active != id {
		t.Fatalf("на заблокированной цели действует %q, ожидалась %q (причина %q)",
			got.Active, id, got.Reason)
	}

	// Базовая линия обязана быть видна в состоянии: иначе отказ выглядит
	// необъяснимым — человек видит успешные пробы и неприменённую стратегию.
	ab := byTarget[available].Baseline
	if !ab.Known || ab.Successes != 10 {
		t.Fatalf("базовая линия доступной цели = %+v, ожидались 10 успехов", ab)
	}
	bb := byTarget[blocked].Baseline
	if !bb.Known || bb.Successes != 0 || bb.Observations != 10 {
		t.Fatalf("базовая линия заблокированной цели = %+v, ожидались 10 наблюдений без успехов", bb)
	}
	// Верхняя граница у мёртвой цели обязана быть заметно ниже, чем у живой:
	// именно её движок и сравнивает с границей стратегии.
	if bb.UpperPermille >= ab.UpperPermille {
		t.Fatalf("верхняя граница мёртвой цели %d не ниже живой %d",
			bb.UpperPermille, ab.UpperPermille)
	}
}

// TestBaselineDoesNotBecomeAppliedStrategy — базовая линия не может быть
// выбрана как стратегия даже на цели, где она успешнее всех.
//
// Проверка на уровне контура, в дополнение к той же проверке в scoring. Здесь
// важен итог: в снимке, который получает трафик, не должно появиться записи,
// «применяющей» пустую стратегию как доказанную. Базовая линия на доступной
// цели набирает лучшую оценку в таблице, и попади она в отбор, контур объявил
// бы её действующей.
func TestBaselineDoesNotBecomeAppliedStrategy(t *testing.T) {
	f := startEngine(t, Options{Targets: []string{"discord.gg"}})
	ctx := ctxt(t)

	// Только базовые наблюдения, и все успешные: в таблице оценок это лучшее,
	// что есть по цели.
	for range 30 {
		f.engine.Observe(Observation{
			Baseline: true, Target: "discord.gg",
			Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base,
		})
	}
	if err := f.engine.Replan(ctx); err != nil {
		t.Fatalf("Replan: %v", err)
	}

	st, err := f.engine.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Targets[0].Active != "" {
		t.Fatalf("действует %q: базовая линия не стратегия и применяться не может",
			st.Targets[0].Active)
	}
	if st.Targets[0].Trial != "" {
		t.Fatalf("на долю проверки поставлена %q: базовая линия не стратегия",
			st.Targets[0].Trial)
	}
	// Обстановка теста обязана быть той, что заявлена: базовая линия измерена
	// и успешна. Иначе тест прошёл бы просто потому, что наблюдений нет.
	if b := st.Targets[0].Baseline; !b.Known || b.Successes != 30 {
		t.Fatalf("базовая линия = %+v, ожидались 30 успехов", b)
	}
}

// TestBaselineKeyMatchesIngest — наблюдение базовой линии попадает ровно в тот
// ключ, по которому его потом ищет порог повышения.
//
// Шов неочевидный: контур кладёт наблюдение по scoring.Key с пустым
// идентификатором, а scoring ищет его через BaselineKey. Разойдясь, эти два
// места дали бы молчаливый отказ — базовая линия копилась бы в одном ключе, а
// проверялась в другом, и ни один кандидат никогда не повышался бы без всякой
// видимой причины.
func TestBaselineKeyMatchesIngest(t *testing.T) {
	f := startEngine(t, Options{Targets: []string{target}})

	f.engine.Observe(Observation{
		Baseline: true, Target: target,
		Outcome: core.OutcomeFail, Source: store.SourceProbe, At: base,
	})
	if err := f.engine.Replan(ctxt(t)); err != nil {
		t.Fatalf("Replan: %v", err)
	}

	st, err := f.engine.Status(ctxt(t))
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if b := st.Targets[0].Baseline; !b.Known || b.Observations != 1 {
		t.Fatalf("базовая линия = %+v, ожидалось одно определённое наблюдение; "+
			"ключ приёма расходится с ключом %+v", b, scoring.BaselineKey(target, vantage))
	}
}

// TestStatusFileRefreshesBetweenReplans — файл состояния обновляется по
// наблюдениям, а не только при пересчёте снимка.
//
// Написано по настоящей жалобе: владелец увидел `intake.accepted: 0` и
// `estimates: 0` сразу после семи выполненных проб. Наблюдения были приняты —
// контур разбирает их непрерывно, — а файл состояния писался только при
// пересчёте, то есть по умолчанию раз в минуту. Команда status читает файл, и
// человек делает единственный доступный ему вывод: движок не учится.
//
// Проверяется именно файл, а не Status через команду: команда спрашивает
// движок напрямую и была свежей всегда, поэтому дефект тестами и не ловился.
func TestStatusFileRefreshesBetweenReplans(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")

	f := startEngine(t, Options{
		Targets:    []string{target},
		StatusPath: path,
		// Пересчёта по таймеру нет вовсе: будь свежесть файла связана с
		// пересчётом, обновиться ему было бы нечем, и тест бы это поймал.
		Interval:       0,
		StatusInterval: 10 * time.Millisecond,
	})

	// Ждём первый снимок: контур считает его в своей горутине, и читать файл
	// раньше этого — гонка самого теста.
	if err := f.engine.Ready(ctxt(t)); err != nil {
		t.Fatalf("контур не дошёл до первого снимка: %v", err)
	}

	// Состояние на старте уже выложено (первый снимок), и наблюдений в нём
	// нет. Это и есть исходная точка жалобы.
	before, err := waitStatusFile(t, path)
	if err != nil {
		t.Fatalf("состояние не выложено при старте: %v", err)
	}
	if before.Intake.Accepted != 0 {
		t.Fatalf("на старте принято %d наблюдений, ожидалось ноль", before.Intake.Accepted)
	}

	for range 7 {
		if !f.engine.Observe(Observation{
			Baseline: true, Target: target,
			Outcome: core.OutcomeFail, Source: store.SourceProbe, At: base,
		}) {
			t.Fatal("наблюдение не принято")
		}
	}

	// Ждём именно появления чисел в ФАЙЛЕ, без единого пересчёта.
	deadline := time.Now().Add(2 * time.Second)
	var got Status
	for time.Now().Before(deadline) {
		got, err = ReadStatusFile(path)
		if err == nil && got.Intake.Accepted == 7 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("состояние не прочитано: %v", err)
	}
	if got.Intake.Accepted != 7 {
		t.Fatalf("в файле принято %d наблюдений, ожидалось 7: файл устаревает между пересчётами, "+
			"и status показывает нули после реально выполненных проб", got.Intake.Accepted)
	}
	if got.Intake.Estimates == 0 {
		t.Fatal("в файле нет оценок: наблюдение не стало знанием")
	}

	// Номер снимка не изменился: свежесть файла достигнута публикацией, а не
	// скрытым пересчётом. Иначе таймер состояния подменял бы период пересчёта
	// и обесценивал выдержку.
	if got.SnapshotRev != before.SnapshotRev {
		t.Fatalf("снимок сменился с №%d на №%d: публикация состояния не должна пересчитывать решения",
			before.SnapshotRev, got.SnapshotRev)
	}
	// И время сборки состояния обязано отличать «свежие данные» от «свежие
	// решения».
	if !got.UpdatedAt.After(before.UpdatedAt) && !got.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("время записи состояния уехало назад: было %s, стало %s",
			before.UpdatedAt, got.UpdatedAt)
	}
}

// waitStatusFile ждёт появления файла состояния и читает его.
//
// Ожидание нужно потому, что первый снимок публикуется горутиной контура, а не
// вызывающим: читать файл сразу после запуска — гонка теста, а не свойство
// движка.
func waitStatusFile(t *testing.T, path string) (Status, error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		var st Status
		st, err = ReadStatusFile(path)
		if err == nil {
			return st, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return Status{}, err
}

// TestStatusFileNotRewrittenWhenNothingChanges — в покое движок не трогает
// диск.
//
// Вторая половина свойства выше. Выкладывать состояние по таймеру безусловно
// означало бы писать файл каждые две секунды всю жизнь процесса — работу,
// которая никогда ничего не меняет. Проверяется по времени изменения файла.
func TestStatusFileNotRewrittenWhenNothingChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")

	startEngine(t, Options{
		Targets:        []string{target},
		StatusPath:     path,
		StatusInterval: 5 * time.Millisecond,
	})

	// Даём таймеру многократно сработать, ничего не наблюдая.
	var first os.FileInfo
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		fi, err := os.Stat(path)
		if err == nil {
			first = fi
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if first == nil {
		t.Fatal("состояние не выложено при старте")
	}

	time.Sleep(200 * time.Millisecond)
	second, err := os.Stat(path)
	if err != nil {
		t.Fatalf("состояние исчезло: %v", err)
	}
	if !second.ModTime().Equal(first.ModTime()) {
		t.Fatalf("файл перезаписан без изменений состояния: было %s, стало %s; "+
			"запись «на всякий случай» каждые несколько секунд — работа, которая ничего не меняет",
			first.ModTime(), second.ModTime())
	}
}

// TestRetryTransient — логика повторов обращения к файлу состояния.
//
// Проверяется на любой платформе намеренно: сама неполадка возможна только на
// Windows (там читатель блокирует замену файла, а открытие в момент замены
// даёт ошибку совместного доступа), но решение о том, сколько раз повторять и
// что считать временным, от платформы не зависит. Тот же приём, что с
// pickMinRTT и parseServiceQuery: платформенный дефект лечится чистой
// функцией, которую можно проверить где угодно.
func TestRetryTransient(t *testing.T) {
	transient := errors.New("файл занят")
	permanent := errors.New("каталога нет")
	isTransient := func(err error) bool { return errors.Is(err, transient) }

	t.Run("временная неудача пережидается", func(t *testing.T) {
		calls := 0
		err := retryTransient(5, 0, isTransient, func() error {
			calls++
			if calls < 3 {
				return transient
			}
			return nil
		})
		if err != nil {
			t.Fatalf("повторы не помогли: %v", err)
		}
		if calls != 3 {
			t.Fatalf("попыток %d, ожидалось 3", calls)
		}
	})

	t.Run("постоянная неудача не повторяется", func(t *testing.T) {
		// Повторять настоящую неполадку — значит задерживать ответ и прятать
		// причину. Отсутствие каталога само не пройдёт.
		calls := 0
		err := retryTransient(5, 0, isTransient, func() error {
			calls++
			return permanent
		})
		if !errors.Is(err, permanent) {
			t.Fatalf("ошибка = %v, ожидалась постоянная", err)
		}
		if calls != 1 {
			t.Fatalf("попыток %d, ожидалась одна: постоянную неудачу повторять незачем", calls)
		}
	})

	t.Run("успех с первого раза не повторяется", func(t *testing.T) {
		calls := 0
		if err := retryTransient(5, 0, isTransient, func() error { calls++; return nil }); err != nil {
			t.Fatalf("ошибка на успешной попытке: %v", err)
		}
		if calls != 1 {
			t.Fatalf("попыток %d, ожидалась одна", calls)
		}
	})

	t.Run("попытки кончаются, причина сохраняется", func(t *testing.T) {
		// Подменять настоящую причину словами «не удалось за N попыток»
		// нельзя: потребителю нужна именно причина.
		calls := 0
		err := retryTransient(3, 0, isTransient, func() error { calls++; return transient })
		if !errors.Is(err, transient) {
			t.Fatalf("ошибка = %v, ожидалась последняя настоящая", err)
		}
		if calls != 3 {
			t.Fatalf("попыток %d, ожидалось 3", calls)
		}
	})
}

// TestStatusFileReadsAreNeverTorn — читатель видит состояние целиком: либо
// прежнее, либо новое, но никогда половину.
//
// # Почему проверяется именно это, а не «запись всегда удаётся»
//
// Первая версия теста держала четырёх читателей в плотном цикле без пауз и
// требовала, чтобы каждая запись удалась. На Windows она падала с «Access is
// denied», и **неправ был тест, а не движок**: замена файла там отказывает,
// пока файл открыт, и непрерывно читающие горутины не оставляют замене ни
// одного промежутка. Такой нагрузки не создаёт ни один настоящий потребитель —
// команда status открывает файл на микросекунды раз в несколько секунд.
//
// Попытка исправить это со стороны продукта (открывать файл с флагом
// FILE_SHARE_DELETE, чтобы не мешать замене) прогоном владельца **опровергнута**:
// MoveFileEx отказывает независимо от флагов совместного доступа у читателя.
// Код с опровергнутым обоснованием убран.
//
// Поэтому тест проверяет то, что движок действительно обещает:
//
//   - целостность: прочитанное состояние разбирается и несёт номер снимка;
//   - продвижение: читатели видят РАЗНЫЕ номера, то есть записи доходят;
//   - отсутствие пропажи: имя файла всегда указывает на какое-то состояние,
//     «файла нет» посреди замены не бывает.
//
// Неудача отдельной записи под нагрузкой читателей ошибкой не считается: это
// свойство Windows, и ответ движка на него — повторить на следующем тике
// (см. publishStatus). Страдает свежесть на пару секунд, не данные.
func TestStatusFileReadsAreNeverTorn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")

	if err := WriteStatusFile(path, Status{Vantage: vantage, SnapshotRev: 1}); err != nil {
		t.Fatalf("первая запись: %v", err)
	}

	var (
		wg       sync.WaitGroup
		stop     = make(chan struct{})
		mu       sync.Mutex
		readErr  error
		seenRevs = map[uint64]bool{}
		reads    int
	)

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}

				st, err := ReadStatusFile(path)

				mu.Lock()
				switch {
				case err != nil:
					// Пропажа файла — настоящая неполадка: замена обязана
					// быть атомарной, и имя всегда указывает на состояние.
					if readErr == nil && os.IsNotExist(errUnwrapAll(err)) {
						readErr = fmt.Errorf("файл состояния пропал посреди замены: %w", err)
					}
				case st.SnapshotRev == 0:
					if readErr == nil {
						readErr = errors.New("прочитано состояние без номера снимка: файл виден не целиком")
					}
				default:
					seenRevs[st.SnapshotRev] = true
					reads++
				}
				mu.Unlock()

				// Пауза делает нагрузку похожей на настоящую: status читают
				// изредка, а не в плотном цикле. Без неё тест проверял бы
				// недостижимое свойство (см. пояснение выше).
				time.Sleep(time.Millisecond)
			}
		}()
	}

	for rev := uint64(2); rev <= 40; rev++ {
		// Неудача записи под нагрузкой не провал: движок повторит на
		// следующем тике. Проверяется не она, а то, что видят читатели.
		_ = WriteStatusFile(path, Status{Vantage: vantage, SnapshotRev: rev})
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if readErr != nil {
		t.Fatalf("чтение состояния не выдержало перезаписи: %v", readErr)
	}
	if reads == 0 {
		t.Fatal("ни одного успешного чтения: тест ничего не проверил")
	}
	// Продвижение обязательно: иначе тест прошёл бы и при писателе, который
	// не записал ничего после первого снимка.
	if len(seenRevs) < 2 {
		t.Fatalf("читатели увидели только номера %v: записи не доходят, и тест ничего не доказывает", seenRevs)
	}
}

// errUnwrapAll разворачивает ошибку до исходной — так же, как это делает
// команда status, чтобы отличить «файла нет» от прочих неудач.
func errUnwrapAll(err error) error {
	for {
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return err
		}
		next := u.Unwrap()
		if next == nil {
			return err
		}
		err = next
	}
}

// TestReadStatusFileMissingStaysRecognizable — отсутствие файла остаётся
// опознаваемым как «файла нет».
//
// На этом различении стоит команда status: она отвечает «движок не запущен или
// запущен с другим --state-dir» вместо невнятной ошибки чтения. Проверка нужна
// потому, что путь чтения состояния был заменён ради Windows (readFileShared с
// флагом FILE_SHARE_DELETE), и своя обёртка над ошибкой легко теряет признак,
// по которому os.IsNotExist её узнаёт. Потеря была бы тихой: команда начала бы
// печатать «процесс не может получить доступ» вместо понятного объяснения.
func TestReadStatusFileMissingStaysRecognizable(t *testing.T) {
	_, err := ReadStatusFile(filepath.Join(t.TempDir(), "нет-такого.json"))
	if err == nil {
		t.Fatal("чтение несуществующего файла обязано дать ошибку")
	}
	// Так же, как это делает cmd/evasion: разворачиваем до исходной ошибки.
	inner := err
	for {
		u, ok := inner.(interface{ Unwrap() error })
		if !ok {
			break
		}
		next := u.Unwrap()
		if next == nil {
			break
		}
		inner = next
	}
	if !os.IsNotExist(inner) {
		t.Fatalf("ошибка %v (%T) не опознаётся как «файла нет»: "+
			"команда status перестанет объяснять, что движок не запущен", inner, inner)
	}
}

// TestPortfolioCarriesFreshness — у стратегии в портфеле видна свежесть и
// объём наблюдений.
//
// Требование 5.9: «состояние портфеля: сколько стратегий, в каких статусах, их
// свежесть». Без свежести doctor не сможет выполнить отдельное требование того
// же пункта — сказать прямо, что после перерыва оценкам нельзя доверять, — и
// показал бы затухшие оценки как действующие.
//
// Отдельно проверяется, что число целей идёт рядом с числом наблюдений: сумма
// по целям без этого вводит в заблуждение, потому что порог повышения (5.5)
// задан на пару «цель × точка наблюдения», а не на стратегию.
func TestPortfolioCarriesFreshness(t *testing.T) {
	s := splitStrategy(5)
	id := mustID(t, s)

	f := startEngine(t, Options{
		Targets:   []string{"youtube.com", "discord.gg"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusTesting}},
	})
	ctx := ctxt(t)

	// Наблюдения по двум целям и в разное время: свежесть обязана взять
	// позднейшее, а объём — сумму.
	early := base
	late := base.Add(time.Hour)
	for range 3 {
		f.engine.Observe(Observation{
			StrategyID: id, Target: "youtube.com",
			Outcome: core.OutcomeFail, Source: store.SourceProbe, At: early,
		})
	}
	for range 2 {
		f.engine.Observe(Observation{
			StrategyID: id, Target: "discord.gg",
			Outcome: core.OutcomeOK, Source: store.SourceProbe, At: late,
		})
	}
	if err := f.engine.Replan(ctx); err != nil {
		t.Fatalf("Replan: %v", err)
	}

	st, err := f.engine.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.Portfolio) != 1 {
		t.Fatalf("портфель = %+v, ожидалась одна стратегия", st.Portfolio)
	}
	h := st.Portfolio[0]

	if h.Observations != 5 {
		t.Fatalf("наблюдений %d, ожидалось 5 (сумма по двум целям)", h.Observations)
	}
	if h.Targets != 2 {
		t.Fatalf("целей %d, ожидалось 2: без этого числа сумма наблюдений вводит в заблуждение", h.Targets)
	}
	if !h.LastObservation.Equal(late) {
		t.Fatalf("свежесть = %s, ожидалось позднейшее наблюдение %s", h.LastObservation, late)
	}
}

// TestPortfolioFreshnessAbsentMeansNoObservations — у стратегии без наблюдений
// свежесть пуста, а не подставлена текущим временем.
//
// Это то же правило о нулевых значениях: «наблюдений нет вовсе» и «наблюдения
// давние» — разные состояния. Подставь сюда время сборки состояния, и
// только что добавленная стратегия выглядела бы свежепроверенной, а doctor
// никогда не предложил бы перевалидацию.
func TestPortfolioFreshnessAbsentMeansNoObservations(t *testing.T) {
	s := splitStrategy(7)
	id := mustID(t, s)

	f := startEngine(t, Options{
		Targets:   []string{target},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusCandidate}},
	})

	st, err := f.engine.Status(ctxt(t))
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	h := st.Portfolio[0]
	if !h.LastObservation.IsZero() {
		t.Fatalf("свежесть = %s, ожидалось нулевое время: наблюдений о стратегии нет", h.LastObservation)
	}
	if h.Observations != 0 || h.Targets != 0 {
		t.Fatalf("наблюдений %d по %d целям, ожидались нули", h.Observations, h.Targets)
	}
}

// Свойства самой сводки наблюдений (scoring.Evidence) проверяются в пакете
// scoring, рядом с кодом: мутация в internal/scoring/table.go гоняет тесты
// того же пакета, и тест, лежащий здесь, она просто не находила — проходил
// вхолостую и выглядел декоративным. Батарея это и показала.
