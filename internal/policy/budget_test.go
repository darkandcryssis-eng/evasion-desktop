package policy

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/proxy"
)

// decisionBudget — бюджет на одно решение по ClientHello (8.1). Решение
// принимается на каждом соединении, поэтому превышение здесь оплачивает
// пользователь при каждом открытии.
const decisionBudget = 10 * time.Microsecond

// benchTable собирает таблицу из extra записей плюс целевая, чтобы можно было
// показать: стоимость решения от размера таблицы не зависит.
func benchTable(tb testing.TB, extra int) *Table {
	tb.Helper()
	entries := make([]Entry, 0, extra+2)
	entries = append(entries,
		Entry{Domain: "youtube.com", Strategy: splitStrategy(5)},
		Entry{Domain: "api.youtube.com"},
	)
	for i := range extra {
		entries = append(entries, Entry{Domain: fmt.Sprintf("host%d.example%d.net", i, i), Strategy: splitStrategy(i % 64)})
	}
	snap, err := NewSnapshot(testVantage, 1, entries)
	if err != nil {
		tb.Fatalf("NewSnapshot: %v", err)
	}
	tab := NewTable()
	tab.Install(snap)
	return tab
}

// TestSelectZeroAllocations подтверждает нулевой бюджет аллокаций на горячем
// пути (8.1). Проверяются все ветви, в каждой из которых аллокация могла бы
// возникнуть: приведение регистра, обход суффиксов до корня при промахе,
// сопоставление по SNI и отказ по адресу.
func TestSelectZeroAllocations(t *testing.T) {
	tab := benchTable(t, 256)
	empty := NewTable()

	for _, tc := range []struct {
		name string
		tab  *Table
		meta proxy.ConnMeta
	}{
		{"попадание по host", tab, proxy.ConnMeta{Host: "www.youtube.com", Port: 443, IsClientHello: true}},
		{"попадание по SNI", tab, proxy.ConnMeta{Host: "front.example.net", SNI: "www.youtube.com", IsClientHello: true}},
		{"заглавные буквы", tab, proxy.ConnMeta{Host: "WWW.YouTube.COM", SNI: "WWW.YouTube.COM", IsClientHello: true}},
		{"завершающая точка", tab, proxy.ConnMeta{Host: "www.youtube.com.", IsClientHello: true}},
		{"исключение", tab, proxy.ConnMeta{Host: "v1.api.youtube.com", IsClientHello: true}},
		{"промах до корня", tab, proxy.ConnMeta{Host: "a.b.c.d.example.org", SNI: "a.b.c.d.example.org", IsClientHello: true}},
		{"адрес вместо имени", tab, proxy.ConnMeta{Host: "142.250.185.78", IsClientHello: true}},
		{"имя длиннее допустимого", tab, proxy.ConnMeta{Host: longName(300)}},
		{"таблица без снимка", empty, proxy.ConnMeta{Host: "www.youtube.com", SNI: "www.youtube.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			avg := testing.AllocsPerRun(1000, func() {
				_ = tc.tab.Select(tc.meta)
			})
			if avg != 0 {
				t.Fatalf("аллокаций на решение = %v, требуется 0", avg)
			}
		})
	}
}

// minWindow — окно измерения, ниже которого результату верить нельзя.
// maxIters — предел повторов, чтобы тест не крутился вечно на медленной
// машине.
const (
	minWindow = 50 * time.Millisecond
	maxIters  = 1 << 24
)

// perDecision превращает измеренное окно в стоимость одного решения — или
// отказывается это делать, если измерение не состоялось.
//
// Вынесено в чистую функцию намеренно. Опасный случай здесь — нулевое окно:
// оно означает «не измерено», а не «бесконечно быстро», и принять его за
// успех нельзя (на этих граблях проект уже стоял — признак
// ThroughputMeasured). Но воспроизводится он только там, где разрешение
// таймера грубое, то есть на Windows, а проверяться обязан на любой машине.
// Приём тот же, что с pickMinRTT: платформенно-зависимую логику превращаем в
// функцию, которую можно проверить где угодно.
// Три отказа измерения различены сигнальными ошибками, а не одним общим
// текстом. Различать их стоит потому, что лечатся они по-разному: нулевое
// окно означает, что мерить вообще не получилось, короткое — что повторов
// мало для этого таймера, а отсутствие повторов — ошибку в самом тесте.
// Нулевое окно проверяется первым и не сливается с коротким: ноль — это «не
// измерено», и сказать об этом человеку надо именно так.
var (
	errNoIterations      = errors.New("повторов не было: измерение не состоялось")
	errWindowNotMeasured = errors.New("окно измерения нулевое: длительность не измерена, а не равна нулю")
	errWindowTooShort    = errors.New("окно короче требуемого: разрешения таймера не хватает")
)

func perDecision(elapsed time.Duration, iters int, min time.Duration) (time.Duration, error) {
	switch {
	case iters <= 0:
		return 0, fmt.Errorf("%w (повторов %d)", errNoIterations, iters)
	case elapsed <= 0:
		return 0, fmt.Errorf("%w (повторов %d)", errWindowNotMeasured, iters)
	case elapsed < min:
		return 0, fmt.Errorf("%w (окно %v, требуется %v, повторов %d)", errWindowTooShort, elapsed, min, iters)
	}
	return elapsed / time.Duration(iters), nil
}

// TestPerDecisionRejectsUnmeasuredWindow проверяет разбор измерения на любой
// платформе, включая случай грубого таймера, который на Linux не наступает.
func TestPerDecisionRejectsUnmeasuredWindow(t *testing.T) {
	// Нулевое окно — отдельный диагноз, а не разновидность короткого:
	// «не измерено» и «мало повторов» лечатся по-разному.
	if _, err := perDecision(0, 1<<20, minWindow); !errors.Is(err, errWindowNotMeasured) {
		t.Fatalf("ошибка = %v, ожидалась errWindowNotMeasured", err)
	}
	if _, err := perDecision(time.Millisecond, 1<<20, minWindow); !errors.Is(err, errWindowTooShort) {
		t.Fatalf("ошибка = %v, ожидалась errWindowTooShort", err)
	}
	if _, err := perDecision(100*time.Millisecond, 0, minWindow); !errors.Is(err, errNoIterations) {
		t.Fatalf("ошибка = %v, ожидалась errNoIterations", err)
	}
	per, err := perDecision(100*time.Millisecond, 1_000_000, minWindow)
	if err != nil {
		t.Fatalf("годное измерение отвергнуто: %v", err)
	}
	if per != 100*time.Nanosecond {
		t.Fatalf("стоимость решения = %v, ожидалось 100ns", per)
	}
}

// TestSelectWithinBudget измеряет среднее время решения и требует, чтобы оно
// укладывалось в бюджет — на малой и на большой таблице, потому что таблицу
// наполняет автопилот и её размер нам неподвластен.
//
// Окно измерения набирается до осмысленной длительности, а не берётся наугад:
// короткое окно на грубом таймере дало бы ноль, а ноль здесь не результат
// (см. perDecision).
func TestSelectWithinBudget(t *testing.T) {

	for _, tc := range []struct {
		name  string
		extra int
	}{
		{"малая таблица", 2},
		{"таблица на 10000 записей", 10000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tab := benchTable(t, tc.extra)
			meta := proxy.ConnMeta{Host: "www.youtube.com", SNI: "www.youtube.com", Port: 443, IsClientHello: true}

			per, iters, elapsed, err := measurePerDecision(tab, meta)
			if err != nil {
				t.Fatalf("измерение не состоялось: %v", err)
			}
			if per > decisionBudget {
				t.Fatalf("решение занимает %v при бюджете %v (%d повторов за %v)", per, decisionBudget, iters, elapsed)
			}
			t.Logf("решение: %v при бюджете %v (%d повторов за %v)", per, decisionBudget, iters, elapsed)
		})
	}
}

// measurePerDecision измеряет среднюю стоимость решения, наращивая число
// повторов до осмысленного окна. Возвращает стоимость, число повторов и само
// окно — последние два нужны для отчёта: «35 нс» без указания, на чём
// измерено, доверия не заслуживает.
func measurePerDecision(tab *Table, meta proxy.ConnMeta) (time.Duration, int, time.Duration, error) {
	iters := 1 << 16
	var elapsed time.Duration
	for {
		start := time.Now()
		for range iters {
			if sel := tab.Select(meta); sel.Strategy == nil {
				return 0, iters, 0, errors.New("измеряется горячий путь с попаданием, а попадания нет")
			}
		}
		elapsed = time.Since(start)
		if elapsed >= minWindow || iters >= maxIters {
			break
		}
		iters *= 2
	}
	per, err := perDecision(elapsed, iters, minWindow)
	return per, iters, elapsed, err
}

// clockGranularity измеряет наименьший различимый шаг монотонных часов.
//
// Нужна потому, что шаг этот платформенный и различается на порядки: там, где
// одна платформа даёт наносекунды, другая отдаёт сотни микросекунд или
// миллисекунды. Измерение хвоста обязано строиться на измеренном шаге, а не на
// предположении о нём: именно это предположение и сломало первую версию теста
// на машине владельца.
//
// Берётся наименьшая ненулевая разница из нескольких попыток: случайная
// задержка может удлинить отдельный замер, но не сократить его ниже шага часов.
func clockGranularity() time.Duration {
	best := time.Duration(math.MaxInt64)
	for range 32 {
		start := time.Now()
		var d time.Duration
		for d == 0 {
			d = time.Since(start)
		}
		if d < best {
			best = d
		}
	}
	return best
}

// tailBudgetEnv — переменная окружения, задающая время на измерение хвоста.
//
// Существует для платформ с грубыми часами. Там блок вызовов приходится делать
// длинным, чтобы он вообще измерялся, и на p99 нужны десятки секунд. Тратить их
// в обычном прогоне незачем, но и объявлять бюджет 8.1 непроверенным навсегда
// нельзя — владелец включает длинное измерение, когда хочет его получить.
const tailBudgetEnv = "EVASION_TAIL_BUDGET"

// Параметры измерения хвоста.
const (
	// defaultTailBudget — сколько времени тест тратит на хвост по умолчанию.
	defaultTailBudget = 2 * time.Second
	// blockTicks — во сколько шагов часов должен укладываться один блок.
	// Десять шагов дают погрешность блока около десяти процентов: меньше
	// смысла нет, больше — дороже.
	blockTicks = 10
	// minTailBlocks — сколько блоков нужно, чтобы говорить про p99. На сотне
	// блоков девяносто девятый процентиль определяется одним-двумя
	// значениями, и называть это p99 было бы преувеличением.
	minTailBlocks = 200
	// maxTailBlocks — предел числа блоков. На платформе с тонкими часами
	// блоки выходят короткими, и в отведённое время их укладываются миллионы;
	// пользы от этого нет — для p99 хватает десятков тысяч, — а время прогона
	// тестов дорого.
	maxTailBlocks = 50_000
)

// TestSelectTailWithinBudget проверяет бюджет так, как он задан в 8.1: по p99,
// а не по среднему. Среднее скрывает хвост, а оплачивает пользователь именно
// хвост — соединение, которому не повезло.
//
// Честная оговорка о методе. Одно решение занимает десятки наносекунд, то есть
// меньше шага монотонных часов на любой платформе. Измерить отдельный вызов
// нельзя: цена отсчёта больше измеряемого. Поэтому измеряются блоки вызовов, и
// p99 считается по средним внутри блока. Это p99 блоков, а не p99 вызовов, и
// заменой ему он не является: одиночный выброс внутри блока размывается по его
// среднему.
//
// Размер блока выводится из измеренного шага часов, а не задаётся числом.
// Первая версия теста брала 64 вызова на блок и падала на машине владельца:
// там шаг часов оказался много больше, чем блок, и все блоки измерялись нулём.
// Предохранитель тогда отказался объявить «0 нс, бюджет выдержан» — и
// правильно, но считать это измерением было нельзя.
//
// Если на платформе шаг часов настолько грубый, что p99 за отведённое время не
// набирается, тест пропускается с замерами, а не притворяется выполненным
// (8.1: «если недостижимы — сообщить с замерами», 9.3). Длинное измерение
// включается переменной EVASION_TAIL_BUDGET, например 60s.
func TestSelectTailWithinBudget(t *testing.T) {
	tab := benchTable(t, 1000)
	meta := proxy.ConnMeta{Host: "www.youtube.com", SNI: "www.youtube.com", Port: 443, IsClientHello: true}

	per, _, _, err := measurePerDecision(tab, meta)
	if err != nil {
		t.Fatalf("измерение не состоялось: %v", err)
	}
	grain := clockGranularity()

	wall := defaultTailBudget
	if v := os.Getenv(tailBudgetEnv); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("%s=%q: %v", tailBudgetEnv, v, err)
		}
		wall = parsed
	}

	// Блок должен длиться не меньше blockTicks шагов часов, иначе его
	// длительность — шум, а не измерение.
	blockSize := int(int64(blockTicks*grain) / int64(per))
	if blockSize < 1 {
		blockSize = 1
	}
	blockDur := time.Duration(blockSize) * per
	blocks := int(int64(wall) / int64(blockDur))
	if blocks > maxTailBlocks {
		blocks = maxTailBlocks
	}

	if blocks < minTailBlocks {
		t.Skipf("p99 на этой платформе за %v не набрать: шаг часов %v, решение %v, "+
			"блок %d вызовов (%v), блоков уместилось %d из %d. "+
			"Среднее при этом измерено и в бюджет %v укладывается. "+
			"Для длинного измерения: %s=%v",
			wall, grain, per, blockSize, blockDur, blocks, minTailBlocks,
			decisionBudget, tailBudgetEnv, time.Duration(minTailBlocks)*blockDur)
	}

	samples := make([]time.Duration, 0, blocks)
	for range blocks {
		start := time.Now()
		for range blockSize {
			if sel := tab.Select(meta); sel.Strategy == nil {
				t.Fatal("измеряется горячий путь с попаданием")
			}
		}
		samples = append(samples, time.Since(start)/time.Duration(blockSize))
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	if samples[len(samples)/2] <= 0 {
		t.Fatalf("медианный блок измерен нулём при блоке %d вызовов и шаге часов %v: "+
			"измерения нет, а не «мгновенно»", blockSize, grain)
	}

	p50 := samples[len(samples)/2]
	p99 := samples[len(samples)*99/100]
	worst := samples[len(samples)-1]

	if p99 > decisionBudget {
		t.Fatalf("p99 решения = %v при бюджете %v (p50 %v, худший блок %v, блок %d вызовов)",
			p99, decisionBudget, p50, worst, blockSize)
	}
	t.Logf("p50 = %v, p99 = %v, худший блок = %v, бюджет %v (блоков %d по %d вызовов, шаг часов %v)",
		p50, p99, worst, decisionBudget, blocks, blockSize, grain)
}

func longName(n int) string {
	b := make([]byte, n)
	for i := range b {
		if i%4 == 3 {
			b[i] = '.'
			continue
		}
		b[i] = 'a'
	}
	return string(b)
}

func BenchmarkSelectHit(b *testing.B) {
	tab := benchTable(b, 256)
	meta := proxy.ConnMeta{Host: "www.youtube.com", SNI: "www.youtube.com", Port: 443, IsClientHello: true}
	for b.Loop() {
		if sel := tab.Select(meta); sel.Strategy == nil {
			b.Fatal("ожидалось попадание")
		}
	}
}

func BenchmarkSelectMiss(b *testing.B) {
	tab := benchTable(b, 256)
	meta := proxy.ConnMeta{Host: "a.b.c.d.example.org", SNI: "a.b.c.d.example.org", Port: 443, IsClientHello: true}
	for b.Loop() {
		if sel := tab.Select(meta); sel.Strategy != nil {
			b.Fatal("ожидался промах")
		}
	}
}

func BenchmarkSelectUpperCase(b *testing.B) {
	tab := benchTable(b, 256)
	meta := proxy.ConnMeta{Host: "WWW.YouTube.COM", SNI: "WWW.YouTube.COM", Port: 443, IsClientHello: true}
	for b.Loop() {
		if sel := tab.Select(meta); sel.Strategy == nil {
			b.Fatal("ожидалось попадание")
		}
	}
}

// BenchmarkSelectLargeTable показывает главное свойство устройства: стоимость
// решения задана числом меток в имени, а не размером таблицы.
func BenchmarkSelectLargeTable(b *testing.B) {
	for _, size := range []int{16, 1000, 10000} {
		b.Run(fmt.Sprintf("записей=%d", size), func(b *testing.B) {
			tab := benchTable(b, size)
			meta := proxy.ConnMeta{Host: "www.youtube.com", SNI: "www.youtube.com", Port: 443, IsClientHello: true}
			for b.Loop() {
				if sel := tab.Select(meta); sel.Strategy == nil {
					b.Fatal("ожидалось попадание")
				}
			}
		})
	}
}

func BenchmarkNewSnapshot(b *testing.B) {
	entries := make([]Entry, 0, 1000)
	shared := splitStrategy(5)
	for i := range 1000 {
		entries = append(entries, Entry{Domain: fmt.Sprintf("host%d.example%d.net", i, i), Strategy: shared})
	}
	for b.Loop() {
		if _, err := NewSnapshot(testVantage, 1, entries); err != nil {
			b.Fatal(err)
		}
	}
}
