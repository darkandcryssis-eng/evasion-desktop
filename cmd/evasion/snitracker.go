package main

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/config"
)

// sniTracker копит уникальные имена серверов (SNI), которые ClientHello
// называют в пределах радиуса, и периодически печатает топ. Нужен диагностике:
// движок УЖЕ разбирает SNI на каждом ClientHello (счётчик
// «целых_десинк_применим» — это именно их число), но имена наружу не отдаёт.
// А когда голос не поднимается, важно знать, идёт ли клиент к ожидаемому
// voice-гейтвею (`*.discord.media`) или к чему-то, чего в радиусе нет.
//
// Отслеживаются ТОЛЬКО имена, подпадающие под `DomainSet` (т.е. радиус из
// конфига). Остальные (youtube чужого вкладчика, браузер, обычный HTTPS)
// в счётчик не кладутся — ни по приватности, ни по пользе: мы диагностируем
// обход, а не browsing-профиль пользователя.
//
// Приём идёт из горутины продуктового перехвата через OnClientHello; поэтому
// пара operations должна быть потокобезопасна (у хука может быть другой
// вызывающий, например песочница, когда появится OnClientHello и там).
type sniTracker struct {
	radius *config.DomainSet
	log    *slog.Logger

	mu      sync.Mutex
	counts  map[string]int // SNI → количество ClientHello
	outside int            // SNI вне радиуса — только счётчик, без имён
	lastLog time.Time
}

// newSNITracker создаёт пустой трекер. nil-радиус допустим: Observe тогда ничего
// не делает (счётчики не растут, лог молчит) — удобно для вариантов, где трекер
// не нужен.
func newSNITracker(radius *config.DomainSet, log *slog.Logger) *sniTracker {
	return &sniTracker{radius: radius, log: log, counts: map[string]int{}}
}

// sniTrackerLogEvery — не чаще этого печатается сводка топа SNI. Совпадает с
// `helloLogEvery` в intercept.engine — осознанно: обе строки идут рядом в логе,
// и расходиться им незачем.
const sniTrackerLogEvery = 30 * time.Second

// sniTrackerTopN — сколько самых частых имён показывать в сводке. 20 с запасом
// покрывает Discord, YouTube и прочее под одним радиусом; длиннее — журнал
// режется до бесполезной лапши.
const sniTrackerTopN = 20

// Observe записывает одно наблюдение SNI. Пустое имя (ClientHello без SNI, что
// бывает у ECH) игнорируется — счётчик `outside` не инкрементируется, потому
// что без имени мы не знаем, в радиус оно или нет, и наказывать его отдельно
// нечестно.
func (t *sniTracker) Observe(sni string) {
	if t == nil || sni == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.radius == nil || !t.radius.Matches("", sni) {
		t.outside++
		return
	}
	t.counts[sni]++
	now := time.Now()
	if t.lastLog.IsZero() || now.Sub(t.lastLog) >= sniTrackerLogEvery {
		t.logLocked(now)
	}
}

// Flush печатает текущую сводку принудительно, без учёта таймера. Нужен в двух
// местах: тесты (чтобы можно было проверить итоговое состояние после пачки
// наблюдений, а не только снимок первого) и завершение движка (финальный лог
// по аналогии с остановкой QUIC-блокировки). Делать это из Observe на каждом
// вызове нельзя — лог залило бы.
func (t *sniTracker) Flush() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.logLocked(time.Now())
}

// logLocked печатает сводку. Вызывающий должен держать t.mu.
func (t *sniTracker) logLocked(now time.Time) {
	t.lastLog = now
	if len(t.counts) == 0 {
		// Внутри радиуса SNI пока не встречали — говорим это прямо, не
		// скрывая факт за молчанием. Пустой лог «ничего не было» неотличим от
		// «я забыл написать».
		t.log.Info("SNI радиуса", "уникальных", 0, "вне_радиуса", t.outside, "топ", "")
		return
	}
	type pair struct {
		name  string
		count int
	}
	all := make([]pair, 0, len(t.counts))
	for n, c := range t.counts {
		all = append(all, pair{n, c})
	}
	// По убыванию числа, при равенстве — по имени, чтобы порядок был устойчив
	// (вывод стабильно читается при одинаковых запусках).
	sort.Slice(all, func(i, j int) bool {
		if all[i].count != all[j].count {
			return all[i].count > all[j].count
		}
		return all[i].name < all[j].name
	})
	parts := make([]string, 0, sniTrackerTopN)
	for i, p := range all {
		if i >= sniTrackerTopN {
			break
		}
		parts = append(parts, fmt.Sprintf("%s:%d", p.name, p.count))
	}
	t.log.Info("SNI радиуса",
		"уникальных", len(t.counts),
		"вне_радиуса", t.outside,
		"топ", strings.Join(parts, " "))
}

// composeHooks строит составной OnClientHello из двух хуков. Нужен потому, что
// intercept.Options.OnClientHello один, а наблюдателей у нас два — трекер SNI
// и трекер QUIC-only. nil-любой стороны разрешён, чтобы оба использовались
// опционально.
func composeHooks(a, b func(string)) func(string) {
	switch {
	case a == nil && b == nil:
		return nil
	case a == nil:
		return b
	case b == nil:
		return a
	}
	return func(sni string) {
		a(sni)
		b(sni)
	}
}
