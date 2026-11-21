package rtctrack

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Pair — пара (SNI, порт), по которой ведётся статистика.
//
// В Discord RTC-сокеты уходят на `*.discord.media` на одном из набора портов
// Cloudflare. SNI сам по себе не разделяет серверы (все начинаются на
// `.discord.media`), но пара (SNI, порт) уникальна — именно её удушает или
// не удушает TSPU.
type Pair struct {
	SNI  string
	Port uint16
}

// String для диагностики.
func (p Pair) String() string { return fmt.Sprintf("%s:%d", p.SNI, p.Port) }

// Stat — агрегат по одной паре.
//
// Хранится в памяти; на диске не персистируется в этой версии (отдельная
// волна). Все поля читаются только через Snapshot (ценная копия), чтобы
// гонка между наблюдателем и читателем не могла испортить картину.
type Stat struct {
	// Observed — всего замеченных соединений (ClientHello отправлен).
	Observed int
	// Settled — соединений, дошедших до шифрованного обмена (пассивный
	// признак успеха рукопожатия).
	Settled int
	// Reset — соединений, разорванных сервером по RST.
	Reset int
	// TotalDwell — суммарное время жизни соединений, по которым пришёл
	// Elapsed. Нужно для среднего dwell (AvgDwell = TotalDwell / Elapsed).
	TotalDwell time.Duration
	// Elapsed — сколько раз пришёл Elapsed. Отделено от Settled, потому что
	// в движке одно соединение может дать и Settled (признак успеха на
	// рукопожатии), и позднее Reset (разорвано в середине звонка).
	Elapsed int
	// LastAt — время последнего события по паре. Нужно для обрезания
	// устаревшей статистики: пара, не наблюдавшаяся сутки, уже не
	// характеризует текущий сетевой фон.
	LastAt time.Time
}

// AvgDwell — среднее время жизни по данным Elapsed; 0 если Elapsed==0.
// Не метод Stat, а функция, чтобы снимок (прочитанный Snapshot'ом) было удобно
// обрабатывать как чистые данные без зависимости от Stat.
func (s Stat) AvgDwell() time.Duration {
	if s.Elapsed == 0 {
		return 0
	}
	return s.TotalDwell / time.Duration(s.Elapsed)
}

// SuccessRate — доля успешных попыток в permille (0..1000).
//
// Формула: (Observed - Reset) / Observed. Observed растёт на каждом замеченном
// ClientHello, Reset — на явных признаках срыва (retransmit = первая попытка
// осталась без ответа). Settled остаётся как явный положительный сигнал (когда
// движок им располагает), но в живом прогоне заметить "соединение живо" без
// INBOUND-перехвата нельзя: Settled автоматически не ставится, SuccessRate
// опирается на отсутствие Reset.
//
// Если Observed == 0, возвращает 0 (пусто = нет данных).
func (s Stat) SuccessRate() int {
	if s.Observed == 0 {
		return 0
	}
	// Если Settled > 0 — он более точный сигнал, предпочитаем его.
	if s.Settled > 0 {
		return (s.Settled * 1000) / s.Observed
	}
	// Иначе выводим: все попытки, которые НЕ отметились Reset'ом, считаем
	// пока работающими. Это оптимистично, но честно падает по мере накопления
	// Reset'ов.
	return ((s.Observed - s.Reset) * 1000) / s.Observed
}

// LivenessScore — эвристический индекс живучести пары, 0..1000.
//
// Собирает в одно число два сигнала: доля успешных рукопожатий и среднее
// время жизни соединения. Больше значит «эта пара (сервер, порт) чаще
// доходит до медиа и дольше держится».
//
// Это НЕ строгое доказательство, а эмпирический индекс для ранжирования: при
// одинаковых успехах предпочтительна пара с бо́льшим dwell; при одинаковом
// dwell — с бо́льшей долей успехов. Формула склеивает их в permille.
//
// Для пар без Elapsed-наблюдений возвращает только долю успехов.
func (s Stat) LivenessScore() int {
	sr := s.SuccessRate()
	if s.Elapsed == 0 {
		return sr
	}
	avg := s.AvgDwell()
	// Нормируем dwell по 10 минутам: канал, проживший 10+ мин — максимум.
	// 600 секунд = 600000 мс = 60000 permille, нормируем.
	const normalizeMs = 600_000
	dwellPermille := int(avg.Milliseconds() * 1000 / normalizeMs)
	if dwellPermille > 1000 {
		dwellPermille = 1000
	}
	// Среднее арифметическое с равным весом: оба сигнала одинаково важны.
	return (sr + dwellPermille) / 2
}

// Tracker — потокобезопасный агрегатор.
type Tracker struct {
	mu    sync.Mutex
	stats map[Pair]*Stat
	now   func() time.Time
}

// NewTracker создаёт пустой трекер. now можно задать для детерминированных
// тестов; nil означает time.Now.
func NewTracker(now func() time.Time) *Tracker {
	if now == nil {
		now = time.Now
	}
	return &Tracker{
		stats: make(map[Pair]*Stat),
		now:   now,
	}
}

// get возвращает (создавая при отсутствии) запись статистики для пары.
// Мьютекс должен быть зажат.
func (t *Tracker) get(p Pair) *Stat {
	s := t.stats[p]
	if s == nil {
		s = &Stat{}
		t.stats[p] = s
	}
	return s
}

// Observe регистрирует замеченное начало соединения.
func (t *Tracker) Observe(p Pair) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.get(p)
	s.Observed++
	s.LastAt = t.now()
}

// Settled регистрирует переход в шифрованный обмен (ClientHello прошёл).
func (t *Tracker) Settled(p Pair) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.get(p)
	s.Settled++
	s.LastAt = t.now()
}

// Reset регистрирует разрыв по RST.
func (t *Tracker) Reset(p Pair) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.get(p)
	s.Reset++
	s.LastAt = t.now()
}

// Elapsed регистрирует завершение соединения с указанной длительностью.
func (t *Tracker) Elapsed(p Pair, dur time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.get(p)
	s.Elapsed++
	s.TotalDwell += dur
	s.LastAt = t.now()
}

// Snapshot возвращает копию текущей карты статистики.
//
// Копия, не ссылка: внешний потребитель волен сортировать и фильтровать как
// угодно, не блокируя трекер.
func (t *Tracker) Snapshot() map[Pair]Stat {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[Pair]Stat, len(t.stats))
	for p, s := range t.stats {
		out[p] = *s
	}
	return out
}

// Rank возвращает k лучших пар по LivenessScore в убывающем порядке.
// Пары с Observed < minObserved (слишком малая выборка) исключаются: по одной
// пробе судить нельзя. При равенстве счёта сравнение по SNI/порту — для
// детерминизма.
func (t *Tracker) Rank(k int, minObserved int) []RankEntry {
	snap := t.Snapshot()
	entries := make([]RankEntry, 0, len(snap))
	for p, s := range snap {
		if s.Observed < minObserved {
			continue
		}
		entries = append(entries, RankEntry{Pair: p, Stat: s, Score: s.LivenessScore()})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Score != entries[j].Score {
			return entries[i].Score > entries[j].Score
		}
		if entries[i].Pair.SNI != entries[j].Pair.SNI {
			return entries[i].Pair.SNI < entries[j].Pair.SNI
		}
		return entries[i].Pair.Port < entries[j].Pair.Port
	})
	if k > 0 && len(entries) > k {
		entries = entries[:k]
	}
	return entries
}

// RankEntry — одна строка ранжирования.
type RankEntry struct {
	Pair  Pair
	Stat  Stat
	Score int // LivenessScore, вынесен в поле, чтоб потребитель не считал заново
}

// Len — число отслеживаемых пар.
func (t *Tracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.stats)
}

// Prune удаляет записи, последнее событие которых старше olderThan. Нужно
// очищать копящиеся «мёртвые» пары, которые уже неактуальны.
func (t *Tracker) Prune(olderThan time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := t.now().Add(-olderThan)
	removed := 0
	for p, s := range t.stats {
		if s.LastAt.Before(cutoff) {
			delete(t.stats, p)
			removed++
		}
	}
	return removed
}
