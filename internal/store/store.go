package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
)

// Source — откуда получено наблюдение.
//
// Нужен потому, что наблюдения разного происхождения имеют разный вес (5.7):
// активная проба идёт с весом единицы, пассивное наблюдение живого трафика — с
// весом 0.3, потому что условия пассивного наблюдения не контролируются.
// Хранить источник обязательно: без него вес пришлось бы угадывать при
// пересчёте оценок.
type Source uint8

const (
	// SourceUnknown — источник не указан. Нулевое значение намеренно
	// бессмысленно: незаполненное наблюдение не должно сойти за измеренное.
	SourceUnknown Source = iota
	// SourceProbe — активная проба, инициированная движком.
	SourceProbe
	// SourceLiveTraffic — соединение пользователя, к которому применялась
	// стратегия.
	SourcePassive
	// SourceLiveTraffic — явное обозначение живого трафика.
	SourceLiveTraffic
)

// sourceTokens сопоставляет источник с обозначением.
var sourceTokens = []struct {
	source Source
	token  string
}{
	{SourceUnknown, "unknown"},
	{SourceProbe, "probe"},
	{SourcePassive, "passive"},
	{SourceLiveTraffic, "live"},
}

// String возвращает обозначение источника.
func (s Source) String() string {
	for _, e := range sourceTokens {
		if e.source == s {
			return e.token
		}
	}
	return "unknown"
}

// MarshalText сериализует источник.
func (s Source) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText разбирает обозначение источника.
func (s *Source) UnmarshalText(text []byte) error {
	for _, e := range sourceTokens {
		if e.token == string(text) {
			*s = e.source
			return nil
		}
	}
	return &core.UnknownTokenError{Kind: "источник наблюдения", Token: string(text)}
}

// Observation — одно наблюдение исхода.
//
// Ключ наблюдения — четвёрка «стратегия × цель × точка наблюдения × время»
// (6.1), и все четыре части обязательны. Плоское поле «работает» начало бы
// врать при появлении второй цели или второй сети, поэтому отдельного признака
// успеха у стратегии нет вовсе: есть только наблюдения с ключом.
type Observation struct {
	// At — момент наблюдения. Часть ключа: оценки затухают со временем (5.7),
	// и без времени затухание неисчислимо.
	At time.Time
	// StrategyID — применённая стратегия. Пусто означает наблюдение без
	// стратегии: такие тоже нужны как базовая линия доступности цели.
	StrategyID core.StrategyID
	// Target — цель наблюдения. Ключ цели, а не адрес: адреса меняются,
	// а вопрос «работает ли стратегия для этой цели» задаётся про имя.
	Target string
	// VantageID — точка наблюдения. Обязательна: поведение DPI существенно
	// различается между операторами и регионами, и наблюдение без точки
	// наблюдения ответа ни на что не даёт (6.1).
	VantageID core.VantageID
	// Phase — уровень оценки, на котором получен исход.
	Phase core.Phase
	// Outcome — исход.
	Outcome core.Outcome
	// Reason — машинно-читаемая причина исхода.
	Reason core.Reason
	// Source — происхождение наблюдения; определяет вес (5.7).
	Source Source
	// StrategyApplied — стратегия была фактически применена.
	//
	// Хранится отдельно от StrategyID, потому что «стратегия выбрана» и
	// «стратегия применена» — разные вещи. Без этого признака наблюдение,
	// в котором стратегия сорвалась до отправки, попало бы в статистику как
	// её проверка.
	StrategyApplied bool
	// RTT — время установки соединения; осмысленно только при RTTMeasured.
	RTT time.Duration
	// RTTMeasured — время установки измерено. Ноль законен: на Windows
	// разрешение таймера грубое, и соединение по петле измеряется нулём.
	RTTMeasured bool
	// Throughput — байт в секунду; осмысленно только при ThroughputMeasured.
	Throughput int64
	// ThroughputMeasured — скорость измерена.
	ThroughputMeasured bool
}

// validate проверяет, пригодно ли наблюдение к записи.
//
// Проверка нужна на входе, а не при чтении: наблюдение без точки наблюдения
// или без цели не ошибочно по форме, но бессмысленно по сути, и попав в
// хранилище, оно навсегда испортило бы срезы. Чинить такое потом нечем —
// утраченный контекст не восстановить.
func (o Observation) validate() error {
	switch {
	case o.At.IsZero():
		return errors.New("store: наблюдение без времени")
	case o.Target == "":
		return errors.New("store: наблюдение без цели")
	case o.VantageID == "":
		return errors.New("store: наблюдение без точки наблюдения")
	case o.Source == SourceUnknown:
		return errors.New("store: наблюдение без источника: вес неизвестен")
	}
	return nil
}

// StrategyEventKind — вид события жизненного цикла стратегии.
type StrategyEventKind uint8

const (
	// EventUnknown — вид не указан.
	EventUnknown StrategyEventKind = iota
	// EventCreated — стратегия порождена генератором.
	EventCreated
	// EventStatusChanged — изменился статус (4.5).
	EventStatusChanged
	// EventSelected — стратегия выбрана рабочей для цели.
	EventSelected
	// EventRetired — стратегия выведена.
	EventRetired
	// EventCollateralDetected — обнаружен побочный вред: контрольные цели
	// начали падать при этой стратегии (4.5).
	EventCollateralDetected
)

// eventKindTokens сопоставляет вид события с обозначением.
var eventKindTokens = []struct {
	kind  StrategyEventKind
	token string
}{
	{EventUnknown, "unknown"},
	{EventCreated, "created"},
	{EventStatusChanged, "status_changed"},
	{EventSelected, "selected"},
	{EventRetired, "retired"},
	{EventCollateralDetected, "collateral_detected"},
}

// String возвращает обозначение вида события.
func (k StrategyEventKind) String() string {
	for _, e := range eventKindTokens {
		if e.kind == k {
			return e.token
		}
	}
	return "unknown"
}

// MarshalText сериализует вид события.
func (k StrategyEventKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// StrategyEvent — событие жизненного цикла стратегии.
//
// Хранится бессрочно, в отличие от наблюдений (6.4): объём мал, а история
// решений нужна, чтобы понять, почему портфель пришёл в текущее состояние.
// Удалить её — значит лишиться возможности разобрать прошлое поведение
// автопилота.
type StrategyEvent struct {
	// At — момент события.
	At time.Time
	// StrategyID — о какой стратегии событие.
	StrategyID core.StrategyID
	// Kind — вид события.
	Kind StrategyEventKind
	// VantageID — точка наблюдения, в которой принято решение. Может быть
	// пустой у событий, не привязанных к сети (порождение генератором).
	VantageID core.VantageID
	// Target — цель, если событие привязано к цели.
	Target string
	// From, To — прежнее и новое состояние для EventStatusChanged.
	From, To string
	// Note — машинно-читаемое пояснение причины решения.
	Note string
}

// validate проверяет событие.
func (e StrategyEvent) validate() error {
	switch {
	case e.At.IsZero():
		return errors.New("store: событие без времени")
	case e.StrategyID == "":
		return errors.New("store: событие без стратегии")
	case e.Kind == EventUnknown:
		return errors.New("store: событие без вида")
	}
	return nil
}

// Query задаёт срез наблюдений.
//
// Срез всегда ограничен точкой наблюдения и окном времени: без них запрос
// смешал бы наблюдения из разных условий, а это ровно та ошибка, против
// которой устроен ключ из 6.1.
type Query struct {
	// VantageID — точка наблюдения. Обязательна.
	VantageID core.VantageID
	// Target — цель; пусто означает «все цели».
	Target string
	// StrategyID — стратегия; пусто означает «все стратегии».
	StrategyID core.StrategyID
	// Since, Until — окно времени. Until по нулевому значению означает «до
	// сейчас».
	Since, Until time.Time
	// Phase — уровень оценки; по нулевому значению берётся быстрый.
	Phase core.Phase
	// IncludeAllPhases — не ограничивать выборку уровнем.
	IncludeAllPhases bool
}

// validate проверяет запрос.
func (q Query) validate() error {
	if q.VantageID == "" {
		return errors.New("store: запрос без точки наблюдения")
	}
	if !q.Until.IsZero() && q.Until.Before(q.Since) {
		return fmt.Errorf("store: окно времени вывернуто: с %s по %s", q.Since, q.Until)
	}
	return nil
}

// Tally — срез наблюдений по ключу: сколько каких исходов.
//
// Отдаются количества, а не готовая доля успехов. Доля зависит от весов
// исходов, а веса принадлежат конфигурации и могут поменяться (5.7). Если бы
// хранилище считало долю само, при смене весов пришлось бы либо
// пересчитывать историю, либо жить с несопоставимыми числами.
type Tally struct {
	// StrategyID, Target — ключ среза.
	StrategyID core.StrategyID
	Target     string
	// Counts — количество наблюдений по исходам.
	Counts map[core.Outcome]int64
	// WeightedCounts — количества с учётом веса источника, умноженные на 1000.
	//
	// Целые числа, а не дробные: срезы складываются и переносятся между
	// машинами, и накопленная погрешность дробных чисел сделала бы одинаковые
	// данные неодинаковыми. Множитель 1000 задаёт точность до тысячных.
	WeightedCounts map[core.Outcome]int64
	// First, Last — время первого и последнего наблюдения в срезе. Нужно
	// признаку свежести (4.5): оценка по старым наблюдениям недействительна.
	First, Last time.Time
	// Total — всего наблюдений в срезе.
	Total int64
}

// RetentionPolicy — сроки хранения (6.4).
//
// Удаление обязательно, а не желательно: без него журнал наблюдений растёт
// без предела. Сроки настраиваются, удаление автоматическое.
type RetentionPolicy struct {
	// Observations — срок хранения наблюдений.
	Observations time.Duration
	// Tallies — срок хранения материализованных срезов.
	Tallies time.Duration
	// Events — срок хранения событий стратегий. Ноль означает «бессрочно»:
	// объём мал, а история решений нужна, чтобы разобрать прошлое поведение.
	Events time.Duration
}

// PurgeStats — что было удалено.
type PurgeStats struct {
	Observations int64
	Tallies      int64
	Events       int64
}

// Store — хранилище наблюдений.
//
// Намеренно пакетный: приём идёт пачками, потому что поштучная запись на диск
// не выдержала бы потока наблюдений и, главное, заставила бы вызывающего ждать.
// Буферизацию между горячим путём и хранилищем берёт на себя Writer.
//
// Реализация обязана выдерживать одного писателя и многих читателей: именно так
// её использует контур управления (4.2, правило 2).
type Store interface {
	// AppendObservations добавляет наблюдения. Только добавление, без
	// обновлений — схема рассчитана на переход к колоночной СУБД (6.5).
	AppendObservations(ctx context.Context, obs []Observation) error
	// AppendStrategyEvents добавляет события жизненного цикла стратегий.
	AppendStrategyEvents(ctx context.Context, events []StrategyEvent) error
	// Tallies возвращает срезы наблюдений по запросу.
	Tallies(ctx context.Context, q Query) ([]Tally, error)
	// Observations возвращает сырые наблюдения по запросу, от старых к новым.
	//
	// Отдаётся сырьё, а не срез (Tally), ради одного потребителя — прогрева
	// оценок при перезапуске (тёплый старт). Оценка восстанавливается точно
	// только из наблюдений в порядке их наступления: по этому порядку scoring
	// считает серию провалов и чередование исходов, а срез порядок теряет и
	// воспроизвести его не даёт. Для вывода и аналитики по-прежнему служат
	// Tallies — там порядок не нужен, а объём меньше.
	//
	// Порядок строгий, по возрастанию времени: scoring.Table.Observe
	// детерминирован только на упорядоченной последовательности, и затухание
	// применяется лишь вперёд во времени. Наблюдения, равные по времени,
	// сохраняют порядок записи — он и есть порядок наступления.
	Observations(ctx context.Context, q Query) ([]Observation, error)
	// StrategyEvents возвращает события стратегии от новых к старым.
	StrategyEvents(ctx context.Context, id core.StrategyID, limit int) ([]StrategyEvent, error)
	// Purge удаляет устаревшее согласно сроку хранения.
	Purge(ctx context.Context, now time.Time, policy RetentionPolicy) (PurgeStats, error)
	// Close закрывает хранилище, дописав всё принятое.
	Close() error
}

// weightPermille — вес источника наблюдения, умноженный на тысячу.
//
// Целые числа вместо дробных: взвешенные количества складываются и переносятся
// между машинами, и накопленная погрешность дробных чисел сделала бы одинаковые
// данные неодинаковыми. Множитель 1000 задаёт точность до тысячных.
//
// Значения следуют заданию (5.7): активное наблюдение идёт с весом единицы,
// пассивное — с весом 0.3, потому что условия пассивного наблюдения не
// контролируются: повторная отправка ClientHello случается и при обычной потере
// пакета, и неизвестно, что делал канал в этот момент.
var weightPermille = map[Source]int64{
	SourceUnknown:     0,
	SourceProbe:       1000,
	SourceLiveTraffic: 1000,
	SourcePassive:     300,
}

// WeightPermille возвращает вес источника, умноженный на тысячу.
//
// Экспортируется потому, что вес нужен каждой реализации хранилища, а
// дублировать таблицу нельзя: разойдясь, две копии дали бы несопоставимые
// взвешенные количества у разных бэкендов — и расхождение заметили бы только
// при переносе данных, то есть слишком поздно.
//
// Неизвестный источник весит ноль: наблюдение без известного происхождения не
// должно влиять на оценку.
func WeightPermille(s Source) int64 { return weightPermille[s] }

// ValidateObservation проверяет пригодность наблюдения к записи.
//
// Экспортируется потому, что проверка нужна каждой реализации хранилища.
// Дублировать её нельзя: разойдясь, копии стали бы принимать разные данные, и
// расхождение заметили бы только при переносе — то есть слишком поздно.
func ValidateObservation(o Observation) error { return o.validate() }

// ValidateStrategyEvent проверяет пригодность события к записи.
func ValidateStrategyEvent(e StrategyEvent) error { return e.validate() }

// ValidateQuery проверяет пригодность запроса срезов.
func ValidateQuery(q Query) error { return q.validate() }
