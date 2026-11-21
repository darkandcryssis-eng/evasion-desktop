package telemetry

import (
	"sync/atomic"
)

// Counter — вид счётчика.
//
// Набор задан перечислением, а не строковыми именами, потому что инкремент
// происходит на горячем пути. Карта «имя → счётчик» потребовала бы блокировки
// либо выделения памяти при первой записи, а на горячем пути бюджет аллокаций
// нулевой (4.2, правило 1). При перечислении инкремент — это индексация
// массива и атомарное сложение.
//
// Цена: добавление счётчика требует правки этого перечисления, а не только
// места вызова. Обмен осознанный: измерение не должно искажать измеряемое.
type Counter uint8

const (
	// CounterConnAccepted — принято соединений от клиента.
	CounterConnAccepted Counter = iota
	// CounterConnUpstreamFailed — не удалось соединиться с сервером.
	CounterConnUpstreamFailed
	// CounterClientHelloSeen — распознан ClientHello.
	CounterClientHelloSeen
	// CounterClientHelloMalformed — начало потока не является пригодным
	// ClientHello.
	CounterClientHelloMalformed

	// CounterStrategyApplied — стратегия применена к соединению.
	CounterStrategyApplied
	// CounterStrategySkipped — стратегия не применялась: соединение вне
	// радиуса, режим наблюдения или стратегии нет.
	CounterStrategySkipped
	// CounterStrategyUnexecutable — стратегия отвергнута шлюзом возможностей.
	CounterStrategyUnexecutable
	// CounterStrategyFailed — исполнение стратегии прервано ошибкой.
	CounterStrategyFailed
	// CounterPassthroughFallback — откат к пропуску без изменений после
	// неудачи применения стратегии.
	CounterPassthroughFallback

	// CounterProbeOK, CounterProbeThrottled, CounterProbeFail,
	// CounterProbeInconclusive — исходы проб. Разрез по исходам, а не по
	// стратегиям: множество стратегий меняется на ходу, и такие наблюдения
	// принадлежат store (6.1).
	CounterProbeOK
	CounterProbeThrottled
	CounterProbeFail
	CounterProbeInconclusive

	// CounterFlowTableOverflow — таблица соединений исчерпана, движок
	// деградировал в прозрачный режим (4.4). Авария, а не статистика.
	CounterFlowTableOverflow
	// CounterObservationsDropped — наблюдения отброшены, потому что приём не
	// успевал. Признак того, что измерениям нельзя доверять в полном объёме.
	CounterObservationsDropped

	// counterCount — число счётчиков. Обязан оставаться последним.
	counterCount
)

// counterNames задаёт машинно-читаемые имена счётчиков.
//
// Массив, а не карта: индексом служит сам счётчик, и промах в соответствии
// обнаруживается тестом на полноту, а не во время работы.
var counterNames = [counterCount]string{
	CounterConnAccepted:         "conn_accepted",
	CounterConnUpstreamFailed:   "conn_upstream_failed",
	CounterClientHelloSeen:      "client_hello_seen",
	CounterClientHelloMalformed: "client_hello_malformed",

	CounterStrategyApplied:      "strategy_applied",
	CounterStrategySkipped:      "strategy_skipped",
	CounterStrategyUnexecutable: "strategy_unexecutable",
	CounterStrategyFailed:       "strategy_failed",
	CounterPassthroughFallback:  "passthrough_fallback",

	CounterProbeOK:           "probe_ok",
	CounterProbeThrottled:    "probe_throttled",
	CounterProbeFail:         "probe_fail",
	CounterProbeInconclusive: "probe_inconclusive",

	CounterFlowTableOverflow:   "flow_table_overflow",
	CounterObservationsDropped: "observations_dropped",
}

// String возвращает имя счётчика.
func (c Counter) String() string {
	if int(c) >= len(counterNames) {
		return "unknown"
	}
	return counterNames[c]
}

// Counters — набор счётчиков движка.
//
// Нулевое значение готово к работе: счётчики можно считать с самого начала, не
// заботясь о порядке создания. Это важно потому, что счётчики нужны раньше, чем
// поднимается всё остальное.
type Counters struct {
	// values — значения счётчиков. Выравнивание по 64 битам обеспечивается
	// типом atomic.Int64; массив, а не срез, чтобы не было косвенности и
	// проверки длины при каждом инкременте.
	values [counterCount]atomic.Int64
}

// Inc увеличивает счётчик на единицу.
//
// Это и есть горячий путь измерения: индексация массива плюс атомарное
// сложение, без аллокаций и без блокировок. Выход индекса за границы
// невозможен, потому что Counter — перечисление, а не произвольное число;
// проверка здесь только утяжелила бы путь.
func (c *Counters) Inc(k Counter) {
	c.values[k].Add(1)
}

// Add увеличивает счётчик на заданную величину.
func (c *Counters) Add(k Counter, delta int64) {
	c.values[k].Add(delta)
}

// Get возвращает текущее значение счётчика.
func (c *Counters) Get(k Counter) int64 {
	return c.values[k].Load()
}

// Snapshot возвращает значения всех счётчиков как данные.
//
// Карта «имя → значение», а не готовый текст: движок отдаёт данные, а не
// представление (2.2). Снимок не согласован между счётчиками — значения
// читаются по одному, и между чтениями они могут измениться. Для наблюдаемости
// это несущественно, а согласованный снимок потребовал бы блокировки
// инкремента на горячем пути, то есть платы там, где её нельзя допускать.
func (c *Counters) Snapshot() map[string]int64 {
	out := make(map[string]int64, counterCount)
	for i := Counter(0); i < counterCount; i++ {
		out[i.String()] = c.values[i].Load()
	}
	return out
}
