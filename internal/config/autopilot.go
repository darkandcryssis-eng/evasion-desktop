package config

import (
	"fmt"
	"runtime"
	"time"

	"github.com/fitting-1c/evasion/internal/control"
	"github.com/fitting-1c/evasion/internal/scoring"
)

// duration — продолжительность в файле конфига.
//
// Записывается строкой ("6h", "45s", "12m"), а не числом: число потребовало бы
// договариваться о единице измерения, и «45» в одном поле значило бы секунды, а
// в другом минуты. Ошибку такого рода в конфиге не видно глазами.
type duration time.Duration

// UnmarshalText разбирает продолжительность по правилам time.ParseDuration.
func (d *duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("config: непонятная продолжительность %q: %w", text, err)
	}
	*d = duration(v)
	return nil
}

// MarshalText записывает продолжительность той же строкой.
func (d duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// Autopilot — числовые параметры автопилота (5.5, 5.7).
//
// Все они обязаны жить в конфиге, а не в коде (10.1). Значения по умолчанию
// берутся у тех пакетов, которые их потребляют (scoring, control), а не
// повторяются здесь: иначе в движке оказалось бы два набора порогов, и
// разошлись бы они молча.
type Autopilot struct {
	// HalfLife — полужизнь оценки: за это время вклад наблюдения уменьшается
	// вдвое (5.7).
	HalfLife time.Duration
	// MinDwell — выдержка до смены стратегии (5.7).
	MinDwell time.Duration
	// SuperiorityMargin — насколько претендент должен быть лучше (5.7).
	SuperiorityMargin float64
	// FailureStreak — сколько провалов подряд считать срывом (5.7).
	FailureStreak int

	// WeightOK, WeightThrottled, WeightFail, WeightInconclusive — веса исходов
	// (5.7). Градуированы: замедление — не то же самое, что обрыв.
	WeightOK           float64
	WeightThrottled    float64
	WeightFail         float64
	WeightInconclusive float64

	// MinObservations, MaxObservations — границы требуемого объёма наблюдений
	// для перехода candidate → testing (5.5).
	MinObservations int
	MaxObservations int
	// PromoteLowerBound — требуемая нижняя граница доли успехов (5.5).
	PromoteLowerBound float64
	// ConfidenceZ — уровень доверия интервала в стандартных отклонениях.
	ConfidenceZ float64
	// InconclusiveShareEscalate — доля неопределённых исходов, выше которой
	// требуемый объём поднимается до верхней границы (5.5).
	InconclusiveShareEscalate float64
	// BaselineMargin — насколько стратегия должна превосходить базовую линию
	// цели, чтобы успех засчитали ей, а не доступности цели.
	BaselineMargin float64

	// TrialPermille — доля реальных соединений под проверяемую стратегию, в
	// промилле (5.1, 5.7: 5% — жёсткий потолок).
	TrialPermille int
	// BlackoutTrialPermille — доля проверки при полном обвале портфеля (5.8).
	BlackoutTrialPermille int

	// ProbeInterval, ProbeJitter, ProbeIntervalDegraded — расписание проб
	// (5.7). Джиттер обязателен: ровный интервал сам по себе рисунок трафика.
	ProbeInterval         time.Duration
	ProbeJitter           float64
	ProbeIntervalDegraded time.Duration

	// WeightPassive — вес пассивного наблюдения (5.7, 5.10). Ниже активного:
	// условия пассивного наблюдения не контролируются.
	WeightPassive float64

	// EstimatesStaleAfter — через какое время без наблюдений оценкам нельзя
	// доверять.
	//
	// Нужно требованию 5.9: после долгого перерыва оценки затухли, и doctor
	// обязан сказать это прямо, а не показывать устаревшие оценки как
	// действующие. Числа задание не называет, поэтому оно выведено: за два
	// периода полужизни вклад наблюдения падает до четверти, и ранжирование
	// по таким оценкам уже ничего не значит.
	//
	// Величина сравнивается со временем ПОСЛЕДНЕГО наблюдения, а не с
	// длительностью простоя движка: движок мог работать и не получать
	// наблюдений вовсе (так и будет, пока в портфеле нет ничего пригодного), и
	// это тот же случай недоверия.
	EstimatesStaleAfter time.Duration
}

// autopilotWire — проводная форма параметров автопилота.
type autopilotWire struct {
	// Продолжительности — указатели по той же причине, что и числа: "0s" это
	// заданное значение (и негодное, его обязана отвергнуть проверка), а
	// отсутствие ключа — «взять по умолчанию». Если бы признаком «не задано»
	// служил сам нуль, настройка "half_life": "0s" молча заменялась бы
	// значением по умолчанию вместо внятной ошибки. Нулевое значение не
	// подменяет отсутствие данных — правило, на котором проект уже стоял
	// трижды.
	HalfLife          *duration `json:"half_life"`
	MinDwell          *duration `json:"min_dwell"`
	SuperiorityMargin *float64  `json:"superiority_margin"`
	FailureStreak     *int      `json:"failure_streak"`

	WeightOK           *float64 `json:"weight_ok"`
	WeightThrottled    *float64 `json:"weight_throttled"`
	WeightFail         *float64 `json:"weight_fail"`
	WeightInconclusive *float64 `json:"weight_inconclusive"`

	MinObservations           *int     `json:"min_observations"`
	MaxObservations           *int     `json:"max_observations"`
	PromoteLowerBound         *float64 `json:"promote_lower_bound"`
	ConfidenceZ               *float64 `json:"confidence_z"`
	InconclusiveShareEscalate *float64 `json:"inconclusive_share_escalate"`
	BaselineMargin            *float64 `json:"baseline_margin"`

	TrialPermille         *int `json:"trial_permille"`
	BlackoutTrialPermille *int `json:"blackout_trial_permille"`

	ProbeInterval         *duration `json:"probe_interval"`
	ProbeJitter           *float64  `json:"probe_jitter"`
	ProbeIntervalDegraded *duration `json:"probe_interval_degraded"`

	WeightPassive *float64 `json:"weight_passive"`

	EstimatesStaleAfter *duration `json:"estimates_stale_after"`
}

// DefaultAutopilot возвращает значения по умолчанию.
//
// Числа берутся у потребителей: веса и пороги — у scoring, выдержка и доли — у
// control. Так у каждого числа остаётся ровно один источник, и «значение по
// умолчанию» нельзя поменять в одном месте, забыв про другое.
//
// Здесь заданы только те величины, у которых потребителя ещё нет: расписание
// проб и вес пассивного наблюдения. Они появятся в probe и в приёмнике
// пассивного сигнала, и тогда переедут туда же.
func DefaultAutopilot() Autopilot {
	s := scoring.DefaultConfig()
	c := control.DefaultConfig()
	return Autopilot{
		HalfLife:          s.HalfLife,
		MinDwell:          c.MinDwell,
		SuperiorityMargin: s.SuperiorityMargin,
		FailureStreak:     s.FailureStreak,

		WeightOK:           s.WeightOK,
		WeightThrottled:    s.WeightThrottled,
		WeightFail:         s.WeightFail,
		WeightInconclusive: s.WeightInconclusive,

		MinObservations:           s.MinObservations,
		MaxObservations:           s.MaxObservations,
		PromoteLowerBound:         s.PromoteLowerBound,
		ConfidenceZ:               s.ConfidenceZ,
		InconclusiveShareEscalate: s.InconclusiveShareEscalate,
		BaselineMargin:            s.BaselineMargin,

		TrialPermille:         c.TrialPermille,
		BlackoutTrialPermille: c.BlackoutTrialPermille,

		// 12 минут ± 40% (5.7).
		ProbeInterval:         12 * time.Minute,
		ProbeJitter:           0.4,
		ProbeIntervalDegraded: 45 * time.Second,

		// 0.3 против 1 у активной пробы (5.7, 5.10).
		WeightPassive: 0.3,

		// Два периода полужизни (6 ч × 2): к этому времени вклад наблюдения
		// падает до четверти. Значение выведено, а не взято из задания — там
		// требование сформулировано словами «после долгого перерыва» (5.9).
		EstimatesStaleAfter: 12 * time.Hour,
	}
}

// apply накладывает заданные в файле значения на значения по умолчанию.
//
// Указатели в проводной форме нужны именно для этого: нулевое значение в JSON
// («weight_inconclusive»: 0) — законная настройка, и отличить её от
// незаполненного поля иначе нельзя. Это тот же запрет, что и везде в проекте:
// нулевое значение не подменяет отсутствие данных.
func (w autopilotWire) apply(a Autopilot) Autopilot {
	if w.HalfLife != nil {
		a.HalfLife = time.Duration(*w.HalfLife)
	}
	if w.MinDwell != nil {
		a.MinDwell = time.Duration(*w.MinDwell)
	}
	if w.SuperiorityMargin != nil {
		a.SuperiorityMargin = *w.SuperiorityMargin
	}
	if w.FailureStreak != nil {
		a.FailureStreak = *w.FailureStreak
	}
	if w.WeightOK != nil {
		a.WeightOK = *w.WeightOK
	}
	if w.WeightThrottled != nil {
		a.WeightThrottled = *w.WeightThrottled
	}
	if w.WeightFail != nil {
		a.WeightFail = *w.WeightFail
	}
	if w.WeightInconclusive != nil {
		a.WeightInconclusive = *w.WeightInconclusive
	}
	if w.MinObservations != nil {
		a.MinObservations = *w.MinObservations
	}
	if w.MaxObservations != nil {
		a.MaxObservations = *w.MaxObservations
	}
	if w.PromoteLowerBound != nil {
		a.PromoteLowerBound = *w.PromoteLowerBound
	}
	if w.ConfidenceZ != nil {
		a.ConfidenceZ = *w.ConfidenceZ
	}
	if w.InconclusiveShareEscalate != nil {
		a.InconclusiveShareEscalate = *w.InconclusiveShareEscalate
	}
	if w.BaselineMargin != nil {
		a.BaselineMargin = *w.BaselineMargin
	}
	if w.TrialPermille != nil {
		a.TrialPermille = *w.TrialPermille
	}
	if w.BlackoutTrialPermille != nil {
		a.BlackoutTrialPermille = *w.BlackoutTrialPermille
	}
	if w.ProbeInterval != nil {
		a.ProbeInterval = time.Duration(*w.ProbeInterval)
	}
	if w.ProbeJitter != nil {
		a.ProbeJitter = *w.ProbeJitter
	}
	if w.ProbeIntervalDegraded != nil {
		a.ProbeIntervalDegraded = time.Duration(*w.ProbeIntervalDegraded)
	}
	if w.WeightPassive != nil {
		a.WeightPassive = *w.WeightPassive
	}
	if w.EstimatesStaleAfter != nil {
		a.EstimatesStaleAfter = time.Duration(*w.EstimatesStaleAfter)
	}
	return a
}

// Scoring собирает конфигурацию оценок.
func (a Autopilot) Scoring() scoring.Config {
	return scoring.Config{
		HalfLife:                  a.HalfLife,
		WeightOK:                  a.WeightOK,
		WeightThrottled:           a.WeightThrottled,
		WeightFail:                a.WeightFail,
		WeightInconclusive:        a.WeightInconclusive,
		MinObservations:           a.MinObservations,
		MaxObservations:           a.MaxObservations,
		PromoteLowerBound:         a.PromoteLowerBound,
		ConfidenceZ:               a.ConfidenceZ,
		SuperiorityMargin:         a.SuperiorityMargin,
		FailureStreak:             a.FailureStreak,
		InconclusiveShareEscalate: a.InconclusiveShareEscalate,
		BaselineMargin:            a.BaselineMargin,
	}
}

// Control собирает конфигурацию контура управления.
func (a Autopilot) Control() control.Config {
	return control.Config{
		MinDwell:              a.MinDwell,
		TrialPermille:         a.TrialPermille,
		BlackoutTrialPermille: a.BlackoutTrialPermille,
	}
}

// validate проверяет параметры автопилота.
//
// Проверка делегируется конструкторам потребителей: scoring.NewTable и
// control.NewDecider уже содержат все правила согласованности, и повторять их
// здесь значило бы завести второй набор, который со временем разойдётся с
// первым. Своих проверок тут только те, у которых потребителя пока нет.
func (a Autopilot) validate() error {
	if _, err := scoring.NewTable(a.Scoring()); err != nil {
		return err
	}
	if _, err := control.NewDecider(a.Control()); err != nil {
		return err
	}
	switch {
	case a.ProbeInterval <= 0:
		return fmt.Errorf("config: интервал проб %v должен быть положительным", a.ProbeInterval)
	case a.ProbeIntervalDegraded <= 0:
		return fmt.Errorf("config: интервал проб при деградации %v должен быть положительным", a.ProbeIntervalDegraded)
	case a.ProbeJitter <= 0 || a.ProbeJitter > 1:
		// Нулевой джиттер запрещён: задание называет его обязательным (5.7),
		// потому что ровный интервал проб сам по себе рисунок трафика.
		return fmt.Errorf("config: джиттер проб %v вне интервала (0, 1]", a.ProbeJitter)
	case a.WeightPassive <= 0 || a.WeightPassive > 1:
		return fmt.Errorf("config: вес пассивного наблюдения %v вне интервала (0, 1]", a.WeightPassive)
	case a.EstimatesStaleAfter <= 0:
		return fmt.Errorf("config: срок устаревания оценок %v должен быть положительным", a.EstimatesStaleAfter)
	case a.EstimatesStaleAfter < a.HalfLife:
		// Срок короче полужизни означал бы, что оценки объявляются
		// недостоверными раньше, чем успели затухнуть хотя бы вдвое, — то есть
		// doctor предупреждал бы почти всегда. Предупреждение, которое звучит
		// постоянно, перестаёт быть предупреждением; этот урок проект уже
		// получил на ложной тревоге об обвале портфеля.
		return fmt.Errorf("config: срок устаревания оценок %v короче полужизни %v: "+
			"предупреждение звучало бы постоянно и обесценилось", a.EstimatesStaleAfter, a.HalfLife)
	}
	return nil
}

// Parallelism — пределы параллельности прогонов (5.4).
//
// Существуют потому, что за некоторым пределом параллельность портит
// измерение, а не ускоряет его: много одновременных соединений к одной цели —
// необычный рисунок трафика, а если DPI держит состояние по адресу источника,
// результаты параллельных прогонов коррелируют, и вместо N независимых
// наблюдений получается одно, размазанное на N.
type Parallelism struct {
	// Workers — воркеров глобально.
	Workers int
	// PerTarget — сколько прогонов одновременно на одну цель.
	PerTarget int
}

// Пределы из 5.4. Верхний предел воркеров задан заданием жёстко.
const (
	maxWorkers          = 16
	defaultWorkersLimit = 8
)

// DefaultParallelism возвращает пределы по умолчанию: min(8, NumCPU) воркеров и
// два прогона на цель (5.4).
func DefaultParallelism() Parallelism {
	workers := runtime.NumCPU()
	if workers > defaultWorkersLimit {
		workers = defaultWorkersLimit
	}
	if workers < 1 {
		workers = 1
	}
	return Parallelism{Workers: workers, PerTarget: 2}
}

func (p Parallelism) validate() error {
	switch {
	case p.Workers < 1:
		return fmt.Errorf("config: воркеров %d, должно быть не меньше одного", p.Workers)
	case p.Workers > maxWorkers:
		return fmt.Errorf("config: воркеров %d, верхний предел %d (5.4)", p.Workers, maxWorkers)
	case p.PerTarget < 1:
		return fmt.Errorf("config: прогонов на цель %d, должно быть не меньше одного", p.PerTarget)
	case p.PerTarget > p.Workers:
		return fmt.Errorf("config: прогонов на цель %d больше числа воркеров %d", p.PerTarget, p.Workers)
	}
	return nil
}

// Budgets — бюджеты горячего пути (8.1).
//
// Лежат в конфиге по требованию 10.1, но смысл у них иной, чем у прочих
// настроек: это не поведение движка, а предел, который обязаны подтверждать
// бенчмарки. Снизить бюджет настройкой нельзя так, чтобы код стал быстрее, —
// можно только узнать, что он больше не укладывается.
type Budgets struct {
	// InterestingConn — проверка «интересно ли это соединение» (8.1).
	InterestingConn time.Duration
	// Decision — решение по ClientHello: разбор, политика, выбор стратегии
	// (8.1, по p99).
	Decision time.Duration
}

// DefaultBudgets возвращает начальные бюджеты из 8.1.
func DefaultBudgets() Budgets {
	return Budgets{
		InterestingConn: time.Microsecond,
		Decision:        10 * time.Microsecond,
	}
}

func (b Budgets) validate() error {
	switch {
	case b.InterestingConn <= 0:
		return fmt.Errorf("config: бюджет проверки соединения %v должен быть положительным", b.InterestingConn)
	case b.Decision <= 0:
		return fmt.Errorf("config: бюджет решения %v должен быть положительным", b.Decision)
	}
	return nil
}

// Retention — сроки хранения (6.4). Удаление автоматическое, поэтому сроки
// обязаны быть явными: «хранить всё» на активной машине означает рост без
// предела.
type Retention struct {
	// Rows — сырые строки соединений и проб.
	Rows time.Duration
	// Aggregates — агрегированные срезы.
	Aggregates time.Duration
	// Events — события стратегий. Ноль означает «бессрочно» (6.4): объём их
	// мал, а история переключений — самое ценное, что есть у движка. Это
	// осознанный признак, а не незаполненное поле, потому что именно таково
	// значение по умолчанию в задании.
	Events time.Duration
}

// DefaultRetention возвращает сроки из 6.4: 30 суток на сырые строки, год на
// срезы, события бессрочно.
func DefaultRetention() Retention {
	return Retention{
		Rows:       30 * 24 * time.Hour,
		Aggregates: 365 * 24 * time.Hour,
		Events:     0,
	}
}

func (r Retention) validate() error {
	switch {
	case r.Rows <= 0:
		return fmt.Errorf("config: срок хранения строк %v должен быть положительным", r.Rows)
	case r.Aggregates <= 0:
		return fmt.Errorf("config: срок хранения срезов %v должен быть положительным", r.Aggregates)
	case r.Events < 0:
		return fmt.Errorf("config: срок хранения событий %v отрицателен", r.Events)
	case r.Aggregates < r.Rows:
		// Срезы живут дольше строк по смыслу: они и есть то, во что строки
		// сворачиваются. Обратный порядок означал бы, что аналитику удаляют
		// раньше данных, из которых её можно пересчитать.
		return fmt.Errorf("config: срок хранения срезов %v меньше срока строк %v", r.Aggregates, r.Rows)
	}
	return nil
}
