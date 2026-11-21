package control

import (
	"math"
	"sort"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/scoring"
)

// Status — состояние работающего движка в машинно-читаемом виде (2.2, 2.3).
//
// Это данные, а не представление: ни готовых подписей, ни цветов, ни
// человекочитаемых формулировок. Доли — числом в промилле, время — временем, а
// не фразой «две минуты назад». Форматирование принадлежит потребителю, и
// именно поэтому структура годится и для CLI с --json, и для будущего
// интерфейса, которого движок не содержит.
type Status struct {
	// Vantage — действующая точка наблюдения (6.1).
	Vantage core.VantageID `json:"vantage"`
	// SnapshotRev — номер живого снимка; 0 означает, что снимка нет.
	SnapshotRev uint64 `json:"snapshot_rev"`
	// PlannedAt — когда снимок был посчитан. Время, а не «сколько прошло»:
	// второе зависит от момента чтения, первое — нет.
	PlannedAt time.Time `json:"planned_at"`
	// UpdatedAt — когда собрано само это состояние.
	//
	// Отдельно от PlannedAt, потому что это разные вопросы, и смешивать их
	// нельзя. PlannedAt отвечает «насколько свежи РЕШЕНИЯ» (снимок считается с
	// выдержкой, раз в период), UpdatedAt — «насколько свежи ДАННЫЕ»
	// (наблюдения принимаются непрерывно). Имея только первое, потребитель
	// неизбежно принимал бы его за второе и считал устаревшими те числа,
	// которые на деле свежи.
	UpdatedAt time.Time `json:"updated_at"`

	// Blackout — полный обвал портфеля: ни одной действующей стратегии (5.8).
	// Признак для тревоги; реагировать на него обязан и интерфейс, а не
	// только человек, читающий журнал.
	Blackout bool `json:"blackout"`
	// TrialPermille — действующая доля проверки, в промилле. При обвале
	// повышенная (5.8).
	TrialPermille int `json:"trial_permille"`

	// Targets — состояние целей радиуса.
	Targets []TargetStatus `json:"targets"`
	// Portfolio — состояние портфеля.
	Portfolio []HoldingStatus `json:"portfolio"`

	// Intake — учёт приёма наблюдений.
	Intake IntakeStatus `json:"intake"`
}

// TargetStatus — состояние одной цели.
type TargetStatus struct {
	// Target — имя цели.
	Target string `json:"target"`
	// Active — действующая стратегия; пусто означает прозрачный пропуск.
	Active core.StrategyID `json:"active"`
	// Since — с какого времени действует Active. Нулевое время при пустой
	// Active законно и означает «ничего не применялось».
	Since time.Time `json:"since"`
	// Switches — сколько раз цель переключалась за время работы.
	Switches int `json:"switches"`
	// Pinned — закреплённая человеком стратегия; пусто означает, что цель
	// ведёт автопилот.
	Pinned core.StrategyID `json:"pinned"`
	// Trial — стратегия на доле проверки; пусто означает, что проверки нет.
	Trial core.StrategyID `json:"trial"`
	// TrialPermille — доля соединений под Trial.
	TrialPermille int `json:"trial_permille"`
	// Reason — причина последнего решения по действующей стратегии.
	Reason Reason `json:"reason"`
	// TrialReason — причина решения по ступени проверки.
	TrialReason Reason `json:"trial_reason"`
	// Degraded — стратегии, срывавшиеся на этой цели. Нужны потому, что от них
	// зависит требуемый объём наблюдений в следующий раз.
	Degraded []core.StrategyID `json:"degraded,omitempty"`
	// Baseline — базовая линия цели: что известно о ней без стратегии.
	Baseline BaselineStatus `json:"baseline"`
	// Candidates — оценки кандидатов по этой цели, по убыванию нижней границы
	// доли успехов. Пусто, если по цели ещё нет ни одного наблюдения.
	//
	// Нужны затем, чтобы вопрос «обходят ли пробы DPI и близко ли до
	// повышения» имел ответ без чтения исходников. Без них застрявший в
	// candidate портфель неотличим от работающего, но ещё не добравшего
	// наблюдений (5.5), и живой прогон песочницы нельзя ни подтвердить, ни
	// опровергнуть: ровно это и случилось при первом прогоне капстоуна.
	Candidates []CandidateStatus `json:"candidates,omitempty"`
}

// CandidateStatus — оценка одной стратегии по одной цели: ровно то, из чего
// складывается решение о повышении (5.5), в машинно-читаемом виде.
type CandidateStatus struct {
	// StrategyID — о какой стратегии речь.
	StrategyID core.StrategyID `json:"strategy_id"`
	// Observations — всего наблюдений по этой цели (с неопределёнными).
	Observations int `json:"observations"`
	// Conclusive — из них определённых (пригодных для доли успехов).
	Conclusive int `json:"conclusive"`
	// Successes — из определённых успешных.
	Successes int `json:"successes"`
	// Inconclusive — неопределённых: проба не состоялась (например, порт не
	// занялся). Отдельно, потому что большая их доля означает не провал
	// стратегии, а негодное измерение (5.5), и диагностируется это только так.
	Inconclusive int `json:"inconclusive"`
	// LowerPermille — достигнутая нижняя граница доли успехов, в промилле.
	// Именно с порогом (promote_lower_bound) и сравнивается.
	LowerPermille int `json:"lower_permille"`
	// Required, Have — требуемый и набранный объём наблюдений для повышения
	// (5.5). Have < Required означает «ещё рано», а не «не работает».
	Required int `json:"required"`
	Have     int `json:"have"`
	// Ready — порог пройден, кандидата можно допускать к доле трафика.
	Ready bool `json:"ready"`
	// Reason — машинно-читаемая причина, если не готов.
	Reason string `json:"reason,omitempty"`
}

// BaselineStatus — базовая линия цели в машинно-читаемом виде.
//
// Нужна затем, чтобы вопрос «почему кандидат не повышается» имел ответ без
// чтения исходников. Без этих чисел отказ по причине no_baseline или
// no_baseline_advantage выглядел бы необъяснимым: человек видел бы успешные
// пробы и неповышенную стратегию. Молчаливая потеря наблюдаемости в этом
// проекте уже один раз выглядела как чужая неисправность.
type BaselineStatus struct {
	// Known — базовая линия измерена. Отдельный признак, потому что ноль в
	// соседних полях законен: «цель заблокирована наглухо» и «о цели ничего не
	// известно» — разные состояния, и ноль не должен подменять второе.
	Known bool `json:"known"`
	// Observations — определённых наблюдений без стратегии.
	Observations int `json:"observations"`
	// Successes — из них успешных: столько раз цель ответила сама.
	Successes int `json:"successes"`
	// UpperPermille — верхняя граница доли успехов цели без стратегии, в
	// промилле. Именно с ней сравнивается нижняя граница стратегии.
	//
	// Промилле, а не дробь: доли в этой структуре целые везде (TrialPermille),
	// и смешивать представления в одном контракте незачем.
	UpperPermille int `json:"upper_permille"`
	// Last — время последнего наблюдения без стратегии. Свежесть базовой
	// линии значима так же, как свежесть оценок (4.5): цель могли
	// разблокировать.
	Last time.Time `json:"last"`
}

// HoldingStatus — состояние одной стратегии портфеля.
type HoldingStatus struct {
	// StrategyID — идентификатор.
	StrategyID core.StrategyID `json:"strategy_id"`
	// Status — ступень жизненного цикла (4.5).
	Status core.Status `json:"status"`
	// Collateral — измеренный побочный вред.
	Collateral bool `json:"collateral"`
	// CollateralAllowed — владелец разрешил применять, несмотря на вред.
	CollateralAllowed bool `json:"collateral_allowed"`
	// HasTree — есть ли у записи само дерево стратегии. Без него применять
	// нечего, и отличать это от «вредит» обязательно: неисправности разные.
	HasTree bool `json:"has_tree"`

	// LastObservation — время последнего наблюдения о стратегии в действующей
	// точке наблюдения. Это признак freshness из 4.5.
	//
	// Нулевое время означает «наблюдений нет вовсе» — законное состояние
	// только что добавленной стратегии. Отличать его от «наблюдения давние»
	// обязательно: первое лечится пробами, второе означает, что оценкам нельзя
	// доверять (5.9).
	LastObservation time.Time `json:"last_observation"`
	// Observations — всего наблюдений о стратегии по всем целям этой точки
	// наблюдения; Targets — по скольким целям они набраны.
	//
	// ВНИМАНИЕ потребителю: Observations — сумма по целям, и сравнивать её с
	// порогом повышения нельзя. Порог (5.5) задан на пару «цель × точка
	// наблюдения», и двадцать наблюдений, размазанных по десяти целям, порога
	// не прошли ни на одной. Поэтому рядом стоит Targets: без него число
	// наблюдений вводит в заблуждение.
	Observations int `json:"observations"`
	Targets      int `json:"targets"`
}

// IntakeStatus — учёт приёма наблюдений.
//
// Отброшенные считаются и показываются намеренно: контур отбрасывает
// наблюдения при переполнении очереди, чтобы не замедлять пользовательский
// трафик, и эта потеря обязана быть видимой. Тихая потеря данных выглядела бы
// как отсутствие сигнала, то есть как неработающий обход.
type IntakeStatus struct {
	// Accepted — принято в очередь.
	Accepted int64 `json:"accepted"`
	// Dropped — отброшено из-за переполнения.
	Dropped int64 `json:"dropped"`
	// Invalid — отвергнуто как непригодное (без стратегии, цели или времени).
	Invalid int64 `json:"invalid"`
	// Queue — ёмкость очереди.
	Queue int `json:"queue"`
	// Estimates — сколько оценок в таблице: «стратегия × цель × точка
	// наблюдения».
	Estimates int `json:"estimates"`
}

// status собирает состояние. Вызывается только горутиной-владельцем, поэтому
// читает состояние без блокировок.
func (e *Engine) status() Status {
	st := Status{
		Vantage:     e.vantage,
		SnapshotRev: e.table.Rev(),
		PlannedAt:   e.lastPlan,
		// Время сборки, а не момента чтения файла: свежесть — свойство данных.
		UpdatedAt:     e.now(),
		Blackout:      e.blackout,
		TrialPermille: e.trialPerm,
		Intake: IntakeStatus{
			Accepted:  e.accepted.Load(),
			Dropped:   e.dropped.Load(),
			Invalid:   e.invalid.Load(),
			Queue:     cap(e.obs),
			Estimates: e.scores.Len(),
		},
	}

	// Содержимое живого снимка — источник истины о том, что получает трафик:
	// именно он, а не память контура, отвечает на вопрос «что применяется
	// прямо сейчас».
	records := e.table.Current().Records()
	byDomain := make(map[string]int, len(records))
	for i, r := range records {
		byDomain[r.Domain] = i
	}

	st.Targets = make([]TargetStatus, 0, len(e.targets))
	for _, target := range dedupSorted(e.targets) {
		mem := e.states[target]
		ts := TargetStatus{
			Target:   target,
			Active:   mem.Current,
			Since:    mem.Since,
			Switches: mem.Switches,
			Pinned:   e.pins[target],
			Degraded: mem.Degraded,
		}
		if i, ok := byDomain[target]; ok {
			ts.Trial = records[i].Trial
			ts.TrialPermille = records[i].TrialPermille
		}
		if dec, ok := e.lastDecisions[target]; ok {
			ts.Reason = dec.Reason
			ts.TrialReason = dec.TrialReason
		}
		ts.Baseline = e.baselineStatus(target)
		ts.Candidates = e.candidateStatuses(target, mem)
		st.Targets = append(st.Targets, ts)
	}

	st.Portfolio = make([]HoldingStatus, 0, len(e.portfolio))
	for _, id := range e.portfolio.StrategyIDs() {
		h := e.portfolio[id]
		ev := e.scores.Evidence(id, e.vantage)
		st.Portfolio = append(st.Portfolio, HoldingStatus{
			StrategyID:        id,
			Status:            h.Status,
			Collateral:        h.Collateral,
			CollateralAllowed: h.CollateralAllowed,
			HasTree:           h.Strategy != nil,
			LastObservation:   ev.Last,
			Observations:      ev.Observations,
			Targets:           ev.Targets,
		})
	}

	return st
}

// candidateStatuses собирает оценки кандидатов по одной цели, отсортированные
// по убыванию нижней границы доли успехов. В список попадают только стратегии,
// по которым на этой цели есть хоть одно наблюдение: нули остальных лишь
// зашумили бы вывод.
//
// Required/Ready считаются ровно тем же EvaluatePromotion, что и решение о
// повышении, с теми же поправками на историю (побочный вред, прежние срывы) —
// иначе в status показывался бы один порог, а решение принималось бы по
// другому.
func (e *Engine) candidateStatuses(target string, mem TargetState) []CandidateStatus {
	now := e.now()
	out := make([]CandidateStatus, 0, len(e.portfolio))
	for _, id := range e.portfolio.StrategyIDs() {
		k := scoring.Key{StrategyID: id, Target: target, VantageID: e.vantage}
		est, ok := e.scores.Estimate(k, now)
		if !ok || est.Observations == 0 {
			continue
		}
		promo := e.scores.EvaluatePromotion(k,
			containsID(mem.Collateral, id), containsID(mem.Degraded, id))
		out = append(out, CandidateStatus{
			StrategyID:    id,
			Observations:  est.Observations,
			Conclusive:    est.Conclusive,
			Successes:     est.Successes,
			Inconclusive:  est.Inconclusive,
			LowerPermille: int(math.Round(promo.LowerBound * 1000)),
			Required:      promo.Required,
			Have:          promo.Have,
			Ready:         promo.Ready,
			Reason:        promo.Reason,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].LowerPermille > out[j].LowerPermille
	})
	return out
}

// baselineStatus собирает базовую линию цели для вывода состояния.
//
// Время берётся из последнего наблюдения, а не из «сейчас»: свежесть — это
// свойство данных, и подменять её моментом чтения нельзя.
func (e *Engine) baselineStatus(target string) BaselineStatus {
	est, ok := e.scores.Baseline(target, e.vantage, e.now())
	if !ok {
		return BaselineStatus{}
	}
	upper, known := e.scores.BaselineUpperBound(target, e.vantage)
	return BaselineStatus{
		// Известной базовая линия считается только при определённых
		// наблюдениях: одни неопределённые исходы (имя не разрешилось) данными
		// о доступности цели не являются.
		Known:         known,
		Observations:  est.Conclusive,
		Successes:     est.Successes,
		UpperPermille: int(math.Round(upper * 1000)),
		Last:          est.Last,
	}
}
