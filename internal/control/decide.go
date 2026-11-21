package control

import (
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/scoring"
)

// Action — что делать с целью.
//
// Нулевое значение означает «решение не принято» и годным решением не
// является: пустая структура Decision не должна читаться как «оставить всё
// как есть». Так же устроены core.CutKind и core.Outcome.
type Action uint8

const (
	// ActionNone — решение не принято.
	ActionNone Action = iota
	// ActionKeep — оставить то, что применено (возможно, ничего).
	ActionKeep
	// ActionApply — применить стратегию из решения.
	ActionApply
	// ActionDisable — снять стратегию: цель идёт прозрачным пропуском.
	ActionDisable
)

// String возвращает машинно-читаемое имя действия — для журнала и status.
func (a Action) String() string {
	switch a {
	case ActionKeep:
		return "keep"
	case ActionApply:
		return "apply"
	case ActionDisable:
		return "disable"
	default:
		return "none"
	}
}

// Valid сообщает, что действие задано. ActionNone годным не считается.
func (a Action) Valid() bool { return a >= ActionKeep && a <= ActionDisable }

// Reason — причина решения.
//
// Отдельный словарь, не core.Reason: там причины исходов соединения («сброс»,
// «таймаут»), здесь причины решений контура («выдержка не истекла»,
// «доказательств мало»). Смешивать их нельзя — это разные вопросы к разным
// подсистемам.
//
// Причина обязательна у каждого решения, включая «оставить»: автопилот,
// который ничего не меняет, обязан уметь объяснить, почему именно. Без этого
// застой выглядел бы неотличимо от поломки, а ровно это и случилось бы сейчас
// — положительного сигнала нет, и решения будут почти всегда «оставить».
type Reason string

const (
	// ReasonPinned — стратегия закреплена человеком.
	ReasonPinned Reason = "pinned"
	// ReasonFirstApply — цели нечего было применять, появился годный претендент.
	ReasonFirstApply Reason = "first_apply"
	// ReasonSuperior — претендент достаточно лучше и прошёл порог доверия.
	ReasonSuperior Reason = "superior"
	// ReasonBrokenReplaced — действующая сорвалась, нашлась замена.
	ReasonBrokenReplaced Reason = "broken_replaced"
	// ReasonBrokenDisabled — действующая сорвалась, замены нет.
	ReasonBrokenDisabled Reason = "broken_disabled"
	// ReasonDwell — выдержка применённой стратегии не истекла.
	ReasonDwell Reason = "dwell"
	// ReasonNoCandidate — претендентов нет вовсе.
	ReasonNoCandidate Reason = "no_candidate"
	// ReasonCurrentIsBest — лучшая из известных и есть действующая.
	ReasonCurrentIsBest Reason = "current_is_best"
	// ReasonNoCurrentEstimate — о действующей нет наблюдений, сравнивать нечем.
	ReasonNoCurrentEstimate Reason = "no_current_estimate"
	// ReasonNotSuperior — претендент недостаточно лучше действующей.
	ReasonNotSuperior Reason = "not_superior"
	// ReasonCandidateBroken — претендент сам сорвался.
	ReasonCandidateBroken Reason = "candidate_broken"
	// ReasonNotPromotable — претендент не прошёл порог доверия.
	ReasonNotPromotable Reason = "not_promotable"
	// ReasonUnknownStrategy — применённой стратегии нет в портфеле.
	ReasonUnknownStrategy Reason = "unknown_strategy"
	// ReasonInvalidState — память о цели противоречива.
	ReasonInvalidState Reason = "invalid_state"
	// ReasonCollateralBlocked — претендент вредит контрольным целям, и владелец
	// этого не разрешал (4.5).
	ReasonCollateralBlocked Reason = "collateral_blocked"
	// ReasonCollateralReplaced — действующая стратегия вредила, нашлась замена.
	ReasonCollateralReplaced Reason = "collateral_replaced"
	// ReasonCollateralDisabled — действующая стратегия вредила, замены нет.
	ReasonCollateralDisabled Reason = "collateral_disabled"

	// Причины по ступени проверки (5.1). Отдельные от причин действующей
	// стратегии: это два независимых решения по одной цели, и объяснять их
	// надо раздельно.

	// ReasonTrialAdmitted — кандидат допущен к доле реальных соединений.
	ReasonTrialAdmitted Reason = "trial_admitted"
	// ReasonNoTrialCandidate — проверять нечего: кандидатов нет.
	ReasonNoTrialCandidate Reason = "no_trial_candidate"
	// ReasonTrialNotPromotable — кандидаты есть, но порог доверия не пройден.
	ReasonTrialNotPromotable Reason = "trial_not_promotable"
	// ReasonTrialSuppressedByPin — цель закреплена человеком, проверки на ней
	// не ведутся.
	ReasonTrialSuppressedByPin Reason = "trial_suppressed_by_pin"
	// ReasonTrialDisabled — доля проверки выключена настройкой.
	ReasonTrialDisabled Reason = "trial_disabled"
	// ReasonTrialFirst — лучший претендент ещё не проверялся на живом трафике:
	// его дорога к полному трафику идёт через долю (5.1), и он на неё
	// поставлен. Это не отказ, а другая ступень.
	ReasonTrialFirst Reason = "trial_first"
	// ReasonBlackoutBootstrap — при полном обвале портфеля лучший кандидат с
	// успехами допущен к повышенной доле сразу, не дожидаясь порога 5.5.
	//
	// Основание — 5.8: когда не работает ничего, риск эксперимента уже ничего
	// не ухудшает. Без этого весь прогрев цель лежит прозрачным пропуском, а
	// это противоречит 1.1 («держать доступ рабочим»): движок молчал бы ровно
	// тогда, когда он нужнее всего. За пределами обвала порог действует как
	// прежде, поэтому фантомов в полный трафик это не пускает — только на
	// повышенную долю и только пока не работает ничего.
	ReasonBlackoutBootstrap Reason = "blackout_bootstrap"
)

// TargetState — память контура о цели: что применено и с какой историей.
//
// Degraded и Collateral нужны потому, что порог доверия поднимается для
// стратегий с историей (scoring.RequiredObservations), а сама таблица оценок
// этих признаков не знает: побочный вред измеряется по контрольным целям, а
// история деградаций живёт в журнале.
type TargetState struct {
	// Current — применённая стратегия; пусто означает «ничего не применено».
	Current core.StrategyID
	// Since — когда Current была применена. Значима только при непустом
	// Current, и тогда обязана быть заполнена: нулевое время означало бы
	// «применена неизвестно когда», а выдержку от такого отсчитывать нельзя.
	// Нулевое значение не подменяет отсутствие данных.
	Since time.Time
	// Switches — сколько раз цель переключалась. Для журнала и status.
	Switches int
	// Degraded — стратегии, которые на этой цели уже срывались.
	Degraded []core.StrategyID
	// Collateral — стратегии, у которых замечен побочный вред.
	Collateral []core.StrategyID
}

// Input — всё, что нужно для решения по одной цели.
type Input struct {
	// Target — цель (домен радиуса).
	Target string
	// Vantage — точка наблюдения: оценки к ней привязаны.
	Vantage core.VantageID
	// State — память контура о цели.
	State TargetState
	// Pinned — закреплённая человеком стратегия; пусто означает «не
	// закреплено». Закрепление обходит все пороги: это осознанная команда
	// «применяй вот это», и спорить с ней статистикой движок не вправе.
	Pinned core.StrategyID
	// Portfolio — что известно о стратегиях: ступень жизненного цикла и
	// побочный вред. Без него нельзя ни отличить кандидата от действующей
	// стратегии, ни исполнить запрет по вреду (4.5).
	Portfolio Portfolio
	// Now — время решения. Приходит параметром, а не из time.Now: иначе
	// выдержку нельзя было бы проверить, не ожидая её по-настоящему.
	Now time.Time
}

// Decision — решение по одной цели вместе с его обоснованием.
type Decision struct {
	// Target — цель, к которой относится решение.
	Target string
	// Action — что делать.
	Action Action
	// StrategyID — что применить; заполнено только при ActionApply.
	StrategyID core.StrategyID
	// Previous — что было применено до решения.
	Previous core.StrategyID
	// Reason — почему принято именно это решение.
	Reason Reason
	// Promotion — разбор порога доверия по претенденту.
	Promotion scoring.PromotionDecision
	// PromotionEvaluated — проверялся ли порог вообще. Без этого признака
	// нулевые Required и Have читались бы как «порог нулевой», а не как
	// «порог не проверяли»: до него могло не дойти дело (закрепление,
	// выдержка, отсутствие претендентов).
	PromotionEvaluated bool

	// Trial — стратегия, допущенная к доле реальных соединений этой цели
	// (5.1); пусто означает, что проверки нет.
	Trial core.StrategyID
	// TrialPermille — доля соединений под Trial, в промилле. Заполняется не
	// здесь, а планом: величина зависит от состояния всего радиуса (при
	// полном обвале портфеля доля повышается, 5.8), а решение по одной цели
	// об этом знать не может.
	TrialPermille int
	// TrialReason — почему выбрана или не выбрана проверяемая стратегия.
	TrialReason Reason
}

// Effective возвращает стратегию, которая должна действовать после решения.
// Пусто означает прозрачный пропуск.
func (d Decision) Effective() core.StrategyID {
	switch d.Action {
	case ActionApply:
		return d.StrategyID
	case ActionKeep:
		return d.Previous
	default:
		return ""
	}
}

// Changes сообщает, меняет ли решение действующую стратегию. Нужно журналу:
// записывать стоит смены, а не каждый опрос.
func (d Decision) Changes() bool { return d.Effective() != d.Previous }

// Decider принимает решения по правилам из Config.
//
// Состояния не хранит: вся память о целях приходит входом (TargetState).
// Поэтому решение — чистая функция от входа, таблицы оценок и времени, и
// проверяется целиком без горутин, сети и ожиданий. Память о целях ведёт
// горутина-владелец (вторая половина пакета).
type Decider struct {
	cfg Config
}

// NewDecider создаёт решатель с проверенной конфигурацией.
func NewDecider(cfg Config) (*Decider, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Decider{cfg: cfg}, nil
}

// Config возвращает действующую конфигурацию.
func (d *Decider) Config() Config { return d.cfg }

// Decide решает, что делать с одной целью.
//
// Порядок правил описан в doc.go и здесь повторён по шагам. Ошибок не
// возвращает намеренно: любое сомнение выражается решением «оставить» с
// причиной, потому что контур управления не вправе остановить работу движка
// из-за того, что ему что-то непонятно про одну цель.
func (d *Decider) Decide(t *scoring.Table, in Input) Decision {
	dec := d.decideActive(t, in)

	// Ступень проверки выбирается отдельно и после: это второе независимое
	// решение по той же цели (5.1). Зависимость одна и односторонняя —
	// проверять нельзя то, что уже применяется ко всему трафику, иначе доля
	// делилась бы между стратегией и ею же.
	if dec.Reason == ReasonInvalidState {
		// Память о цели противоречива: пока она не исправлена, новых
		// соединений под проверку отдавать нельзя.
		dec.TrialReason = ReasonInvalidState
		return dec
	}
	dec.Trial, dec.TrialReason = d.chooseTrial(t, in, dec.Effective())
	return dec
}

// decideActive решает судьбу действующей стратегии цели — ту часть решения,
// которая касается всего остального трафика.
func (d *Decider) decideActive(t *scoring.Table, in Input) Decision {
	dec := Decision{
		Target:   in.Target,
		Action:   ActionKeep,
		Previous: in.State.Current,
	}
	cur := in.State.Current

	// 0. Противоречивая память. «Применена, но неизвестно когда» — дефект
	// владельца состояния, а не повод что-то менять: держим как есть и
	// называем причину, чтобы дефект был виден в журнале.
	if cur != "" && in.State.Since.IsZero() {
		dec.Reason = ReasonInvalidState
		return dec
	}

	// 1. Закрепление — выше всякой статистики.
	//
	// Запрет по побочному вреду закрепление тоже не останавливает: задание
	// запрещает допускать вредящую стратегию в active «без явного разрешения
	// владельца» (4.5), а закрепление и есть это разрешение — осознанная
	// команда человека применять именно её. Цена названа прямо: закрепив
	// вредящую стратегию, владелец берёт её вред на себя, и движок снимать её
	// не станет.
	if in.Pinned != "" {
		dec.Reason = ReasonPinned
		if in.Pinned != cur {
			dec.Action = ActionApply
			dec.StrategyID = in.Pinned
		}
		return dec
	}

	// Без таблицы оценок доказательств нет ни у кого. Это законное состояние
	// свежего движка, а не ошибка.
	if t == nil {
		dec.Reason = ReasonNoCandidate
		return dec
	}

	key := func(id core.StrategyID) scoring.Key {
		return scoring.Key{StrategyID: id, Target: in.Target, VantageID: in.Vantage}
	}

	// 2. Побочный вред у действующей стратегии — самая срочная причина снять
	// её, срочнее даже срыва.
	//
	// Срыв означает, что цель недоступна; вред означает, что из-за нас
	// ломается то, что работало без нас. Второе хуже: пользователь приходит с
	// одной неработающей целью, а получает неработающую сеть. Задание требует
	// снимать такую стратегию, «даже если основная цель при ней ожила» (4.5),
	// и делать это мгновенно (5.1).
	if cur != "" && in.Portfolio.blockedByCollateral(cur) {
		if id, promo, ok := d.firstPromotable(t, in, cur); ok {
			dec.Action = ActionApply
			dec.StrategyID = id
			dec.Reason = ReasonCollateralReplaced
			dec.Promotion = promo
			dec.PromotionEvaluated = true
			return dec
		}
		dec.Action = ActionDisable
		dec.Reason = ReasonCollateralDisabled
		return dec
	}

	// 3. Срыв действующей стратегии — быстрый контур, выдержку не ждём (5.7).
	if cur != "" && t.Broken(key(cur)) {
		if id, promo, ok := d.firstPromotable(t, in, cur); ok {
			dec.Action = ActionApply
			dec.StrategyID = id
			dec.Reason = ReasonBrokenReplaced
			dec.Promotion = promo
			dec.PromotionEvaluated = true
			return dec
		}
		// Замены нет. Снимаем сорвавшуюся стратегию: держать заведомо
		// сорвавшуюся — хуже, чем не применять ничего. Доступа она не даёт, а
		// наблюдения продолжает портить, приписывая цели её провалы.
		dec.Action = ActionDisable
		dec.Reason = ReasonBrokenDisabled
		return dec
	}

	// 4. Выдержка.
	if cur != "" && in.Now.Sub(in.State.Since) < d.cfg.MinDwell {
		dec.Reason = ReasonDwell
		return dec
	}

	// 5. Претендент на полный трафик — только из тех, кому полный трафик уже
	// разрешён ступенью жизненного цикла (5.1).
	id, reason, ok := d.bestForFullTraffic(t, in, cur)
	if !ok {
		dec.Reason = reason
		return dec
	}

	// 6. Превосходство над действующей. Порог берётся у scoring: число
	// принадлежит ему, и второго набора порогов в движке быть не должно.
	if cur != "" {
		curEst, has := t.Estimate(key(cur), in.Now)
		if !has {
			// О действующей стратегии нет наблюдений: сравнивать нечем, и
			// подменять её на этом основании нельзя. Это не застой —
			// наблюдения по действующей поступают с живого трафика постоянно,
			// и их отсутствие само означает неполадку.
			dec.Reason = ReasonNoCurrentEstimate
			return dec
		}
		candEst, _ := t.Estimate(key(id), in.Now)
		if candEst.Score-curEst.Score < t.Config().SuperiorityMargin {
			dec.Reason = ReasonNotSuperior
			return dec
		}
	}

	// 7. Порог доверия.
	promo := d.promotion(t, in, id)
	dec.Promotion = promo
	dec.PromotionEvaluated = true
	if !promo.Ready {
		dec.Reason = ReasonNotPromotable
		return dec
	}

	dec.Action = ActionApply
	dec.StrategyID = id
	if cur == "" {
		dec.Reason = ReasonFirstApply
	} else {
		dec.Reason = ReasonSuperior
	}
	return dec
}

// bestForFullTraffic выбирает лучшую стратегию, которой разрешён весь трафик
// цели, и объясняет отказ, если такой нет.
//
// Почему перебор здесь, а не scoring.Challenger. Challenger отвечает на вопрос
// «кто лучший вообще», ничего не зная о ступенях допуска, и вернул бы
// кандидата, которому полный трафик ещё не разрешён. Нужный же вопрос — «кто
// лучший СРЕДИ допущенных». Поэтому перебор свой, а правило превосходства
// по-прежнему принадлежит scoring: число берётся из его конфигурации, и
// применяется оно в decideActive, одним сравнением.
//
// Встретив действующую стратегию, перебор останавливается: список отсортирован
// по убыванию оценки, поэтому ничто ниже неё превзойти её уже не может.
func (d *Decider) bestForFullTraffic(t *scoring.Table, in Input, cur core.StrategyID) (core.StrategyID, Reason, bool) {
	ranked := t.Rank(in.Target, in.Vantage, in.Now)
	if len(ranked) == 0 {
		return "", ReasonNoCandidate, false
	}

	var sawCurrent, sawBlocked, sawBroken, sawTrialRung bool
	for _, r := range ranked {
		id := r.Key.StrategyID
		if id == cur {
			sawCurrent = true
			break
		}
		// Запрет по побочному вреду проверяется раньше ступени намеренно: он
		// действует на все ступени сразу (4.5, 5.1), и сказать про вредящего
		// кандидата «он сейчас на проверке» было бы неправдой — на проверку
		// его тоже не возьмут.
		if in.Portfolio.blockedByCollateral(id) {
			sawBlocked = true
			continue
		}
		st := in.Portfolio.Status(id)
		if !fullTrafficAllowed(st) {
			// Кандидату полный трафик не разрешён: его дорога — через долю
			// проверки (5.1). Это не отказ, а другая ступень, и назвать её
			// надо отдельной причиной.
			if trialAllowed(st) {
				sawTrialRung = true
			}
			continue
		}
		if t.Broken(scoring.Key{StrategyID: id, Target: in.Target, VantageID: in.Vantage}) {
			sawBroken = true
			continue
		}
		return id, "", true
	}

	// Порядок причин — по полезности для человека: запрет по вреду требует его
	// решения, срыв лечится пробами, ступень проверки означает, что движок уже
	// занят этим кандидатом.
	switch {
	case sawBlocked:
		return "", ReasonCollateralBlocked, false
	case sawBroken:
		return "", ReasonCandidateBroken, false
	case sawTrialRung:
		return "", ReasonTrialFirst, false
	case sawCurrent:
		return "", ReasonCurrentIsBest, false
	}
	return "", ReasonNoCandidate, false
}

// fullTrafficAllowed сообщает, разрешён ли стратегии весь трафик цели (5.1).
//
// Кандидата здесь намеренно нет: прыжок candidate → active минует ступень
// проверки, то есть ровно ту защиту, ради которой ступенчатое допущение и
// введено. Порог 5.5 открывает долю трафика, а не весь трафик.
//
// Отставленная (benched) разрешена: она уже проверена, просто уступила
// лучшей, и именно она служит резервом, о котором говорит 5.8. Деградировавшая
// и выведенная запрещены (4.5), статус unset запрещён тоже — отсутствие
// сведений о стратегии не повод пускать её на весь трафик.
func fullTrafficAllowed(s core.Status) bool {
	switch s {
	case core.StatusTesting, core.StatusActive, core.StatusBenched:
		return true
	default:
		return false
	}
}

// trialAllowed сообщает, можно ли стратегию поставить на долю проверки.
//
// Деградировавшая стратегия сюда входит, и это решение, а не недосмотр.
// Задание требует удерживать доступ в рабочем состоянии, включая случай, когда
// работавшая стратегия перестала работать (1.1), и предлагать перевалидацию
// после перерыва (5.9). Без обратной дороги degraded был бы тупиком, и
// портфель истощался бы с каждым сбоем сети. Возвращается она через долю, а не
// сразу в active, и требует повышенного объёма наблюдений — история срывов
// поднимает порог (scoring.RequiredObservations).
//
// Цена: соединения, отданные вернувшейся стратегии, могут снова сорваться.
// Поэтому доля мала, а срыв снимает её немедленно.
func trialAllowed(s core.Status) bool {
	switch s {
	case core.StatusCandidate, core.StatusTesting, core.StatusDegraded:
		return true
	default:
		return false
	}
}

// chooseTrial выбирает стратегию на долю реальных соединений цели — ступень
// testing из 5.1.
//
// Порог здесь тот же, что задание называет порогом перехода
// candidate → testing (5.5): объём наблюдений и нижняя граница доли успехов.
// Наблюдения для него набираются пробами и соединениями песочницы, то есть
// бесплатно для пользователя; доля реальных соединений — следующая ступень, и
// открывает её именно этот порог.
//
// Кого не берём и почему:
//
//   - действующую стратегию — она и так получает весь остальной трафик, и
//     делить долю между ней и ею же нечего;
//   - сорвавшуюся — проверять заведомо сорванное значит жечь соединения
//     пользователя;
//   - вредящую контрольным целям без разрешения владельца (4.5) — здесь это и
//     есть «мгновенный откат по побочному вреду» из 5.1: как только вред
//     измерен, стратегия перестаёт попадать в снимок;
//   - стратегии вне ступеней candidate и testing: active уже применяется,
//     benched отставлена, degraded и retired запрещены (4.5).
func (d *Decider) chooseTrial(t *scoring.Table, in Input, active core.StrategyID) (core.StrategyID, Reason) {
	if in.Pinned != "" {
		// Цель отдана человеку: ставить на неё опыты за его спиной нельзя.
		return "", ReasonTrialSuppressedByPin
	}
	if t == nil {
		return "", ReasonNoTrialCandidate
	}

	var sawCandidate bool
	for _, r := range t.Rank(in.Target, in.Vantage, in.Now) {
		id := r.Key.StrategyID
		if id == active {
			continue
		}
		if !trialAllowed(in.Portfolio.Status(id)) {
			continue
		}
		if in.Portfolio.blockedByCollateral(id) {
			continue
		}
		if t.Broken(scoring.Key{StrategyID: id, Target: in.Target, VantageID: in.Vantage}) {
			continue
		}
		sawCandidate = true
		if promo := d.promotion(t, in, id); promo.Ready {
			return id, ReasonTrialAdmitted
		}
	}

	// Различать «кандидатов нет» и «есть, но не доказаны» обязательно: первое
	// лечится генератором, второе — пробами. Для человека это разные
	// неисправности.
	if sawCandidate {
		return "", ReasonTrialNotPromotable
	}
	return "", ReasonNoTrialCandidate
}

// promotion проверяет порог доверия для стратегии с учётом её истории на этой
// цели: сорвавшаяся или навредившая ранее стратегия требует больше наблюдений
// (scoring.RequiredObservations).
func (d *Decider) promotion(t *scoring.Table, in Input, id core.StrategyID) scoring.PromotionDecision {
	k := scoring.Key{StrategyID: id, Target: in.Target, VantageID: in.Vantage}
	return t.EvaluatePromotion(k,
		containsID(in.State.Collateral, id),
		containsID(in.State.Degraded, id))
}

// firstPromotable ищет лучшую замену сорвавшейся стратегии: перебирает
// претендентов по убыванию оценки и берёт первого, кто сам не сорвался и
// прошёл порог доверия.
//
// Порог превосходства здесь не применяется сознательно. Сравнивать с заведомо
// сорвавшейся стратегией нечего: превосходство над ней не свидетельство
// качества претендента, а лишь свидетельство её провала. Доказательность при
// этом не ослаблена — порог доверия проверяется полностью.
func (d *Decider) firstPromotable(t *scoring.Table, in Input, skip core.StrategyID) (core.StrategyID, scoring.PromotionDecision, bool) {
	for _, r := range t.Rank(in.Target, in.Vantage, in.Now) {
		id := r.Key.StrategyID
		if id == skip {
			continue
		}
		if t.Broken(scoring.Key{StrategyID: id, Target: in.Target, VantageID: in.Vantage}) {
			continue
		}
		// Замена не имеет права вредить контрольным целям (4.5): менять
		// сорвавшуюся на вредящую — не починка.
		if in.Portfolio.blockedByCollateral(id) {
			continue
		}
		if promo := d.promotion(t, in, id); promo.Ready {
			return id, promo, true
		}
	}
	return "", scoring.PromotionDecision{}, false
}

// containsID сообщает, есть ли идентификатор в списке. Список, а не карта:
// историй на цель единицы, а порядок полезен журналу.
func containsID(list []core.StrategyID, id core.StrategyID) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}
