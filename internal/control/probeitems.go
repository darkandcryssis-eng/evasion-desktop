package control

import (
	"context"
	"sort"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/scoring"
	"github.com/fitting-1c/evasion/internal/strategy"
)

const (
	// probeExploreFloor — ниже этого числа определённых наблюдений кандидата
	// ещё нельзя осмысленно ранжировать по нижней границе, поэтому пробуем его
	// безусловно (исследование). Совпадает с порогом bootstrap: три
	// определённых пробы — минимум, при котором граница о чём-то говорит.
	probeExploreFloor = bootstrapMinConclusive
	// probeFocusTopK — сколько лучших по нижней границе кандидатов (сверх
	// недообследованных) берём в пробу за круг. Остальные ждут: один контур
	// проб не должен размазывать бюджет на весь портфель, иначе никто не
	// добирает до порога повышения (5.5) — доказательства концентрируем на
	// близких к повышению, чтобы они дошли до порога быстрее.
	probeFocusTopK = 3
)

// ProbeItem — пара «цель × стратегия», которой нужны доказательства.
//
// Свой тип, а не тип пакета probe: контур не должен зависеть от того, кто и
// чем добывает наблюдения. Перевод в задание пробе — работа того, кто собирает
// движок, как и с исходами соединений (4.7 п. 4).
type ProbeItem struct {
	// Target — цель радиуса.
	Target string `json:"target"`
	// StrategyID — что проверяем. Пусто только у базовой пробы.
	StrategyID core.StrategyID `json:"strategy_id"`
	// Strategy — дерево стратегии: пробе нужно её исполнить, а не только
	// назвать. nil у базовой пробы.
	Strategy *strategy.Strategy `json:"-"`
	// Baseline — проба без стратегии: измеряется сама цель.
	//
	// Явный признак, а не вывод из пустого StrategyID. Пустой идентификатор
	// случается и при дефекте — наблюдение, потерявшее стратегию по дороге, —
	// и отличать это от осознанной базовой пробы обязательно: иначе проверки
	// пришлось бы снять с обоих случаев сразу, и дефект проходил бы как
	// базовая линия. Нулевое значение не подменяет намерение.
	Baseline bool `json:"baseline"`
	// Degraded — по этой цели замену надо искать быстро (5.7).
	Degraded bool `json:"degraded"`
	// Reason — зачем проверяем. Для журнала и для команды doctor: «почему
	// движок сейчас ходит в сеть» — законный вопрос.
	Reason ProbeReason `json:"reason"`
}

// ProbeReason — зачем нужна проба.
type ProbeReason string

const (
	// ProbeReasonWatchActive — следим за применённой стратегией: срыв надо
	// заметить раньше пользователя (5.7).
	ProbeReasonWatchActive ProbeReason = "watch_active"
	// ProbeReasonEarnEvidence — кандидат набирает доказательства для допуска к
	// доле живого трафика (5.5). Без этого ступень testing недостижима.
	ProbeReasonEarnEvidence ProbeReason = "earn_evidence"
	// ProbeReasonRevalidate — стратегия деградировала и пробует вернуться
	// (5.9): после перерыва оценки затухли, и доверять им нельзя.
	ProbeReasonRevalidate ProbeReason = "revalidate"
	// ProbeReasonBaseline — базовая линия цели: жива ли цель без стратегии.
	//
	// Без неё положительный исход двусмыслен, и оценка стратегии растёт за
	// доступность цели. Эта проба — единственное, что делает остальные
	// истолкуемыми.
	ProbeReasonBaseline ProbeReason = "baseline"
)

// ProbeItems возвращает пары, которым нужны доказательства.
//
// Зачем это вообще нужно. Порог допуска к живому трафику открывается
// наблюдениями (5.5), а кандидату взять их негде: на живой трафик его не
// пускает тот же порог. Пробы — единственный путь, и ходить ими надо по тем
// парам, у которых дело стоит, а не по всем подряд: бюджет живых прогонов —
// главное ограничение движка (2.5).
//
// Порядок пар устойчив: он попадает в журнал и в вывод doctor, а обход карт в
// Go случаен.
func (e *Engine) ProbeItems(ctx context.Context) ([]ProbeItem, error) {
	v, err := e.send(ctx, command{kind: cmdProbeItems})
	if err != nil {
		return nil, err
	}
	items, ok := v.([]ProbeItem)
	if !ok {
		return nil, errUnexpectedReply
	}
	return items, nil
}

// probeItems собирает план проб. Вызывается только горутиной-владельцем.
func (e *Engine) probeItems() []ProbeItem {
	var out []ProbeItem
	now := e.now()

	for _, target := range dedupSorted(e.targets) {
		state := e.states[target]
		degraded := e.targetDegraded(target, state)

		// Базовая линия — по одной пробе на цель, всегда.
		//
		// Идёт первой и не зависит ни от портфеля, ни от ступеней: она
		// измеряет цель, а не стратегию. Без неё исходы остальных проб этой
		// цели нельзя истолковать, поэтому базовая проба нужна и тогда, когда
		// проверять больше нечего — в том числе при пустом портфеле, когда
		// движок иначе не ходил бы в сеть вовсе и не узнал бы, что цель ожила
		// сама.
		//
		// Частота у неё общая с остальными: на деградированной цели чаще
		// (5.7). Это сознательно — когда пользователю плохо, вопрос «не ожила
		// ли цель сама» самый дешёвый из полезных, и ответ на него отделяет
		// починку сети от починки обхода.
		out = append(out, ProbeItem{
			Target: target, Baseline: true,
			Degraded: degraded, Reason: ProbeReasonBaseline,
		})

		// Действующая стратегия: за ней следят, чтобы срыв заметить раньше
		// пользователя. Закреплённая — тоже: закрепление не отменяет
		// наблюдения, оно отменяет только выбор.
		if cur := state.Current; cur != "" {
			if s := e.portfolio.Strategy(cur); s != nil {
				out = append(out, ProbeItem{
					Target: target, StrategyID: cur, Strategy: s,
					Degraded: degraded, Reason: ProbeReasonWatchActive,
				})
			}
		}

		// Остальные — те, кому ступень проверки открыта: кандидаты,
		// проверяемые и деградировавшие. Применяемые и отставленные здесь не
		// нужны: первая уже под наблюдением выше, вторая отставлена
		// осознанно, и тратить на неё живые прогоны незачем, пока она не
		// понадобилась как замена.
		//
		// Бюджет проб концентрируем (focusCandidates): пробуем всех
		// недообследованных и сверх них — лучших по нижней границе, не больше
		// probeFocusTopK. Прочие ждут, пока лидеры не повысятся или не
		// отсеются. Иначе один контур проб делит бюджет на весь портфель, и
		// никто не добирает до порога 5.5 — ровно это наблюдалось живьём.
		var eligible []core.StrategyID
		for _, id := range e.portfolio.StrategyIDs() {
			if id == state.Current {
				continue
			}
			h := e.portfolio[id]
			if h.Strategy == nil || !trialAllowed(h.Status) {
				continue
			}
			// Вредящая стратегия к живому трафику не допускается (4.5), и
			// добывать ей доказательства незачем: порог она всё равно не
			// пройдёт, а соединения потратит.
			if e.portfolio.blockedByCollateral(id) {
				continue
			}
			eligible = append(eligible, id)
		}
		for _, id := range focusCandidates(e.scores, target, e.vantage, now, eligible) {
			out = append(out, e.probeItemFor(target, id, degraded))
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].StrategyID < out[j].StrategyID
	})
	return out
}

// focusCandidates концентрирует бюджет проб: из переданных кандидатов берёт
// всех недообследованных (определённых наблюдений меньше probeExploreFloor —
// их ещё нельзя ранжировать, поэтому пробуем безусловно, исследование) и сверх
// них — не больше probeFocusTopK лучших по нижней границе доли успехов. Прочие
// опускаются: пусть лидеры доберут порог повышения (5.5), вместо того чтобы
// весь портфель копил доказательства еле-еле на одном контуре проб.
//
// Порядок результата устойчив (недообследованные по входному порядку, затем
// лидеры по убыванию границы, при равенстве по идентификатору) — он идёт в
// журнал и в задание пробам.
func focusCandidates(scores *scoring.Table, target string, vantage core.VantageID, now time.Time, ids []core.StrategyID) []core.StrategyID {
	lower := func(id core.StrategyID) float64 {
		return scores.SuccessLowerBound(scoring.Key{StrategyID: id, Target: target, VantageID: vantage})
	}
	var explore, rankable []core.StrategyID
	for _, id := range ids {
		k := scoring.Key{StrategyID: id, Target: target, VantageID: vantage}
		if est, ok := scores.Estimate(k, now); !ok || est.Conclusive < probeExploreFloor {
			explore = append(explore, id)
		} else {
			rankable = append(rankable, id)
		}
	}
	sort.SliceStable(rankable, func(i, j int) bool {
		li, lj := lower(rankable[i]), lower(rankable[j])
		if li != lj {
			return li > lj
		}
		return rankable[i] < rankable[j]
	})
	if len(rankable) > probeFocusTopK {
		rankable = rankable[:probeFocusTopK]
	}
	return append(explore, rankable...)
}

// probeItemFor собирает запись пробы для кандидата (EarnEvidence либо
// Revalidate у деградировавшей).
func (e *Engine) probeItemFor(target string, id core.StrategyID, degraded bool) ProbeItem {
	h := e.portfolio[id]
	reason := ProbeReasonEarnEvidence
	if h.Status == core.StatusDegraded {
		reason = ProbeReasonRevalidate
	}
	return ProbeItem{
		Target: target, StrategyID: id, Strategy: h.Strategy,
		Degraded: degraded, Reason: reason,
	}
}

// targetDegraded сообщает, что по цели замену надо искать быстро.
//
// Два случая, и оба означают «пользователю сейчас плохо»: применять нечего
// вовсе либо последнее решение было вызвано срывом или побочным вредом.
// Интервал проб для таких целей короче (5.7: 45 секунд против двенадцати
// минут), потому что весь смысл быстрого контура — найти замену, пока человек
// ждёт.
func (e *Engine) targetDegraded(target string, state TargetState) bool {
	if state.Current == "" {
		return true
	}
	switch e.lastDecisions[target].Reason {
	case ReasonBrokenReplaced, ReasonBrokenDisabled,
		ReasonCollateralReplaced, ReasonCollateralDisabled:
		return true
	}
	return false
}
