package control

import (
	"sort"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// Holding — стратегия в портфеле вместе с тем, что о ней известно помимо
// оценок.
//
// Оценки сюда не входят: они живут в scoring и считаются по четвёрке
// «стратегия × цель × точка наблюдения × время» (6.1). Здесь только то, что
// относится к стратегии как таковой: её дерево, ступень жизненного цикла и
// побочный вред.
type Holding struct {
	// Strategy — само дерево. Нужно policy: снимок несёт стратегию, а не
	// только идентификатор.
	Strategy *strategy.Strategy
	// Status — ступень жизненного цикла (4.5).
	Status core.Status
	// Collateral — измеренный побочный вред: стратегия ломает то, что обязано
	// работать. Признак измеряется по контрольным целям, а не объявляется
	// (4.5), и приходит сюда уже измеренным.
	Collateral bool
	// CollateralAllowed — владелец разрешил применять стратегию, несмотря на
	// побочный вред.
	//
	// Существует потому, что задание запрещает допускать вредящую стратегию в
	// active «без явного разрешения владельца» (4.5). Разрешение обязано быть
	// отдельным полем, а не отсутствием признака вреда: иначе «вред не
	// обнаружен» и «вред разрешён» слились бы в одно состояние, и снять
	// разрешение было бы нечем.
	CollateralAllowed bool
}

// Portfolio — что движок знает о своих стратегиях.
//
// Карта, а не срез: решения обращаются к портфелю по идентификатору. Владеет
// портфелем горутина контура управления; решатель только читает.
type Portfolio map[core.StrategyID]Holding

// Holding возвращает запись портфеля. Второй результат — есть ли она вообще:
// отсутствие записи и запись с пустым статусом — разные состояния, и первое
// означает дефект (на стратегию ссылаются, а её в портфеле нет).
func (p Portfolio) Holding(id core.StrategyID) (Holding, bool) {
	h, ok := p[id]
	return h, ok
}

// Strategy возвращает дерево стратегии или nil, если её в портфеле нет.
func (p Portfolio) Strategy(id core.StrategyID) *strategy.Strategy {
	return p[id].Strategy
}

// Status возвращает ступень жизненного цикла; StatusUnset, если стратегии в
// портфеле нет.
func (p Portfolio) Status(id core.StrategyID) core.Status { return p[id].Status }

// blockedByCollateral сообщает, запрещена ли стратегия из-за побочного вреда
// (4.5).
//
// Запрет распространяется и на долю проверки, а не только на active: 5.1
// требует мгновенного откатa по побочному вреду, а «мгновенный откат» и
// «продолжаем проверять на пяти процентах» — противоположные вещи. Разрешение
// владельца снимает запрет целиком: это его осознанное решение, и спорить с
// ним движок не вправе.
//
// Отсутствие записи в портфеле запретом НЕ считается, хотя соблазн велик.
// «Вредит» и «о ней ничего не известно» — разные неисправности с разным
// лечением, и смешать их значило бы объяснять пропажу стратегии побочным
// вредом, которого никто не измерял. Отсутствие разбирается отдельно, при
// сборке плана, и даёт свою причину (unknown_strategy).
func (p Portfolio) blockedByCollateral(id core.StrategyID) bool {
	h, ok := p[id]
	if !ok {
		return false
	}
	return h.Collateral && !h.CollateralAllowed
}

// Transition — предлагаемая смена ступени жизненного цикла.
//
// Решатель только предлагает: статус у стратегии один (4.5), а решения
// принимаются по целям, и одна и та же стратегия может на одной цели пойти в
// active, а на другой остаться кандидатом. Сводит предложения в один статус
// владелец портфеля, и правило сведения простое: берётся самая далёкая
// достигнутая ступень. Иначе статус дёргался бы от того, в каком порядке
// перечислены цели.
//
// Target оставлен в записи именно поэтому: без него нельзя ни объяснить
// предложение в журнале, ни применить правило сведения осознанно.
type Transition struct {
	// StrategyID — о какой стратегии речь.
	StrategyID core.StrategyID `json:"strategy_id"`
	// Target — по решению какой цели предложена смена.
	Target string `json:"target"`
	// From, To — ступени до и после.
	From core.Status `json:"from"`
	To   core.Status `json:"to"`
	// Reason — причина решения, из-за которого предложена смена.
	Reason Reason `json:"reason"`
}

// Merge сводит предложения в итоговые статусы по правилу «самая далёкая
// достигнутая ступень».
//
// Порядок ступеней для сведения — не порядок жизненного цикла, а порядок
// «насколько далеко пущена стратегия»: active дальше testing, testing дальше
// candidate. Срыв (degraded) и вывод (retired) в сведении участвуют иначе: они
// сильнее любого повышения, потому что означают запрет, а не достижение.
// Стратегия, сорвавшаяся хотя бы на одной цели, не может считаться active
// по итогам другой — это ровно тот случай, когда плоское поле «работает»
// начинает врать (4.5).
func Merge(transitions []Transition) map[core.StrategyID]core.Status {
	out := make(map[core.StrategyID]core.Status, len(transitions))
	for _, tr := range transitions {
		cur, seen := out[tr.StrategyID]
		if !seen || statusRank(tr.To) > statusRank(cur) {
			out[tr.StrategyID] = tr.To
		}
	}
	return out
}

// statusRank задаёт силу статуса при сведении предложений. Запреты получают
// наибольший вес намеренно: см. Merge.
func statusRank(s core.Status) int {
	switch s {
	case core.StatusCandidate:
		return 1
	case core.StatusBenched:
		return 2
	case core.StatusTesting:
		return 3
	case core.StatusActive:
		return 4
	case core.StatusDegraded:
		return 5
	case core.StatusRetired:
		return 6
	default:
		return 0
	}
}

// StrategyIDs возвращает идентификаторы портфеля в отсортированном порядке —
// для вывода portfolio и воспроизводимых тестов.
func (p Portfolio) StrategyIDs() []core.StrategyID {
	out := make([]core.StrategyID, 0, len(p))
	for id := range p {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
