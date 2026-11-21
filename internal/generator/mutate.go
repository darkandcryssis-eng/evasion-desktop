package generator

import (
	"errors"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// maxVariationAttempts — сколько раз повторить мутацию или скрещивание, если
// результат вышел за пределы формы (слишком глубоко/много узлов). Операции
// по построению чаще дают валидный результат; предел — защита от редких
// случаев, когда обмен поддеревьями превышает глубину.
const maxVariationAttempts = 64

// Mutate возвращает изменённую копию стратегии; исходная не меняется.
//
// Одна точечная мутация за вызов — так шаг поиска мал и управляем: либо
// переписываются параметры одного узла, либо целое поддерево заменяется новым
// случайным. Что именно — решает жребий. Результат валиден и исполним при
// заданных возможностях (как и всё, что порождает генератор).
func (g *Generator) Mutate(s *strategy.Strategy) (*strategy.Strategy, error) {
	if s == nil || len(s.Rules) == 0 {
		return nil, errors.New("generator: нечего мутировать — пустая стратегия")
	}
	for attempt := 0; attempt < maxVariationAttempts; attempt++ {
		cs := cloneStrategy(s)
		// Мутируем дерево случайно выбранного правила.
		ri := g.rng.IntN(len(cs.Rules))
		root := cs.Rules[ri].Action
		if root == nil {
			continue
		}
		g.mutateTree(root)
		if finalized, ok := g.finalize(cs); ok {
			return finalized, nil
		}
	}
	return nil, errors.New("generator: мутация не дала валидной стратегии за отведённые попытки")
}

// mutateTree применяет одну мутацию к дереву с корнем root (на месте).
func (g *Generator) mutateTree(root *strategy.Action) {
	nodes := collectNodes(root)
	nr := nodes[g.rng.IntN(len(nodes))]

	// Если у узла есть параметры (Tamper/Fragment) — с равной вероятностью
	// переписываем их, не трогая ветви: это самый мелкий шаг, двигающий
	// числовую/структурную часть гена, не меняя формы дерева.
	if hasParams(nr.node) && g.rng.Float64() < 0.5 {
		g.remakeParams(nr.node)
		return
	}

	// Иначе заменяем узел целым новым случайным поддеревом в пределах
	// оставшейся глубины: корень поддерева на глубине nr.depth, значит запас —
	// maxDepth − depth + 1.
	budget := g.maxDepth - nr.depth + 1
	if budget < 1 {
		budget = 1
	}
	*nr.node = *g.randomAction(budget)
}

// remakeParams переписывает параметры узла-преобразователя, сохраняя его вид и
// ветви.
func (g *Generator) remakeParams(a *strategy.Action) {
	switch a.Kind {
	case core.ActionTamper:
		a.Params = g.randomTamperParams()
	case core.ActionFragment:
		a.Params = g.randomFragmentParams()
	case core.ActionTCPOverlap:
		a.Params = g.randomTCPOverlapParams()
	}
}

// Crossover возвращает потомка: копию a, в которой случайное поддерево заменено
// случайным поддеревом из b. Исходные стратегии не меняются.
//
// На двоичном дереве скрещивание — это обмен поддеревьями, и выражается он в
// несколько строк (ради этого представление и выбрано деревом, 4.3). Потомок
// валиден и исполним при заданных возможностях; если обмен вывел дерево за
// пределы формы, скрещивание повторяется с другими точками.
func (g *Generator) Crossover(a, b *strategy.Strategy) (*strategy.Strategy, error) {
	if a == nil || len(a.Rules) == 0 || b == nil || len(b.Rules) == 0 {
		return nil, errors.New("generator: для скрещивания нужны две непустые стратегии")
	}
	for attempt := 0; attempt < maxVariationAttempts; attempt++ {
		child := cloneStrategy(a)
		cri := g.rng.IntN(len(child.Rules))
		donor := b.Rules[g.rng.IntN(len(b.Rules))].Action
		recipient := child.Rules[cri].Action
		if recipient == nil || donor == nil {
			continue
		}
		recipients := collectNodes(recipient)
		donors := collectNodes(donor)
		rec := recipients[g.rng.IntN(len(recipients))]
		don := donors[g.rng.IntN(len(donors))]

		// Вживляем копию донорского поддерева на место узла-реципиента.
		*rec.node = *cloneAction(don.node)

		if finalized, ok := g.finalize(child); ok {
			return finalized, nil
		}
	}
	return nil, errors.New("generator: скрещивание не дало валидной стратегии за отведённые попытки")
}

// nodeRef — узел дерева вместе с его глубиной (корень = 1). Глубина нужна, чтобы
// заменяемое поддерево не вышло за предел глубины.
type nodeRef struct {
	node  *strategy.Action
	depth int
}

// collectNodes обходит дерево и возвращает ссылки на все узлы с их глубиной.
// Ссылки указывают в само дерево, поэтому замена содержимого узла через
// *ref.node меняет дерево на месте.
func collectNodes(root *strategy.Action) []nodeRef {
	var out []nodeRef
	var walk func(a *strategy.Action, depth int)
	walk = func(a *strategy.Action, depth int) {
		if a == nil {
			return
		}
		out = append(out, nodeRef{node: a, depth: depth})
		walk(a.Left, depth+1)
		walk(a.Right, depth+1)
	}
	walk(root, 1)
	return out
}

// hasParams сообщает, несёт ли узел параметры (Tamper/Fragment/TCPOverlap).
func hasParams(a *strategy.Action) bool {
	return a.Kind == core.ActionTamper ||
		a.Kind == core.ActionFragment ||
		a.Kind == core.ActionTCPOverlap
}

// cloneStrategy делает глубокую копию стратегии. Идентификатор не копируется:
// его пересчитает finalize по итоговому содержимому.
func cloneStrategy(s *strategy.Strategy) *strategy.Strategy {
	out := &strategy.Strategy{Rules: make([]strategy.Rule, len(s.Rules))}
	for i := range s.Rules {
		out.Rules[i] = strategy.Rule{
			Direction: s.Rules[i].Direction,
			Trigger:   s.Rules[i].Trigger,
			Action:    cloneAction(s.Rules[i].Action),
		}
	}
	return out
}

// cloneAction делает глубокую копию поддерева.
func cloneAction(a *strategy.Action) *strategy.Action {
	if a == nil {
		return nil
	}
	return &strategy.Action{
		Kind:   a.Kind,
		Params: cloneParams(a.Params),
		Left:   cloneAction(a.Left),
		Right:  cloneAction(a.Right),
	}
}

// cloneParams копирует параметры узла. Концретные типы экспортированы, поэтому
// копия — это копия значения под интерфейсом; новые виды параметров нужно
// добавлять сюда (как и в реестр strategy).
func cloneParams(p strategy.Params) strategy.Params {
	switch v := p.(type) {
	case *strategy.TamperParams:
		cp := *v
		return &cp
	case *strategy.FragmentParams:
		cp := *v
		return &cp
	case *strategy.TCPOverlapParams:
		cp := *v
		return &cp
	default:
		// nil (листья Send/Drop, Duplicate) или неизвестный тип: копировать
		// нечего.
		return nil
	}
}
