package desync

import (
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// FuzzBuildPlan строит случайные деревья из байт входа и проверяет, что
// построение плана не паникует и соблюдает инварианты.
//
// desync не разбирает внешние данные (стратегия приходит уже проверенной), но
// генератор будет подавать сюда деревья, выведенные мутациями, и построение
// обязано держаться на любом структурно корректном дереве. Поэтому фаззится не
// разбор, а устойчивость обхода.
//
// Проверяемые инварианты:
//
//  1. BuildPlan не паникует;
//  2. длина каждой реальной отправки не превышает длину входа. Исключение —
//     cover-пакет tcp_overlap: он несёт ВНЕШНИЕ байты пресета (681), а не срез
//     входа, и операция появляется только когда вход длиннее cover'а (иначе
//     ErrCutUnavailable), поэтому и там len(cover) <= len(payload) — инвариант
//     длины держится.
func FuzzBuildPlan(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0}, "payload")
	f.Add([]byte{1, 2, 3, 1, 2, 3}, "0123456789")
	f.Add([]byte{2, 2, 5, 0}, "abc")

	f.Fuzz(func(t *testing.T, shape []byte, payload string) {
		action := growTree(shape, 0, 0)
		if action == nil {
			return
		}
		s := &strategy.Strategy{Rules: []strategy.Rule{{
			Direction: core.DirectionOutbound,
			Trigger:   strategy.Trigger{Match: strategy.MatchAlways},
			Action:    action,
		}}}
		// Отбрасываем структурно непригодные деревья: нас интересует поведение
		// на корректных.
		if err := strategy.Validate(s, strategy.DefaultLimits()); err != nil {
			return
		}

		in := Input{Direction: core.DirectionOutbound, Payload: []byte(payload)}
		plan, err := BuildPlan(s, in)
		if err != nil {
			return
		}
		for _, op := range plan.Ops {
			if op.Kind == OpSendReal && len(op.Payload) > len(payload) {
				t.Fatalf("реальная отправка длиннее входа: %d > %d", len(op.Payload), len(payload))
			}
		}
	})
}

// growTree строит дерево действий из байт shape. Каждый байт выбирает вид узла;
// рекурсия ограничена по глубине и длине shape, чтобы фаззер не строил
// гигантские деревья.
func growTree(shape []byte, pos, depth int) *strategy.Action {
	if pos >= len(shape) || depth > 6 {
		return &strategy.Action{Kind: core.ActionSend}
	}
	switch shape[pos] % 6 {
	case 0:
		return &strategy.Action{Kind: core.ActionSend}
	case 1:
		return &strategy.Action{Kind: core.ActionDrop}
	case 2:
		return &strategy.Action{
			Kind:   core.ActionTamper,
			Params: &strategy.TamperParams{Field: strategy.FieldIPv4TTL, Mode: strategy.TamperReplace, Value: uint64(shape[pos]) % 256},
			Left:   growTree(shape, pos+1, depth+1),
		}
	case 3:
		return &strategy.Action{
			Kind:  core.ActionDuplicate,
			Left:  growTree(shape, pos+1, depth+1),
			Right: growTree(shape, pos+2, depth+1),
		}
	case 4:
		return &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: int(shape[pos])%8 + 1, Order: strategy.FragForward},
			Left:   growTree(shape, pos+1, depth+1),
			Right:  growTree(shape, pos+2, depth+1),
		}
	default:
		// tcp_overlap — лист с cover-пресетом фиксированного размера. На
		// коротких входах даёт ErrCutUnavailable (cover не короче входа),
		// на длинных — реальный план; фаззеру важно, что обход не паникует
		// ни там, ни там.
		names := strategy.CoverPresetNames()
		return &strategy.Action{
			Kind:   core.ActionTCPOverlap,
			Params: &strategy.TCPOverlapParams{Preset: names[int(shape[pos])%len(names)]},
		}
	}
}
