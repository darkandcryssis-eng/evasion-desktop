package desync

import (
	"errors"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// fragmentAt строит стратегию с разрезом по структурной точке.
func fragmentAt(at core.CutKind) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, At: at},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right:  &strategy.Action{Kind: core.ActionSend},
		},
	}}}
}

// helloWithCuts собирает событие с нагрузкой и точками разреза.
func helloWithCuts(payload string, cuts ...core.CutPoint) Input {
	return Input{
		Direction:     core.DirectionOutbound,
		Payload:       []byte(payload),
		Ordinal:       1,
		IsClientHello: true,
		Cuts:          cuts,
	}
}

// realPayloads собирает нагрузки операций отправки реальных данных.
func realPayloads(p Plan) []string {
	var out []string
	for _, op := range p.Ops {
		if op.Kind == OpSendReal {
			out = append(out, string(op.Payload))
		}
	}
	return out
}

func TestCutAtStructuralPoint(t *testing.T) {
	// Точка на 4-м байте делит нагрузку на "ABCD" и "EFGH".
	in := helloWithCuts("ABCDEFGH", core.CutPoint{Kind: core.CutInsideSNI, Offset: 4})
	plan, err := BuildPlan(fragmentAt(core.CutInsideSNI), in)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	got := realPayloads(plan)
	if len(got) != 2 || got[0] != "ABCD" || got[1] != "EFGH" {
		t.Fatalf("разрез дал %q, ожидалось [ABCD EFGH]", got)
	}
}

func TestCutMissingPointIsExplicitError(t *testing.T) {
	// Точки такого вида у события нет. Молча отдать нагрузку целиком нельзя:
	// стратегия была бы оценена как нерабочая, хотя не применялась.
	in := helloWithCuts("ABCDEFGH", core.CutPoint{Kind: core.CutRecordHeader, Offset: 5})
	_, err := BuildPlan(fragmentAt(core.CutInsideSNI), in)
	if !errors.Is(err, ErrCutUnavailable) {
		t.Fatalf("ожидалась ErrCutUnavailable, получено %v", err)
	}
}

func TestCutWithoutAnyPointsIsError(t *testing.T) {
	// Событие без точек разреза вообще — например, не TLS.
	in := helloWithCuts("ABCDEFGH")
	if _, err := BuildPlan(fragmentAt(core.CutBeforeSNI), in); !errors.Is(err, ErrCutUnavailable) {
		t.Fatalf("ожидалась ErrCutUnavailable, получено %v", err)
	}
}

func TestCutAtBoundaryIsError(t *testing.T) {
	// Точка на самом краю дала бы пустую часть, то есть отсутствие разреза.
	for _, off := range []int{0, 8} {
		in := helloWithCuts("ABCDEFGH", core.CutPoint{Kind: core.CutInsideSNI, Offset: off})
		if _, err := BuildPlan(fragmentAt(core.CutInsideSNI), in); !errors.Is(err, ErrCutUnavailable) {
			t.Fatalf("смещение %d: ожидалась ErrCutUnavailable, получено %v", off, err)
		}
	}
}

func TestCutInNestedFragmentUsesAbsoluteOffset(t *testing.T) {
	// Вложенный разрез: внешний режет на 2-м байте по числу, внутренний — по
	// структурной точке с абсолютным смещением 5. Вторая часть начинается со
	// 2-го байта, значит внутри неё разрез должен лечь на 3-й байт.
	//
	// Это и проверяет перевод абсолютного смещения в смещение внутри части:
	// без него внутренний разрез лёг бы на 5-й байт части, то есть не туда.
	s := &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 2},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right: &strategy.Action{
				Kind:   core.ActionFragment,
				Params: &strategy.FragmentParams{Proto: strategy.FragTCP, At: core.CutInsideSNI},
				Left:   &strategy.Action{Kind: core.ActionSend},
				Right:  &strategy.Action{Kind: core.ActionSend},
			},
		},
	}}}

	in := helloWithCuts("ABCDEFGH", core.CutPoint{Kind: core.CutInsideSNI, Offset: 5})
	plan, err := BuildPlan(s, in)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	got := realPayloads(plan)
	// "AB" | "CDE" | "FGH": абсолютное смещение 5 попадает между E и F.
	if len(got) != 3 || got[0] != "AB" || got[1] != "CDE" || got[2] != "FGH" {
		t.Fatalf("вложенный разрез дал %q, ожидалось [AB CDE FGH]", got)
	}
}

func TestCutOutsideNestedPartIsError(t *testing.T) {
	// Структурная точка попадает в первую часть, а разрез требуется во второй.
	// Зажим по границе дал бы пустую часть и ложное впечатление применения.
	s := &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 6},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right: &strategy.Action{
				Kind:   core.ActionFragment,
				Params: &strategy.FragmentParams{Proto: strategy.FragTCP, At: core.CutInsideSNI},
				Left:   &strategy.Action{Kind: core.ActionSend},
				Right:  &strategy.Action{Kind: core.ActionSend},
			},
		},
	}}}

	in := helloWithCuts("ABCDEFGH", core.CutPoint{Kind: core.CutInsideSNI, Offset: 2})
	if _, err := BuildPlan(s, in); !errors.Is(err, ErrCutUnavailable) {
		t.Fatalf("ожидалась ErrCutUnavailable, получено %v", err)
	}
}

func TestCutOnSynthesizedPayloadIsError(t *testing.T) {
	// Тело подменено фейком: структуры исходного сообщения там больше нет,
	// и резать по его точкам бессмысленно.
	s := &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionTamper,
			Params: &strategy.TamperParams{Field: strategy.FieldPayload, Mode: strategy.TamperReplace, Length: 8},
			Left: &strategy.Action{
				Kind:   core.ActionFragment,
				Params: &strategy.FragmentParams{Proto: strategy.FragTCP, At: core.CutInsideSNI},
				Left:   &strategy.Action{Kind: core.ActionSend},
				Right:  &strategy.Action{Kind: core.ActionSend},
			},
		},
	}}}

	in := helloWithCuts("ABCDEFGH", core.CutPoint{Kind: core.CutInsideSNI, Offset: 4})
	if _, err := BuildPlan(s, in); !errors.Is(err, ErrCutUnavailable) {
		t.Fatalf("ожидалась ErrCutUnavailable, получено %v", err)
	}
}

func TestNumericOffsetStillClampedNotError(t *testing.T) {
	// Числовое смещение сохраняет прежнее поведение: зажим по длине, без
	// ошибки. Это оговорено в документации примитива и нужно рукописным
	// стратегиям, которым длина события заранее неизвестна.
	s := &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 9999},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right:  &strategy.Action{Kind: core.ActionSend},
		},
	}}}
	plan, err := BuildPlan(s, helloWithCuts("ABCDEFGH"))
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	got := realPayloads(plan)
	if len(got) != 1 || got[0] != "ABCDEFGH" {
		t.Fatalf("зажим смещения дал %q", got)
	}
}
