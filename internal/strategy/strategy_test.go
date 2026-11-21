package strategy

import (
	"errors"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
)

// leaf возвращает лист указанного вида (Send/Drop) для построения деревьев в
// тестах.
func leaf(kind core.ActionKind) *Action { return &Action{Kind: kind} }

// validStrategy — минимальная корректная стратегия: разрезать ClientHello на
// границе TCP и отправить обе части по порядку.
func validStrategy() *Strategy {
	return &Strategy{Rules: []Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   Trigger{Match: MatchClientHello},
		Action: &Action{
			Kind:   core.ActionFragment,
			Params: &FragmentParams{Proto: FragTCP, Offset: 2, Order: FragForward},
			Left:   leaf(core.ActionSend),
			Right:  leaf(core.ActionSend),
		},
	}}}
}

func TestValidateAcceptsValid(t *testing.T) {
	if err := Validate(validStrategy(), DefaultLimits()); err != nil {
		t.Fatalf("корректная стратегия отвергнута: %v", err)
	}
}

// codeOf извлекает код ValidationError или пустую строку.
func codeOf(err error) string {
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve.Code
	}
	return ""
}

// TestValidateAcceptsFakePreset: подмена тела готовым пресетом (без Length) —
// законная конфигурация. Это форма, которой пользуется стратегия голоса.
func TestValidateAcceptsFakePreset(t *testing.T) {
	s := validStrategy()
	s.Rules[0].Action = &Action{
		Kind: core.ActionDuplicate,
		Left: &Action{
			Kind:   core.ActionTamper,
			Params: &TamperParams{Field: FieldTCPChecksum, Mode: TamperCorrupt},
			Left: &Action{
				Kind:   core.ActionTamper,
				Params: &TamperParams{Field: FieldPayload, Mode: TamperReplace, Preset: PresetTLSGoogle},
				Left:   leaf(core.ActionSend),
			},
		},
		Right: leaf(core.ActionSend),
	}
	if err := Validate(s, DefaultLimits()); err != nil {
		t.Fatalf("стратегия с пресетом фейка отвергнута: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Strategy)
		code string
	}{
		{"нет правил", func(s *Strategy) { s.Rules = nil }, ErrNoRules},
		{"неизвестное направление", func(s *Strategy) { s.Rules[0].Direction = core.Direction(9) }, ErrBadDirection},
		{"nth с нулём", func(s *Strategy) {
			s.Rules[0].Trigger = Trigger{Match: MatchNthPacket, N: 0}
		}, ErrBadTrigger},
		{"поле-триггер по телу", func(s *Strategy) {
			s.Rules[0].Trigger = Trigger{Match: MatchField, Field: FieldPayload, Op: OpEqual}
		}, ErrBadTrigger},
		{"значение шире поля", func(s *Strategy) {
			s.Rules[0].Trigger = Trigger{Match: MatchField, Field: FieldIPv4TTL, Op: OpEqual, Value: 999}
		}, ErrBadTrigger},
		{"нет действия", func(s *Strategy) { s.Rules[0].Action = nil }, ErrNoAction},
		{"неизвестный вид", func(s *Strategy) { s.Rules[0].Action = &Action{Kind: core.ActionKind(42)} }, ErrUnknownKind},
		{"лист с ветвью", func(s *Strategy) {
			s.Rules[0].Action = &Action{Kind: core.ActionSend, Left: leaf(core.ActionSend)}
		}, ErrBadArity},
		{"tamper с right", func(s *Strategy) {
			s.Rules[0].Action = &Action{
				Kind: core.ActionTamper, Params: &TamperParams{Field: FieldIPv4TTL, Mode: TamperReplace, Value: 3},
				Left: leaf(core.ActionSend), Right: leaf(core.ActionSend),
			}
		}, ErrBadArity},
		{"duplicate без right", func(s *Strategy) {
			s.Rules[0].Action = &Action{Kind: core.ActionDuplicate, Left: leaf(core.ActionSend)}
		}, ErrBadArity},
		{"tamper без параметров", func(s *Strategy) {
			s.Rules[0].Action = &Action{Kind: core.ActionTamper, Left: leaf(core.ActionSend)}
		}, ErrMissingParams},
		{"лист с параметрами", func(s *Strategy) {
			s.Rules[0].Action = &Action{Kind: core.ActionSend, Params: &TamperParams{Field: FieldIPv4TTL}}
		}, ErrParamsOnLeaf},
		{"фейк тела без длины", func(s *Strategy) {
			s.Rules[0].Action = &Action{
				Kind: core.ActionTamper, Params: &TamperParams{Field: FieldPayload, Mode: TamperReplace},
				Left: leaf(core.ActionSend),
			}
		}, ErrBadParams},
		{"фейк тела: preset и length вместе", func(s *Strategy) {
			s.Rules[0].Action = &Action{
				Kind: core.ActionTamper, Params: &TamperParams{Field: FieldPayload, Mode: TamperReplace, Preset: PresetTLSGoogle, Length: 10},
				Left: leaf(core.ActionSend),
			}
		}, ErrBadParams},
		{"фейк тела: неизвестный пресет", func(s *Strategy) {
			s.Rules[0].Action = &Action{
				Kind: core.ActionTamper, Params: &TamperParams{Field: FieldPayload, Mode: TamperReplace, Preset: "нет-такого"},
				Left: leaf(core.ActionSend),
			}
		}, ErrBadParams},
		{"preset на числовом поле", func(s *Strategy) {
			s.Rules[0].Action = &Action{
				Kind: core.ActionTamper, Params: &TamperParams{Field: FieldIPv4TTL, Mode: TamperReplace, Value: 3, Preset: PresetTLSGoogle},
				Left: leaf(core.ActionSend),
			}
		}, ErrBadParams},
		{"смещение фрагмента нулевое", func(s *Strategy) {
			s.Rules[0].Action.Params = &FragmentParams{Proto: FragTCP, Offset: 0}
		}, ErrBadParams},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := validStrategy()
			c.mut(s)
			err := Validate(s, DefaultLimits())
			if err == nil {
				t.Fatalf("ожидалась ошибка %q, получено nil", c.code)
			}
			if got := codeOf(err); got != c.code {
				t.Fatalf("код ошибки = %q, ожидался %q (err: %v)", got, c.code, err)
			}
		})
	}
}

func TestValidateDepthAndNodeLimits(t *testing.T) {
	// Строим цепочку Tamper->...->Send глубже предела.
	limits := DefaultLimits()
	limits.MaxDepth = 3
	chain := leaf(core.ActionSend)
	for i := 0; i < 5; i++ {
		chain = &Action{
			Kind:   core.ActionTamper,
			Params: &TamperParams{Field: FieldIPv4TTL, Mode: TamperReplace, Value: 1},
			Left:   chain,
		}
	}
	s := &Strategy{Rules: []Rule{{Direction: core.DirectionOutbound, Trigger: Trigger{Match: MatchAlways}, Action: chain}}}
	if got := codeOf(Validate(s, limits)); got != ErrTooDeep {
		t.Fatalf("ожидался %q, получено %q", ErrTooDeep, got)
	}
}

func TestRequiredCapabilities(t *testing.T) {
	// Fragment(IP, reverse) -> [ Tamper(tcp_checksum, corrupt) -> Send , Drop ]
	s := &Strategy{Rules: []Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   Trigger{Match: MatchClientHello},
		Action: &Action{
			Kind:   core.ActionFragment,
			Params: &FragmentParams{Proto: FragIP, Offset: 4, Order: FragReverse},
			Left: &Action{
				Kind:   core.ActionTamper,
				Params: &TamperParams{Field: FieldTCPChecksum, Mode: TamperCorrupt},
				Left:   leaf(core.ActionSend),
			},
			Right: leaf(core.ActionDrop),
		},
	}}}
	if err := Validate(s, DefaultLimits()); err != nil {
		t.Fatalf("стратегия должна быть корректна: %v", err)
	}
	got := RequiredCapabilities(s)
	want := core.PrimitiveSet(0).
		With(core.CapFragmentIP).
		With(core.CapReorder).
		With(core.CapTamper).
		With(core.CapTamperChecksumCorrupt).
		With(core.CapDrop)
	if got != want {
		t.Fatalf("возможности = %v, ожидалось %v", got, want)
	}
}

func TestComputeIDDeterministicAndSensitive(t *testing.T) {
	id1, err := ComputeID(validStrategy())
	if err != nil {
		t.Fatal(err)
	}
	id2, err := ComputeID(validStrategy())
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("идентификатор недетерминирован: %q != %q", id1, id2)
	}
	// Мутация дерева обязана менять идентификатор.
	mutated := validStrategy()
	mutated.Rules[0].Action.Params = &FragmentParams{Proto: FragTCP, Offset: 7, Order: FragForward}
	id3, err := ComputeID(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if id3 == id1 {
		t.Fatal("мутация не изменила идентификатор")
	}
}
