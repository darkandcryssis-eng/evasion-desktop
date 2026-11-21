package generator

import (
	"math/rand/v2"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// fullCaps — возможности пакетного исполнителя (этап 1): всё, что умеет
// packetexec. Из них генератор вправе строить любой примитив.
func fullCaps() core.PrimitiveSet {
	return core.PrimitiveSet(0).
		With(core.CapDrop).
		With(core.CapTamper).
		With(core.CapTamperChecksumCorrupt).
		With(core.CapDuplicate).
		With(core.CapFragmentTCP).
		With(core.CapReorder).
		With(core.CapDelay)
}

func newGen(t *testing.T, caps core.PrimitiveSet, seed uint64) *Generator {
	t.Helper()
	g, err := New(Config{
		Caps:   caps,
		Limits: strategy.DefaultLimits(),
		Rand:   rand.New(rand.NewPCG(seed, seed)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// assertSound — главный инвариант генератора: что бы он ни выдал, оно валидно,
// исполнимо при возможностях и с проставленным идентификатором.
func assertSound(t *testing.T, s *strategy.Strategy, caps core.PrimitiveSet) {
	t.Helper()
	if s == nil {
		t.Fatal("стратегия nil")
	}
	if err := strategy.Validate(s, strategy.DefaultLimits()); err != nil {
		t.Fatalf("невалидная стратегия: %v", err)
	}
	if req := strategy.RequiredCapabilities(s); !caps.Contains(req) {
		t.Fatalf("стратегия требует возможностей вне набора: нужно %v, есть %v (не хватает %v)",
			req, caps, caps.Missing(req))
	}
	if s.ID == "" {
		t.Fatal("идентификатор не проставлен")
	}
}

func TestRandomIsAlwaysSound(t *testing.T) {
	caps := fullCaps()
	g := newGen(t, caps, 1)
	for i := 0; i < 300; i++ {
		s, err := g.Random()
		if err != nil {
			t.Fatalf("Random #%d: %v", i, err)
		}
		assertSound(t, s, caps)
		// Правило одно: исходящий ClientHello.
		if len(s.Rules) != 1 {
			t.Fatalf("ожидалось одно правило, получено %d", len(s.Rules))
		}
		if s.Rules[0].Direction != core.DirectionOutbound || s.Rules[0].Trigger.Match != strategy.MatchClientHello {
			t.Fatalf("неожиданное правило: %+v", s.Rules[0])
		}
	}
}

// TestRespectsRestrictedCaps — при урезанных возможностях генератор не порождает
// того, что исполнитель не умеет. Проверяем набором без фрагментации,
// дублирования, порчи суммы и Drop: остаётся только Tamper числовых/телесных
// полей без контрольной суммы.
func TestRespectsRestrictedCaps(t *testing.T) {
	caps := core.PrimitiveSet(0).With(core.CapTamper)
	g := newGen(t, caps, 7)
	for i := 0; i < 300; i++ {
		s, err := g.Random()
		if err != nil {
			t.Fatalf("Random #%d: %v", i, err)
		}
		assertSound(t, s, caps)
		// Обойдём дерево: ни fragment, ни duplicate, ни drop, ни правка суммы.
		walkActions(s, func(a *strategy.Action) {
			switch a.Kind {
			case core.ActionFragment, core.ActionDuplicate, core.ActionDrop:
				t.Fatalf("примитив %s вне возможностей", a.Kind)
			}
			if tp, ok := a.Params.(*strategy.TamperParams); ok && tp.Field.IsChecksum() {
				t.Fatal("правка контрольной суммы без CapTamperChecksumCorrupt")
			}
		})
	}
}

// TestNeverTampersTCPOptions — генератор не правит опции TCP (MSS, масштаб
// окна): на ClientHello-сегменте их нет, правка была бы заведомо мёртвой.
func TestNeverTampersTCPOptions(t *testing.T) {
	g := newGen(t, fullCaps(), 13)
	for i := 0; i < 300; i++ {
		s, err := g.Random()
		if err != nil {
			t.Fatalf("Random #%d: %v", i, err)
		}
		walkActions(s, func(a *strategy.Action) {
			if tp, ok := a.Params.(*strategy.TamperParams); ok && tp.Field.IsTCPOption() {
				t.Fatalf("правка опции TCP %s недопустима: её нет на ClientHello", tp.Field)
			}
		})
	}
}

// TestIPVersionRestrictsFields — при заданной версии IP генератор не правит
// поля другой версии (на трафике той версии их нет). TCP-поля и тело остаются.
func TestIPVersionRestrictsFields(t *testing.T) {
	check := func(version int, forbid func(strategy.FieldID) bool, label string) {
		g, err := New(Config{Caps: fullCaps(), Limits: strategy.DefaultLimits(), IPVersion: version, Rand: rand.New(rand.NewPCG(1, 1))})
		if err != nil {
			t.Fatalf("New(ip=%d): %v", version, err)
		}
		for i := 0; i < 300; i++ {
			s, err := g.Random()
			if err != nil {
				t.Fatal(err)
			}
			walkActions(s, func(a *strategy.Action) {
				if tp, ok := a.Params.(*strategy.TamperParams); ok && forbid(tp.Field) {
					t.Fatalf("ip=%d: правка поля %s недопустима (%s)", version, tp.Field, label)
				}
			})
		}
	}
	check(4, strategy.FieldID.IsIPv6, "IPv6-поле на IPv4")
	check(6, strategy.FieldID.IsIPv4, "IPv4-поле на IPv6")
}

func TestNewRejectsBadIPVersion(t *testing.T) {
	if _, err := New(Config{Caps: fullCaps(), Limits: strategy.DefaultLimits(), IPVersion: 5}); err == nil {
		t.Fatal("ожидалась ошибка для недопустимой версии IP")
	}
}

func TestNewRejectsNoInternalPrimitive(t *testing.T) {
	// Пустые возможности: ни одного внутреннего примитива — строить нечего.
	if _, err := New(Config{Caps: 0, Limits: strategy.DefaultLimits()}); err == nil {
		t.Fatal("ожидалась ошибка при пустых возможностях")
	}
	// Только Drop — это лист, не внутренний узел: дерево не построить.
	if _, err := New(Config{Caps: core.PrimitiveSet(0).With(core.CapDrop), Limits: strategy.DefaultLimits()}); err == nil {
		t.Fatal("ожидалась ошибка: Drop — лист, внутреннего примитива нет")
	}
}

func TestNewRejectsBadLimitsAndDepth(t *testing.T) {
	caps := fullCaps()
	if _, err := New(Config{Caps: caps}); err == nil {
		t.Fatal("ожидалась ошибка при нулевых пределах")
	}
	if _, err := New(Config{Caps: caps, Limits: strategy.DefaultLimits(), MaxDepth: 1}); err == nil {
		t.Fatal("ожидалась ошибка при глубине меньше 2")
	}
	lim := strategy.DefaultLimits()
	if _, err := New(Config{Caps: caps, Limits: lim, MaxDepth: lim.MaxDepth + 1}); err == nil {
		t.Fatal("ожидалась ошибка при глубине больше предела валидации")
	}
}

// TestDeterministicWithSeed — один и тот же сид даёт одну и ту же
// последовательность стратегий: поиск воспроизводим.
func TestDeterministicWithSeed(t *testing.T) {
	caps := fullCaps()
	g1 := newGen(t, caps, 42)
	g2 := newGen(t, caps, 42)
	for i := 0; i < 50; i++ {
		s1, err1 := g1.Random()
		s2, err2 := g2.Random()
		if err1 != nil || err2 != nil {
			t.Fatalf("Random: %v / %v", err1, err2)
		}
		if s1.ID != s2.ID {
			t.Fatalf("на шаге %d идентификаторы разошлись: %s != %s", i, s1.ID, s2.ID)
		}
	}
}

func TestMutatePreservesSoundness(t *testing.T) {
	caps := fullCaps()
	g := newGen(t, caps, 3)
	changed := 0
	for i := 0; i < 300; i++ {
		base, err := g.Random()
		if err != nil {
			t.Fatalf("Random: %v", err)
		}
		mut, err := g.Mutate(base)
		if err != nil {
			t.Fatalf("Mutate #%d: %v", i, err)
		}
		assertSound(t, mut, caps)
		if mut.ID != base.ID {
			changed++
		}
	}
	// Мутация обязана хоть иногда менять стратегию, иначе она бесполезна.
	if changed == 0 {
		t.Fatal("мутация ни разу не изменила стратегию")
	}
}

func TestCrossoverPreservesSoundness(t *testing.T) {
	caps := fullCaps()
	g := newGen(t, caps, 9)
	for i := 0; i < 300; i++ {
		a, err := g.Random()
		if err != nil {
			t.Fatalf("Random a: %v", err)
		}
		b, err := g.Random()
		if err != nil {
			t.Fatalf("Random b: %v", err)
		}
		child, err := g.Crossover(a, b)
		if err != nil {
			t.Fatalf("Crossover #%d: %v", i, err)
		}
		assertSound(t, child, caps)
	}
}

// TestMutateDoesNotTouchOriginal — мутация возвращает копию, исходная не
// меняется (глубокое копирование дерева).
func TestMutateDoesNotTouchOriginal(t *testing.T) {
	caps := fullCaps()
	g := newGen(t, caps, 11)
	base, err := g.Random()
	if err != nil {
		t.Fatal(err)
	}
	before, err := strategy.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Mutate(base); err != nil {
		t.Fatal(err)
	}
	after, err := strategy.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("мутация изменила исходную стратегию")
	}
}

// walkActions обходит все узлы всех правил стратегии.
func walkActions(s *strategy.Strategy, fn func(*strategy.Action)) {
	var walk func(a *strategy.Action)
	walk = func(a *strategy.Action) {
		if a == nil {
			return
		}
		fn(a)
		walk(a.Left)
		walk(a.Right)
	}
	for i := range s.Rules {
		walk(s.Rules[i].Action)
	}
}
