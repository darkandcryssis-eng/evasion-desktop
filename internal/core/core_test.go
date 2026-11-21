package core

import (
	"encoding"
	"testing"
)

// Проверяем, что перечисления переживают текстовый цикл сериализации и что
// неизвестные токены отвергаются (данные недоверенны).

func TestDirectionTextRoundTrip(t *testing.T) {
	for _, d := range []Direction{DirectionOutbound, DirectionInbound} {
		text, err := d.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v): %v", d, err)
		}
		var got Direction
		if err := got.UnmarshalText(text); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", text, err)
		}
		if got != d {
			t.Fatalf("цикл изменил значение: %v -> %q -> %v", d, text, got)
		}
	}
}

func TestDirectionUnmarshalUnknown(t *testing.T) {
	var d Direction
	if err := d.UnmarshalText([]byte("sideways")); err == nil {
		t.Fatal("ожидалась ошибка на неизвестном направлении")
	}
}

func TestActionKindRoundTripAndArity(t *testing.T) {
	cases := []struct {
		kind  ActionKind
		arity int
		leaf  bool
	}{
		{ActionSend, 0, true},
		{ActionDrop, 0, true},
		{ActionTamper, 1, false},
		{ActionDuplicate, 2, false},
		{ActionFragment, 2, false},
	}
	for _, c := range cases {
		n, ok := c.kind.Arity()
		if !ok || n != c.arity {
			t.Fatalf("Arity(%v) = %d,%v; ожидалось %d,true", c.kind, n, ok, c.arity)
		}
		if c.kind.IsLeaf() != c.leaf {
			t.Fatalf("IsLeaf(%v) = %v; ожидалось %v", c.kind, c.kind.IsLeaf(), c.leaf)
		}
		text, err := c.kind.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v): %v", c.kind, err)
		}
		var got ActionKind
		if err := got.UnmarshalText(text); err != nil || got != c.kind {
			t.Fatalf("цикл изменил вид: %v -> %q -> %v (err=%v)", c.kind, text, got, err)
		}
	}
}

func TestActionKindUnknownArity(t *testing.T) {
	if _, ok := ActionKind(200).Arity(); ok {
		t.Fatal("неизвестный вид не должен иметь арности")
	}
}

func TestCapabilitySetOps(t *testing.T) {
	s := PrimitiveSet(0).With(CapTamper).With(CapFragmentTCP)
	if !s.Has(CapTamper) || !s.Has(CapFragmentTCP) {
		t.Fatal("добавленные возможности должны присутствовать")
	}
	if s.Has(CapReorder) {
		t.Fatal("недобавленная возможность присутствует")
	}

	required := PrimitiveSet(0).With(CapTamper)
	if !s.Contains(required) {
		t.Fatal("множество должно содержать своё подмножество")
	}
	notThere := PrimitiveSet(0).With(CapReorder)
	if s.Contains(notThere) {
		t.Fatal("множество не должно содержать отсутствующую возможность")
	}
	if miss := s.Missing(notThere); !miss.Has(CapReorder) {
		t.Fatal("Missing должен вернуть недостающую возможность")
	}
	if miss := s.Missing(required); miss != 0 {
		t.Fatalf("Missing для покрытого требования должен быть пуст, получено %v", miss)
	}
}

func TestPrimitiveSetTextRoundTrip(t *testing.T) {
	s := PrimitiveSet(0).With(CapDrop).With(CapTamperChecksumCorrupt).With(CapReorder)
	text, err := s.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	var got PrimitiveSet
	if err := got.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText(%q): %v", text, err)
	}
	if got != s {
		t.Fatalf("цикл изменил множество: %v -> %q -> %v", s, text, got)
	}
}

func TestPrimitiveSetEmptyAndUnknown(t *testing.T) {
	var got PrimitiveSet
	if err := got.UnmarshalText([]byte("")); err != nil || got != 0 {
		t.Fatalf("пустая строка должна дать пустое множество, got=%v err=%v", got, err)
	}
	if err := got.UnmarshalText([]byte("tamper,bogus")); err == nil {
		t.Fatal("ожидалась ошибка на неизвестном токене возможности")
	}
}

// Статическая проверка: типы реализуют текстовые интерфейсы, на которые
// опирается JSON-сериализация.
var (
	_ encoding.TextMarshaler   = Direction(0)
	_ encoding.TextUnmarshaler = (*Direction)(nil)
	_ encoding.TextMarshaler   = ActionKind(0)
	_ encoding.TextUnmarshaler = (*ActionKind)(nil)
	_ encoding.TextMarshaler   = PrimitiveSet(0)
	_ encoding.TextUnmarshaler = (*PrimitiveSet)(nil)
)
