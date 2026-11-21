package generator

import (
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// capsWithOverlap — пакетные возможности плюс CapTCPOverlap: только с ней
// генератор вправе порождать tcp_overlap.
func capsWithOverlap() core.PrimitiveSet {
	return fullCaps().With(core.CapTCPOverlap)
}

// validCoverPreset сообщает, что имя входит в набор cover-пресетов. Генератор
// обязан брать preset только оттуда — иначе overlap собьётся по размеру.
func validCoverPreset(name string) bool {
	for _, n := range strategy.CoverPresetNames() {
		if n == name {
			return true
		}
	}
	return false
}

// TestGeneratesTCPOverlapWhenCapable — при наличии CapTCPOverlap генератор
// хотя бы иногда строит tcp_overlap, и каждый такой узел несёт корректный
// cover-пресет (имя из CoverPresetNames) без поддеревьев (это лист).
func TestGeneratesTCPOverlapWhenCapable(t *testing.T) {
	caps := capsWithOverlap()
	g := newGen(t, caps, 5)
	seen := 0
	for i := 0; i < 500; i++ {
		s, err := g.Random()
		if err != nil {
			t.Fatalf("Random #%d: %v", i, err)
		}
		assertSound(t, s, caps)
		walkActions(s, func(a *strategy.Action) {
			if a.Kind != core.ActionTCPOverlap {
				return
			}
			seen++
			if a.Left != nil || a.Right != nil {
				t.Fatal("tcp_overlap — лист, но у узла есть ветви")
			}
			p, ok := a.Params.(*strategy.TCPOverlapParams)
			if !ok {
				t.Fatalf("tcp_overlap без TCPOverlapParams: %T", a.Params)
			}
			if !validCoverPreset(p.Preset) {
				t.Fatalf("tcp_overlap с пресетом вне набора cover: %q", p.Preset)
			}
		})
	}
	if seen == 0 {
		t.Fatal("за 500 попыток генератор ни разу не построил tcp_overlap")
	}
}

// TestTCPOverlapNotGeneratedWithoutCap — без CapTCPOverlap tcp_overlap не
// порождается (иначе поиск плодил бы неисполнимое).
func TestTCPOverlapNotGeneratedWithoutCap(t *testing.T) {
	caps := fullCaps() // без CapTCPOverlap
	g := newGen(t, caps, 17)
	for i := 0; i < 500; i++ {
		s, err := g.Random()
		if err != nil {
			t.Fatalf("Random #%d: %v", i, err)
		}
		walkActions(s, func(a *strategy.Action) {
			if a.Kind == core.ActionTCPOverlap {
				t.Fatal("tcp_overlap порождён без CapTCPOverlap")
			}
		})
	}
}

// TestMutateCrossoverSoundWithOverlap — мутация и скрещивание остаются
// корректными, когда в наборе есть tcp_overlap. В частности это ловит потерю
// TCPOverlapParams при клонировании (cloneParams обязан копировать их тип —
// иначе узел станет невалидным).
func TestMutateCrossoverSoundWithOverlap(t *testing.T) {
	caps := capsWithOverlap()
	g := newGen(t, caps, 23)
	for i := 0; i < 400; i++ {
		a, err := g.Random()
		if err != nil {
			t.Fatalf("Random a #%d: %v", i, err)
		}
		b, err := g.Random()
		if err != nil {
			t.Fatalf("Random b #%d: %v", i, err)
		}
		mut, err := g.Mutate(a)
		if err != nil {
			t.Fatalf("Mutate #%d: %v", i, err)
		}
		assertSound(t, mut, caps)
		child, err := g.Crossover(a, b)
		if err != nil {
			t.Fatalf("Crossover #%d: %v", i, err)
		}
		assertSound(t, child, caps)
	}
}

// TestTCPOverlapParamsSurviveClone — прямая проверка cloneParams: копия узла
// tcp_overlap сохраняет имя пресета.
func TestTCPOverlapParamsSurviveClone(t *testing.T) {
	orig := &strategy.Action{
		Kind:   core.ActionTCPOverlap,
		Params: &strategy.TCPOverlapParams{Preset: strategy.PresetTLSCover681Yandex},
	}
	cl := cloneAction(orig)
	p, ok := cl.Params.(*strategy.TCPOverlapParams)
	if !ok {
		t.Fatalf("клон потерял TCPOverlapParams: %T", cl.Params)
	}
	if p.Preset != strategy.PresetTLSCover681Yandex {
		t.Fatalf("клон изменил пресет: %q", p.Preset)
	}
	// Копия независима: правка клона не трогает оригинал.
	p.Preset = strategy.PresetTLSCover681
	if op := orig.Params.(*strategy.TCPOverlapParams); op.Preset != strategy.PresetTLSCover681Yandex {
		t.Fatal("клон делит буфер параметров с оригиналом")
	}
}
