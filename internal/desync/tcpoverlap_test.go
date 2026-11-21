package desync

import (
	"bytes"
	"errors"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// overlapStrategy — стратегия с единственным правилом tcp_overlap на заданном
// cover-пресете, срабатывающим на любое событие (MatchAlways), чтобы в тесте
// можно было подавать произвольную нагрузку, а не только настоящий ClientHello.
func overlapStrategy(preset string) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchAlways},
		Action: &strategy.Action{
			Kind:   core.ActionTCPOverlap,
			Params: &strategy.TCPOverlapParams{Preset: preset},
		},
	}}}
}

// TestTCPOverlapGeometry — рабочий случай M < L: план состоит из двух
// подлинных отправок, cover идёт первым со смещением L-M, настоящая нагрузка
// второй со смещением 0. Это и есть вся механика overlap; геометрия смещений
// — то, на что опирается packetexec при расчёте seq.
func TestTCPOverlapGeometry(t *testing.T) {
	cover, ok := strategy.FakePreset(strategy.PresetTLSCover681)
	if !ok {
		t.Fatal("базовый cover-пресет не найден в реестре")
	}
	M := len(cover)
	// Нагрузка заведомо длиннее cover'а: берём M+64, чтобы была чистая зона
	// L-M, где настоящие байты не перекрыты.
	L := M + 64
	payload := bytes.Repeat([]byte{0xAB}, L)

	plan, err := BuildPlan(overlapStrategy(strategy.PresetTLSCover681),
		Input{Direction: core.DirectionOutbound, Payload: payload})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Ops) != 2 {
		t.Fatalf("ожидали 2 операции (cover+real), получили %d", len(plan.Ops))
	}

	coverOp, realOp := plan.Ops[0], plan.Ops[1]

	// Cover: подлинная отправка (НЕ фейк с правками), ровно байты пресета,
	// смещение L-M.
	if coverOp.Kind != OpSendReal {
		t.Fatalf("cover: вид %v, ожидали OpSendReal", coverOp.Kind)
	}
	if !bytes.Equal(coverOp.Payload, cover) {
		t.Fatal("cover: нагрузка не совпадает с байтами пресета")
	}
	if coverOp.StreamOffset != L-M {
		t.Fatalf("cover: смещение %d, ожидали %d (L-M)", coverOp.StreamOffset, L-M)
	}

	// Real: подлинная отправка всей нагрузки со смещением 0.
	if realOp.Kind != OpSendReal {
		t.Fatalf("real: вид %v, ожидали OpSendReal", realOp.Kind)
	}
	if !bytes.Equal(realOp.Payload, payload) {
		t.Fatal("real: нагрузка не совпадает с исходной")
	}
	if realOp.StreamOffset != 0 {
		t.Fatalf("real: смещение %d, ожидали 0", realOp.StreamOffset)
	}
}

// TestTCPOverlapEdgeUnavailable — крайние значения, при которых перекрытие
// невозможно (нет чистой зоны L-M): M == L, M > L и пустая нагрузка (L=0).
// Во всех случаях приём обязан вернуть ErrCutUnavailable, а НЕ пустую или
// урезанную операцию: молчаливый зажим выглядел бы как применённая стратегия,
// ничего не изменившая, и портил бы измерения (тот же запрет, что у разреза).
func TestTCPOverlapEdgeUnavailable(t *testing.T) {
	cover, _ := strategy.FakePreset(strategy.PresetTLSCover681)
	M := len(cover)

	cases := []struct {
		name string
		L    int
	}{
		{"M == L (нагрузка ровно с cover)", M},
		{"M > L на 1 байт", M - 1},
		{"нагрузка много короче cover", 100},
		{"пустая нагрузка L=0", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0x7}, c.L)
			_, err := BuildPlan(overlapStrategy(strategy.PresetTLSCover681),
				Input{Direction: core.DirectionOutbound, Payload: payload})
			if !errors.Is(err, ErrCutUnavailable) {
				t.Fatalf("L=%d: ошибка %v, ожидали ErrCutUnavailable", c.L, err)
			}
		})
	}
}

// TestTCPOverlapMinimalWorking — граница ровно на единицу выше непригодной:
// L = M+1 уже даёт перекрытие (чистая зона в 1 байт). Проверяет, что условие
// именно M >= L (строгая граница), а не M > L или M >= L-1.
func TestTCPOverlapMinimalWorking(t *testing.T) {
	cover, _ := strategy.FakePreset(strategy.PresetTLSCover681)
	M := len(cover)
	payload := bytes.Repeat([]byte{0x1}, M+1)

	plan, err := BuildPlan(overlapStrategy(strategy.PresetTLSCover681),
		Input{Direction: core.DirectionOutbound, Payload: payload})
	if err != nil {
		t.Fatalf("L=M+1 должно работать, получили %v", err)
	}
	if len(plan.Ops) != 2 {
		t.Fatalf("ожидали 2 операции, получили %d", len(plan.Ops))
	}
	if plan.Ops[0].StreamOffset != 1 {
		t.Fatalf("cover-смещение %d, ожидали 1 (L-M)", plan.Ops[0].StreamOffset)
	}
}

// TestTCPOverlapAllCoverPresetsSameGeometry — все cover-пресеты (базовый и
// SNI-варианты) имеют один размер 681, значит при одной нагрузке дают
// идентичную геометрию смещений и различаются только байтами cover'а (SNI).
// Это и есть инвариант взаимозаменяемости вариантов в одной стратегии.
func TestTCPOverlapAllCoverPresetsSameGeometry(t *testing.T) {
	const L = 681 + 64
	payload := bytes.Repeat([]byte{0x5A}, L)

	var firstOffset int
	for i, name := range strategy.CoverPresetNames() {
		cover, ok := strategy.FakePreset(name)
		if !ok {
			t.Fatalf("cover-пресет %q не найден", name)
		}
		if len(cover) != 681 {
			t.Fatalf("cover-пресет %q: %d байт, ожидали 681", name, len(cover))
		}
		plan, err := BuildPlan(overlapStrategy(name),
			Input{Direction: core.DirectionOutbound, Payload: payload})
		if err != nil {
			t.Fatalf("%q: BuildPlan: %v", name, err)
		}
		if len(plan.Ops) != 2 {
			t.Fatalf("%q: ожидали 2 операции, получили %d", name, len(plan.Ops))
		}
		if !bytes.Equal(plan.Ops[0].Payload, cover) {
			t.Fatalf("%q: cover-операция несёт не байты своего пресета", name)
		}
		off := plan.Ops[0].StreamOffset
		if i == 0 {
			firstOffset = off
		} else if off != firstOffset {
			t.Fatalf("%q: смещение cover %d, у остальных %d — размеры разошлись",
				name, off, firstOffset)
		}
	}
}

func TestTCPSplitSeqOverlapGeometry(t *testing.T) {
	cover, _ := strategy.FakePreset(strategy.PresetTLSCover681)
	payload := bytes.Repeat([]byte{0x5c}, 800)
	s := overlapStrategy(strategy.PresetTLSCover681)
	s.Rules[0].Action.Params.(*strategy.TCPOverlapParams).Offset = 1
	plan, err := BuildPlan(s, Input{Direction: core.DirectionOutbound, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Ops) != 2 || plan.Ops[0].StreamOffset != -len(cover) || plan.Ops[1].StreamOffset != 1 {
		t.Fatalf("unexpected split-seqovl geometry: %+v", plan.Ops)
	}
	wantFirst := append(append([]byte(nil), cover...), payload[0])
	if !bytes.Equal(plan.Ops[0].Payload, wantFirst) || !bytes.Equal(plan.Ops[1].Payload, payload[1:]) {
		t.Fatal("split-seqovl changed the real byte stream")
	}
	if payload[0] != 0x5c {
		t.Fatal("input payload was modified")
	}
}

func TestTCPSplitSeqOverlapRejectsUnsafeGeometry(t *testing.T) {
	s := overlapStrategy(strategy.PresetTLSCover681)
	params := s.Rules[0].Action.Params.(*strategy.TCPOverlapParams)
	for _, tc := range []struct {
		offset, length int
	}{{0, 1}, {1, 1}, {2, 2}, {600, 800}} {
		params.Offset = tc.offset
		_, err := BuildPlan(s, Input{Direction: core.DirectionOutbound, Payload: make([]byte, tc.length)})
		if tc.offset == 0 {
			continue
		}
		if !errors.Is(err, ErrCutUnavailable) {
			t.Fatalf("offset=%d length=%d: %v", tc.offset, tc.length, err)
		}
	}
}
