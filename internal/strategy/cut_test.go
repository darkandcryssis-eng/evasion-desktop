package strategy

import (
	"strings"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
)

// fragWith строит стратегию с заданными параметрами фрагментации.
func fragWith(p *FragmentParams) *Strategy {
	return &Strategy{Rules: []Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   Trigger{Match: MatchClientHello},
		Action: &Action{
			Kind:   core.ActionFragment,
			Params: p,
			Left:   &Action{Kind: core.ActionSend},
			Right:  &Action{Kind: core.ActionSend},
		},
	}}}
}

// Требование «ровно один способ задания места разреза» не выражено типами
// (выбор в пользу удобства генератора, 4.3), поэтому его обязаны держать тесты.
func TestFragmentPlaceExactlyOneWay(t *testing.T) {
	cases := []struct {
		name   string
		params *FragmentParams
		errHas string
	}{
		{"только смещение", &FragmentParams{Proto: FragTCP, Offset: 5}, ""},
		{"только точка", &FragmentParams{Proto: FragTCP, At: core.CutInsideSNI}, ""},
		{"оба способа", &FragmentParams{Proto: FragTCP, Offset: 5, At: core.CutInsideSNI}, "ровно одно"},
		{"ни одного", &FragmentParams{Proto: FragTCP}, "не задано место разреза"},
		{"неизвестная точка", &FragmentParams{Proto: FragTCP, At: core.CutKind(200)}, "недопустимая точка"},
		{"смещение сверх предела", &FragmentParams{Proto: FragTCP, Offset: 1 << 30}, "превышает предел"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Validate(fragWith(c.params), DefaultLimits())
			switch {
			case c.errHas == "" && err != nil:
				t.Fatalf("ожидалась годная стратегия, получено %v", err)
			case c.errHas != "" && err == nil:
				t.Fatalf("ожидалась ошибка с %q", c.errHas)
			case c.errHas != "" && !strings.Contains(err.Error(), c.errHas):
				t.Fatalf("ошибка %q не содержит %q", err, c.errHas)
			}
		})
	}
}

func TestFragmentCutPointRoundTrip(t *testing.T) {
	// Стратегия с точкой разреза должна переноситься через сериализацию без
	// потерь: портфель хранится данными, и найденное генератором выгружается
	// на другую машину (10.2).
	s := fragWith(&FragmentParams{Proto: FragTCP, At: core.CutInsideSNI})
	data, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"at":"inside_sni"`) {
		t.Fatalf("обозначение точки не попало в запись: %s", data)
	}
	back, err := Unmarshal(data, DefaultLimits())
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	p, ok := back.Rules[0].Action.Params.(*FragmentParams)
	if !ok {
		t.Fatal("параметры не того типа")
	}
	if p.At != core.CutInsideSNI || p.Offset != 0 {
		t.Fatalf("после переноса at=%v offset=%d", p.At, p.Offset)
	}
}

func TestFragmentHandWrittenCutPoint(t *testing.T) {
	// Рукописное описание с точкой разреза (10.2).
	src := `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},
	  "action":{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni"},
	  "left":{"kind":"send"},"right":{"kind":"send"}}}]}`
	s, err := Unmarshal([]byte(src), DefaultLimits())
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	p := s.Rules[0].Action.Params.(*FragmentParams)
	if p.At != core.CutInsideSNI {
		t.Fatalf("точка разреза %v", p.At)
	}
}

func TestFragmentUnknownCutTokenRejected(t *testing.T) {
	src := `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},
	  "action":{"kind":"fragment","params":{"proto":"tcp","at":"inside-sni"},
	  "left":{"kind":"send"},"right":{"kind":"send"}}}]}`
	if _, err := Unmarshal([]byte(src), DefaultLimits()); err == nil {
		t.Fatal("неизвестное обозначение точки должно отвергаться")
	}
}

func TestFragmentCutPointCapabilities(t *testing.T) {
	// Способ задания места разреза не меняет требуемых возможностей: разрез
	// остаётся разрезом того же уровня. Иначе исполнитель этапа 0 перестал бы
	// принимать структурные разрезы без причины.
	byOffset := RequiredCapabilities(fragWith(&FragmentParams{Proto: FragTCP, Offset: 5}))
	byPoint := RequiredCapabilities(fragWith(&FragmentParams{Proto: FragTCP, At: core.CutInsideSNI}))
	if byOffset != byPoint {
		t.Fatalf("возможности разошлись: %v против %v", byOffset, byPoint)
	}
}
