package desync

import (
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// fieldMap — простой источник полей для тестов триггера MatchField.
type fieldMap map[strategy.FieldID]uint64

func (m fieldMap) Field(f strategy.FieldID) (uint64, bool) {
	v, ok := m[f]
	return v, ok
}

func TestTriggerMatches(t *testing.T) {
	cases := []struct {
		name    string
		trigger strategy.Trigger
		input   Input
		want    bool
	}{
		{
			name:    "always",
			trigger: strategy.Trigger{Match: strategy.MatchAlways},
			input:   Input{},
			want:    true,
		},
		{
			name:    "client_hello да",
			trigger: strategy.Trigger{Match: strategy.MatchClientHello},
			input:   Input{IsClientHello: true},
			want:    true,
		},
		{
			name:    "client_hello нет",
			trigger: strategy.Trigger{Match: strategy.MatchClientHello},
			input:   Input{IsClientHello: false},
			want:    false,
		},
		{
			name:    "nth совпал",
			trigger: strategy.Trigger{Match: strategy.MatchNthPacket, N: 3},
			input:   Input{Ordinal: 3},
			want:    true,
		},
		{
			name:    "nth не совпал",
			trigger: strategy.Trigger{Match: strategy.MatchNthPacket, N: 3},
			input:   Input{Ordinal: 2},
			want:    false,
		},
		{
			name:    "field equal",
			trigger: strategy.Trigger{Match: strategy.MatchField, Field: strategy.FieldTCPFlags, Op: strategy.OpEqual, Value: 0x12},
			input:   Input{Fields: fieldMap{strategy.FieldTCPFlags: 0x12}},
			want:    true,
		},
		{
			name:    "field has_bits — RST установлен",
			trigger: strategy.Trigger{Match: strategy.MatchField, Field: strategy.FieldTCPFlags, Op: strategy.OpHasBits, Value: 0x04},
			input:   Input{Fields: fieldMap{strategy.FieldTCPFlags: 0x14}},
			want:    true,
		},
		{
			name:    "field has_bits — бит отсутствует",
			trigger: strategy.Trigger{Match: strategy.MatchField, Field: strategy.FieldTCPFlags, Op: strategy.OpHasBits, Value: 0x04},
			input:   Input{Fields: fieldMap{strategy.FieldTCPFlags: 0x10}},
			want:    false,
		},
		{
			// В режиме прокси источника полей нет: триггер по полю не
			// срабатывает — это осознанный «не сработал», а не ошибка.
			name:    "field без источника",
			trigger: strategy.Trigger{Match: strategy.MatchField, Field: strategy.FieldTCPFlags, Op: strategy.OpEqual, Value: 0x12},
			input:   Input{Fields: nil},
			want:    false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.input.triggerMatches(c.trigger); got != c.want {
				t.Fatalf("triggerMatches = %v, ожидалось %v", got, c.want)
			}
		})
	}
}

// TestBuildPlanDirectionFilter проверяет, что правило другого направления не
// рассматривается, даже если его триггер подходит.
func TestBuildPlanDirectionFilter(t *testing.T) {
	// Правило по входящему RST, а событие исходящее — правило не должно
	// сработать, план станет сквозным пропуском.
	s := &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionInbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchAlways},
		Action:    drop(),
	}}}
	plan, err := BuildPlan(s, outboundHello("DATA"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Ops) != 1 || plan.Ops[0].Kind != OpSendReal {
		t.Fatalf("ожидался сквозной пропуск, получено %s", dumpPlan(plan))
	}
}
