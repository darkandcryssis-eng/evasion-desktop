package strategy

import (
	"strings"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
)

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	orig := validStrategy()
	data, err := Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Unmarshal(data, DefaultLimits())
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	id, err := ComputeID(orig)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != id {
		t.Fatalf("идентификатор после цикла = %q, ожидался %q", got.ID, id)
	}
	// Повторная сериализация должна дать те же байты (канонична).
	data2, err := Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(data2) {
		t.Fatalf("повторная сериализация расходится:\n%s\n%s", data, data2)
	}
}

func TestUnmarshalHandWritten(t *testing.T) {
	// Стратегию можно написать руками (требование 10.2).
	src := `{
	  "rules": [{
	    "direction": "outbound",
	    "trigger": {"match": "client_hello"},
	    "action": {
	      "kind": "duplicate",
	      "left": {
	        "kind": "tamper",
	        "params": {"field": "ipv4_ttl", "mode": "replace", "value": 3},
	        "left": {"kind": "send"}
	      },
	      "right": {"kind": "send"}
	    }
	  }]
	}`
	s, err := Unmarshal([]byte(src), DefaultLimits())
	if err != nil {
		t.Fatalf("разбор рукописной стратегии: %v", err)
	}
	if s.ID == "" {
		t.Fatal("идентификатор не вычислен")
	}
}

func TestAutoTTLRoundTrip(t *testing.T) {
	s := validStrategy()
	s.Rules[0].Action = &Action{
		Kind:   core.ActionTamper,
		Params: &TamperParams{Field: FieldIPv6HopLimit, Mode: TamperAutoTTL, Value: 3},
		Left:   leaf(core.ActionSend),
	}
	data, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"mode":"auto_ttl"`) {
		t.Fatalf("serialized mode missing: %s", data)
	}
	got, err := Unmarshal(data, DefaultLimits())
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	again, err := Marshal(got)
	if err != nil {
		t.Fatalf("Marshal after round-trip: %v", err)
	}
	if string(data) != string(again) {
		t.Fatalf("serialization changed after round-trip:\n%s\n%s", data, again)
	}
	id, err := ComputeID(s)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != id {
		t.Fatalf("round-trip ID = %q, want %q", got.ID, id)
	}
}

func TestUnmarshalRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // подстрока ожидаемого сообщения
	}{
		{"лишний ключ", `{"rules":[{"direction":"outbound","trigger":{"match":"always"},"action":{"kind":"send"},"bogus":1}]}`, "unknown field"},
		{"параметры у листа", `{"rules":[{"direction":"outbound","trigger":{"match":"always"},"action":{"kind":"send","params":{"field":"ipv4_ttl","mode":"replace"}}}]}`, "не должно быть параметров"},
		{"неизвестный вид", `{"rules":[{"direction":"outbound","trigger":{"match":"always"},"action":{"kind":"warp"}}]}`, "неизвестн"},
		{"неизвестное поле", `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"tamper","params":{"field":"nonsense","mode":"replace"},"left":{"kind":"send"}}}]}`, "неизвестн"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Unmarshal([]byte(c.src), DefaultLimits())
			if err == nil {
				t.Fatalf("ожидалась ошибка, получено nil")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("сообщение %q не содержит %q", err.Error(), c.want)
			}
		})
	}
}

func TestUnmarshalRejectsWrongID(t *testing.T) {
	src := `{"id":"deadbeef","rules":[{"direction":"outbound","trigger":{"match":"always"},"action":{"kind":"send"}}]}`
	_, err := Unmarshal([]byte(src), DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "не совпадает") {
		t.Fatalf("ожидалась ошибка несовпадения идентификатора, получено %v", err)
	}
}
