package core

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestStatusTokensRoundTrip(t *testing.T) {
	for _, s := range Statuses() {
		text, err := s.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v): %v", s, err)
		}
		var back Status
		if err := back.UnmarshalText(text); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", text, err)
		}
		if back != s {
			t.Fatalf("круговой разбор дал %v вместо %v", back, s)
		}
	}
}

// TestStatusZeroValueIsNotAStep: стратегия без статуса — дефект портфеля, а не
// «новая стратегия». Новая называется candidate явно.
func TestStatusZeroValueIsNotAStep(t *testing.T) {
	var s Status
	if s.Valid() {
		t.Fatal("нулевой статус не должен считаться годным")
	}
	if s.ServesLiveTraffic() || s.ServesAllTraffic() {
		t.Fatal("стратегия без статуса не допускается к трафику")
	}
	for _, v := range Statuses() {
		if v == StatusUnset {
			t.Fatal("StatusUnset не ступень и в перечислении быть не должен")
		}
	}
}

// TestStatusAdmission закрепляет таблицу допуска из 5.1. Главное различие —
// candidate против testing: первый допускается только к соединениям, которые
// движок инициирует сам, второй уже к доле реального трафика. На этом
// различии держится запрет генетического поиска на живом трафике (1.4 п. 6).
func TestStatusAdmission(t *testing.T) {
	for _, tc := range []struct {
		status Status
		live   bool
		all    bool
	}{
		{StatusCandidate, false, false},
		{StatusTesting, true, false},
		{StatusActive, true, true},
		{StatusBenched, false, false},
		{StatusDegraded, false, false},
		{StatusRetired, false, false},
	} {
		t.Run(tc.status.String(), func(t *testing.T) {
			if got := tc.status.ServesLiveTraffic(); got != tc.live {
				t.Fatalf("ServesLiveTraffic = %v, ожидалось %v", got, tc.live)
			}
			if got := tc.status.ServesAllTraffic(); got != tc.all {
				t.Fatalf("ServesAllTraffic = %v, ожидалось %v", got, tc.all)
			}
		})
	}
}

func TestStatusUnknownTokenRejected(t *testing.T) {
	var s Status
	err := s.UnmarshalText([]byte("хорошая"))
	if err == nil {
		t.Fatal("неизвестное имя статуса должно быть ошибкой, а не StatusUnset")
	}
	var unknown *UnknownTokenError
	if !errors.As(err, &unknown) {
		t.Fatalf("ошибка = %v, ожидалась UnknownTokenError", err)
	}
	if unknown.Kind != "status" {
		t.Fatalf("вид = %q, ожидался status", unknown.Kind)
	}
}

// TestStatusJSONIsText: статусы попадают в архив и в вывод --json текстом, а
// не числом. Числа привязали бы архив к текущему порядку констант, и
// перестановка молча испортила бы историю.
func TestStatusJSONIsText(t *testing.T) {
	data, err := json.Marshal(struct {
		Status Status `json:"status"`
	}{StatusTesting})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(data) != `{"status":"testing"}` {
		t.Fatalf("JSON = %s, ожидался текстовый статус", data)
	}
}
