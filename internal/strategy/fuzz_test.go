package strategy

import "testing"

// FuzzUnmarshal проверяет, что разбор недоверенного описания стратегии никогда
// не паникует и не зацикливается: это самый выгодный для фаззинга участок
// проекта (разбор внешних данных, требование 8.2). От корректности результата
// фаззинг не зависит — важно отсутствие паники и то, что принятая стратегия
// затем проходит валидацию без расхождений.
func FuzzUnmarshal(f *testing.F) {
	seeds := []string{
		`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"send"}}]}`,
		`{"rules":[{"direction":"inbound","trigger":{"match":"field","field":"tcp_flags","op":"has_bits","value":4},"action":{"kind":"drop"}}]}`,
		`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"fragment","params":{"proto":"tcp","offset":2},"left":{"kind":"send"},"right":{"kind":"send"}}}]}`,
		`{}`,
		`not json`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	limits := DefaultLimits()
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Unmarshal(data, limits)
		if err != nil {
			return
		}
		// Принятая стратегия обязана быть валидной (Unmarshal валидирует) и
		// повторно сериализуемой без ошибки — иначе разбор и проверка
		// рассогласованы.
		if err := Validate(s, limits); err != nil {
			t.Fatalf("принятая стратегия не проходит повторную валидацию: %v", err)
		}
		if _, err := Marshal(s); err != nil {
			t.Fatalf("принятая стратегия не сериализуется: %v", err)
		}
	})
}
