package strategy

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// nestedDescription строит описание стратегии с цепочкой tamper-узлов заданной
// глубины. Используется для проверки предохранителя и замера стоимости разбора.
func nestedDescription(depth int) []byte {
	var b strings.Builder
	b.WriteString(`{"rules":[{"direction":"outbound","trigger":{"match":"always"},"action":`)
	for range depth {
		b.WriteString(`{"kind":"tamper","params":{"field":"ipv4_ttl","mode":"replace","value":1},"left":`)
	}
	b.WriteString(`{"kind":"send"}`)
	b.WriteString(strings.Repeat(`}`, depth))
	b.WriteString(`}]}`)
	return []byte(b.String())
}

// deepButSmallDepth — глубина, которая превышает предел вложенности, но
// умещается в предел размера по умолчанию (~8 КБ против 32 КиБ). Нужна, чтобы
// тест проверял именно отсечку по вложенности, а не по размеру.
const deepButSmallDepth = 100

func TestEncodedShapeRejectsDeepInput(t *testing.T) {
	data := nestedDescription(deepButSmallDepth)
	if len(data) > DefaultLimits().MaxInputBytes {
		t.Fatalf("ввод %d байт перекрывает предел размера — тест проверял бы не то", len(data))
	}
	_, err := Unmarshal(data, DefaultLimits())
	if err == nil {
		t.Fatal("глубокое описание должно быть отвергнуто")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Code != ErrInputTooDeep {
		t.Fatalf("код ошибки = %q, ожидался %q", codeOf(err), ErrInputTooDeep)
	}
}

func TestEncodedShapeRejectsOversizedInput(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxInputBytes = 128
	src := `{"rules":[{"direction":"outbound","trigger":{"match":"always"},"action":{"kind":"send"}}]}` +
		strings.Repeat(" ", 200)
	if got := codeOf(mustErr(t, src, limits)); got != ErrInputTooLarge {
		t.Fatalf("код ошибки = %q, ожидался %q", got, ErrInputTooLarge)
	}
}

// mustErr возвращает ошибку разбора, падая, если разбор неожиданно удался.
func mustErr(t *testing.T, src string, limits Limits) error {
	t.Helper()
	_, err := Unmarshal([]byte(src), limits)
	if err == nil {
		t.Fatal("ожидалась ошибка, получено nil")
	}
	return err
}

// TestEncodedShapeIgnoresBracesInStrings проверяет, что скобки внутри
// строкового литерала не считаются вложенностью. Без обработки кавычек и
// экранирования предохранитель отвергал бы законные описания.
func TestEncodedShapeIgnoresBracesInStrings(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxEncodedNesting = 6
	// Строка со скобками и экранированной кавычкой внутри значения id.
	src := `{"id":"{{{{{{{{{{\"}}}}}}}}","rules":[{"direction":"outbound",` +
		`"trigger":{"match":"always"},"action":{"kind":"send"}}]}`
	if err := checkEncodedShape([]byte(src), limits); err != nil {
		t.Fatalf("скобки внутри строки не должны считаться вложенностью: %v", err)
	}
}

func TestEncodedShapeAcceptsLegitimateStrategy(t *testing.T) {
	data, err := Marshal(validStrategy())
	if err != nil {
		t.Fatal(err)
	}
	if err := checkEncodedShape(data, DefaultLimits()); err != nil {
		t.Fatalf("законная стратегия отвергнута предохранителем: %v", err)
	}
}

// TestEncodedShapeBoundsParseCost фиксирует, что отсечка глубины действительно
// держит стоимость разбора: без неё описание глубины 2000 разбиралось сотни
// миллисекунд. Порог намеренно щедрый — тест проверяет отсутствие
// квадратичного взрыва, а не конкретную скорость машины.
func TestEncodedShapeBoundsParseCost(t *testing.T) {
	// Предел размера поднят намеренно: иначе ввод отсёкся бы по размеру и тест
	// не проверил бы защиту от квадратичного разбора. Глубина 4000 без
	// предохранителя разбиралась 3.34 с.
	limits := DefaultLimits()
	limits.MaxInputBytes = 1 << 20

	data := nestedDescription(4000)
	start := time.Now()
	if _, err := Unmarshal(data, limits); err == nil {
		t.Fatal("ожидался отказ")
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("отказ занял %s — предохранитель не работает", elapsed)
	}
}

func BenchmarkUnmarshalValid(b *testing.B) {
	data, err := Marshal(validStrategy())
	if err != nil {
		b.Fatal(err)
	}
	limits := DefaultLimits()
	for b.Loop() {
		if _, err := Unmarshal(data, limits); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshalRejectDeep(b *testing.B) {
	data := nestedDescription(deepButSmallDepth)
	limits := DefaultLimits()
	for b.Loop() {
		if _, err := Unmarshal(data, limits); err == nil {
			b.Fatal("ожидался отказ")
		}
	}
}

// TestLimitsNormalizedRaisesGuard проверяет, что предохранитель поднимается под
// поднятый в конфиге MaxDepth: иначе законная глубокая стратегия отвергалась бы
// на разборе с неочевидной причиной.
func TestLimitsNormalizedRaisesGuard(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxDepth = 64
	limits.MaxEncodedNesting = 8 // заведомо ниже нужного

	got := limits.normalized()
	if got.MaxEncodedNesting < limits.MaxDepth {
		t.Fatalf("предохранитель %d ниже смыслового предела %d",
			got.MaxEncodedNesting, limits.MaxDepth)
	}

	// Стратегия глубины 40 законна при MaxDepth=64 и должна разобраться.
	data := nestedDescription(40)
	if _, err := Unmarshal(data, limits); err != nil {
		t.Fatalf("законная глубокая стратегия отвергнута: %v", err)
	}
}
