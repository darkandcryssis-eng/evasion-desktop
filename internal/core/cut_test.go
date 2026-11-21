package core

import "testing"

func TestCutKindTokensRoundTrip(t *testing.T) {
	for _, k := range CutKinds() {
		text, err := k.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v): %v", k, err)
		}
		var back CutKind
		if err := back.UnmarshalText(text); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", text, err)
		}
		if back != k {
			t.Fatalf("круговой перенос %v дал %v", k, back)
		}
	}
}

func TestCutKindTokensAreDistinct(t *testing.T) {
	seen := make(map[string]CutKind)
	for _, k := range CutKinds() {
		s := k.String()
		if prev, dup := seen[s]; dup {
			t.Fatalf("обозначение %q у двух видов: %d и %d", s, uint8(prev), uint8(k))
		}
		seen[s] = k
	}
	if len(seen) != len(CutKinds()) {
		t.Fatalf("обозначений %d при %d видах", len(seen), len(CutKinds()))
	}
}

func TestCutNoneIsNotValid(t *testing.T) {
	// CutNone — признак отсутствия разреза, а не его вид. Если бы он считался
	// допустимым, валидация стратегии пропустила бы описание без места разреза.
	if CutNone.Valid() {
		t.Fatal("CutNone не должен быть допустимым видом")
	}
	if _, err := CutNone.MarshalText(); err == nil {
		t.Fatal("сериализация CutNone должна давать ошибку")
	}
	if CutNone != 0 {
		t.Fatal("CutNone обязан быть нулевым значением, иначе отсутствие поля читается неоднозначно")
	}
}

func TestCutKindUnknownTokenRejected(t *testing.T) {
	// Опечатка в описании не должна превращаться в отсутствие разреза.
	var k CutKind
	for _, bad := range []string{"", "none", "inside-sni", "InsideSNI", "sni"} {
		if err := k.UnmarshalText([]byte(bad)); err == nil {
			t.Fatalf("обозначение %q должно быть отвергнуто", bad)
		}
	}
}

func TestCutKindsIsCopy(t *testing.T) {
	// Список видов — источник пространства поиска для генератора. Он не должен
	// позволять испортить внутреннюю таблицу.
	a := CutKinds()
	if len(a) == 0 {
		t.Fatal("список видов пуст")
	}
	a[0] = CutNone
	b := CutKinds()
	if b[0] == CutNone {
		t.Fatal("CutKinds отдаёт ссылку на внутреннюю таблицу")
	}
}
