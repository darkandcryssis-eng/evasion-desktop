package tlsfake

import (
	"bytes"
	"testing"
)

// Все варианты cover'а обязаны быть РОВНО 681 байт: смещение overlap-пакета
// считается как L - M, где M — длина cover'а. Разошёлся размер хоть на байт —
// рукопожатие под ActionTCPOverlap сорвётся. Это главный инвариант вариантов.
func TestCover681VariantsSize(t *testing.T) {
	cases := map[string]func() []byte{
		"apple":     CoverClientHello681Apple,
		"microsoft": CoverClientHello681Microsoft,
		"yandex":    CoverClientHello681Yandex,
	}
	for name, build := range cases {
		if got := len(build()); got != cover681Size {
			t.Fatalf("вариант %s: размер %d, ожидали %d", name, got, cover681Size)
		}
	}
	// И совпадать с размером базового cover'а — иначе их нельзя подменять
	// в одной стратегии без пересчёта.
	if CoverClientHello681Size() != cover681Size {
		t.Fatalf("базовый cover %d, константа %d — рассинхрон",
			CoverClientHello681Size(), cover681Size)
	}
}

// Каждый вариант — валидная TLS-запись handshake с самосогласованной длиной
// и своим SNI. Если padding сломал структуру, разбор длины записи это поймает.
func TestCover681VariantsValidTLS(t *testing.T) {
	cases := []struct {
		name    string
		build   func() []byte
		wantSNI string
	}{
		{"apple", CoverClientHello681Apple, "www.apple.com"},
		{"microsoft", CoverClientHello681Microsoft, "www.microsoft.com"},
		{"yandex", CoverClientHello681Yandex, "ya.ru"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := c.build()
			if rec[0] != 0x16 {
				t.Fatalf("первый байт 0x%02x, ожидали 0x16 (handshake)", rec[0])
			}
			if rec[1] != 0x03 {
				t.Fatalf("legacy_version[0] 0x%02x, ожидали 0x03", rec[1])
			}
			declared := int(rec[3])<<8 | int(rec[4])
			if declared != len(rec)-5 {
				t.Fatalf("длина записи %d, ожидали %d (len-5)", declared, len(rec)-5)
			}
			if !bytes.Contains(rec, []byte(c.wantSNI)) {
				t.Fatalf("не содержит ожидаемый SNI %q", c.wantSNI)
			}
		})
	}
}

// Варианты отличаются друг от друга и от базового google-cover'а — иначе
// размывания сигнатуры нет и смысл вариантов теряется.
func TestCover681VariantsDiffer(t *testing.T) {
	base := CoverClientHello681()
	all := map[string][]byte{
		"base":      base,
		"apple":     CoverClientHello681Apple(),
		"microsoft": CoverClientHello681Microsoft(),
		"yandex":    CoverClientHello681Yandex(),
	}
	names := []string{"base", "apple", "microsoft", "yandex"}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if bytes.Equal(all[names[i]], all[names[j]]) {
				t.Fatalf("cover %s и %s совпадают — нет размывания сигнатуры",
					names[i], names[j])
			}
		}
	}
}

// Каждый вызов возвращает независимую копию — правка одной не трогает другие
// и не портит кэш.
func TestCover681VariantsReturnCopy(t *testing.T) {
	a := CoverClientHello681Apple()
	b := CoverClientHello681Apple()
	if &a[0] == &b[0] {
		t.Fatal("возвращена ссылка на общий буфер, ожидали копию")
	}
	a[0] = 0xff
	if b[0] == 0xff {
		t.Fatal("мутация одной копии затронула другую")
	}
}
