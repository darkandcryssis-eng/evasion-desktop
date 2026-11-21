package tlsfake

import (
	"bytes"
	"testing"
)

// Каждый пресет должен быть валидной TLS-записью handshake с правильным
// заголовком и объявленной длиной.
func TestAllPresetsAreValidTLSRecords(t *testing.T) {
	cases := []struct {
		name    string
		build   func() []byte
		wantSNI string
	}{
		{"google", GoogleClientHello, "www.google.com"},
		{"cloudflare", CloudflareClientHello, "www.cloudflare.com"},
		{"apple", AppleClientHello, "www.apple.com"},
		{"microsoft", MicrosoftClientHello, "www.microsoft.com"},
		{"yandex", YandexClientHello, "ya.ru"},
		{"vk", VKClientHello, "vk.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := c.build()
			if len(rec) < 5 {
				t.Fatalf("пресет %s слишком короток: %d байт", c.name, len(rec))
			}
			if rec[0] != 0x16 {
				t.Fatalf("пресет %s: первый байт 0x%02x, ожидали 0x16 (handshake)", c.name, rec[0])
			}
			declared := int(rec[3])<<8 | int(rec[4])
			if declared != len(rec)-5 {
				t.Fatalf("пресет %s: длина в заголовке %d, фактически %d",
					c.name, declared, len(rec)-5)
			}
			// SNI должен присутствовать: это самая характерная подпись
			// ClientHello для DPI, и ошибиться тут значило бы ломать приём.
			if !bytes.Contains(rec, []byte(c.wantSNI)) {
				t.Fatalf("пресет %s не содержит ожидаемый SNI %q", c.name, c.wantSNI)
			}
		})
	}
}

// Каждый вызов пресета возвращает НОВЫЙ срез — правка одного не портит другие.
func TestPresetsReturnIndependentSlices(t *testing.T) {
	a := GoogleClientHello()
	b := GoogleClientHello()
	a[0] = 0xff
	if b[0] == 0xff {
		t.Fatal("два вызова пресета делят один буфер")
	}
}

// Разные пресеты имеют разное содержимое — иначе нет смысла в множественности.
func TestPresetsDiffer(t *testing.T) {
	g := GoogleClientHello()
	c := CloudflareClientHello()
	if bytes.Equal(g, c) {
		t.Fatal("google и cloudflare пресеты совпадают — реестр не работает")
	}
}

// Детерминизм: пресет собирается одинаково от сеанса к сеансу. Нужно для
// золотых тестов и воспроизведения записи.
func TestPresetDeterministic(t *testing.T) {
	a := BuildClientHello("www.example.com")
	b := BuildClientHello("www.example.com")
	if !bytes.Equal(a, b) {
		t.Fatal("BuildClientHello с одним SNI вернул разные байты")
	}
}

// BuildClientHello с пустым SNI не падает (валидный ClientHello без
// server_name).
func TestBuildClientHelloEmptySNI(t *testing.T) {
	rec := BuildClientHello("")
	if rec[0] != 0x16 {
		t.Fatalf("с пустым SNI: первый байт 0x%02x", rec[0])
	}
}
