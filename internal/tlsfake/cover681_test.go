package tlsfake

import "testing"

// TestCover681Size — размер пресета фиксирован: внешние потребители (приём
// ActionTCPOverlap) рассчитывают на 681 байт. Если встроенный файл будет
// случайно заменён на другой пресет, тест сразу об этом скажет.
func TestCover681Size(t *testing.T) {
	const want = 681
	if got := CoverClientHello681Size(); got != want {
		t.Fatalf("размер %d, ожидали %d", got, want)
	}
	if got := len(CoverClientHello681()); got != want {
		t.Fatalf("len(bytes) = %d, ожидали %d", got, want)
	}
}

// TestCover681IsTLSHandshake — первый байт должен быть 0x16 (TLS handshake
// content type), байты 3-4 — big-endian длина записи, равная len-5. Это
// защита от того, что в встроенный файл попадёт мусор или не-TLS payload.
func TestCover681IsTLSHandshake(t *testing.T) {
	data := CoverClientHello681()
	if data[0] != 0x16 {
		t.Fatalf("первый байт %#x, ожидали 0x16 (TLS handshake)", data[0])
	}
	if data[1] != 0x03 {
		t.Fatalf("legacy_version[0] %#x, ожидали 0x03", data[1])
	}
	recLen := int(data[3])<<8 | int(data[4])
	if recLen != len(data)-5 {
		t.Fatalf("длина записи %d, ожидали %d (len-5)", recLen, len(data)-5)
	}
}

// TestCover681ReturnsCopy — каждый вызов должен возвращать независимую
// копию: изменение одной не влияет на другую. Защита от общего доступа и
// случайных мутаций пресета.
func TestCover681ReturnsCopy(t *testing.T) {
	a := CoverClientHello681()
	b := CoverClientHello681()
	if &a[0] == &b[0] {
		t.Fatal("возвращена ссылка на тот же буфер, ожидали копию")
	}
	a[0] = 0xff
	if b[0] == 0xff {
		t.Fatal("мутация одной копии затронула другую")
	}
}
