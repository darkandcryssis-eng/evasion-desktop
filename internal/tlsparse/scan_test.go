package tlsparse

import (
	"encoding/binary"
	"testing"
)

// TestScanSNI — щадящий поиск находит имя в целом сообщении и в обрезанном
// ПОСЛЕ имени (как в первом QUIC Initial), но не выдаёт имя, обрезанное внутри.
func TestScanSNI(t *testing.T) {
	full := buildMinimalClientHello(t, "example.com")
	ch, err := ParseClientHello(full.Data)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	msg := full.Data[ch.Record.PayloadOff:ch.Record.End()]

	// Целое сообщение.
	if sni, ok := ScanSNI(msg); !ok || string(sni) != "example.com" {
		t.Fatalf("на целом сообщении ожидался example.com, получено %q ok=%v", sni, ok)
	}

	// Конец имени в координатах сообщения (SNIOff абсолютен в full.Data).
	sniEndInMsg := (ch.SNIOff - ch.Record.PayloadOff) + ch.SNILen
	if sniEndInMsg <= 0 || sniEndInMsg > len(msg) {
		t.Fatalf("не удалось локализовать SNI в сообщении: конец %d, длина %d", sniEndInMsg, len(msg))
	}

	// Обрезано ровно по концу имени — расширение server_name целиком присутствует.
	if sni, ok := ScanSNI(msg[:sniEndInMsg]); !ok || string(sni) != "example.com" {
		t.Fatalf("усечение сразу за именем должно сохранять находку, получено %q ok=%v", sni, ok)
	}

	// Обрезано внутри имени — находки быть не должно (имя не целиком).
	if _, ok := ScanSNI(msg[:sniEndInMsg-2]); ok {
		t.Error("усечение внутри имени не должно давать SNI")
	}
}

// TestScanSNIRejects — не-ClientHello, пустой и мусорный ввод имени не дают и
// не падают.
func TestScanSNIRejects(t *testing.T) {
	cases := map[string][]byte{
		"пусто":            nil,
		"не client_hello":  {0x02, 0x00, 0x00, 0x00},
		"только заголовок": {0x01, 0x00, 0x00, 0x10},
		"мусор":            []byte("not a tls client hello message"),
	}
	for name, b := range cases {
		if _, ok := ScanSNI(b); ok {
			t.Errorf("%s: ожидался отказ", name)
		}
	}
}

// TestParseClientHelloLenientFull — на целом ClientHello нестрогий разбор даёт
// те же смещения, что и строгий. Это страховка: нестрогий путь не должен
// вычислять SNI иначе, чем основной, иначе десинк резал бы не там.
func TestParseClientHelloLenientFull(t *testing.T) {
	const name = "a.example.com"
	m := buildMinimalClientHello(t, name)

	strict, err := ParseClientHello(m.Data)
	if err != nil {
		t.Fatalf("строгий разбор: %v", err)
	}
	lenient, ok := ParseClientHelloLenient(m.Data)
	if !ok {
		t.Fatal("нестрогий разбор не нашёл SNI в целом сообщении")
	}
	if lenient.HandshakeOff != strict.HandshakeOff {
		t.Fatalf("HandshakeOff: нестрогий %d, строгий %d", lenient.HandshakeOff, strict.HandshakeOff)
	}
	if lenient.ExtensionsOff != strict.ExtensionsOff {
		t.Fatalf("ExtensionsOff: нестрогий %d, строгий %d", lenient.ExtensionsOff, strict.ExtensionsOff)
	}
	if lenient.SNIOff != strict.SNIOff || lenient.SNILen != strict.SNILen {
		t.Fatalf("SNI off/len: нестрогий %d/%d, строгий %d/%d",
			lenient.SNIOff, lenient.SNILen, strict.SNIOff, strict.SNILen)
	}
	sni, ok := lenient.SNI(m.Data)
	if !ok || string(sni) != name {
		t.Fatalf("SNI = %q (ok=%v), ожидалось %q", sni, ok, name)
	}
}

// TestParseClientHelloLenientTruncatedAfterSNI — главный случай: большой
// ClientHello разбит на TCP-сегменты, но server_name целиком в первом.
// Воспроизводим первый сегмент точно: заголовки записи и рукопожатия объявляют
// полную (большую) длину, но доступны лишь байты первого сегмента, кончающиеся
// сразу за именем. Строгий разбор на таком вводе отказывает (ErrIncomplete) —
// это и есть исходная проблема; нестрогий обязан найти имя и те же смещения.
func TestParseClientHelloLenientTruncatedAfterSNI(t *testing.T) {
	const name = "video.googlevideo.example"
	m := buildMinimalClientHello(t, name)

	strict, err := ParseClientHello(m.Data)
	if err != nil {
		t.Fatalf("строгий разбор: %v", err)
	}
	sniEnd := strict.SNIOff + strict.SNILen

	// Берём байты до конца имени и раздуваем объявленные длины так, будто за
	// сегментом следует ещё около 2000 байт рукопожатия (ключевые доли и пр.).
	const tail = 2000
	seg := make([]byte, sniEnd)
	copy(seg, m.Data[:sniEnd])
	// Длина тела записи (2 байта по смещению recordLengthOff).
	recLen := (strict.Record.PayloadLen) + tail
	binary.BigEndian.PutUint16(seg[recordLengthOff:], uint16(recLen))
	// Длина сообщения рукопожатия (3 байта сразу за типом, по смещению 6).
	msgLen := strict.HandshakeLen + tail
	msgLenOff := recordHeaderLen + 1
	seg[msgLenOff] = byte(msgLen >> 16)
	seg[msgLenOff+1] = byte(msgLen >> 8)
	seg[msgLenOff+2] = byte(msgLen)

	// Строгий разбор на таком вводе отказывает — это и есть исходная проблема.
	if _, err := ParseClientHello(seg); err == nil {
		t.Fatal("строгий разбор на первом сегменте не должен успевать")
	}

	lenient, ok := ParseClientHelloLenient(seg)
	if !ok {
		t.Fatal("нестрогий разбор не нашёл SNI в первом сегменте")
	}
	if lenient.SNIOff != strict.SNIOff || lenient.SNILen != strict.SNILen {
		t.Fatalf("SNI off/len: нестрогий %d/%d, строгий %d/%d",
			lenient.SNIOff, lenient.SNILen, strict.SNIOff, strict.SNILen)
	}
	sni, ok := lenient.SNI(seg)
	if !ok || string(sni) != name {
		t.Fatalf("SNI = %q (ok=%v), ожидалось %q", sni, ok, name)
	}
}

// TestParseClientHelloLenientTruncatedBeforeSNI — если сегмент обрезан внутри
// имени или раньше, имени ещё не видно: отказ, а не угадывание.
func TestParseClientHelloLenientTruncatedBeforeSNI(t *testing.T) {
	const name = "a.example.com"
	m := buildMinimalClientHello(t, name)
	strict, err := ParseClientHello(m.Data)
	if err != nil {
		t.Fatalf("строгий разбор: %v", err)
	}
	sniEnd := strict.SNIOff + strict.SNILen

	cuts := map[string]int{
		"внутри имени":         sniEnd - 2,
		"по началу имени":      strict.SNIOff,
		"до списка расширений": strict.ExtensionsOff - 1,
	}
	for label, n := range cuts {
		if n <= 0 || n >= len(m.Data) {
			t.Fatalf("%s: неверная точка реза %d", label, n)
		}
		if _, ok := ParseClientHelloLenient(m.Data[:n]); ok {
			t.Errorf("%s: имя не целиком, ожидался отказ", label)
		}
	}
}

// TestParseClientHelloLenientRejects — не-TLS, не-рукопожатие и мусор не дают
// SNI и не паникуют.
func TestParseClientHelloLenientRejects(t *testing.T) {
	m := buildMinimalClientHello(t, "a.example.com")

	// Запись не рукопожатия: тот же буфер с типом application_data.
	appData := make([]byte, len(m.Data))
	copy(appData, m.Data)
	appData[0] = byte(ContentApplicationData)

	cases := map[string][]byte{
		"пусто":          nil,
		"мусор":          []byte("not a tls record at all, really"),
		"не рукопожатие": appData,
		"обрывок записи": m.Data[:3],
	}
	for label, b := range cases {
		if _, ok := ParseClientHelloLenient(b); ok {
			t.Errorf("%s: ожидался отказ", label)
		}
	}
}
