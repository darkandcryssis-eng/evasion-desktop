package tlsparse

import (
	"bytes"
	"testing"
)

// TestParseClientHelloMessage: разбор «голого» сообщения рукопожатия (как в
// CRYPTO-кадре QUIC) даёт тот же SNI, что и разбор поверх записи TLS. Сообщение
// получаем, срезав с полного ClientHello слой записи по границам, которые
// возвращает ParseClientHello.
func TestParseClientHelloMessage(t *testing.T) {
	full := buildMinimalClientHello(t, "example.com")

	ch, err := ParseClientHello(full.Data)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	// Тело записи — это и есть сообщение рукопожатия без слоя записей.
	msg := full.Data[ch.Record.PayloadOff:ch.Record.End()]

	got, err := ParseClientHelloMessage(msg)
	if err != nil {
		t.Fatalf("ParseClientHelloMessage: %v", err)
	}
	if got.Record != (Record{}) {
		t.Fatal("у голого сообщения не должно быть записи")
	}
	sni, ok := got.SNI(msg)
	if !ok {
		t.Fatal("SNI не найден в голом сообщении")
	}
	if !bytes.Equal(sni, []byte("example.com")) {
		t.Fatalf("SNI: ожидалось example.com, получено %q", sni)
	}
}

// TestParseClientHelloMessageFragmented: если объявленная длина сообщения
// больше имеющихся байт (ClientHello не поместился — у QUIC он может лечь в
// несколько Initial), это честная ошибка, а не чтение за границей.
func TestParseClientHelloMessageFragmented(t *testing.T) {
	full := buildMinimalClientHello(t, "example.com")
	ch, _ := ParseClientHello(full.Data)
	msg := full.Data[ch.Record.PayloadOff:ch.Record.End()]
	// Обрежем тело: заголовок сообщения обещает больше, чем осталось.
	if _, err := ParseClientHelloMessage(msg[:len(msg)-5]); err != ErrFragmentedHandshake {
		t.Fatalf("ожидалась ErrFragmentedHandshake, получено %v", err)
	}
}
