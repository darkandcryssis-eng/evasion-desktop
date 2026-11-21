package tlsparse

import (
	"crypto/tls"
	"errors"
	"github.com/fitting-1c/evasion/internal/core"
	"net"
	"testing"
	"time"
)

// realClientHello возвращает байты настоящего ClientHello, сформированного
// стандартной библиотекой.
//
// Так эталон не зависит от моего представления о формате: если бы тест сверял
// разбор с пакетом, собранным тем же кодом, согласованная ошибка в раскладке
// полей осталась бы незамеченной. Рукопожатие заведомо не завершается — сервер
// не отвечает, и нам нужен только первый отправленный клиентом блок.
func realClientHello(t testing.TB, serverName string) []byte {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	captured := make(chan []byte, 1)

	go func() {
		buf := make([]byte, 8192)
		n, err := serverConn.Read(buf)
		if err != nil && n == 0 {
			captured <- nil
			return
		}
		captured <- buf[:n]
		_ = serverConn.Close()
	}()

	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if serverName != "" {
		cfg.ServerName = serverName
	} else {
		// Без имени сервера проверка сертификата невозможна, а нам нужен
		// именно ClientHello без расширения server_name.
		cfg.InsecureSkipVerify = true
	}

	go func() {
		c := tls.Client(clientConn, cfg)
		_ = c.Handshake()
		_ = clientConn.Close()
	}()

	select {
	case data := <-captured:
		if len(data) == 0 {
			t.Fatal("не удалось перехватить ClientHello")
		}
		return data
	case <-time.After(10 * time.Second):
		t.Fatal("таймаут ожидания ClientHello")
		return nil
	}
}

func TestParseRealClientHello(t *testing.T) {
	const name = "www.example.com"
	data := realClientHello(t, name)

	ch, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("разбор настоящего ClientHello: %v", err)
	}

	if ch.Record.Type != ContentHandshake {
		t.Fatalf("тип содержимого = %d", ch.Record.Type)
	}
	// Версия слоя записей у ClientHello остаётся 1.0–1.2 даже для TLS 1.3.
	if ch.Record.Version < recordVersionMin || ch.Record.Version > recordVersionMax {
		t.Fatalf("версия записи = 0x%04x", ch.Record.Version)
	}

	sni, ok := ch.SNI(data)
	if !ok {
		t.Fatal("SNI не найден в настоящем ClientHello")
	}
	if string(sni) != name {
		t.Fatalf("SNI = %q, ожидалось %q", sni, name)
	}
	if ch.HasECH {
		t.Fatal("расширения ECH в обычном ClientHello быть не должно")
	}
	if ch.ExtensionsLen == 0 {
		t.Fatal("список расширений не найден")
	}

	// Сообщение должно целиком умещаться в запись и в буфер.
	if ch.HandshakeOff+ch.HandshakeLen > len(data) {
		t.Fatalf("сообщение выходит за буфер: off=%d len=%d buf=%d",
			ch.HandshakeOff, ch.HandshakeLen, len(data))
	}
}

func TestParseClientHelloWithoutSNI(t *testing.T) {
	data := realClientHello(t, "")

	ch, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if ch.SNILen != 0 {
		t.Fatalf("SNI не должен быть найден, получено %d байт", ch.SNILen)
	}
	if _, ok := ch.SNI(data); ok {
		t.Fatal("SNI не должен быть доступен")
	}
}

// TestParseEveryPrefixOfRealHello — ключевая проверка на неполноту: для каждого
// префикса настоящего ClientHello разбор обязан либо честно сказать «данных
// мало», либо вернуть полный правильный SNI. Чего он делать не вправе — так это
// возвращать успех с обрезанным или пустым именем: по такому решению движок
// применил бы стратегию не к тому соединению.
func TestParseEveryPrefixOfRealHello(t *testing.T) {
	const name = "www.example.com"
	full := realClientHello(t, name)

	for n := range len(full) {
		prefix := full[:n]
		ch, err := ParseClientHello(prefix)
		switch {
		case err == nil:
			// Успех допустим только на полном сообщении.
			sni, ok := ch.SNI(prefix)
			if !ok || string(sni) != name {
				t.Fatalf("префикс %d байт: разбор удался, но SNI = %q (ok=%v)", n, sni, ok)
			}
		case errors.Is(err, ErrIncomplete), errors.Is(err, ErrFragmentedHandshake):
			// Ожидаемые причины для неполного ввода.
		default:
			t.Fatalf("префикс %d байт: неожиданная ошибка %v", n, err)
		}
	}
}

func TestParseRejectsNonTLS(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"запрос HTTP", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), ErrNotTLS},
		{"неизвестный тип содержимого", []byte{0x99, 0x03, 0x01, 0x00, 0x10}, ErrNotTLS},
		{"версия записи вне диапазона", []byte{22, 0x05, 0x00, 0x00, 0x10}, ErrNotTLS},
		{"нулевая длина тела", []byte{22, 0x03, 0x01, 0x00, 0x00}, ErrNotTLS},
		{"один байт мусора", []byte{0xff}, ErrNotTLS},
		{"пустой буфер", nil, ErrIncomplete},
		{"обрезанный заголовок записи", []byte{22, 0x03}, ErrIncomplete},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseClientHello(c.data); !errors.Is(err, c.want) {
				t.Fatalf("ошибка = %v, ожидалась %v", err, c.want)
			}
		})
	}
}

func TestParseRejectsNonHandshakeRecord(t *testing.T) {
	// Запись прикладных данных: корректный TLS, но не рукопожатие.
	data := []byte{byte(ContentApplicationData), 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4}
	if _, err := ParseClientHello(data); !errors.Is(err, ErrNotHandshake) {
		t.Fatalf("ошибка = %v, ожидалась ErrNotHandshake", err)
	}
}

func TestParseRejectsOtherHandshakeType(t *testing.T) {
	// Тип сообщения 2 — ServerHello.
	data := []byte{byte(ContentHandshake), 0x03, 0x03, 0x00, 0x04, 2, 0, 0, 0}
	if _, err := ParseClientHello(data); !errors.Is(err, ErrNotClientHello) {
		t.Fatalf("ошибка = %v, ожидалась ErrNotClientHello", err)
	}
}

// TestParseDetectsFragmentedHandshake проверяет, что сообщение, не уместившееся
// в запись, распознаётся явной ошибкой. Молчаливый разбор первой половины дал
// бы неверный SNI и неверное решение о стратегии.
func TestParseDetectsFragmentedHandshake(t *testing.T) {
	full := realClientHello(t, "www.example.com")
	rec, err := ParseRecord(full)
	if err != nil {
		t.Fatal(err)
	}

	// Урезаем тело записи вдвое, оставив в заголовке сообщения прежнюю длину:
	// так выглядит рукопожатие, продолжающееся в следующей записи.
	half := rec.PayloadLen / 2
	data := make([]byte, 0, recordHeaderLen+half)
	data = append(data, full[:recordHeaderLen]...)
	data = append(data, full[recordHeaderLen:recordHeaderLen+half]...)
	// Длина записи в заголовке должна соответствовать фактическому телу.
	data[recordLengthOff] = byte(half >> 8)
	data[recordLengthOff+1] = byte(half)

	if _, err := ParseClientHello(data); !errors.Is(err, ErrFragmentedHandshake) {
		t.Fatalf("ошибка = %v, ожидалась ErrFragmentedHandshake", err)
	}
}

// TestParseZeroAllocations подтверждает нулевой бюджет аллокаций на горячем
// пути: разбор ClientHello входит в решение по соединению (8.1).
func TestParseZeroAllocations(t *testing.T) {
	data := realClientHello(t, "www.example.com")
	var cuts [8]core.CutPoint

	avg := testing.AllocsPerRun(1000, func() {
		ch, err := ParseClientHello(data)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ch.SNI(data); !ok {
			t.Fatal("SNI не найден")
		}
		// Точки разреза считаем в заранее выделенный массив.
		_ = ch.CutPoints(cuts[:0])
	})
	if avg != 0 {
		t.Fatalf("аллокаций на разбор = %v, требуется 0", avg)
	}
}

func BenchmarkParseClientHello(b *testing.B) {
	data := realClientHello(b, "www.example.com")
	for b.Loop() {
		if _, err := ParseClientHello(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseClientHelloWithCutPoints(b *testing.B) {
	data := realClientHello(b, "www.example.com")
	var cuts [8]core.CutPoint
	for b.Loop() {
		ch, err := ParseClientHello(data)
		if err != nil {
			b.Fatal(err)
		}
		_ = ch.CutPoints(cuts[:0])
	}
}
