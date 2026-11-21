package tlsparse

import (
	"encoding/binary"
	"testing"
)

// Минимальный ClientHello, собираемый побайтно.
//
// Нужен для двух целей.
//
// Первая — затравки фаззера. Настоящий ClientHello от стандартной библиотеки
// занимает около 1500 байт (постквантовая ключевая доля), и фаззер на таком
// входе уходит в минимизацию найденных путей, тратя на неё весь бюджет: замерено
// 13 тыс. итераций за 12 с против 750 тыс. на компактной затравке при той же
// проверяемой логике. Рабочие процессы при этом загружены — это не зависание, а
// бесполезная работа. Затравки обязаны быть маленькими.
//
// Вторая — точная проверка арифметики смещений. В сообщении, собранном вручную,
// положение имени известно заранее, поэтому можно сверить вычисленное смещение с
// посчитанным на бумаге. На настоящем сообщении такая сверка невозможна: его
// раскладка меняется от версии библиотеки.

// minimalHello — собранный ClientHello и ожидаемые смещения в нём.
type minimalHello struct {
	Data []byte
	// SNIOff, SNILen — где должно оказаться имя сервера.
	SNIOff, SNILen int
	// HandshakeOff — где должно начаться тело сообщения рукопожатия.
	HandshakeOff int
	// ExtensionsOff — где должен начаться список расширений.
	ExtensionsOff int
}

// buildMinimalClientHello собирает самый короткий корректный ClientHello с
// заданным именем сервера. Пустое имя означает отсутствие расширения
// server_name.
//
// Смещения считаются по ходу сборки, а не вычисляются повторно: так ожидаемое
// значение выводится из самой раскладки и не может разойтись с ней.
func buildMinimalClientHello(t testing.TB, name string) minimalHello {
	t.Helper()

	var out minimalHello

	// --- расширение server_name ---
	var sniExt []byte
	var sniOffsetInExt int
	if name != "" {
		// server_name_list: тип имени (1 байт), длина (2 байта), байты имени.
		entry := make([]byte, 0, 3+len(name))
		entry = append(entry, sniTypeHostName)
		entry = binary.BigEndian.AppendUint16(entry, uint16(len(name)))
		// Смещение имени внутри данных расширения: 2 байта длины списка плюс
		// 3 байта заголовка записи.
		sniOffsetInExt = 2 + 3
		entry = append(entry, name...)

		data := make([]byte, 0, 2+len(entry))
		data = binary.BigEndian.AppendUint16(data, uint16(len(entry)))
		data = append(data, entry...)

		sniExt = make([]byte, 0, 4+len(data))
		sniExt = binary.BigEndian.AppendUint16(sniExt, extServerName)
		sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(data)))
		sniExt = append(sniExt, data...)
		// Внутри расширения данные начинаются после 4 байт заголовка.
		sniOffsetInExt += 4
	}

	// --- тело ClientHello ---
	body := make([]byte, 0, 64+len(sniExt))
	body = binary.BigEndian.AppendUint16(body, 0x0303) // legacy_version
	body = append(body, make([]byte, clientRandomLen)...)
	body = append(body, 0)                        // legacy_session_id: пусто
	body = binary.BigEndian.AppendUint16(body, 2) // cipher_suites: 2 байта
	body = append(body, 0x13, 0x01)               // TLS_AES_128_GCM_SHA256
	body = append(body, 1, 0)                     // compression_methods: [0]
	extsLenPos := len(body)                       //
	body = binary.BigEndian.AppendUint16(body, uint16(len(sniExt)))
	extsStartInBody := len(body)
	body = append(body, sniExt...)
	_ = extsLenPos

	// --- заголовки сообщения и записи ---
	pkt := make([]byte, 0, recordHeaderLen+handshakeHeaderLen+len(body))
	pkt = append(pkt, byte(ContentHandshake))
	pkt = binary.BigEndian.AppendUint16(pkt, 0x0301)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(handshakeHeaderLen+len(body)))
	pkt = append(pkt, handshakeTypeClientHello)
	// Длина сообщения рукопожатия — три байта.
	pkt = append(pkt, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	pkt = append(pkt, body...)

	out.Data = pkt
	out.HandshakeOff = recordHeaderLen + handshakeHeaderLen
	out.ExtensionsOff = out.HandshakeOff + extsStartInBody
	if name != "" {
		out.SNIOff = out.ExtensionsOff + sniOffsetInExt
		out.SNILen = len(name)
	}
	return out
}

// TestMinimalHelloOffsetsExact сверяет вычисленные разбором смещения с
// посчитанными при сборке. Это самая прямая проверка арифметики смещений: в
// отличие от сверки по содержимому, она ловит ошибку даже если байты имени
// случайно совпали.
func TestMinimalHelloOffsetsExact(t *testing.T) {
	const name = "a.example.com"
	m := buildMinimalClientHello(t, name)

	ch, err := ParseClientHello(m.Data)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}

	if ch.HandshakeOff != m.HandshakeOff {
		t.Fatalf("HandshakeOff = %d, ожидалось %d", ch.HandshakeOff, m.HandshakeOff)
	}
	if ch.ExtensionsOff != m.ExtensionsOff {
		t.Fatalf("ExtensionsOff = %d, ожидалось %d", ch.ExtensionsOff, m.ExtensionsOff)
	}
	if ch.SNIOff != m.SNIOff || ch.SNILen != m.SNILen {
		t.Fatalf("SNI off/len = %d/%d, ожидалось %d/%d",
			ch.SNIOff, ch.SNILen, m.SNIOff, m.SNILen)
	}
	sni, ok := ch.SNI(m.Data)
	if !ok || string(sni) != name {
		t.Fatalf("SNI = %q (ok=%v), ожидалось %q", sni, ok, name)
	}
	// Сообщение должно занимать ровно одну запись и весь буфер.
	if ch.Record.End() != len(m.Data) {
		t.Fatalf("конец записи = %d, длина буфера = %d", ch.Record.End(), len(m.Data))
	}
}

func TestMinimalHelloIsSmall(t *testing.T) {
	m := buildMinimalClientHello(t, "a.ru")
	// Затравка фаззера должна быть компактной; порог щедрый, он лишь
	// фиксирует намерение не допустить разрастания.
	if len(m.Data) > 128 {
		t.Fatalf("минимальный ClientHello занимает %d байт — слишком много для затравки", len(m.Data))
	}
}

func TestMinimalHelloWithoutSNI(t *testing.T) {
	m := buildMinimalClientHello(t, "")
	ch, err := ParseClientHello(m.Data)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if ch.SNILen != 0 {
		t.Fatalf("имя не должно быть найдено, получено %d байт", ch.SNILen)
	}
}

// TestMinimalHelloMultipleNames проверяет выбор первого имени типа host_name:
// стандарт допускает список, и решение «какое считать настоящим» не должно
// зависеть от порядка разбора.
func TestMinimalHelloMultipleNames(t *testing.T) {
	first, second := "first.example", "second.example"

	// Собираем расширение с двумя записями вручную.
	entries := make([]byte, 0, 64)
	for _, n := range []string{first, second} {
		entries = append(entries, sniTypeHostName)
		entries = binary.BigEndian.AppendUint16(entries, uint16(len(n)))
		entries = append(entries, n...)
	}
	data := binary.BigEndian.AppendUint16(nil, uint16(len(entries)))
	data = append(data, entries...)

	ext := binary.BigEndian.AppendUint16(nil, extServerName)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(data)))
	ext = append(ext, data...)

	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, make([]byte, clientRandomLen)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 0x13, 0x01)
	body = append(body, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	pkt := []byte{byte(ContentHandshake), 0x03, 0x01}
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(handshakeHeaderLen+len(body)))
	pkt = append(pkt, handshakeTypeClientHello,
		byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	pkt = append(pkt, body...)

	ch, err := ParseClientHello(pkt)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	sni, ok := ch.SNI(pkt)
	if !ok {
		t.Fatal("имя не найдено")
	}
	if string(sni) != first {
		t.Fatalf("выбрано имя %q, ожидалось первое %q", sni, first)
	}
}

// TestMinimalHelloWithoutExtensions проверяет корректность разбора сообщения
// вовсе без списка расширений: такое допустимо и не должно быть ошибкой.
func TestMinimalHelloWithoutExtensions(t *testing.T) {
	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, make([]byte, clientRandomLen)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 0x13, 0x01)
	body = append(body, 1, 0)
	// Блока расширений нет вовсе — тело на этом заканчивается.

	pkt := []byte{byte(ContentHandshake), 0x03, 0x01}
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(handshakeHeaderLen+len(body)))
	pkt = append(pkt, handshakeTypeClientHello,
		byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	pkt = append(pkt, body...)

	ch, err := ParseClientHello(pkt)
	if err != nil {
		t.Fatalf("сообщение без расширений не должно быть ошибкой: %v", err)
	}
	if ch.SNILen != 0 || ch.ExtensionsLen != 0 {
		t.Fatalf("ожидались нулевые расширения и SNI, получено %d/%d",
			ch.ExtensionsLen, ch.SNILen)
	}
}

// TestMinimalHelloLyingLengths проверяет, что ложные длины внутри сообщения
// дают ошибку разбора, а не выход за границы: именно это и проверяется на
// фаззинге, но здесь зафиксировано как явный случай.
func TestMinimalHelloLyingLengths(t *testing.T) {
	m := buildMinimalClientHello(t, "a.example.com")

	// Длина расширений объявлена больше, чем осталось байт в сообщении.
	// Поле длины расширений — два байта перед их началом.
	broken := make([]byte, len(m.Data))
	copy(broken, m.Data)
	binary.BigEndian.PutUint16(broken[m.ExtensionsOff-2:], 0xffff)

	if _, err := ParseClientHello(broken); err == nil {
		t.Fatal("ложная длина расширений должна приводить к ошибке")
	}
}
