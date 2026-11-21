package tlsparse

// Разбор сообщения ClientHello (RFC 8446, раздел 4.1.2).
//
// Заголовок сообщения рукопожатия — 4 байта: тип (1 байт) и длина (3 байта).
// Далее тело ClientHello в таком порядке:
//
//	2 байта    legacy_version
//	32 байта   random
//	1 + N      legacy_session_id (длина, затем значение)
//	2 + N      cipher_suites (длина в байтах, затем значения)
//	1 + N      legacy_compression_methods
//	2 + N      extensions (длина, затем список)
//
// Каждое расширение: 2 байта тип, 2 байта длина, затем данные.
const (
	handshakeHeaderLen = 4
	// handshakeTypeClientHello — тип сообщения ClientHello.
	handshakeTypeClientHello = 1
	// clientRandomLen — длина поля random, фиксирована стандартом.
	clientRandomLen = 32
)

// Типы расширений, которые разбор различает по имени.
const (
	// extServerName — расширение server_name, несущее SNI.
	extServerName uint16 = 0
	// extEncryptedClientHello — зашифрованный ClientHello. Разбор его не
	// читает, но наличие важно знать: при нём видимое имя сервера может быть
	// подставным, и решения по SNI теряют смысл.
	extEncryptedClientHello uint16 = 0xfe0d
)

// sniTypeHostName — тип записи в списке server_name, означающий доменное имя.
const sniTypeHostName = 0

// ClientHello — результат разбора: структурные смещения в исходном буфере.
//
// Смещения отсчитываются от начала буфера, переданного в ParseClientHello, то
// есть от начала тела соединения. Это позволяет desync резать поток по этим
// границам, не пересчитывая ничего.
type ClientHello struct {
	// Record — заголовок записи, в которой лежит сообщение.
	Record Record

	// HandshakeOff, HandshakeLen — смещение и длина тела сообщения
	// рукопожатия (без его четырёхбайтного заголовка).
	HandshakeOff, HandshakeLen int

	// LegacyVersion — поле legacy_version из тела ClientHello.
	LegacyVersion uint16

	// SessionIDOff, SessionIDLen — расположение legacy_session_id.
	SessionIDOff, SessionIDLen int
	// ExtensionsOff, ExtensionsLen — расположение списка расширений.
	ExtensionsOff, ExtensionsLen int

	// SNIOff, SNILen — расположение байт доменного имени внутри расширения
	// server_name. Нулевая длина означает, что имени нет.
	SNIOff, SNILen int

	// HasECH — в сообщении присутствует расширение encrypted_client_hello.
	HasECH bool
}

// SNI возвращает байты доменного имени как представление исходного буфера.
//
// Строка намеренно не создаётся: сравнение с группами домёнов выполняется по
// байтам, а преобразование в строку выделяло бы память на каждом соединении —
// прямо на горячем пути, где бюджет аллокаций равен нулю (8.1).
func (ch ClientHello) SNI(buf []byte) ([]byte, bool) {
	if ch.SNILen <= 0 {
		return nil, false
	}
	end := ch.SNIOff + ch.SNILen
	if ch.SNIOff < 0 || end > len(buf) {
		return nil, false
	}
	return buf[ch.SNIOff:end], true
}

// ParseClientHello разбирает ClientHello в начале буфера.
//
// buf — байты тела соединения с самого начала (первый байт должен быть
// заголовком записи TLS). Буфер не изменяется, память не выделяется.
//
// Разбор идёт по вложенным курсорам: каждая структура с объявленной длиной
// получает свой участок, за пределы которого выйти не может. Поэтому ложная
// длина внутри расширения портит только разбор этого расширения, а не чтение за
// границей буфера.
func ParseClientHello(buf []byte) (ClientHello, error) {
	rec, err := ParseRecord(buf)
	if err != nil {
		return ClientHello{}, err
	}
	if rec.Type != ContentHandshake {
		return ClientHello{Record: rec}, ErrNotHandshake
	}
	ch, err := parseHandshake(buf, rec.PayloadOff, rec.End())
	ch.Record = rec
	return ch, err
}

// ParseClientHelloMessage разбирает «голое» сообщение рукопожатия ClientHello,
// переданное без слоя записей TLS.
//
// Так ClientHello несёт CRYPTO-кадр QUIC (RFC 9001): в QUIC слой записей TLS
// заменён пакетами, и рукопожатие лежит прямо в кадре, без заголовка записи.
// Поле Record остаётся нулевым — записи здесь нет; смещения (в том числе SNI)
// отсчитываются от начала buf, как и у ParseClientHello.
func ParseClientHelloMessage(buf []byte) (ClientHello, error) {
	return parseHandshake(buf, 0, len(buf))
}

// parseHandshake разбирает сообщение рукопожатия ClientHello, лежащее в
// buf[payloadOff:end]. payloadOff — абсолютное смещение начала сообщения в buf
// (для TLS это начало тела записи, для QUIC — ноль); по нему локальные позиции
// курсора переводятся в смещения исходного буфера. Общая часть разбора для
// ParseClientHello (поверх записи TLS) и ParseClientHelloMessage (голое
// сообщение QUIC) — чтобы логика ClientHello жила в одном месте.
func parseHandshake(buf []byte, payloadOff, end int) (ClientHello, error) {
	var ch ClientHello

	body := cursor{buf: buf[payloadOff:end]}

	msgType, ok := body.u8()
	if !ok {
		return ch, ErrIncomplete
	}
	if msgType != handshakeTypeClientHello {
		return ch, ErrNotClientHello
	}
	msgLen32, ok := body.u24()
	if !ok {
		return ch, ErrIncomplete
	}
	msgLen := int(msgLen32)

	// Сообщение рукопожатия может не уместиться в запись. Это допустимо по
	// стандарту, но первая версия такие сообщения не собирает: нужен буфер
	// нескольких записей и склейка. Признаёмся явной ошибкой.
	if msgLen > body.remaining() {
		return ch, ErrFragmentedHandshake
	}

	// Абсолютное смещение тела сообщения: начало тела записи плюс заголовок
	// сообщения рукопожатия.
	ch.HandshakeOff = payloadOff + handshakeHeaderLen
	ch.HandshakeLen = msgLen

	hello, ok := body.sub(msgLen)
	if !ok {
		return ch, ErrIncomplete
	}
	// base — смещение начала hello в исходном буфере; по нему локальные
	// позиции курсора переводятся в абсолютные.
	base := ch.HandshakeOff

	if ch.LegacyVersion, ok = hello.u16(); !ok {
		return ch, ErrMalformed
	}
	if !hello.skip(clientRandomLen) {
		return ch, ErrMalformed
	}

	// legacy_session_id: один байт длины.
	sidLen, ok := hello.u8()
	if !ok {
		return ch, ErrMalformed
	}
	ch.SessionIDOff = base + hello.pos
	ch.SessionIDLen = int(sidLen)
	if !hello.skip(int(sidLen)) {
		return ch, ErrMalformed
	}

	// cipher_suites: два байта длины В БАЙТАХ (не в числе наборов).
	suitesLen, ok := hello.u16()
	if !ok {
		return ch, ErrMalformed
	}
	if !hello.skip(int(suitesLen)) {
		return ch, ErrMalformed
	}

	// legacy_compression_methods: один байт длины.
	compLen, ok := hello.u8()
	if !ok {
		return ch, ErrMalformed
	}
	if !hello.skip(int(compLen)) {
		return ch, ErrMalformed
	}

	// Расширений может не быть вовсе (древние клиенты). Тогда и SNI нет, но
	// сообщение корректно.
	if hello.remaining() == 0 {
		return ch, nil
	}

	extsLen, ok := hello.u16()
	if !ok {
		return ch, ErrMalformed
	}
	ch.ExtensionsOff = base + hello.pos
	ch.ExtensionsLen = int(extsLen)
	exts, ok := hello.sub(int(extsLen))
	if !ok {
		return ch, ErrMalformed
	}

	if err := parseExtensions(&ch, &exts, ch.ExtensionsOff); err != nil {
		return ch, err
	}
	return ch, nil
}

// parseExtensions проходит список расширений, запоминая интересные.
//
// base — абсолютное смещение начала списка расширений, нужное для перевода
// локальных позиций в смещения исходного буфера.
func parseExtensions(ch *ClientHello, exts *cursor, base int) error {
	for exts.remaining() > 0 {
		extType, ok := exts.u16()
		if !ok {
			return ErrMalformed
		}
		extLen, ok := exts.u16()
		if !ok {
			return ErrMalformed
		}
		// Смещение данных расширения до продвижения курсора.
		dataOff := base + exts.pos
		data, ok := exts.sub(int(extLen))
		if !ok {
			return ErrMalformed
		}

		switch extType {
		case extServerName:
			if err := parseServerName(ch, &data, dataOff); err != nil {
				return err
			}
		case extEncryptedClientHello:
			ch.HasECH = true
		}
	}
	return nil
}

// parseServerName разбирает расширение server_name и запоминает расположение
// первого имени типа host_name.
//
// base — абсолютное смещение начала данных расширения.
func parseServerName(ch *ClientHello, data *cursor, base int) error {
	// server_name_list: два байта длины списка.
	listLen, ok := data.u16()
	if !ok {
		return ErrMalformed
	}
	listOff := base + data.pos
	list, ok := data.sub(int(listLen))
	if !ok {
		return ErrMalformed
	}

	for list.remaining() > 0 {
		nameType, ok := list.u8()
		if !ok {
			return ErrMalformed
		}
		nameLen, ok := list.u16()
		if !ok {
			return ErrMalformed
		}
		nameOff := listOff + list.pos
		if !list.skip(int(nameLen)) {
			return ErrMalformed
		}
		// Берём первое имя типа host_name и дальше не ищем: стандарт
		// допускает список, но на практике в нём одно имя, а выбор «какое из
		// нескольких считать настоящим» был бы политикой, а не разбором.
		if nameType == sniTypeHostName && ch.SNILen == 0 {
			ch.SNIOff = nameOff
			ch.SNILen = int(nameLen)
		}
	}
	return nil
}
