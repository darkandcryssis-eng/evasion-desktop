package tlsparse

import "errors"

// ScanSNI ищет имя сервера (SNI) в сообщении ClientHello, НЕ требуя, чтобы
// сообщение было целым.
//
// Зачем отдельно от ParseClientHelloMessage. В QUIC постквантовый ClientHello
// не помещается в один Initial, но расширение server_name лежит в начале
// рукопожатия — в самом первом Initial. Обычный разбор на обрезанном сообщении
// честно отказывает (ErrFragmentedHandshake), потому что строит точные
// смещения для десинка и обязан видеть всё. Здесь задача другая: по первому
// пакету понять, к какому имени идёт соединение. Поэтому разбираем ровно
// столько, сколько есть, и отдаём имя, если оно целиком присутствует.
//
// Возвращает байты имени (представление msg, без копии) и true только если
// расширение server_name встречено и имя в нём помещается в доступных байтах.
// Иначе — (nil, false): имени ещё/уже не видно. Границы проверяет курсор —
// за пределы msg разбор не выходит ни на каком вводе (8.2).
func ScanSNI(msg []byte) ([]byte, bool) {
	c := cursor{buf: msg}

	mt, ok := c.u8()
	if !ok || mt != handshakeTypeClientHello {
		return nil, false
	}
	// Объявленную длину сообщения читаем, но НЕ требуем её наличия в буфере:
	// в этом всё отличие от строгого разбора.
	if _, ok := c.u24(); !ok {
		return nil, false
	}
	if _, ok := c.u16(); !ok { // legacy_version
		return nil, false
	}
	if !c.skip(clientRandomLen) {
		return nil, false
	}
	sidLen, ok := c.u8()
	if !ok || !c.skip(int(sidLen)) {
		return nil, false
	}
	suitesLen, ok := c.u16()
	if !ok || !c.skip(int(suitesLen)) {
		return nil, false
	}
	compLen, ok := c.u8()
	if !ok || !c.skip(int(compLen)) {
		return nil, false
	}
	if _, ok := c.u16(); !ok { // объявленная длина списка расширений — тоже не требуем
		return nil, false
	}

	// Идём по расширениям в пределах доступных байт. Усечение в конце — просто
	// конец доступного: останавливаемся (имя не найдено), а не ошибка.
	for c.remaining() > 0 {
		extType, ok := c.u16()
		if !ok {
			return nil, false
		}
		extLen, ok := c.u16()
		if !ok {
			return nil, false
		}
		data, ok := c.sub(int(extLen))
		if !ok {
			// Расширение (возможно, и само server_name) обрезано — не угадываем.
			return nil, false
		}
		if extType == extServerName {
			return scanServerName(&data)
		}
	}
	return nil, false
}

// scanServerName достаёт первое имя типа host_name из данных расширения
// server_name. Та же структура, что в строгом parseServerName, но отдаёт байты
// напрямую, без записи смещений.
func scanServerName(data *cursor) ([]byte, bool) {
	listLen, ok := data.u16()
	if !ok {
		return nil, false
	}
	list, ok := data.sub(int(listLen))
	if !ok {
		return nil, false
	}
	for list.remaining() > 0 {
		nameType, ok := list.u8()
		if !ok {
			return nil, false
		}
		nameLen, ok := list.u16()
		if !ok {
			return nil, false
		}
		name, ok := list.bytes(int(nameLen))
		if !ok {
			return nil, false
		}
		if nameType == sniTypeHostName {
			return name, true
		}
	}
	return nil, false
}

// ParseClientHelloLenient разбирает ClientHello поверх записи TLS, допуская,
// что запись не целиком в буфере.
//
// Зачем. Большой постквантовый ClientHello не помещается в один TCP-сегмент и
// разбивается на несколько: первый сегмент несёт заголовок записи, начало
// рукопожатия и — почти всегда — расширение server_name (оно идёт в начале
// списка). Строгий ParseClientHello на таком вводе честно отказывает
// (ErrIncomplete при усечённом теле, ErrFragmentedHandshake при объявленной
// длине больше доступной), потому что строит точные смещения всего сообщения и
// обязан видеть его целиком. Здесь задача ýже: найти SNI и его смещения в
// первом сегменте, чтобы применить к этому сегменту десинк, не дожидаясь
// склейки (к моменту склейки первый сегмент уже ушёл бы в сеть сырым).
//
// Отличия от строгого разбора:
//   - запись принимается и при ErrIncomplete (тело усечено сегментом);
//   - объявленная длина сообщения рукопожатия и длина списка расширений
//     читаются, но не требуются к наличию в буфере — идём по доступным байтам,
//     как ScanSNI;
//   - успех только если расширение server_name встречено и доменное имя в нём
//     целиком присутствует в buf.
//
// Возвращает ClientHello с заполненными Record, HandshakeOff, ExtensionsOff,
// SNIOff/SNILen (смещения абсолютны относительно начала buf, как у
// ParseClientHello) и true. Иначе — (ClientHello{}, false). Границы проверяет
// курсор: за пределы buf разбор не выходит ни на каком вводе (8.2).
func ParseClientHelloLenient(buf []byte) (ClientHello, bool) {
	rec, err := ParseRecord(buf)
	if err != nil && !errors.Is(err, ErrIncomplete) {
		return ClientHello{}, false
	}
	if rec.Type != ContentHandshake {
		return ClientHello{}, false
	}

	var ch ClientHello
	ch.Record = rec

	// Курсор идёт по всему buf, начиная с тела записи: позиции сразу
	// абсолютны и годятся как смещения для десинка без пересчёта.
	c := cursor{buf: buf, pos: rec.PayloadOff}

	mt, ok := c.u8()
	if !ok || mt != handshakeTypeClientHello {
		return ClientHello{}, false
	}
	// Объявленную длину сообщения читаем, но НЕ требуем её помещения в буфер:
	// в этом и смысл нестрогого разбора.
	if _, ok := c.u24(); !ok {
		return ClientHello{}, false
	}
	ch.HandshakeOff = rec.PayloadOff + handshakeHeaderLen

	if _, ok := c.u16(); !ok { // legacy_version
		return ClientHello{}, false
	}
	if !c.skip(clientRandomLen) {
		return ClientHello{}, false
	}
	sidLen, ok := c.u8()
	if !ok {
		return ClientHello{}, false
	}
	ch.SessionIDOff = c.pos
	ch.SessionIDLen = int(sidLen)
	if !c.skip(int(sidLen)) {
		return ClientHello{}, false
	}
	suitesLen, ok := c.u16()
	if !ok || !c.skip(int(suitesLen)) {
		return ClientHello{}, false
	}
	compLen, ok := c.u8()
	if !ok || !c.skip(int(compLen)) {
		return ClientHello{}, false
	}
	if _, ok := c.u16(); !ok { // объявленная длина списка расширений — тоже не требуем
		return ClientHello{}, false
	}
	ch.ExtensionsOff = c.pos

	// Идём по расширениям в пределах доступных байт. Усечение до server_name —
	// это «имя ещё не видно»: отказ, а не угадывание.
	for c.remaining() > 0 {
		extType, ok := c.u16()
		if !ok {
			return ClientHello{}, false
		}
		extLen, ok := c.u16()
		if !ok {
			return ClientHello{}, false
		}
		dataOff := c.pos
		data, ok := c.sub(int(extLen))
		if !ok {
			// Расширение (возможно, и само server_name) обрезано — не угадываем.
			return ClientHello{}, false
		}
		switch extType {
		case extServerName:
			off, length, ok := scanServerNameOffset(&data, dataOff)
			if !ok {
				return ClientHello{}, false
			}
			ch.SNIOff = off
			ch.SNILen = length
			return ch, true
		case extEncryptedClientHello:
			ch.HasECH = true
		}
	}
	return ClientHello{}, false
}

// scanServerNameOffset достаёт смещение и длину первого имени типа host_name
// из данных расширения server_name. Структура та же, что в scanServerName, но
// отдаёт абсолютные смещения (а не байты): base — абсолютное смещение начала
// данных расширения в исходном буфере, по нему локальные позиции курсора
// переводятся в смещения буфера.
func scanServerNameOffset(data *cursor, base int) (off, length int, ok bool) {
	listLen, ok := data.u16()
	if !ok {
		return 0, 0, false
	}
	listOff := base + data.pos
	list, ok := data.sub(int(listLen))
	if !ok {
		return 0, 0, false
	}
	for list.remaining() > 0 {
		nameType, ok := list.u8()
		if !ok {
			return 0, 0, false
		}
		nameLen, ok := list.u16()
		if !ok {
			return 0, 0, false
		}
		nameOff := listOff + list.pos
		if !list.skip(int(nameLen)) {
			return 0, 0, false
		}
		if nameType == sniTypeHostName {
			return nameOff, int(nameLen), true
		}
	}
	return 0, 0, false
}
