package packet

import (
	"encoding/binary"
	"fmt"
)

// Protocol — номер протокола верхнего уровня (поле «протокол» в IPv4, «следующий
// заголовок» в IPv6).
type Protocol uint8

// Номера протоколов и заголовков расширения, которые различает разбор.
const (
	ProtoHopByHop Protocol = 0  // заголовок расширения: параметры для каждого узла
	ProtoTCP      Protocol = 6  //
	ProtoUDP      Protocol = 17 //
	ProtoRouting  Protocol = 43 // заголовок расширения: маршрутизация
	ProtoFragment Protocol = 44 // заголовок расширения: фрагментация
	ProtoNone     Protocol = 59 // явное «дальше ничего нет»
	ProtoDestOpts Protocol = 60 // заголовок расширения: параметры получателя
)

// String возвращает метку протокола для логов и машинного вывода.
func (p Protocol) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoHopByHop:
		return "hopbyhop"
	case ProtoRouting:
		return "routing"
	case ProtoFragment:
		return "fragment"
	case ProtoDestOpts:
		return "destopts"
	case ProtoNone:
		return "none"
	default:
		return fmt.Sprintf("proto(%d)", uint8(p))
	}
}

// Version — версия сетевого протокола разобранного пакета.
type Version uint8

// Версии, которые обрабатывает движок. Обе — с первого дня: если бы движок
// понимал только IPv4, трафик по IPv6 прошёл бы мимо логики, и стратегия
// выглядела бы нерабочей, хотя просто не применялась (требование 3.2).
const (
	VersionNone Version = 0
	Version4    Version = 4
	Version6    Version = 6
)

// String возвращает метку версии.
func (v Version) String() string {
	switch v {
	case Version4:
		return "ipv4"
	case Version6:
		return "ipv6"
	default:
		return "unknown"
	}
}

// maxExtHeaders — предел длины цепочки заголовков расширения IPv6.
//
// Нужен против враждебного ввода: цепочка в принципе может быть сколь угодно
// длинной, а обход без предела на специально собранном пакете превращается в
// затяжной цикл на горячем пути. Восемь — заведомо больше, чем встречается в
// практике (обычно ноль или один).
const maxExtHeaders = 8

// Dissection — результат разбора пакета: смещения слоёв в исходном буфере.
//
// Смещения, а не срезы, выбраны намеренно. Структура остаётся значимой, никаких
// аллокаций разбор не делает, а десинк может править байты оригинала по этим
// смещениям. Цена — вызывающий обязан держать исходный буфер рядом с
// результатом разбора, и путаница «чужой Dissection к чужому буферу» компилятором
// не поймается.
type Dissection struct {
	// Version — версия сетевого слоя.
	Version Version
	// Protocol — протокол верхнего уровня после обхода заголовков расширения.
	Protocol Protocol

	// L3Len — длина сетевого заголовка; сам он начинается с нулевого смещения.
	// Для IPv6 включает заголовки расширения, чтобы L4Off = L3Len всегда.
	L3Len int
	// L4Off, L4Len — смещение и длина заголовка верхнего уровня. Нулевые, если
	// протокол не TCP и не UDP либо заголовок недоступен.
	L4Off, L4Len int
	// PayloadOff, PayloadLen — смещение и длина полезной нагрузки.
	PayloadOff, PayloadLen int

	// Truncated — объявленная длина пакета больше, чем байт в буфере.
	// Разбор при этом не прерывается: доступная часть пригодна для решений,
	// но строить по ней новые пакеты нельзя.
	Truncated bool
	// Fragment — пакет является фрагментом не с нулевым смещением, поэтому
	// заголовка верхнего уровня в нём нет.
	Fragment bool
}

// Dissect разбирает пакет, начиная с сетевого заголовка.
//
// Один проход, ноль аллокаций: функция только считает смещения. Буфер не
// изменяется.
//
// Поведение на неполных данных осознанно разделено: несоответствие объявленной и
// фактической длины отмечается признаком Truncated и не является ошибкой
// (перехват может отдать обрезанный пакет, и решение по нему всё равно нужно
// принять), а противоречивая раскладка заголовков — ошибка.
func Dissect(buf []byte) (Dissection, error) {
	var d Dissection
	if len(buf) < 1 {
		return d, ErrShortBuffer
	}

	switch buf[0] >> 4 {
	case 4:
		return dissectIPv4(buf)
	case 6:
		return dissectIPv6(buf)
	default:
		return d, ErrBadVersion
	}
}

// dissectIPv4 разбирает пакет IPv4.
func dissectIPv4(buf []byte) (Dissection, error) {
	d := Dissection{Version: Version4}

	h, err := ParseIPv4Header(buf)
	if err != nil {
		return d, err
	}
	d.L3Len = h.HeaderLen()
	d.Protocol = h.Protocol()

	// Объявленная общая длина — источник истины о размере пакета; буфер может
	// быть и длиннее (выравнивание), и короче (обрезка при перехвате).
	total := int(h.TotalLen())
	if total < d.L3Len {
		return d, ErrBadHeaderLen
	}
	if total > len(buf) {
		d.Truncated = true
		total = len(buf)
	}

	// Фрагмент с ненулевым смещением не содержит заголовка верхнего уровня:
	// там продолжение данных. Разбирать его как TCP означало бы читать мусор.
	if h.FragOffset() != 0 {
		d.Fragment = true
		d.PayloadOff = d.L3Len
		d.PayloadLen = total - d.L3Len
		return d, nil
	}

	return dissectL4(buf, d, total)
}

// dissectIPv6 разбирает пакет IPv6, обходя цепочку заголовков расширения.
func dissectIPv6(buf []byte) (Dissection, error) {
	d := Dissection{Version: Version6}

	h, err := ParseIPv6Header(buf)
	if err != nil {
		return d, err
	}

	// В IPv6 объявленная длина не включает основной заголовок, в отличие от
	// IPv4 — отсюда сложение.
	total := ipv6HeaderLen + int(h.PayloadLen())
	if total > len(buf) {
		d.Truncated = true
		total = len(buf)
	}

	next := h.NextHeader()
	off := ipv6HeaderLen

	// Обход цепочки расширений. Каждый такой заголовок объявляет собственную
	// длину, и только за последним начинается протокол верхнего уровня.
	for i := 0; ; i++ {
		if i > maxExtHeaders {
			return d, ErrExtChainTooLong
		}
		switch next {
		case ProtoHopByHop, ProtoRouting, ProtoDestOpts:
			// Формат: байт «следующий заголовок», байт длины, затем данные.
			// Длина объявлена в 8-байтных блоках СВЕРХ первых восьми байт,
			// поэтому полная длина = (len+1) * 8.
			if off+2 > len(buf) {
				d.Truncated = true
				return finishNoL4(d, off, total), nil
			}
			extLen := (int(buf[off+1]) + 1) * 8
			if off+extLen > total {
				d.Truncated = true
				return finishNoL4(d, off, total), nil
			}
			next = Protocol(buf[off])
			off += extLen
		case ProtoFragment:
			// Заголовок фрагментации всегда 8 байт. Смещение фрагмента лежит в
			// старших 13 битах слова по смещению +2.
			if off+8 > total {
				d.Truncated = true
				return finishNoL4(d, off, total), nil
			}
			fragOff := binary.BigEndian.Uint16(buf[off+2:]) >> 3
			nextInChain := Protocol(buf[off])
			off += 8
			if fragOff != 0 {
				// Не первый фрагмент: заголовка верхнего уровня нет.
				d.Fragment = true
				d.Protocol = nextInChain
				return finishNoL4(d, off, total), nil
			}
			next = nextInChain
		default:
			// Не заголовок расширения — значит протокол верхнего уровня.
			d.L3Len = off
			d.Protocol = next
			return dissectL4(buf, d, total)
		}
	}
}

// finishNoL4 заполняет результат, когда заголовок верхнего уровня недоступен:
// всё, что осталось после сетевого слоя, считается полезной нагрузкой.
func finishNoL4(d Dissection, off, total int) Dissection {
	d.L3Len = off
	if off > total {
		// Защита от отрицательной длины на обрезанном вводе.
		off = total
		d.L3Len = off
	}
	d.PayloadOff = off
	d.PayloadLen = total - off
	return d
}

// dissectL4 разбирает заголовок верхнего уровня, если это TCP или UDP.
//
// total — длина пакета, которой можно доверять (минимум из объявленной и
// фактической).
func dissectL4(buf []byte, d Dissection, total int) (Dissection, error) {
	// Срез ограничиваем total, а не len(buf): байты за объявленной длиной
	// пакета не принадлежат ему и не должны попасть ни в заголовок, ни в тело.
	if total > len(buf) {
		total = len(buf)
	}
	if d.L3Len > total {
		return d, ErrBadHeaderLen
	}
	rest := buf[d.L3Len:total]

	switch d.Protocol {
	case ProtoTCP:
		th, err := ParseTCPHeader(rest)
		if err != nil {
			// Усечённый заголовок TCP — не повод отбрасывать весь разбор:
			// версия и адреса уже известны и пригодны для решений.
			if err == ErrShortBuffer {
				d.Truncated = true
				return finishNoL4(d, d.L3Len, total), nil
			}
			return d, err
		}
		if err := th.ValidateOptions(); err != nil {
			return d, err
		}
		d.L4Off = d.L3Len
		d.L4Len = th.HeaderLen()
	case ProtoUDP:
		uh, err := ParseUDPHeader(rest)
		if err != nil {
			d.Truncated = true
			return finishNoL4(d, d.L3Len, total), nil
		}
		d.L4Off = d.L3Len
		d.L4Len = udpHeaderLen
		// Объявленная длина датаграммы меньше заголовка — пакет противоречив.
		if int(uh.Len()) < udpHeaderLen {
			return d, ErrBadHeaderLen
		}
	default:
		// Прочие протоколы движку не нужны: ни один примитив их не трогает.
		return finishNoL4(d, d.L3Len, total), nil
	}

	d.PayloadOff = d.L4Off + d.L4Len
	d.PayloadLen = total - d.PayloadOff
	if d.PayloadLen < 0 {
		d.PayloadLen = 0
	}
	return d, nil
}
