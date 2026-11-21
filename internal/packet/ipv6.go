package packet

import "encoding/binary"

// Раскладка основного заголовка IPv6 (RFC 8200), длина фиксирована — 40 байт:
//
//	0       версия (4 бита) | старшие 4 бита класса трафика
//	1       младшие 4 бита класса трафика | старшие 4 бита метки потока
//	2–3     младшие 16 бит метки потока
//	4–5     длина полезной нагрузки (без основного заголовка)
//	6       следующий заголовок
//	7       предел переходов
//	8–23    адрес источника
//	24–39   адрес назначения
const (
	ipv6HeaderLen     = 40
	ipv6PayloadLenOff = 4
	ipv6NextHeaderOff = 6
	ipv6HopLimitOff   = 7
	ipv6SrcOff        = 8
	ipv6DstOff        = 24
	ipv6AddrLen       = 16
	ipv6FlowLabelMax  = 0x000fffff // 20 бит
)

// IPv6Header — представление основного заголовка IPv6 поверх чужого буфера.
// Как и в IPv4, сеттеры правят исходный пакет.
type IPv6Header []byte

// ParseIPv6Header строит представление основного заголовка IPv6.
//
// Заголовки расширения здесь не обходятся: их цепочку разбирает Dissect,
// поскольку именно он отвечает за поиск протокола верхнего уровня.
func ParseIPv6Header(buf []byte) (IPv6Header, error) {
	if len(buf) < ipv6HeaderLen {
		return nil, ErrShortBuffer
	}
	if buf[0]>>4 != 6 {
		return nil, ErrBadVersion
	}
	return IPv6Header(buf[:ipv6HeaderLen]), nil
}

// TrafficClass возвращает байт класса трафика.
func (h IPv6Header) TrafficClass() uint8 {
	// Поле расположено на стыке байт: младшие 4 бита байта 0 — старшая
	// половина класса, старшие 4 бита байта 1 — младшая половина.
	return h[0]<<4 | h[1]>>4
}

// SetTrafficClass записывает байт класса трафика, не затрагивая версию и метку
// потока.
func (h IPv6Header) SetTrafficClass(v uint8) {
	// Версия (старшие 4 бита байта 0) сохраняется; старшая половина класса
	// кладётся в младшие 4 бита байта 0.
	h[0] = h[0]&0xf0 | v>>4
	// Младшая половина класса — в старшие 4 бита байта 1; младшие 4 бита байта
	// 1 принадлежат метке потока и сохраняются.
	h[1] = v<<4 | h[1]&0x0f
}

// FlowLabel возвращает 20-битную метку потока.
func (h IPv6Header) FlowLabel() uint32 {
	// Младшие 4 бита байта 1 — старшая часть метки, байты 2–3 — остальное.
	return uint32(h[1]&0x0f)<<16 | uint32(binary.BigEndian.Uint16(h[2:]))
}

// SetFlowLabel записывает метку потока, сохраняя класс трафика.
func (h IPv6Header) SetFlowLabel(v uint32) {
	v &= ipv6FlowLabelMax
	// Старшие 4 бита байта 1 принадлежат классу трафика — сохраняем их.
	h[1] = h[1]&0xf0 | uint8(v>>16)&0x0f
	binary.BigEndian.PutUint16(h[2:], uint16(v))
}

// PayloadLen возвращает объявленную длину полезной нагрузки: всё, что следует
// за основным заголовком, включая заголовки расширения.
func (h IPv6Header) PayloadLen() uint16 {
	return binary.BigEndian.Uint16(h[ipv6PayloadLenOff:])
}

// SetPayloadLen записывает длину полезной нагрузки.
func (h IPv6Header) SetPayloadLen(v uint16) {
	binary.BigEndian.PutUint16(h[ipv6PayloadLenOff:], v)
}

// SetNextHeader записывает номер следующего заголовка. Нужен при вставке
// заголовка расширения: фиксированный заголовок начинает указывать на него.
func (h IPv6Header) SetNextHeader(p Protocol) { h[ipv6NextHeaderOff] = byte(p) }

// NextHeader возвращает номер следующего заголовка — либо протокол верхнего
// уровня, либо заголовок расширения.
func (h IPv6Header) NextHeader() Protocol { return Protocol(h[ipv6NextHeaderOff]) }

// HopLimit возвращает предел переходов — аналог TTL в IPv4.
func (h IPv6Header) HopLimit() uint8 { return h[ipv6HopLimitOff] }

// SetHopLimit записывает предел переходов.
func (h IPv6Header) SetHopLimit(v uint8) { h[ipv6HopLimitOff] = v }

// Src возвращает представление адреса источника (16 байт исходного буфера).
func (h IPv6Header) Src() []byte { return h[ipv6SrcOff : ipv6SrcOff+ipv6AddrLen] }

// Dst возвращает представление адреса назначения (16 байт исходного буфера).
func (h IPv6Header) Dst() []byte { return h[ipv6DstOff : ipv6DstOff+ipv6AddrLen] }
