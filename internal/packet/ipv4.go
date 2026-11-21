package packet

import "encoding/binary"

// Смещения полей заголовка IPv4 (RFC 791). Это константы протокола, а не
// настройки, поэтому им место в коде.
//
//	0      версия (4 бита) | длина заголовка в 32-битных словах (4 бита)
//	1      тип обслуживания (DSCP + ECN)
//	2–3    общая длина пакета
//	4–5    идентификатор
//	6–7    флаги (3 бита) | смещение фрагмента (13 бит)
//	8      время жизни
//	9      протокол
//	10–11  контрольная сумма заголовка
//	12–15  адрес источника
//	16–19  адрес назначения
//	далее  опции, до границы длины заголовка
const (
	ipv4VerIHLOff     = 0
	ipv4TOSOff        = 1
	ipv4TotalLenOff   = 2
	ipv4IDOff         = 4
	ipv4FlagsFragOff  = 6
	ipv4TTLOff        = 8
	ipv4ProtoOff      = 9
	ipv4ChecksumOff   = 10
	ipv4SrcOff        = 12
	ipv4DstOff        = 16
	ipv4MinHeaderLen  = 20
	ipv4MaxHeaderLen  = 60 // длина задаётся 4 битами в словах: 15 * 4
	ipv4AddrLen       = 4
	ipv4FragOffsetMax = 0x1fff // 13 бит
)

// IPv4Header — представление заголовка IPv4 поверх чужого буфера.
//
// Это именно представление, а не копия: срез указывает в исходный пакет, и
// любой сеттер правит оригинал. Такой выбор сделан ради нуля аллокаций на
// горячем пути; цена — вызывающий обязан следить за временем жизни буфера и за
// тем, что представление становится недействительным при его перевыделении.
type IPv4Header []byte

// ParseIPv4Header строит представление заголовка, проверив границы и
// согласованность объявленной длины.
//
// Опции заголовка не разбираются: ни один примитив первой версии их не трогает,
// а разбор без потребителя был бы непроверяемым кодом. Их наличие учитывается
// только в длине заголовка.
func ParseIPv4Header(buf []byte) (IPv4Header, error) {
	if len(buf) < ipv4MinHeaderLen {
		return nil, ErrShortBuffer
	}
	if buf[ipv4VerIHLOff]>>4 != 4 {
		return nil, ErrBadVersion
	}
	// Длина заголовка объявлена в 32-битных словах, отсюда умножение на 4.
	hdrLen := int(buf[ipv4VerIHLOff]&0x0f) * 4
	if hdrLen < ipv4MinHeaderLen || hdrLen > ipv4MaxHeaderLen {
		return nil, ErrBadHeaderLen
	}
	if len(buf) < hdrLen {
		return nil, ErrShortBuffer
	}
	return IPv4Header(buf[:hdrLen]), nil
}

// HeaderLen возвращает длину заголовка в байтах, включая опции.
func (h IPv4Header) HeaderLen() int { return len(h) }

// TOS возвращает байт типа обслуживания (DSCP и ECN вместе).
func (h IPv4Header) TOS() uint8 { return h[ipv4TOSOff] }

// SetTOS записывает байт типа обслуживания.
func (h IPv4Header) SetTOS(v uint8) { h[ipv4TOSOff] = v }

// TotalLen возвращает объявленную общую длину пакета (заголовок и данные).
func (h IPv4Header) TotalLen() uint16 {
	return binary.BigEndian.Uint16(h[ipv4TotalLenOff:])
}

// SetTotalLen записывает общую длину пакета.
func (h IPv4Header) SetTotalLen(v uint16) {
	binary.BigEndian.PutUint16(h[ipv4TotalLenOff:], v)
}

// ID возвращает идентификатор пакета.
func (h IPv4Header) ID() uint16 { return binary.BigEndian.Uint16(h[ipv4IDOff:]) }

// SetID записывает идентификатор пакета.
func (h IPv4Header) SetID(v uint16) { binary.BigEndian.PutUint16(h[ipv4IDOff:], v) }

// Flags возвращает три бита флагов фрагментации, выровненные вправо
// (бит 0 — «ещё фрагменты», бит 1 — «не фрагментировать»).
func (h IPv4Header) Flags() uint8 {
	// Флаги занимают старшие 3 бита байта 6; сдвигаем их в младшие разряды,
	// чтобы наружу отдавать значение 0..7, а не маску внутри байта.
	return h[ipv4FlagsFragOff] >> 5
}

// SetFlags записывает три бита флагов, сохраняя смещение фрагмента.
func (h IPv4Header) SetFlags(v uint8) {
	// Старшие 3 бита — флаги, младшие 5 бит того же байта принадлежат смещению
	// фрагмента, поэтому их необходимо сохранить.
	h[ipv4FlagsFragOff] = (v&0x07)<<5 | h[ipv4FlagsFragOff]&0x1f
}

// FragOffset возвращает смещение фрагмента в 8-байтных блоках.
func (h IPv4Header) FragOffset() uint16 {
	// Поле занимает младшие 13 бит двухбайтного слова по смещению 6.
	return binary.BigEndian.Uint16(h[ipv4FlagsFragOff:]) & ipv4FragOffsetMax
}

// SetFragOffset записывает смещение фрагмента, сохраняя флаги.
func (h IPv4Header) SetFragOffset(v uint16) {
	word := binary.BigEndian.Uint16(h[ipv4FlagsFragOff:])
	// Старшие 3 бита (флаги) переносим без изменений, младшие 13 заменяем.
	word = word&^uint16(ipv4FragOffsetMax) | v&ipv4FragOffsetMax
	binary.BigEndian.PutUint16(h[ipv4FlagsFragOff:], word)
}

// TTL возвращает время жизни.
func (h IPv4Header) TTL() uint8 { return h[ipv4TTLOff] }

// SetTTL записывает время жизни.
func (h IPv4Header) SetTTL(v uint8) { h[ipv4TTLOff] = v }

// Protocol возвращает номер протокола верхнего уровня.
func (h IPv4Header) Protocol() Protocol { return Protocol(h[ipv4ProtoOff]) }

// Checksum возвращает записанную в заголовке контрольную сумму.
func (h IPv4Header) Checksum() uint16 {
	return binary.BigEndian.Uint16(h[ipv4ChecksumOff:])
}

// SetChecksum записывает контрольную сумму как есть, без пересчёта.
//
// Нужен именно такой «тупой» сеттер: примитив порчи суммы обязан уметь записать
// заведомо неверное значение, и если бы запись всегда сопровождалась
// пересчётом, это было бы невыразимо.
func (h IPv4Header) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(h[ipv4ChecksumOff:], v)
}

// RecomputeChecksum пересчитывает и записывает контрольную сумму заголовка.
func (h IPv4Header) RecomputeChecksum() {
	// Обнулять поле перед подсчётом не требуется: IPv4HeaderChecksum
	// пропускает его байты при суммировании, не изменяя буфер.
	h.SetChecksum(IPv4HeaderChecksum(h))
}

// Src возвращает представление адреса источника (4 байта исходного буфера).
func (h IPv4Header) Src() []byte { return h[ipv4SrcOff : ipv4SrcOff+ipv4AddrLen] }

// Dst возвращает представление адреса назначения (4 байта исходного буфера).
func (h IPv4Header) Dst() []byte { return h[ipv4DstOff : ipv4DstOff+ipv4AddrLen] }
