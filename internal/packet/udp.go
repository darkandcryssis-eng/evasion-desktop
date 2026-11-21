package packet

import "encoding/binary"

// Раскладка заголовка UDP (RFC 768), длина фиксирована — 8 байт:
//
//	0–1  порт источника
//	2–3  порт назначения
//	4–5  длина (заголовок и данные)
//	6–7  контрольная сумма
const (
	udpSrcPortOff  = 0
	udpDstPortOff  = 2
	udpLenOff      = 4
	udpChecksumOff = 6
	udpHeaderLen   = 8
)

// UDPHeader — представление заголовка UDP поверх чужого буфера.
//
// UDP нужен проекту не для десинка, а для обнаружения QUIC: в первой версии
// трафик QUIC к отслеживаемым группам блокируется, чтобы приложение откатилось
// на TCP (3.3). Поэтому набор операций здесь минимальный — чтение.
type UDPHeader []byte

// ParseUDPHeader строит представление заголовка UDP.
func ParseUDPHeader(buf []byte) (UDPHeader, error) {
	if len(buf) < udpHeaderLen {
		return nil, ErrShortBuffer
	}
	return UDPHeader(buf[:udpHeaderLen]), nil
}

// SrcPort возвращает порт источника.
func (h UDPHeader) SrcPort() uint16 { return binary.BigEndian.Uint16(h[udpSrcPortOff:]) }

// DstPort возвращает порт назначения.
func (h UDPHeader) DstPort() uint16 { return binary.BigEndian.Uint16(h[udpDstPortOff:]) }

// Len возвращает объявленную длину датаграммы, включая заголовок.
func (h UDPHeader) Len() uint16 { return binary.BigEndian.Uint16(h[udpLenOff:]) }

// Checksum возвращает контрольную сумму. Ноль означает «не вычислялась» — это
// допустимо для UDP поверх IPv4 и недопустимо поверх IPv6.
func (h UDPHeader) Checksum() uint16 { return binary.BigEndian.Uint16(h[udpChecksumOff:]) }

// SetChecksum записывает контрольную сумму как есть, без пересчёта.
func (h UDPHeader) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(h[udpChecksumOff:], v)
}
