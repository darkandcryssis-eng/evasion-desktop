package packet

import (
	"encoding/binary"
	"testing"
)

// Конструкторы тестовых пакетов. Собираются побайтно вручную, а не своим же
// кодом сборки: тест, который строит пакет теми же функциями, что проверяет,
// не поймает согласованную ошибку в раскладке полей.
//
// Адреса взяты из документационных диапазонов (RFC 5737 для IPv4, RFC 3849 для
// IPv6), чтобы случайный живой прогон не ушёл к реальному хосту.

// testIPv4Src, testIPv4Dst — 192.0.2.1 и 198.51.100.2.
var (
	testIPv4Src = []byte{192, 0, 2, 1}
	testIPv4Dst = []byte{198, 51, 100, 2}
	// 2001:db8::1 и 2001:db8::2
	testIPv6Src = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	testIPv6Dst = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
)

// tcpSegment собирает заголовок TCP с полем контрольной суммы, равным нулю, и
// заданным телом. Опции не добавляются, смещение данных — 5 слов.
func tcpSegment(payload []byte) []byte {
	seg := make([]byte, tcpMinHeaderLen+len(payload))
	binary.BigEndian.PutUint16(seg[tcpSrcPortOff:], 50000)
	binary.BigEndian.PutUint16(seg[tcpDstPortOff:], 443)
	binary.BigEndian.PutUint32(seg[tcpSeqOff:], 0x11223344)
	binary.BigEndian.PutUint32(seg[tcpAckOff:], 0)
	// Старшие 4 бита байта 12 — смещение данных в 32-битных словах.
	seg[tcpDataOffsetOff] = 5 << 4
	seg[tcpFlagsOff] = FlagPSH | FlagACK
	binary.BigEndian.PutUint16(seg[tcpWindowOff:], 65535)
	copy(seg[tcpMinHeaderLen:], payload)
	return seg
}

// buildIPv4TCP собирает пакет IPv4 + TCP с телом "hello" и нулевыми суммами.
func buildIPv4TCP(t testing.TB) []byte {
	t.Helper()
	seg := tcpSegment([]byte("hello"))
	pkt := make([]byte, ipv4MinHeaderLen+len(seg))

	pkt[ipv4VerIHLOff] = 4<<4 | 5 // версия 4, длина заголовка 5 слов
	pkt[ipv4TOSOff] = 0
	binary.BigEndian.PutUint16(pkt[ipv4TotalLenOff:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[ipv4IDOff:], 0x1234)
	// 0x4000 — установлен бит «не фрагментировать», смещение нулевое.
	binary.BigEndian.PutUint16(pkt[ipv4FlagsFragOff:], 0x4000)
	pkt[ipv4TTLOff] = 64
	pkt[ipv4ProtoOff] = byte(ProtoTCP)
	copy(pkt[ipv4SrcOff:], testIPv4Src)
	copy(pkt[ipv4DstOff:], testIPv4Dst)
	copy(pkt[ipv4MinHeaderLen:], seg)
	return pkt
}

// buildIPv6TCP собирает пакет IPv6 + TCP с тем же телом.
func buildIPv6TCP(t testing.TB) []byte {
	t.Helper()
	seg := tcpSegment([]byte("hello"))
	pkt := make([]byte, ipv6HeaderLen+len(seg))

	pkt[0] = 6 << 4 // версия 6, класс трафика нулевой
	// Длина полезной нагрузки в IPv6 НЕ включает основной заголовок.
	binary.BigEndian.PutUint16(pkt[ipv6PayloadLenOff:], uint16(len(seg)))
	pkt[ipv6NextHeaderOff] = byte(ProtoTCP)
	pkt[ipv6HopLimitOff] = 64
	copy(pkt[ipv6SrcOff:], testIPv6Src)
	copy(pkt[ipv6DstOff:], testIPv6Dst)
	copy(pkt[ipv6HeaderLen:], seg)
	return pkt
}

// buildIPv4UDP собирает пакет IPv4 + UDP. Тело начинается с байта 0xc0 —
// так выглядит длинный заголовок QUIC, что понадобится при обнаружении QUIC.
func buildIPv4UDP(t testing.TB) []byte {
	t.Helper()
	payload := []byte{0xc0, 0x00, 0x00, 0x00, 'a', 'b', 'c'}
	dgram := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(dgram[udpSrcPortOff:], 55555)
	binary.BigEndian.PutUint16(dgram[udpDstPortOff:], 443)
	binary.BigEndian.PutUint16(dgram[udpLenOff:], uint16(len(dgram)))
	copy(dgram[udpHeaderLen:], payload)

	pkt := make([]byte, ipv4MinHeaderLen+len(dgram))
	pkt[ipv4VerIHLOff] = 4<<4 | 5
	binary.BigEndian.PutUint16(pkt[ipv4TotalLenOff:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[ipv4IDOff:], 0x1234)
	binary.BigEndian.PutUint16(pkt[ipv4FlagsFragOff:], 0x4000)
	pkt[ipv4TTLOff] = 64
	pkt[ipv4ProtoOff] = byte(ProtoUDP)
	copy(pkt[ipv4SrcOff:], testIPv4Src)
	copy(pkt[ipv4DstOff:], testIPv4Dst)
	copy(pkt[ipv4MinHeaderLen:], dgram)
	return pkt
}

// buildIPv6ExtTCP собирает пакет IPv6 с цепочкой расширений
// «параметры для каждого узла» → «параметры получателя» → TCP.
//
// Нужен потому, что именно обход цепочки — место, где легко промахнуться:
// длина заголовка расширения объявлена в 8-байтных блоках СВЕРХ первых восьми
// байт.
func buildIPv6ExtTCP(t testing.TB) []byte {
	t.Helper()
	seg := tcpSegment([]byte("hello"))

	// Два заголовка расширения по 8 байт каждый (объявленная длина 0).
	hopByHop := make([]byte, 8)
	hopByHop[0] = byte(ProtoDestOpts) // следующий — параметры получателя
	hopByHop[1] = 0                   // длина: (0+1)*8 = 8 байт

	destOpts := make([]byte, 8)
	destOpts[0] = byte(ProtoTCP)
	destOpts[1] = 0

	rest := make([]byte, 0, len(hopByHop)+len(destOpts)+len(seg))
	rest = append(rest, hopByHop...)
	rest = append(rest, destOpts...)
	rest = append(rest, seg...)

	pkt := make([]byte, ipv6HeaderLen+len(rest))
	pkt[0] = 6 << 4
	binary.BigEndian.PutUint16(pkt[ipv6PayloadLenOff:], uint16(len(rest)))
	pkt[ipv6NextHeaderOff] = byte(ProtoHopByHop)
	pkt[ipv6HopLimitOff] = 64
	copy(pkt[ipv6SrcOff:], testIPv6Src)
	copy(pkt[ipv6DstOff:], testIPv6Dst)
	copy(pkt[ipv6HeaderLen:], rest)
	return pkt
}

// buildIPv4TCPWithOptions собирает пакет, где заголовок TCP несёт опции MSS и
// масштаб окна, разделённые заполнителем.
func buildIPv4TCPWithOptions(t testing.TB) []byte {
	t.Helper()
	// MSS (вид 2, длина 4, значение 1460), заполнитель, масштаб окна
	// (вид 3, длина 3, значение 7), конец списка и выравнивание до 4 байт.
	opts := []byte{
		TCPOptMSS, 4, 0x05, 0xb4,
		TCPOptNop,
		TCPOptWindowScl, 3, 7,
		TCPOptEnd,
		0, 0, 0, // выравнивание области опций до кратности 4
	}
	payload := []byte("hello")
	seg := make([]byte, tcpMinHeaderLen+len(opts)+len(payload))
	binary.BigEndian.PutUint16(seg[tcpSrcPortOff:], 50000)
	binary.BigEndian.PutUint16(seg[tcpDstPortOff:], 443)
	binary.BigEndian.PutUint32(seg[tcpSeqOff:], 0x11223344)
	// Смещение данных: фиксированная часть плюс опции, в 32-битных словах.
	seg[tcpDataOffsetOff] = byte((tcpMinHeaderLen+len(opts))/4) << 4
	seg[tcpFlagsOff] = FlagSYN
	binary.BigEndian.PutUint16(seg[tcpWindowOff:], 65535)
	copy(seg[tcpMinHeaderLen:], opts)
	copy(seg[tcpMinHeaderLen+len(opts):], payload)

	pkt := make([]byte, ipv4MinHeaderLen+len(seg))
	pkt[ipv4VerIHLOff] = 4<<4 | 5
	binary.BigEndian.PutUint16(pkt[ipv4TotalLenOff:], uint16(len(pkt)))
	pkt[ipv4TTLOff] = 64
	pkt[ipv4ProtoOff] = byte(ProtoTCP)
	copy(pkt[ipv4SrcOff:], testIPv4Src)
	copy(pkt[ipv4DstOff:], testIPv4Dst)
	copy(pkt[ipv4MinHeaderLen:], seg)
	return pkt
}
