package windivert

// Address — непрозрачный адрес пакета WinDivert (WINDIVERT_ADDRESS, 80 байт).
//
// Движок хранит его целиком и возвращает в Send: без него повторная инъекция не
// состоится. Учитываются направление и готовность контрольных сумм.
type Address [addrSize]byte

func (a Address) WithFinalUDPChecksums() any {
	a[flagsOffset] |= (1 << 5) | (1 << 7)
	return a
}

// Раскладка WINDIVERT_ADDRESS 2.x: Timestamp (8 байт), затем 32-битное слово с
// упакованными полями (Layer:8, Event:8, затем по одному биту Sniffed, Outbound,
// Loopback, Impostor, IPv6, IPChecksum, TCPChecksum, UDPChecksum, затем
// Reserved1:8), Reserved2 (4 байта) и объединение данных слоёв (64 байта).
//
// На little-endian x86 младший байт слова лежит первым, поэтому байт признаков
// (где Sniffed — бит 0, Outbound — бит 1) приходится на смещение 10: Timestamp
// занимает 0..7, байт Layer — 8, байт Event — 9, байт признаков — 10.
const (
	addrSize     = 80
	flagsOffset  = 10
	flagOutbound = 1 << 1
)

// Outbound сообщает, исходящий ли пакет. По нему проставляется направление в
// capture.Packet, а контур решает, трогать ли пакет (исходящие ClientHello) или
// пропустить (входящие).
func (a Address) Outbound() bool { return a[flagsOffset]&flagOutbound != 0 }

// WithInterface возвращает адрес с другим сетевым интерфейсом (подынтерфейс 0):
// пакет, отправленный с таким адресом, уходит через заданный интерфейс.
func (a Address) WithInterface(ifIdx uint32) Address {
	a[16], a[17], a[18], a[19] = byte(ifIdx), byte(ifIdx>>8), byte(ifIdx>>16), byte(ifIdx>>24)
	a[20], a[21], a[22], a[23] = 0, 0, 0, 0
	return a
}

// IfIdx — индекс сетевого интерфейса пакета (слой Network: первое поле
// объединения данных, сразу за 16-байтовым заголовком адреса).
func (a Address) IfIdx() uint32 {
	return uint32(a[16]) | uint32(a[17])<<8 | uint32(a[18])<<16 | uint32(a[19])<<24
}

// WithFinalTCPChecksums prevents WinDivert from repairing checksums after the
// TCP executor calculated them and applied any deliberate checksum corruption.
// The original captured address remains unchanged for untouched packets.
func (a Address) WithFinalTCPChecksums() any {
	a[flagsOffset] |= (1 << 5) | (1 << 6)
	return a
}
