package rtcredirect

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/fitting-1c/evasion/internal/packet"
)

// tcpPacket собирает исходящий/входящий IPv4+TCP пакет с верными суммами.
// src/dst — порты; flags — байт флагов TCP; payloadLen — сколько байт тела.
func tcpPacket(t *testing.T, srcPort, dstPort uint16, flags uint8, payloadLen int) []byte {
	t.Helper()
	const ipLen, tcpLen = 20, 20
	buf := make([]byte, ipLen+tcpLen+payloadLen)
	// IPv4.
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = 6 // TCP
	copy(buf[12:16], net.ParseIP("10.0.0.2").To4())
	copy(buf[16:20], net.ParseIP("104.29.149.18").To4())
	// TCP.
	binary.BigEndian.PutUint16(buf[20:22], srcPort)
	binary.BigEndian.PutUint16(buf[22:24], dstPort)
	buf[32] = 0x50 // data offset = 5 слов
	buf[33] = flags
	binary.BigEndian.PutUint16(buf[34:36], 0xffff) // окно
	for i := 0; i < payloadLen; i++ {
		buf[ipLen+tcpLen+i] = byte(i)
	}
	d, err := packet.Dissect(buf)
	if err != nil {
		t.Fatalf("разбор шаблона: %v", err)
	}
	if !d.RecomputeChecksums(buf) {
		t.Fatalf("суммы шаблона не пересчитаны")
	}
	return buf
}

func portsOf(t *testing.T, buf []byte) (src, dst uint16) {
	t.Helper()
	d, err := packet.Dissect(buf)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	th, ok := d.TCP(buf)
	if !ok {
		t.Fatalf("не TCP")
	}
	return th.SrcPort(), th.DstPort()
}

func mustValidChecksums(t *testing.T, buf []byte) {
	t.Helper()
	d, err := packet.Dissect(buf)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !d.VerifyChecksums(buf) {
		t.Fatalf("контрольные суммы не сходятся после переклейки")
	}
}

// TestRedirectOutboundThenInbound: исходящий на душимый порт уводится на живой,
// входящий с живого возвращается на исходный — полный цикл NAT.
func TestRedirectOutboundThenInbound(t *testing.T) {
	r := New([]uint16{2053, 2083, 2087, 2096}, 8443)

	// Исходящий SYN от локального 50000 на душимый 2083.
	out := tcpPacket(t, 50000, 2083, packet.FlagSYN, 0)
	if !r.Apply(out, true) {
		t.Fatal("исходящий на душимый порт должен переклеиться")
	}
	if _, dst := portsOf(t, out); dst != 8443 {
		t.Fatalf("порт назначения должен стать 8443, получено %d", dst)
	}
	mustValidChecksums(t, out)

	// Входящий SYN-ACK с живого 8443 на локальный 50000.
	in := tcpPacket(t, 8443, 50000, packet.FlagSYN|packet.FlagACK, 0)
	if !r.Apply(in, false) {
		t.Fatal("входящий с живого порта для отслеживаемого соединения должен восстановиться")
	}
	if src, _ := portsOf(t, in); src != 2083 {
		t.Fatalf("порт источника должен вернуться к 2083, получено %d", src)
	}
	mustValidChecksums(t, in)
}

// TestRedirectLeavesNativeGoodPortUntouched: нативное соединение на живой порт
// (8443/443) не трогается ни в одну сторону.
func TestRedirectLeavesNativeGoodPortUntouched(t *testing.T) {
	r := New([]uint16{2053, 2083, 2087, 2096}, 8443)

	// Исходящий на 8443 — не душимый, не трогаем.
	out := tcpPacket(t, 51000, 8443, packet.FlagSYN, 0)
	if r.Apply(out, true) {
		t.Fatal("нативный исходящий на 8443 трогать нельзя")
	}
	if src, dst := portsOf(t, out); src != 51000 || dst != 8443 {
		t.Fatalf("порты нативного 8443 изменены: %d->%d", src, dst)
	}

	// Входящий с 8443 на локальный 51000, которого нет в карте — не трогаем.
	in := tcpPacket(t, 8443, 51000, packet.FlagSYN|packet.FlagACK, 0)
	if r.Apply(in, false) {
		t.Fatal("входящий 8443 для неотслеживаемого локального порта трогать нельзя")
	}
	if src, _ := portsOf(t, in); src != 8443 {
		t.Fatalf("порт источника нативного 8443 изменён: %d", src)
	}
}

// TestRedirectStaleEntryClearedOnFreshSyn: если локальный порт раньше был
// переклеенным соединением, а теперь открывает нативное на не-душимый порт,
// устаревшая запись снимается — иначе входящие 8443 переклеились бы ошибочно.
func TestRedirectStaleEntryClearedOnFreshSyn(t *testing.T) {
	r := New([]uint16{2083}, 8443)

	// Было переклеенное соединение с локального 50000.
	out1 := tcpPacket(t, 50000, 2083, packet.FlagSYN, 0)
	if !r.Apply(out1, true) {
		t.Fatal("ожидалась переклейка")
	}
	// Тот же локальный порт переиспользован под нативное 8443 (чистый SYN).
	out2 := tcpPacket(t, 50000, 8443, packet.FlagSYN, 0)
	if r.Apply(out2, true) {
		t.Fatal("нативный SYN на 8443 трогать нельзя")
	}
	// Теперь входящий 8443 на 50000 НЕ должен переклеиться (запись снята).
	in := tcpPacket(t, 8443, 50000, packet.FlagSYN|packet.FlagACK, 0)
	if r.Apply(in, false) {
		t.Fatal("после снятия устаревшей записи входящий 8443 трогать нельзя")
	}
}

// TestRedirectForgetsOnClose: FIN/RST на входящем забывает соединение.
func TestRedirectForgetsOnClose(t *testing.T) {
	r := New([]uint16{2083}, 8443)
	out := tcpPacket(t, 50000, 2083, packet.FlagSYN, 0)
	r.Apply(out, true)

	fin := tcpPacket(t, 8443, 50000, packet.FlagFIN|packet.FlagACK, 0)
	if !r.Apply(fin, false) {
		t.Fatal("входящий FIN отслеживаемого соединения должен восстановиться")
	}
	if _, _, tracked := r.Stats(); tracked != 0 {
		t.Fatalf("после FIN соединение должно быть забыто, осталось %d", tracked)
	}
}

// TestRedirectInactive: без портов переклейка бездействует.
func TestRedirectInactive(t *testing.T) {
	r := New(nil, 8443)
	if r.Active() {
		t.Fatal("без душимых портов переклейка не должна быть активной")
	}
	out := tcpPacket(t, 50000, 2083, packet.FlagSYN, 0)
	if r.Apply(out, true) {
		t.Fatal("неактивная переклейка не должна трогать пакеты")
	}
}

// TestRedirectDataSegmentRewritten: не только SYN, но и сегмент с данными на
// душимый порт уводится (соединение живёт дольше рукопожатия).
func TestRedirectDataSegmentRewritten(t *testing.T) {
	r := New([]uint16{2096}, 8443)
	data := tcpPacket(t, 52000, 2096, packet.FlagACK|packet.FlagPSH, 120)
	if !r.Apply(data, true) {
		t.Fatal("сегмент с данными на душимый порт должен переклеиться")
	}
	if _, dst := portsOf(t, data); dst != 8443 {
		t.Fatalf("порт назначения должен стать 8443, получено %d", dst)
	}
	mustValidChecksums(t, data)
}
