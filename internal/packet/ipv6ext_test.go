package packet

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// ipv6TCPPacket собирает валидный IPv6/TCP-пакет (40 байт заголовка IPv6 без
// расширений + 20 TCP + нагрузка).
func ipv6TCPPacket(t *testing.T, payload []byte) []byte {
	t.Helper()
	buf := make([]byte, 40+20+len(payload))
	buf[0] = 0x60 // версия 6
	binary.BigEndian.PutUint16(buf[4:6], uint16(20+len(payload)))
	buf[6] = 6  // next header = TCP
	buf[7] = 64 // hop limit
	copy(buf[8:24], net.ParseIP("2001:db8::1").To16())
	copy(buf[24:40], net.ParseIP("2001:db8::2").To16())
	binary.BigEndian.PutUint16(buf[40:42], 50000)
	binary.BigEndian.PutUint16(buf[42:44], 443)
	binary.BigEndian.PutUint32(buf[44:48], 1000)
	buf[52] = 0x50
	buf[53] = 0x18
	binary.BigEndian.PutUint16(buf[54:56], 65535)
	copy(buf[60:], payload)
	d, err := Dissect(buf)
	if err != nil {
		t.Fatalf("разбор IPv6: %v", err)
	}
	if !d.RecomputeChecksums(buf) {
		t.Fatalf("пересчёт сумм IPv6 не удался")
	}
	return buf
}

func TestInsertIPv6HopByHop(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x01, 0x44, 0x55}
	buf := ipv6TCPPacket(t, payload)
	orig := append([]byte(nil), buf...)

	d, err := Dissect(buf)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	out, d2, err := d.InsertIPv6HopByHop(buf)
	if err != nil {
		t.Fatalf("InsertIPv6HopByHop: %v", err)
	}

	if !bytes.Equal(buf, orig) {
		t.Errorf("исходный буфер изменён")
	}
	if len(out) != len(buf)+8 {
		t.Fatalf("длина пакета %d, ожидалось %d", len(out), len(buf)+8)
	}

	h := IPv6Header(out[:40])
	// Фиксированный заголовок указывает на Hop-by-Hop (0), а длина нагрузки
	// учла 8 вставленных байт.
	if h.NextHeader() != ProtoHopByHop {
		t.Errorf("next header фиксированного = %v, ожидался hopbyhop", h.NextHeader())
	}
	if int(h.PayloadLen()) != len(out)-40 {
		t.Errorf("payload len %d, ожидалось %d", h.PayloadLen(), len(out)-40)
	}
	// Разбор проходит цепочку расширений и доходит до TCP; L3Len включает
	// Hop-by-Hop (40+8); нагрузка цела.
	if d2.Protocol != ProtoTCP {
		t.Errorf("протокол после вставки = %v, ожидался tcp", d2.Protocol)
	}
	if d2.L3Len != 48 {
		t.Errorf("L3Len=%d, ожидалось 48 (40 + 8 Hop-by-Hop)", d2.L3Len)
	}
	p, ok := d2.Payload(out)
	if !ok || !bytes.Equal(p, payload) {
		t.Errorf("нагрузка после вставки %x, ожидалось %x", p, payload)
	}
	if !d2.RecomputeChecksums(out) || !d2.VerifyChecksums(out) {
		t.Error("суммы пакета после вставки неверны")
	}
}

func TestInsertIPv6HopByHopRejectsIPv4(t *testing.T) {
	buf := md5PacketV4(t, []byte{0x16, 0x03}) // IPv4-пакет (хелпер из tcpoption_test.go)
	d, _ := Dissect(buf)
	if _, _, err := d.InsertIPv6HopByHop(buf); err == nil {
		t.Error("ожидалась ошибка: Hop-by-Hop применим только к IPv6")
	}
}
