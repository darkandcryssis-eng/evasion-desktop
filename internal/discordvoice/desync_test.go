package discordvoice

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/fitting-1c/evasion/internal/packet"
)

// buildUDPv4 собирает валидный исходящий IPv4+UDP-пакет с заданной нагрузкой и
// верными контрольными суммами. Эталон для проверки крафта decoy.
func buildUDPv4(t *testing.T, payload []byte) []byte {
	t.Helper()
	buf := make([]byte, 20+8+len(payload))
	buf[0] = 0x45 // версия 4, IHL 5
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64 // TTL
	buf[9] = 17 // UDP
	copy(buf[12:16], net.ParseIP("10.0.0.1").To4())
	copy(buf[16:20], net.ParseIP("66.22.200.1").To4())
	binary.BigEndian.PutUint16(buf[20:22], 50001)                  // src port
	binary.BigEndian.PutUint16(buf[22:24], 50002)                  // dst port
	binary.BigEndian.PutUint16(buf[24:26], uint16(8+len(payload))) // UDP len
	copy(buf[28:], payload)

	d, err := packet.Dissect(buf)
	if err != nil {
		t.Fatalf("разбор эталона: %v", err)
	}
	if !d.RecomputeChecksums(buf) {
		t.Fatalf("пересчёт сумм эталона не удался")
	}
	if !d.VerifyChecksums(buf) {
		t.Fatalf("эталон должен иметь верные суммы")
	}
	return buf
}

func TestBuildDecoyLowTTLIsValidAndShortLived(t *testing.T) {
	raw := buildUDPv4(t, buildDiscovery(discoveryTypeReq))
	rawCopy := append([]byte(nil), raw...)

	decoy, err := BuildDecoy(raw, FoolTTL, 5, nil)
	if err != nil {
		t.Fatalf("BuildDecoy: %v", err)
	}

	// Шаблон не тронут.
	if !bytes.Equal(raw, rawCopy) {
		t.Fatal("BuildDecoy изменил шаблон")
	}

	d, _ := packet.Dissect(decoy)
	h, ok := d.IPv4(decoy)
	if !ok {
		t.Fatal("decoy должен остаться IPv4")
	}
	if h.TTL() != 5 {
		t.Fatalf("TTL decoy = %d, ожидалось 5", h.TTL())
	}
	// Низкий TTL, но суммы верные — иначе до DPI не дойдёт.
	if !d.VerifyChecksums(decoy) {
		t.Fatal("decoy с низким TTL обязан иметь верные суммы")
	}
}

func TestBuildDecoyBadChecksumCorruptsUDPOnly(t *testing.T) {
	raw := buildUDPv4(t, buildDiscovery(discoveryTypeReq))

	decoy, err := BuildDecoy(raw, FoolBadChecksum, 64, nil)
	if err != nil {
		t.Fatalf("BuildDecoy: %v", err)
	}

	d, _ := packet.Dissect(decoy)
	// Сумма UDP должна быть битой — весь пакет проверку не проходит.
	if d.VerifyChecksums(decoy) {
		t.Fatal("decoy с битой суммой UDP не должен проходить проверку сумм")
	}
	// Но IP-заголовок валиден: сумма IPv4 считается только по заголовку, и
	// битой её делать не нужно — пакет должен дойти до DPI.
	h, _ := d.IPv4(decoy)
	if !verifyIPv4HeaderChecksum(h) {
		t.Fatal("IP-заголовок decoy должен оставаться валидным")
	}
}

func TestBuildDecoyReplacePayload(t *testing.T) {
	raw := buildUDPv4(t, buildDiscovery(discoveryTypeReq))
	// Замена нагрузки той же длины (74 байта) — мусор вместо IP discovery.
	junk := bytes.Repeat([]byte{0xAB}, discoveryLen)

	decoy, err := BuildDecoy(raw, FoolTTL, 5, junk)
	if err != nil {
		t.Fatalf("BuildDecoy: %v", err)
	}
	d, _ := packet.Dissect(decoy)
	pl, _ := d.Payload(decoy)
	if !bytes.Equal(pl, junk) {
		t.Fatal("нагрузка decoy должна быть заменена")
	}
	if !d.VerifyChecksums(decoy) {
		t.Fatal("после замены нагрузки суммы должны быть пересчитаны верно")
	}
}

func TestBuildDecoyRejectsWrongLengthPayload(t *testing.T) {
	raw := buildUDPv4(t, buildDiscovery(discoveryTypeReq))
	if _, err := BuildDecoy(raw, FoolTTL, 5, []byte{0x01, 0x02}); err == nil {
		t.Fatal("замена нагрузки другой длины должна отвергаться")
	}
}

func TestBuildDecoyRejectsNonUDP(t *testing.T) {
	// TCP-пакет (протокол 6) как шаблон — не UDP.
	buf := make([]byte, 20+20)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = 6 // TCP
	copy(buf[12:16], net.ParseIP("10.0.0.1").To4())
	copy(buf[16:20], net.ParseIP("66.22.200.1").To4())
	if _, err := BuildDecoy(buf, FoolTTL, 5, nil); err == nil {
		t.Fatal("не-UDP шаблон должен отвергаться")
	}
}

// verifyIPv4HeaderChecksum проверяет только сумму IPv4-заголовка (сумма по
// самому заголовку), чтобы отделить валидность IP от битой суммы UDP.
func verifyIPv4HeaderChecksum(h packet.IPv4Header) bool {
	var sum uint32
	for i := 0; i+1 < h.HeaderLen(); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return uint16(sum) == 0xFFFF
}
