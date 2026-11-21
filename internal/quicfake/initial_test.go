package quicfake

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Длина должна быть ровно 74 — это требование BuildDecoy у голоса Discord.
// Любое отклонение поломает приём на UDP-decoy.
func TestBenignInitial74Length(t *testing.T) {
	p := BenignInitial74()
	if len(p) != 74 {
		t.Fatalf("длина %d, ожидали 74", len(p))
	}
}

// Flags должен быть ровно 0xc0: long header + fixed + Initial + PN len 1.
func TestBenignInitial74Flags(t *testing.T) {
	p := BenignInitial74()
	if p[0] != 0xc0 {
		t.Fatalf("flags 0x%02x, ожидали 0xc0", p[0])
	}
}

// Версия должна быть 0x00000001 (QUIC v1 — RFC 9000) — ключевая сигнатура
// для DPI-классификатора.
func TestBenignInitial74Version(t *testing.T) {
	p := BenignInitial74()
	ver := binary.BigEndian.Uint32(p[1:5])
	if ver != quicV1Version {
		t.Fatalf("версия 0x%08x, ожидали 0x%08x", ver, quicV1Version)
	}
}

// DCID — 8 байт заданного значения; SCID — 0 байт.
func TestBenignInitial74CIDs(t *testing.T) {
	p := BenignInitial74()
	if p[5] != dcidLen {
		t.Fatalf("DCID len %d, ожидали %d", p[5], dcidLen)
	}
	if !bytes.Equal(p[6:14], benignDCID[:]) {
		t.Fatalf("DCID %x, ожидали %x", p[6:14], benignDCID)
	}
	if p[14] != scidLen {
		t.Fatalf("SCID len %d, ожидали %d", p[14], scidLen)
	}
}

// Validate должен принять свой же пакет без ошибки.
func TestValidateAcceptsOwn(t *testing.T) {
	if err := Validate(BenignInitial74()); err != nil {
		t.Fatalf("Validate отверг свой же пакет: %v", err)
	}
}

// Validate отвергает слишком короткий буфер.
func TestValidateRejectsTooShort(t *testing.T) {
	if err := Validate([]byte{0xc0, 0x00, 0x00}); err == nil {
		t.Fatal("Validate принял слишком короткий буфер")
	}
}

// Validate отвергает non-long-header (например, обычный HTTP/3 short header).
func TestValidateRejectsShortHeader(t *testing.T) {
	buf := make([]byte, 74)
	buf[0] = 0x40 // short header (bit 0 = 0, fixed bit = 1)
	if err := Validate(buf); err == nil {
		t.Fatal("Validate принял short header")
	}
}

// Validate отвергает чужую версию (например, 0x00000029 — QUIC draft 29).
func TestValidateRejectsWrongVersion(t *testing.T) {
	buf := BenignInitial74()
	binary.BigEndian.PutUint32(buf[1:5], 0x00000029)
	if err := Validate(buf); err == nil {
		t.Fatal("Validate принял чужую версию")
	}
}

// Детерминизм: два вызова дают идентичные байты. Нужно для золотых тестов и
// воспроизведения записи (replay).
func TestBenignInitial74Deterministic(t *testing.T) {
	a := BenignInitial74()
	b := BenignInitial74()
	if !bytes.Equal(a, b) {
		t.Fatal("BenignInitial74 недетерминирован")
	}
}

// Возвращаемый срез — свой: правка не ломает последующие вызовы.
func TestBenignInitial74Independent(t *testing.T) {
	a := BenignInitial74()
	a[0] = 0xff
	b := BenignInitial74()
	if b[0] == 0xff {
		t.Fatal("разные вызовы делят один срез")
	}
}
