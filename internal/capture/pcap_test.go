package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
)

// buildPCAP собирает минимальный файл pcap в памяти для тестов.
func buildPCAP(t *testing.T, bo binary.ByteOrder, magic []byte, linkType uint32, packets [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer

	hdr := make([]byte, pcapGlobalHeaderLen)
	copy(hdr[:4], magic)
	bo.PutUint16(hdr[4:6], 2)  // version_major
	bo.PutUint16(hdr[6:8], 4)  // version_minor
	bo.PutUint32(hdr[20:24], linkType)
	buf.Write(hdr)

	for _, p := range packets {
		rec := make([]byte, pcapRecordHeaderLen)
		bo.PutUint32(rec[8:12], uint32(len(p)))  // incl_len
		bo.PutUint32(rec[12:16], uint32(len(p))) // orig_len
		buf.Write(rec)
		buf.Write(p)
	}
	return buf.Bytes()
}

var magicMicroBE = []byte{0xa1, 0xb2, 0xc3, 0xd4}

// TestPCAPReadsRawPacketsInOrder — сырые IP-пакеты выдаются по порядку, затем
// io.EOF, с направлением Outbound.
func TestPCAPReadsRawPacketsInOrder(t *testing.T) {
	data := buildPCAP(t, binary.BigEndian, magicMicroBE, linkTypeRaw,
		[][]byte{{0x45, 0x11}, {0x45, 0x22}})

	src, err := NewPCAPSource(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewPCAPSource: %v", err)
	}

	p1, err := src.Recv()
	if err != nil || !bytes.Equal(p1.Data, []byte{0x45, 0x11}) || p1.Dir != core.DirectionOutbound {
		t.Fatalf("первый пакет: %+v err=%v", p1, err)
	}
	p2, err := src.Recv()
	if err != nil || !bytes.Equal(p2.Data, []byte{0x45, 0x22}) {
		t.Fatalf("второй пакет: %+v err=%v", p2, err)
	}
	if _, err := src.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("по концу ожидался io.EOF, получено %v", err)
	}
}

// TestPCAPStripsEthernetHeader — при канале ethernet снимается 14-байтный
// заголовок, остаётся IP-уровень.
func TestPCAPStripsEthernetHeader(t *testing.T) {
	frame := make([]byte, ethernetHeaderLen+3)
	frame[ethernetHeaderLen] = 0x45 // первый байт IP
	frame[ethernetHeaderLen+1] = 0xAB
	frame[ethernetHeaderLen+2] = 0xCD

	data := buildPCAP(t, binary.BigEndian, magicMicroBE, linkTypeEthernet, [][]byte{frame})
	src, err := NewPCAPSource(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewPCAPSource: %v", err)
	}
	p, err := src.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(p.Data, []byte{0x45, 0xAB, 0xCD}) {
		t.Fatalf("заголовок ethernet снят неверно: %x", p.Data)
	}
}

// TestPCAPLittleEndian — порядок байт определяется по magic (здесь обратный).
func TestPCAPLittleEndian(t *testing.T) {
	magicLE := []byte{0xd4, 0xc3, 0xb2, 0xa1}
	data := buildPCAP(t, binary.LittleEndian, magicLE, linkTypeRaw, [][]byte{{0x45, 0x01}})
	src, err := NewPCAPSource(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewPCAPSource: %v", err)
	}
	if src.bo != binary.LittleEndian {
		t.Fatalf("порядок байт определён неверно")
	}
	p, err := src.Recv()
	if err != nil || !bytes.Equal(p.Data, []byte{0x45, 0x01}) {
		t.Fatalf("пакет: %+v err=%v", p, err)
	}
}

// TestPCAPNanoMagicIsAccepted — наносекундный вариант magic принимается
// (отличается только разрешением времени, которое источник не использует).
func TestPCAPNanoMagicIsAccepted(t *testing.T) {
	magicNanoBE := []byte{0xa1, 0xb2, 0x3c, 0x4d}
	data := buildPCAP(t, binary.BigEndian, magicNanoBE, linkTypeRaw, [][]byte{{0x45}})
	if _, err := NewPCAPSource(bytes.NewReader(data)); err != nil {
		t.Fatalf("наносекундный magic должен приниматься: %v", err)
	}
}

// TestPCAPRejectsNonPCAP — чужое магическое число это ошибка, а не пустой поток.
func TestPCAPRejectsNonPCAP(t *testing.T) {
	data := buildPCAP(t, binary.BigEndian, []byte{0xDE, 0xAD, 0xBE, 0xEF}, linkTypeRaw, nil)
	if _, err := NewPCAPSource(bytes.NewReader(data)); err == nil {
		t.Fatalf("ожидалась ошибка на не-pcap")
	}
}

// TestPCAPRejectsUnknownLinkType — неизвестная инкапсуляция это ошибка, а не
// молчаливый пропуск.
func TestPCAPRejectsUnknownLinkType(t *testing.T) {
	data := buildPCAP(t, binary.BigEndian, magicMicroBE, 113 /* LINUX_SLL */, nil)
	if _, err := NewPCAPSource(bytes.NewReader(data)); err == nil {
		t.Fatalf("ожидалась ошибка на неподдержанном типе канала")
	}
}

// TestPCAPTruncatedBodyIsError — обрыв тела записи это порча, а не штатный
// конец: io.EOF обратно не превращается.
func TestPCAPTruncatedBodyIsError(t *testing.T) {
	// Заголовок обещает 4 байта, а есть только 2.
	data := buildPCAP(t, binary.BigEndian, magicMicroBE, linkTypeRaw, nil)
	rec := make([]byte, pcapRecordHeaderLen)
	binary.BigEndian.PutUint32(rec[8:12], 4)
	data = append(data, rec...)
	data = append(data, 0x45, 0x00) // только 2 байта тела

	src, err := NewPCAPSource(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewPCAPSource: %v", err)
	}
	_, err = src.Recv()
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("обрыв тела должен быть ошибкой, не io.EOF: %v", err)
	}
}

// TestPCAPByteOrderUnit — разбор порядка байт по magic проверяется без файла.
func TestPCAPByteOrderUnit(t *testing.T) {
	cases := []struct {
		magic []byte
		bo    binary.ByteOrder
		ok    bool
	}{
		{[]byte{0xa1, 0xb2, 0xc3, 0xd4}, binary.BigEndian, true},
		{[]byte{0xd4, 0xc3, 0xb2, 0xa1}, binary.LittleEndian, true},
		{[]byte{0xa1, 0xb2, 0x3c, 0x4d}, binary.BigEndian, true},
		{[]byte{0x4d, 0x3c, 0xb2, 0xa1}, binary.LittleEndian, true},
		{[]byte{0x00, 0x00, 0x00, 0x00}, nil, false},
	}
	for _, c := range cases {
		bo, err := pcapByteOrder(c.magic)
		if c.ok && (err != nil || bo != c.bo) {
			t.Errorf("magic %x: ожидался %v, получено %v err=%v", c.magic, c.bo, bo, err)
		}
		if !c.ok && err == nil {
			t.Errorf("magic %x: ожидалась ошибка", c.magic)
		}
	}
}
