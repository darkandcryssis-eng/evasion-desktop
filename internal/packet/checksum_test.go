package packet

import "testing"

// Эталонные значения контрольных сумм посчитаны независимой реализацией
// (отдельный скрипт на Python по RFC 1071), а не этим же кодом. Это важно:
// самосогласованный тест подтвердил бы лишь повторяемость ошибки, а не
// правильность арифметики.
const (
	refIPv4HeaderChecksum    = 0x3c60
	refTCPChecksumOverIPv4   = 0x764c
	refTCPChecksumOverIPv6   = 0x070f
	refUDPChecksumOverIPv4   = 0xb476
	refIPv4ChecksumAfterTTL3 = 0x7960
)

func TestIPv4HeaderChecksumMatchesReference(t *testing.T) {
	pkt := buildIPv4TCP(t)
	h, err := ParseIPv4Header(pkt)
	if err != nil {
		t.Fatal(err)
	}
	// Поле суммы в заготовке нулевое, поэтому подсчёт даёт эталон.
	if got := IPv4HeaderChecksum(h); got != refIPv4HeaderChecksum {
		t.Fatalf("сумма заголовка IPv4 = 0x%04x, эталон 0x%04x", got, refIPv4HeaderChecksum)
	}
}

func TestTCPChecksumOverIPv4MatchesReference(t *testing.T) {
	pkt := buildIPv4TCP(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !d.RecomputeChecksums(pkt) {
		t.Fatal("пересчёт сумм не выполнен")
	}
	th, ok := d.TCP(pkt)
	if !ok {
		t.Fatal("заголовок TCP не найден")
	}
	if got := th.Checksum(); got != refTCPChecksumOverIPv4 {
		t.Fatalf("сумма TCP = 0x%04x, эталон 0x%04x", got, refTCPChecksumOverIPv4)
	}
	h, _ := d.IPv4(pkt)
	if got := h.Checksum(); got != refIPv4HeaderChecksum {
		t.Fatalf("сумма IPv4 = 0x%04x, эталон 0x%04x", got, refIPv4HeaderChecksum)
	}
}

func TestTCPChecksumOverIPv6MatchesReference(t *testing.T) {
	pkt := buildIPv6TCP(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !d.RecomputeChecksums(pkt) {
		t.Fatal("пересчёт сумм не выполнен")
	}
	th, ok := d.TCP(pkt)
	if !ok {
		t.Fatal("заголовок TCP не найден")
	}
	if got := th.Checksum(); got != refTCPChecksumOverIPv6 {
		t.Fatalf("сумма TCP поверх IPv6 = 0x%04x, эталон 0x%04x", got, refTCPChecksumOverIPv6)
	}
}

func TestUDPChecksumOverIPv4MatchesReference(t *testing.T) {
	pkt := buildIPv4UDP(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !d.RecomputeChecksums(pkt) {
		t.Fatal("пересчёт сумм не выполнен")
	}
	uh, ok := d.UDP(pkt)
	if !ok {
		t.Fatal("заголовок UDP не найден")
	}
	if got := uh.Checksum(); got != refUDPChecksumOverIPv4 {
		t.Fatalf("сумма UDP = 0x%04x, эталон 0x%04x", got, refUDPChecksumOverIPv4)
	}
}

// TestVerifyChecksumsAcceptsRecomputed сцепляет две независимые функции:
// пересчёт и проверку. Они реализованы по-разному (одна пропускает поле суммы,
// другая включает его и ждёт нулевой свёртки), поэтому согласие между ними —
// содержательный факт, а не тавтология.
func TestVerifyChecksumsAcceptsRecomputed(t *testing.T) {
	for name, build := range map[string]func(testing.TB) []byte{
		"ipv4_tcp": buildIPv4TCP,
		"ipv6_tcp": buildIPv6TCP,
		"ipv4_udp": buildIPv4UDP,
	} {
		t.Run(name, func(t *testing.T) {
			pkt := build(t)
			d, err := Dissect(pkt)
			if err != nil {
				t.Fatal(err)
			}
			if !d.RecomputeChecksums(pkt) {
				t.Fatal("пересчёт не выполнен")
			}
			if !d.VerifyChecksums(pkt) {
				t.Fatal("проверка не признала пересчитанные суммы")
			}
		})
	}
}

func TestVerifyChecksumsRejectsCorrupted(t *testing.T) {
	pkt := buildIPv4TCP(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !d.RecomputeChecksums(pkt) {
		t.Fatal("пересчёт не выполнен")
	}
	// Портим один байт тела, суммы не обновляя.
	pkt[len(pkt)-1] ^= 0xff
	if d.VerifyChecksums(pkt) {
		t.Fatal("испорченный пакет признан корректным")
	}
}

func TestUpdateChecksum16MatchesReference(t *testing.T) {
	// Правка TTL с 64 на 3. TTL делит 16-битное слово с номером протокола,
	// поэтому в формулу идут слова целиком, а не отдельные байты.
	const (
		oldWord = uint16(64)<<8 | 6
		newWord = uint16(3)<<8 | 6
	)
	got := UpdateChecksum16(refIPv4HeaderChecksum, oldWord, newWord)
	if got != refIPv4ChecksumAfterTTL3 {
		t.Fatalf("инкрементальная сумма = 0x%04x, эталон 0x%04x", got, refIPv4ChecksumAfterTTL3)
	}
}

// TestUpdateChecksum16EquivalentToFullRecompute — свойство, которое и делает
// инкрементальный пересчёт пригодным: его результат обязан совпадать с полным
// пересчётом при любом новом значении поля. Проверяется на всём диапазоне TTL.
func TestUpdateChecksum16EquivalentToFullRecompute(t *testing.T) {
	for ttl := 0; ttl <= 255; ttl++ {
		pkt := buildIPv4TCP(t)
		h, err := ParseIPv4Header(pkt)
		if err != nil {
			t.Fatal(err)
		}
		h.RecomputeChecksum()

		before := h.Checksum()
		oldWord := uint16(h.TTL())<<8 | uint16(h.Protocol())
		h.SetTTL(uint8(ttl))
		newWord := uint16(ttl)<<8 | uint16(h.Protocol())

		incremental := UpdateChecksum16(before, oldWord, newWord)
		h.RecomputeChecksum()
		if full := h.Checksum(); incremental != full {
			t.Fatalf("ttl=%d: инкрементально 0x%04x, полностью 0x%04x", ttl, incremental, full)
		}
	}
}

// TestOnesComplementSumOddLength фиксирует обработку непарного последнего байта:
// он складывается как старший байт слова, а буфер при этом не меняется.
func TestOnesComplementSumOddLength(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56}
	before := make([]byte, len(data))
	copy(before, data)

	sum := onesComplementSum(data, 0)
	want := uint32(0x1234) + uint32(0x5600)
	if sum != want {
		t.Fatalf("сумма = 0x%x, ожидалась 0x%x", sum, want)
	}
	for i := range data {
		if data[i] != before[i] {
			t.Fatal("буфер изменён при подсчёте суммы")
		}
	}
}
