package packet

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestDissectIPv4TCP(t *testing.T) {
	pkt := buildIPv4TCP(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != Version4 || d.Protocol != ProtoTCP {
		t.Fatalf("версия/протокол = %v/%v", d.Version, d.Protocol)
	}
	if d.L3Len != 20 || d.L4Off != 20 || d.L4Len != 20 {
		t.Fatalf("смещения: L3Len=%d L4Off=%d L4Len=%d", d.L3Len, d.L4Off, d.L4Len)
	}
	if d.PayloadOff != 40 || d.PayloadLen != 5 {
		t.Fatalf("тело: off=%d len=%d", d.PayloadOff, d.PayloadLen)
	}
	if d.Truncated || d.Fragment {
		t.Fatal("пакет целый и не фрагмент")
	}
	body, ok := d.Payload(pkt)
	if !ok || string(body) != "hello" {
		t.Fatalf("тело = %q, ok=%v", body, ok)
	}
}

func TestDissectIPv6TCP(t *testing.T) {
	pkt := buildIPv6TCP(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != Version6 || d.Protocol != ProtoTCP {
		t.Fatalf("версия/протокол = %v/%v", d.Version, d.Protocol)
	}
	if d.L3Len != ipv6HeaderLen || d.L4Off != ipv6HeaderLen {
		t.Fatalf("смещения: L3Len=%d L4Off=%d", d.L3Len, d.L4Off)
	}
	if d.PayloadLen != 5 {
		t.Fatalf("длина тела = %d", d.PayloadLen)
	}
}

// TestDissectIPv6ExtensionChain проверяет обход цепочки расширений: без него
// трафик IPv6 с расширениями прошёл бы мимо логики, а стратегия выглядела бы
// нерабочей (3.2).
func TestDissectIPv6ExtensionChain(t *testing.T) {
	pkt := buildIPv6ExtTCP(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if d.Protocol != ProtoTCP {
		t.Fatalf("протокол = %v, ожидался tcp", d.Protocol)
	}
	// Два расширения по 8 байт сдвигают заголовок TCP на 16 байт.
	if d.L3Len != ipv6HeaderLen+16 {
		t.Fatalf("L3Len = %d, ожидалось %d", d.L3Len, ipv6HeaderLen+16)
	}
	if d.PayloadLen != 5 {
		t.Fatalf("длина тела = %d", d.PayloadLen)
	}
	th, ok := d.TCP(pkt)
	if !ok {
		t.Fatal("заголовок TCP не найден за цепочкой расширений")
	}
	if th.DstPort() != 443 {
		t.Fatalf("порт назначения = %d", th.DstPort())
	}
}

func TestDissectIPv6ExtensionChainTooLong(t *testing.T) {
	// Цепочка из заголовков «параметры получателя», замкнутая сама на себя по
	// виду: каждый указывает на следующий такой же. Разбор обязан прекратиться
	// по предельному счётчику, а не крутиться.
	const count = maxExtHeaders + 3
	rest := make([]byte, 0, count*8)
	for range count {
		ext := make([]byte, 8)
		ext[0] = byte(ProtoDestOpts)
		ext[1] = 0
		rest = append(rest, ext...)
	}
	pkt := make([]byte, ipv6HeaderLen+len(rest))
	pkt[0] = 6 << 4
	binary.BigEndian.PutUint16(pkt[ipv6PayloadLenOff:], uint16(len(rest)))
	pkt[ipv6NextHeaderOff] = byte(ProtoDestOpts)
	copy(pkt[ipv6HeaderLen:], rest)

	if _, err := Dissect(pkt); !errors.Is(err, ErrExtChainTooLong) {
		t.Fatalf("ошибка = %v, ожидалась ErrExtChainTooLong", err)
	}
}

func TestDissectIPv4Fragment(t *testing.T) {
	pkt := buildIPv4TCP(t)
	h, err := ParseIPv4Header(pkt)
	if err != nil {
		t.Fatal(err)
	}
	// Ненулевое смещение фрагмента: заголовка TCP в таком пакете нет.
	h.SetFragOffset(10)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Fragment {
		t.Fatal("пакет должен быть распознан как фрагмент")
	}
	if d.L4Off != 0 || d.L4Len != 0 {
		t.Fatalf("у фрагмента не должно быть заголовка L4: off=%d len=%d", d.L4Off, d.L4Len)
	}
	if _, ok := d.TCP(pkt); ok {
		t.Fatal("доступ к TCP во фрагменте должен быть закрыт")
	}
}

func TestDissectTruncated(t *testing.T) {
	full := buildIPv4TCP(t)
	// Обрезаем пакет посередине тела: объявленная длина останется прежней.
	pkt := full[:len(full)-3]
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Truncated {
		t.Fatal("пакет должен быть помечен усечённым")
	}
	if d.PayloadLen != 2 {
		t.Fatalf("длина доступного тела = %d, ожидалось 2", d.PayloadLen)
	}
	// Пересчитывать суммы по неполному пакету нельзя: результат был бы неверен.
	if d.RecomputeChecksums(pkt) {
		t.Fatal("пересчёт сумм на усечённом пакете должен быть отклонён")
	}
}

func TestDissectTruncatedBeforeL4(t *testing.T) {
	full := buildIPv4TCP(t)
	// Оставляем сетевой заголовок и половину заголовка TCP.
	pkt := full[:ipv4MinHeaderLen+10]
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatalf("усечение до заголовка L4 не должно быть ошибкой: %v", err)
	}
	if !d.Truncated {
		t.Fatal("ожидался признак усечения")
	}
	if d.L4Len != 0 {
		t.Fatalf("заголовок L4 не должен считаться разобранным: len=%d", d.L4Len)
	}
	// Версия и адреса при этом доступны — по ним можно принимать решения.
	if _, ok := d.IPv4(pkt); !ok {
		t.Fatal("сетевой заголовок должен остаться доступным")
	}
}

func TestDissectRejects(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want error
	}{
		{"пустой буфер", nil, ErrShortBuffer},
		{"версия 5", []byte{5 << 4, 0, 0, 0}, ErrBadVersion},
		{"короткий IPv4", []byte{4<<4 | 5, 0, 0, 20}, ErrShortBuffer},
		{"короткий IPv6", append([]byte{6 << 4}, make([]byte, 10)...), ErrShortBuffer},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Dissect(c.pkt); !errors.Is(err, c.want) {
				t.Fatalf("ошибка = %v, ожидалась %v", err, c.want)
			}
		})
	}
}

func TestDissectBadIPv4HeaderLen(t *testing.T) {
	pkt := buildIPv4TCP(t)
	// Длина заголовка 4 слова (16 байт) — меньше минимума в 20 байт.
	pkt[ipv4VerIHLOff] = 4<<4 | 4
	if _, err := Dissect(pkt); !errors.Is(err, ErrBadHeaderLen) {
		t.Fatalf("ошибка = %v, ожидалась ErrBadHeaderLen", err)
	}
}

func TestDissectTotalLenBelowHeader(t *testing.T) {
	pkt := buildIPv4TCP(t)
	// Объявленная общая длина меньше длины заголовка — пакет противоречив.
	binary.BigEndian.PutUint16(pkt[ipv4TotalLenOff:], 10)
	if _, err := Dissect(pkt); !errors.Is(err, ErrBadHeaderLen) {
		t.Fatalf("ошибка = %v, ожидалась ErrBadHeaderLen", err)
	}
}

func TestDissectIgnoresBytesBeyondTotalLen(t *testing.T) {
	pkt := buildIPv4TCP(t)
	// Добавляем хвост за объявленной длиной: такое бывает при выравнивании
	// кадра. Эти байты пакету не принадлежат и в тело попасть не должны.
	padded := append(pkt, 0xaa, 0xbb, 0xcc, 0xdd)
	d, err := Dissect(padded)
	if err != nil {
		t.Fatal(err)
	}
	if d.PayloadLen != 5 {
		t.Fatalf("длина тела = %d, ожидалось 5 (хвост не должен учитываться)", d.PayloadLen)
	}
	if d.Truncated {
		t.Fatal("пакет не усечён")
	}
}

func TestDissectUDP(t *testing.T) {
	pkt := buildIPv4UDP(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if d.Protocol != ProtoUDP {
		t.Fatalf("протокол = %v", d.Protocol)
	}
	uh, ok := d.UDP(pkt)
	if !ok {
		t.Fatal("заголовок UDP не найден")
	}
	if uh.DstPort() != 443 {
		t.Fatalf("порт назначения = %d", uh.DstPort())
	}
	if d.PayloadLen != 7 {
		t.Fatalf("длина тела = %d", d.PayloadLen)
	}
}

func TestDissectUnknownProtocol(t *testing.T) {
	pkt := buildIPv4TCP(t)
	pkt[ipv4ProtoOff] = 1 // ICMP: движку не нужен
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatalf("неизвестный протокол не должен быть ошибкой: %v", err)
	}
	if d.L4Len != 0 {
		t.Fatal("заголовок L4 для неизвестного протокола разбирать не следует")
	}
	if d.PayloadLen != 25 {
		t.Fatalf("длина тела = %d, ожидалось 25", d.PayloadLen)
	}
}

// TestDissectZeroAllocations подтверждает бюджет из 8.1: разбор на горячем пути
// не выделяет памяти. Проверяется замером, а не визуально.
func TestDissectZeroAllocations(t *testing.T) {
	pkt := buildIPv4TCP(t)
	avg := testing.AllocsPerRun(1000, func() {
		d, err := Dissect(pkt)
		if err != nil {
			t.Fatal(err)
		}
		// Доступ к слоям тоже не должен аллоцировать.
		if _, ok := d.TCP(pkt); !ok {
			t.Fatal("TCP не найден")
		}
		if _, ok := d.Payload(pkt); !ok {
			t.Fatal("тело не найдено")
		}
	})
	if avg != 0 {
		t.Fatalf("аллокаций на разбор = %v, требуется 0", avg)
	}
}

func BenchmarkDissectIPv4TCP(b *testing.B) {
	pkt := buildIPv4TCP(b)
	for b.Loop() {
		if _, err := Dissect(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDissectIPv6TCP(b *testing.B) {
	pkt := buildIPv6TCP(b)
	for b.Loop() {
		if _, err := Dissect(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRecomputeChecksums(b *testing.B) {
	pkt := buildIPv4TCP(b)
	d, err := Dissect(pkt)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if !d.RecomputeChecksums(pkt) {
			b.Fatal("пересчёт не выполнен")
		}
	}
}
