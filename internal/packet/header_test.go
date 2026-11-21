package packet

import (
	"encoding/binary"
	"errors"
	"testing"
)

// Тесты полей, которые лежат не на границе байт. Это самое ошибкоопасное место
// пакета: промах в сдвиге или маске не ломает программу, а портит пакет,
// который сеть молча отбросит.

// TestIPv4FlagsAndFragOffsetIndependent проверяет, что флаги и смещение
// фрагмента, делящие одно 16-битное слово, правятся независимо.
func TestIPv4FlagsAndFragOffsetIndependent(t *testing.T) {
	pkt := buildIPv4TCP(t)
	h, err := ParseIPv4Header(pkt)
	if err != nil {
		t.Fatal(err)
	}

	// Исходно: установлен бит «не фрагментировать» (значение флагов 2),
	// смещение нулевое.
	if got := h.Flags(); got != 0x02 {
		t.Fatalf("флаги = 0x%02x, ожидалось 0x02", got)
	}
	if got := h.FragOffset(); got != 0 {
		t.Fatalf("смещение = %d, ожидалось 0", got)
	}

	// Пишем максимальное смещение — флаги обязаны сохраниться.
	h.SetFragOffset(ipv4FragOffsetMax)
	if got := h.Flags(); got != 0x02 {
		t.Fatalf("после правки смещения флаги = 0x%02x, ожидалось 0x02", got)
	}
	if got := h.FragOffset(); got != ipv4FragOffsetMax {
		t.Fatalf("смещение = %d, ожидалось %d", got, ipv4FragOffsetMax)
	}

	// Пишем флаги — смещение обязано сохраниться.
	h.SetFlags(0x05)
	if got := h.Flags(); got != 0x05 {
		t.Fatalf("флаги = 0x%02x, ожидалось 0x05", got)
	}
	if got := h.FragOffset(); got != ipv4FragOffsetMax {
		t.Fatalf("после правки флагов смещение = %d, ожидалось %d", got, ipv4FragOffsetMax)
	}

	// Флаги занимают 3 бита: старшие биты аргумента не должны затереть смещение.
	h.SetFlags(0xff)
	if got := h.FragOffset(); got != ipv4FragOffsetMax {
		t.Fatalf("переполнение флагов затёрло смещение: %d", got)
	}
}

// TestIPv6TrafficClassAndFlowLabelIndependent проверяет поля IPv6, лежащие на
// стыке байт: класс трафика (8 бит через границу) и метку потока (20 бит).
func TestIPv6TrafficClassAndFlowLabelIndependent(t *testing.T) {
	pkt := buildIPv6TCP(t)
	h, err := ParseIPv6Header(pkt)
	if err != nil {
		t.Fatal(err)
	}

	h.SetTrafficClass(0xa5)
	h.SetFlowLabel(0x0dcba)

	if got := h.TrafficClass(); got != 0xa5 {
		t.Fatalf("класс трафика = 0x%02x, ожидалось 0xa5", got)
	}
	if got := h.FlowLabel(); got != 0x0dcba {
		t.Fatalf("метка потока = 0x%05x, ожидалось 0x0dcba", got)
	}
	// Версия обязана остаться шестёркой: она делит байт 0 с классом трафика.
	if got := pkt[0] >> 4; got != 6 {
		t.Fatalf("версия испорчена: %d", got)
	}

	// Обратный порядок правок: теперь метка не должна пострадать от класса.
	h.SetFlowLabel(ipv6FlowLabelMax)
	h.SetTrafficClass(0x00)
	if got := h.FlowLabel(); got != ipv6FlowLabelMax {
		t.Fatalf("правка класса затёрла метку: 0x%05x", got)
	}
	if got := pkt[0] >> 4; got != 6 {
		t.Fatalf("версия испорчена: %d", got)
	}

	// Значение шире 20 бит обрезается, а не переливается в соседние поля.
	h.SetFlowLabel(0xfffffff)
	if got := h.FlowLabel(); got != ipv6FlowLabelMax {
		t.Fatalf("метка = 0x%x, ожидалось обрезание до 0x%05x", got, ipv6FlowLabelMax)
	}
	if got := h.TrafficClass(); got != 0x00 {
		t.Fatalf("переполнение метки затёрло класс трафика: 0x%02x", got)
	}
}

func TestTCPSeqWrapAround(t *testing.T) {
	pkt := buildIPv4TCP(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	th, ok := d.TCP(pkt)
	if !ok {
		t.Fatal("заголовок TCP не найден")
	}

	// Арифметика номеров циклическая по модулю 2^32: сложение в uint32
	// оборачивается именно так, как требует протокол.
	th.SetSeq(0xffffffff)
	th.SetSeq(th.Seq() + 2)
	if got := th.Seq(); got != 1 {
		t.Fatalf("номер = %d, ожидалось 1 (перенос через 2^32)", got)
	}
}

func TestTCPOptionsIteration(t *testing.T) {
	pkt := buildIPv4TCPWithOptions(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	th, ok := d.TCP(pkt)
	if !ok {
		t.Fatal("заголовок TCP не найден")
	}

	var kinds []uint8
	for opt := range th.Options() {
		kinds = append(kinds, opt.Kind)
	}
	// Ожидаем MSS, заполнитель, масштаб окна; на «конце списка» перебор
	// прекращается, поэтому четвёртой опции быть не должно.
	want := []uint8{TCPOptMSS, TCPOptNop, TCPOptWindowScl}
	if len(kinds) != len(want) {
		t.Fatalf("опции = %v, ожидались %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("опции = %v, ожидались %v", kinds, want)
		}
	}

	mss, err := th.MSS()
	if err != nil || mss != 1460 {
		t.Fatalf("MSS = %d, err = %v; ожидалось 1460", mss, err)
	}
	ws, err := th.WindowScale()
	if err != nil || ws != 7 {
		t.Fatalf("масштаб окна = %d, err = %v; ожидалось 7", ws, err)
	}
}

func TestTCPOptionsMutation(t *testing.T) {
	pkt := buildIPv4TCPWithOptions(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	th, _ := d.TCP(pkt)

	if err := th.SetMSS(536); err != nil {
		t.Fatal(err)
	}
	if err := th.SetWindowScale(0); err != nil {
		t.Fatal(err)
	}
	mss, err := th.MSS()
	if err != nil || mss != 536 {
		t.Fatalf("MSS после правки = %d, err = %v", mss, err)
	}
	ws, err := th.WindowScale()
	if err != nil || ws != 0 {
		t.Fatalf("масштаб окна после правки = %d, err = %v", ws, err)
	}
	// Длина заголовка не изменилась: опции правятся на месте.
	if th.HeaderLen() != d.L4Len {
		t.Fatal("правка опций изменила длину заголовка")
	}
}

func TestTCPOptionsMissing(t *testing.T) {
	pkt := buildIPv4TCP(t) // без опций
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	th, _ := d.TCP(pkt)

	if _, err := th.MSS(); !errors.Is(err, ErrOptionNotFound) {
		t.Fatalf("ошибка = %v, ожидалась ErrOptionNotFound", err)
	}
	if err := th.SetMSS(1460); !errors.Is(err, ErrOptionNotFound) {
		t.Fatalf("ошибка = %v, ожидалась ErrOptionNotFound", err)
	}
}

// TestTCPBadOptionRejected проверяет, что опция с длиной, выходящей за
// заголовок, отбраковывает весь разбор: иначе чтение значения ушло бы за
// границу области опций.
func TestTCPBadOptionRejected(t *testing.T) {
	pkt := buildIPv4TCPWithOptions(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	// Первая опция — MSS по смещению 0 области опций; ставим ей длину 200.
	optsOff := d.L4Off + tcpMinHeaderLen
	pkt[optsOff+1] = 200

	if _, err := Dissect(pkt); !errors.Is(err, ErrBadOption) {
		t.Fatalf("ошибка = %v, ожидалась ErrBadOption", err)
	}
}

// TestTCPOptionLengthZeroDoesNotLoop — опция с объявленной длиной 0 обнулила бы
// шаг цикла и подвесила бы перебор. Проверяем, что этого не происходит.
func TestTCPOptionLengthZeroDoesNotLoop(t *testing.T) {
	pkt := buildIPv4TCPWithOptions(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	optsOff := d.L4Off + tcpMinHeaderLen
	pkt[optsOff+1] = 0

	th := TCPHeader(pkt[d.L4Off : d.L4Off+d.L4Len])
	if err := th.ValidateOptions(); !errors.Is(err, ErrBadOption) {
		t.Fatalf("ошибка = %v, ожидалась ErrBadOption", err)
	}
	// Перебор обязан завершиться, а не зациклиться.
	count := 0
	for range th.Options() {
		count++
		if count > 100 {
			t.Fatal("перебор опций не завершается")
		}
	}
}

func TestIPv4SetTotalLenAndRecompute(t *testing.T) {
	pkt := buildIPv4TCP(t)
	h, err := ParseIPv4Header(pkt)
	if err != nil {
		t.Fatal(err)
	}
	h.RecomputeChecksum()
	first := h.Checksum()

	// Меняем длину и пересчитываем: сумма обязана измениться.
	h.SetTotalLen(h.TotalLen() - 1)
	h.RecomputeChecksum()
	if h.Checksum() == first {
		t.Fatal("сумма не изменилась после правки общей длины")
	}

	// Возврат к исходному значению должен вернуть исходную сумму.
	h.SetTotalLen(h.TotalLen() + 1)
	h.RecomputeChecksum()
	if h.Checksum() != first {
		t.Fatalf("сумма = 0x%04x, ожидалось возвращение к 0x%04x", h.Checksum(), first)
	}
}

func TestSetChecksumKeepsCorruptValue(t *testing.T) {
	pkt := buildIPv4TCP(t)
	d, err := Dissect(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !d.RecomputeChecksums(pkt) {
		t.Fatal("пересчёт не выполнен")
	}
	th, _ := d.TCP(pkt)

	// Примитив порчи суммы пишет значение ПОСЛЕ пересчёта; сеттер обязан
	// сохранить его как есть, иначе порча была бы невыразима.
	th.SetChecksum(0xdead)
	if got := th.Checksum(); got != 0xdead {
		t.Fatalf("сумма = 0x%04x, ожидалось 0xdead", got)
	}
	if d.VerifyChecksums(pkt) {
		t.Fatal("испорченная сумма должна не проходить проверку")
	}
}

func TestUDPDeclaredLenBelowHeader(t *testing.T) {
	pkt := buildIPv4UDP(t)
	// Объявленная длина датаграммы меньше заголовка — противоречие.
	binary.BigEndian.PutUint16(pkt[ipv4MinHeaderLen+udpLenOff:], 4)
	if _, err := Dissect(pkt); !errors.Is(err, ErrBadHeaderLen) {
		t.Fatalf("ошибка = %v, ожидалась ErrBadHeaderLen", err)
	}
}
