package flow

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// helloOnTLS — поддельный детектор: нагрузка, начинающаяся с 0x16 (handshake),
// считается полным ClientHello. Ядро таблицы от tlsparse не зависит.
func helloOnTLS(payload []byte) ([]byte, bool, bool) {
	if len(payload) > 0 && payload[0] == 0x16 {
		return payload, true, true
	}
	return nil, false, false
}

// helloNeedsMarker — поддельный детектор для проверки сборки: TLS распознаётся
// по первому байту 0x16, но «имя сервера» считается видимым, только когда в
// (возможно, склеенной) нагрузке встречается байт-маркер 0x53. До него —
// isTLS=true, complete=false, то есть «TLS есть, имени ещё не видно».
func helloNeedsMarker(payload []byte) ([]byte, bool, bool) {
	if len(payload) == 0 || payload[0] != 0x16 {
		return nil, false, false
	}
	if bytes.IndexByte(payload, 0x53) >= 0 {
		return payload, true, true
	}
	return nil, false, true
}

func keyAB(t *testing.T) Key {
	t.Helper()
	return NewKey(net.ParseIP("10.0.0.1"), 5000, net.ParseIP("93.184.216.34"), 443)
}

// TestKeyIsDirectionIndependent — обе стороны соединения дают один ключ.
func TestKeyIsDirectionIndependent(t *testing.T) {
	out := NewKey(net.ParseIP("10.0.0.1"), 5000, net.ParseIP("93.184.216.34"), 443)
	in := NewKey(net.ParseIP("93.184.216.34"), 443, net.ParseIP("10.0.0.1"), 5000)
	if out != in {
		t.Fatalf("ключ зависит от направления: %+v != %+v", out, in)
	}
}

// TestKeyIPv6 — IPv6 обрабатывается наравне с IPv4 (3.2).
func TestKeyIPv6(t *testing.T) {
	k := NewKey(net.ParseIP("2001:db8::1"), 5000, net.ParseIP("2606:2800:220::1"), 443)
	if k == (Key{}) {
		t.Fatalf("ключ IPv6 не построен")
	}
	if k != NewKey(net.ParseIP("2606:2800:220::1"), 443, net.ParseIP("2001:db8::1"), 5000) {
		t.Fatalf("ключ IPv6 зависит от направления")
	}
}

// TestSynThenClientHelloApplies — пустой сегмент пропускается, первый сегмент с
// ClientHello даёт Apply, поток уходит с пути.
func TestSynThenClientHelloApplies(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloOnTLS)
	k := keyAB(t)
	now := time.Unix(0, 0)

	// SYN: данных нет — Pass, поток отслеживается.
	if a := tbl.Outbound(k, 1000, nil, now); a.Disposition != Pass || a.AtCapacity {
		t.Fatalf("SYN: ожидался Pass без AtCapacity, получено %+v", a)
	}
	if tbl.Len() != 1 {
		t.Fatalf("после SYN поток должен отслеживаться, Len=%d", tbl.Len())
	}

	// Первый сегмент с данными — ClientHello.
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x05}
	a := tbl.Outbound(k, 1000, hello, now)
	if a.Disposition != Apply {
		t.Fatalf("ClientHello: ожидался Apply, получено %v", a.Disposition)
	}
	if string(a.Hello) != string(hello) {
		t.Fatalf("Hello передан неверно: %x", a.Hello)
	}
	if len(a.SegLens) != 0 {
		t.Fatalf("одиночный ClientHello: SegLens должен быть пуст, получено %v", a.SegLens)
	}

	// Дальнейшие пакеты — уже с пути ушли, Pass без повторного разбора.
	if a := tbl.Outbound(k, 1005, []byte{0x16, 0x99}, now); a.Disposition != Pass {
		t.Fatalf("после решения ожидался Pass, получено %v", a.Disposition)
	}
}

// TestAssemblesMultiSegmentHello — имя сервера видно только во втором сегменте:
// первый УДЕРЖИВАЕТСЯ (Buffering), на втором склейка показывает имя и
// возвращается Apply со всей склейкой, её seq и границами сегментов.
func TestAssemblesMultiSegmentHello(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloNeedsMarker)
	k := keyAB(t)
	now := time.Unix(0, 0)

	seg1 := []byte{0x16, 0x03, 0x01, 0x00, 0x00} // TLS, без маркера имени
	seg2 := []byte{0xaa, 0x53, 0xbb}             // маркер 0x53 — имя стало видно

	// Первый сегмент: сборка началась, сегмент УДЕРЖАН (в сеть не идёт).
	a := tbl.Outbound(k, 2000, seg1, now)
	if a.Disposition != Pass || !a.Buffering || a.Incomplete {
		t.Fatalf("первый сегмент сборки: ожидался Pass+Buffering, получено %+v", a)
	}
	if tbl.Len() != 1 {
		t.Fatalf("поток сборки должен отслеживаться, Len=%d", tbl.Len())
	}

	// Второй сегмент (ровно за первым): склейка показывает имя — Apply.
	a = tbl.Outbound(k, 2000+uint32(len(seg1)), seg2, now)
	if a.Disposition != Apply || a.Buffering {
		t.Fatalf("второй сегмент: ожидался Apply без Buffering, получено %+v", a)
	}
	if a.BaseSeq != 2000 {
		t.Fatalf("BaseSeq: ожидался 2000, получено %d", a.BaseSeq)
	}
	wantSeg := []int{len(seg1), len(seg2)}
	if len(a.SegLens) != 2 || a.SegLens[0] != wantSeg[0] || a.SegLens[1] != wantSeg[1] {
		t.Fatalf("SegLens: ожидался %v, получено %v", wantSeg, a.SegLens)
	}
	want := append(append([]byte{}, seg1...), seg2...)
	if !bytes.Equal(a.Hello, want) {
		t.Fatalf("Hello должен быть склейкой сегментов: получено %x, ожидалось %x", a.Hello, want)
	}

	// Решение принято — поток settled.
	if a := tbl.Outbound(k, 9999, []byte{0x16, 0x53}, now); a.Disposition != Pass {
		t.Fatalf("после сборки ожидался Pass, получено %v", a.Disposition)
	}
}

// TestAssemblyIgnoresBareAckMidStream — чистый ACK (без данных) посреди сборки
// проходит в сеть (не Buffering), не двигает склейку и не срывает её.
func TestAssemblyIgnoresBareAckMidStream(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloNeedsMarker)
	k := keyAB(t)
	now := time.Unix(0, 0)

	seg1 := []byte{0x16, 0x03, 0x01}
	if a := tbl.Outbound(k, 3000, seg1, now); a.Disposition != Pass || !a.Buffering {
		t.Fatalf("первый сегмент сборки: ожидался Pass+Buffering, получено %+v", a)
	}
	// Пустой сегмент (ACK) — буфер не трогаем, в сеть пропускаем (не Buffering).
	if a := tbl.Outbound(k, 3000+uint32(len(seg1)), nil, now); a.Disposition != Pass || a.Buffering || a.Incomplete {
		t.Fatalf("ACK посреди сборки: ожидался чистый Pass, получено %+v", a)
	}
	// Следующий сегмент с данными продолжает склейку ровно за первым.
	seg2 := []byte{0x53}
	a := tbl.Outbound(k, 3000+uint32(len(seg1)), seg2, now)
	if a.Disposition != Apply || len(a.SegLens) != 2 {
		t.Fatalf("после ACK сборка должна продолжиться: %+v", a)
	}
}

// TestAssemblyBreaksOnSequenceGap — разрыв нумерации ВПЕРЁД (переупорядочение
// или настоящая дыра) делает корректную склейку невозможной: поток уходит с
// пометкой Incomplete, а удержанные сегменты возвращаются на досылку сырьём.
// Повтор уже удержанных байт, в отличие от этого, не срывает сборку — см.
// TestAssemblyToleratesRetransmit.
func TestAssemblyBreaksOnSequenceGap(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloNeedsMarker)
	k := keyAB(t)
	now := time.Unix(0, 0)

	seg1 := []byte{0x16, 0x03, 0x01}
	tbl.Outbound(k, 4000, seg1, now)

	// Сегмент с неожиданным seq (не продолжает склейку).
	a := tbl.Outbound(k, 5000, []byte{0x53}, now)
	if a.Disposition != Pass || !a.Incomplete {
		t.Fatalf("разрыв нумерации: ожидался Pass+Incomplete, получено %+v", a)
	}
	// Удержанный первый сегмент возвращён на досылку сырьём.
	if a.BaseSeq != 4000 || !bytes.Equal(a.Hello, seg1) || len(a.SegLens) != 1 || a.SegLens[0] != len(seg1) {
		t.Fatalf("при срыве удержанное должно вернуться на досылку: Hello=%x BaseSeq=%d SegLens=%v", a.Hello, a.BaseSeq, a.SegLens)
	}
	// Поток settled — дальше не разбирается.
	if a := tbl.Outbound(k, 4000+uint32(len(seg1)), []byte{0x53}, now); a.Disposition != Pass || a.Incomplete {
		t.Fatalf("после срыва сборки поток должен быть settled: %+v", a)
	}
}

// TestAssemblyToleratesRetransmit — повтор удержанного сегмента (та же
// ретрансмиссия, что мы сами провоцируем, придержав первый сегмент) НЕ срывает
// сборку: дубликат гасится (в сеть не идёт), а когда приходит настоящий
// следующий сегмент — склейка завершается как обычно. Это и есть лечение
// затупа GUI на cdn.discordapp.com (прежде повтор давал Incomplete → сырой SNI
// → RST).
func TestAssemblyToleratesRetransmit(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloNeedsMarker)
	k := keyAB(t)
	now := time.Unix(0, 0)

	seg1 := []byte{0x16, 0x03, 0x01, 0x00, 0x00} // TLS, без маркера
	seg2 := []byte{0xaa, 0x53, 0xbb}             // маркер 0x53 — имя видно

	// Первый сегмент удержан.
	if a := tbl.Outbound(k, 2000, seg1, now); a.Disposition != Pass || !a.Buffering {
		t.Fatalf("сегмент 1: ожидался Pass+Buffering, получено %+v", a)
	}
	// Повтор первого сегмента (тот же seq) — гасится, сборка жива.
	if a := tbl.Outbound(k, 2000, seg1, now); a.Disposition != Pass || !a.Buffering || a.Incomplete {
		t.Fatalf("повтор удержанного: ожидался Pass+Buffering без Incomplete, получено %+v", a)
	}
	// Ещё один повтор — всё ещё терпим.
	if a := tbl.Outbound(k, 2000, seg1, now); a.Disposition != Pass || !a.Buffering || a.Incomplete {
		t.Fatalf("второй повтор: ожидался Pass+Buffering, получено %+v", a)
	}
	// Настоящий второй сегмент завершает склейку.
	a := tbl.Outbound(k, 2000+uint32(len(seg1)), seg2, now)
	if a.Disposition != Apply || a.Buffering {
		t.Fatalf("второй сегмент после повторов: ожидался Apply, получено %+v", a)
	}
	wantSeg := []int{len(seg1), len(seg2)}
	if len(a.SegLens) != 2 || a.SegLens[0] != wantSeg[0] || a.SegLens[1] != wantSeg[1] {
		t.Fatalf("SegLens: ожидался %v, получено %v", wantSeg, a.SegLens)
	}
	want := append(append([]byte{}, seg1...), seg2...)
	if !bytes.Equal(a.Hello, want) {
		t.Fatalf("Hello: получено %x, ожидалось %x", a.Hello, want)
	}
}

// TestAssemblyToleratesCoalescedRetransmit — ретрансмиссия, несущая удержанный
// сегмент И следующий за ним (клиент коалесцировал при повторе), добавляет
// только новый хвост и завершает склейку, не теряя и не дублируя байт.
func TestAssemblyToleratesCoalescedRetransmit(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloNeedsMarker)
	k := keyAB(t)
	now := time.Unix(0, 0)

	seg1 := []byte{0x16, 0x03, 0x01, 0x00, 0x00}
	tail := []byte{0xaa, 0x53, 0xbb} // хвост с маркером

	if a := tbl.Outbound(k, 2000, seg1, now); a.Disposition != Pass || !a.Buffering {
		t.Fatalf("сегмент 1: %+v", a)
	}
	// Повтор с seq первого сегмента, но несущий seg1+tail.
	coalesced := append(append([]byte{}, seg1...), tail...)
	a := tbl.Outbound(k, 2000, coalesced, now)
	if a.Disposition != Apply || a.Buffering {
		t.Fatalf("коалесцированный повтор: ожидался Apply, получено %+v", a)
	}
	wantSeg := []int{len(seg1), len(tail)}
	if len(a.SegLens) != 2 || a.SegLens[0] != wantSeg[0] || a.SegLens[1] != wantSeg[1] {
		t.Fatalf("SegLens: ожидался %v, получено %v", wantSeg, a.SegLens)
	}
	if !bytes.Equal(a.Hello, coalesced) {
		t.Fatalf("Hello: получено %x, ожидалось %x", a.Hello, coalesced)
	}
}

// TestAssemblyGivesUpAfterStallLimit — если недостающий сегмент так и не
// приходит, а удержанный лишь повторяется, после предела холостых повторов
// сборка сдаётся и возвращает удержанное на досылку (не висит вечно).
func TestAssemblyGivesUpAfterStallLimit(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloNeedsMarker)
	k := keyAB(t)
	now := time.Unix(0, 0)

	seg1 := []byte{0x16, 0x03, 0x01, 0x00, 0x00}
	if a := tbl.Outbound(k, 2000, seg1, now); a.Disposition != Pass || !a.Buffering {
		t.Fatalf("сегмент 1: %+v", a)
	}
	// Первые maxAssemblyStalls повторов терпим (Buffering).
	for i := 1; i <= maxAssemblyStalls; i++ {
		a := tbl.Outbound(k, 2000, seg1, now)
		if a.Disposition != Pass || !a.Buffering || a.Incomplete {
			t.Fatalf("повтор %d: ожидался Pass+Buffering, получено %+v", i, a)
		}
	}
	// Следующий повтор переполняет предел — сдаёмся, удержанное на досылку.
	a := tbl.Outbound(k, 2000, seg1, now)
	if a.Disposition != Pass || !a.Incomplete {
		t.Fatalf("за пределом холостых повторов ожидался Pass+Incomplete, получено %+v", a)
	}
	if a.BaseSeq != 2000 || !bytes.Equal(a.Hello, seg1) || len(a.SegLens) != 1 {
		t.Fatalf("при срыве удержанное должно вернуться: Hello=%x BaseSeq=%d SegLens=%v",
			a.Hello, a.BaseSeq, a.SegLens)
	}
}

// TestGiveUpReasonIsReported — каждый путь отказа проставляет свою причину в
// Action.Reason. По ней движок строит разбивку пропусков в журнале, и причина
// затупа видна точно (разрыв вперёд / лимит / холостые повторы / не-TLS), а не
// одним общим счётчиком.
func TestGiveUpReasonIsReported(t *testing.T) {
	seg := []byte{0x16, 0x03, 0x01, 0x00, 0x00} // TLS, без маркера имени

	t.Run("разрыв вперёд", func(t *testing.T) {
		tbl := NewTable(16, time.Minute, helloNeedsMarker)
		k := keyAB(t)
		now := time.Unix(0, 0)
		tbl.Outbound(k, 2000, seg, now)
		a := tbl.Outbound(k, 9000, []byte{0x53}, now) // seq далеко вперёд
		if !a.Incomplete || a.Reason != GiveUpSeqGap {
			t.Fatalf("ожидался GiveUpSeqGap, получено Incomplete=%v Reason=%v", a.Incomplete, a.Reason)
		}
	})

	t.Run("холостые повторы", func(t *testing.T) {
		tbl := NewTable(16, time.Minute, helloNeedsMarker)
		k := keyAB(t)
		now := time.Unix(0, 0)
		tbl.Outbound(k, 2000, seg, now)
		var a Action
		for i := 0; i <= maxAssemblyStalls; i++ {
			a = tbl.Outbound(k, 2000, seg, now) // тот же seq — повтор удержанного
		}
		if !a.Incomplete || a.Reason != GiveUpStall {
			t.Fatalf("ожидался GiveUpStall, получено Incomplete=%v Reason=%v", a.Incomplete, a.Reason)
		}
	})

	t.Run("лимит сегментов", func(t *testing.T) {
		tbl := NewTable(16, time.Minute, helloNeedsMarker)
		k := keyAB(t)
		now := time.Unix(0, 0)
		seq := uint32(2000)
		small := []byte{0x16} // TLS, маркера нет
		tbl.Outbound(k, seq, small, now)
		seq += uint32(len(small))
		var a Action
		for i := 2; i <= maxAssemblySegments; i++ {
			a = tbl.Outbound(k, seq, small, now)
			seq += uint32(len(small))
		}
		if !a.Incomplete || a.Reason != GiveUpSegments {
			t.Fatalf("ожидался GiveUpSegments, получено Incomplete=%v Reason=%v", a.Incomplete, a.Reason)
		}
	})

	t.Run("не TLS в склейке", func(t *testing.T) {
		// Детектор: первый сегмент TLS без имени, но склейка с 0xFF
		// перестаёт быть TLS.
		detect := func(payload []byte) ([]byte, bool, bool) {
			if len(payload) == 0 || payload[0] != 0x16 {
				return nil, false, false
			}
			if bytes.IndexByte(payload, 0xff) >= 0 {
				return nil, false, false // уже не TLS
			}
			return nil, false, true // TLS, имени нет
		}
		tbl := NewTable(16, time.Minute, detect)
		k := keyAB(t)
		now := time.Unix(0, 0)
		seg1 := []byte{0x16, 0x03}
		tbl.Outbound(k, 2000, seg1, now)
		a := tbl.Outbound(k, 2000+uint32(len(seg1)), []byte{0xff}, now)
		if !a.Incomplete || a.Reason != GiveUpNotTLS {
			t.Fatalf("ожидался GiveUpNotTLS, получено Incomplete=%v Reason=%v", a.Incomplete, a.Reason)
		}
	})
}

// TestGiveUpReasonStrings — текстовые метки причин не пустые и различимы: по ним
// строится разбивка в журнале.
func TestGiveUpReasonStrings(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range []GiveUpReason{GiveUpSegments, GiveUpBytes, GiveUpSeqGap, GiveUpNotTLS, GiveUpStall} {
		s := r.String()
		if s == "" || s == "неизвестно" {
			t.Fatalf("причина %d дала пустую/неизвестную метку %q", r, s)
		}
		if seen[s] {
			t.Fatalf("метка %q повторяется — причины неразличимы", s)
		}
		seen[s] = true
	}
}

// TestAssemblyGivesUpAtSegmentLimit — если имя не показалось за предельное число
// сегментов, сборка прекращается с Incomplete, а удержанные сегменты (без
// последнего, срывающего предел) возвращаются на досылку.
func TestAssemblyGivesUpAtSegmentLimit(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloNeedsMarker)
	k := keyAB(t)
	now := time.Unix(0, 0)

	seq := uint32(6000)
	seg := []byte{0x16, 0x03, 0x01} // TLS, никогда не содержит маркера
	// Первый сегмент начинает сборку.
	if a := tbl.Outbound(k, seq, seg, now); a.Disposition != Pass || !a.Buffering {
		t.Fatalf("сегмент 1: %+v", a)
	}
	seq += uint32(len(seg))
	// Сегменты 2..maxAssemblySegments продолжают сборку, не завершая её.
	for i := 2; i < maxAssemblySegments; i++ {
		if a := tbl.Outbound(k, seq, seg, now); a.Disposition != Pass || !a.Buffering {
			t.Fatalf("сегмент %d: ожидался Pass+Buffering, получено %+v", i, a)
		}
		seq += uint32(len(seg))
	}
	// Сегмент maxAssemblySegments исчерпывает предел — сдаёмся.
	a := tbl.Outbound(k, seq, seg, now)
	if a.Disposition != Pass || !a.Incomplete {
		t.Fatalf("на пределе сегментов ожидался Pass+Incomplete, получено %+v", a)
	}
	// Удержано ровно maxAssemblySegments-1 сегментов (последний снят со склейки).
	if len(a.SegLens) != maxAssemblySegments-1 {
		t.Fatalf("на досылку ожидалось %d сегментов, получено %d", maxAssemblySegments-1, len(a.SegLens))
	}
	if len(a.Hello) != (maxAssemblySegments-1)*len(seg) {
		t.Fatalf("длина удержанного буфера неверна: %d", len(a.Hello))
	}
}

// TestNonTLSFirstDataPassesAndSettles — не-TLS первый сегмент пропускается, и
// поток больше не разбирается.
func TestNonTLSFirstDataPassesAndSettles(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloOnTLS)
	k := keyAB(t)
	now := time.Unix(0, 0)

	a := tbl.Outbound(k, 1000, []byte("GET / HTTP/1.1\r\n"), now)
	if a.Disposition != Pass || a.Hello != nil {
		t.Fatalf("не-TLS: ожидался Pass без Hello, получено %+v", a)
	}
	// Даже если следом придёт что-то «похожее на TLS» — поток уже settled.
	if a := tbl.Outbound(k, 1016, []byte{0x16, 0x03, 0x01, 0x00, 0x05}, now); a.Disposition != Pass {
		t.Fatalf("settled-поток повторно разбираться не должен, получено %v", a.Disposition)
	}
}

// TestCapacityDegradesToTransparent — при переполнении новый поток идёт
// прозрачно с признаком AtCapacity, без вытеснения (4.4).
func TestCapacityDegradesToTransparent(t *testing.T) {
	tbl := NewTable(1, time.Minute, helloOnTLS)
	now := time.Unix(0, 0)

	first := keyAB(t)
	tbl.Outbound(first, 1000, nil, now) // занял единственную ячейку

	second := NewKey(net.ParseIP("10.0.0.2"), 6000, net.ParseIP("93.184.216.34"), 443)
	a := tbl.Outbound(second, 1000, []byte{0x16, 0x03, 0x01, 0x00, 0x05}, now)
	if !a.AtCapacity || a.Disposition != Pass {
		t.Fatalf("переполнение: ожидался Pass с AtCapacity, получено %+v", a)
	}
	// Второй поток не взят — первый не вытеснен.
	if tbl.Len() != 1 {
		t.Fatalf("вытеснения быть не должно, Len=%d", tbl.Len())
	}
}

// TestSweepExpiresStaleFlows — потоки старше ttl убираются, освобождая ёмкость.
func TestSweepExpiresStaleFlows(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloOnTLS)
	k := keyAB(t)
	start := time.Unix(0, 0)
	tbl.Outbound(k, 1000, nil, start)

	if n := tbl.Sweep(start.Add(30 * time.Second)); n != 0 {
		t.Fatalf("свежий поток истекать не должен, убрано %d", n)
	}
	if n := tbl.Sweep(start.Add(2 * time.Minute)); n != 1 {
		t.Fatalf("устаревший поток должен быть убран, убрано %d", n)
	}
	if tbl.Len() != 0 {
		t.Fatalf("после истечения таблица должна опустеть, Len=%d", tbl.Len())
	}
}

// TestForgetRemovesFlow — явное освобождение по FIN/RST.
func TestForgetRemovesFlow(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloOnTLS)
	k := keyAB(t)
	tbl.Outbound(k, 1000, nil, time.Unix(0, 0))
	tbl.Forget(k)
	if tbl.Len() != 0 {
		t.Fatalf("Forget должен убрать поток, Len=%d", tbl.Len())
	}
	tbl.Forget(k) // повторный безвреден
}

// TestUnknownFlowWithDataDecidesImmediately — поток, впервые увиденный сразу с
// данными (захват начат в середине), решается на этом пакете.
func TestUnknownFlowWithDataDecidesImmediately(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloOnTLS)
	k := keyAB(t)
	a := tbl.Outbound(k, 1000, []byte{0x16, 0x03, 0x01, 0x00, 0x05}, time.Unix(0, 0))
	if a.Disposition != Apply {
		t.Fatalf("ожидался Apply на первом же сегменте с данными, получено %v", a.Disposition)
	}
}

// TestRetransmittedClientHelloRaisesRetransmit: повторная отправка ClientHello
// (тот же seq) на уже решённом потоке поднимает Retransmit — пассивный признак
// срыва (5.10). Сам пакет при этом проходит (Pass).
func TestRetransmittedClientHelloRaisesRetransmit(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloOnTLS)
	key := keyAB(t)
	hello := []byte{0x16, 0x03, 0x01, 0xAA}
	now := time.Now()

	// Первый ClientHello на seq 1000 — Apply, поток уходит с пути.
	if act := tbl.Outbound(key, 1000, hello, now); act.Disposition != Apply {
		t.Fatalf("первый ClientHello должен дать Apply, получено %+v", act)
	}

	// Повтор того же сегмента (тот же seq) — признак срыва.
	act := tbl.Outbound(key, 1000, hello, now.Add(time.Second))
	if !act.Retransmit {
		t.Fatal("повтор ClientHello должен поднять Retransmit")
	}
	if act.Disposition != Pass {
		t.Fatalf("повтор всё равно пропускается (Pass), получено %v", act.Disposition)
	}
	if !bytes.Equal(act.Hello, hello) {
		t.Fatal("Retransmit должен нести байты повторного ClientHello для разбора имени")
	}
}

// TestRetransmitRaisedOncePerFlow: повтор поднимает признак не более раза на
// поток. Одно сорванное соединение — одно наблюдение, а не по числу
// ретрансмиссий, которых TCP делает несколько.
func TestRetransmitRaisedOncePerFlow(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloOnTLS)
	key := keyAB(t)
	hello := []byte{0x16, 0x03, 0x01, 0xAA}
	now := time.Now()

	tbl.Outbound(key, 1000, hello, now)
	first := tbl.Outbound(key, 1000, hello, now.Add(time.Second))
	second := tbl.Outbound(key, 1000, hello, now.Add(2*time.Second))

	if !first.Retransmit {
		t.Fatal("первый повтор должен поднять Retransmit")
	}
	if second.Retransmit {
		t.Fatal("второй повтор того же потока не должен поднимать Retransmit повторно")
	}
}

// TestPostHelloDataIsNotRetransmit: обычные данные после ClientHello (seq выше)
// — это продолжение соединения, а не повтор. Признак срыва подниматься не
// должен, иначе каждый пакет успешной сессии считался бы срывом.
func TestPostHelloDataIsNotRetransmit(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloOnTLS)
	key := keyAB(t)
	hello := []byte{0x16, 0x03, 0x01, 0xAA}
	now := time.Now()

	tbl.Outbound(key, 1000, hello, now)
	// Данные на seq 1004 (за ClientHello) — рукопожатие пошло дальше.
	act := tbl.Outbound(key, 1004, []byte{0x17, 0x03, 0x03, 0x01}, now.Add(time.Second))
	if act.Retransmit {
		t.Fatal("данные за ClientHello не должны считаться повтором")
	}
}

// TestNonTLSFlowDoesNotWatchRetransmit: поток, в котором ClientHello не было
// (не TLS), повтор по тому же seq не отслеживает — сторожить нечего.
func TestNonTLSFlowDoesNotWatchRetransmit(t *testing.T) {
	tbl := NewTable(16, time.Minute, helloOnTLS)
	key := keyAB(t)
	now := time.Now()

	// Не TLS → settled без наблюдения за повтором.
	data := []byte{0x47, 0x45, 0x54} // "GET"
	tbl.Outbound(key, 1000, data, now)
	act := tbl.Outbound(key, 1000, data, now.Add(time.Second))
	if act.Retransmit {
		t.Fatal("поток без ClientHello не должен поднимать Retransmit")
	}
}
