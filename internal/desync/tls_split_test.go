package desync

import (
	"bytes"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// tlsRecord строит валидную TLS-запись handshake с заданным телом.
// Содержимое тела не парсится — для тестов TLS-split достаточно, чтобы заголовок
// описывал реальную длину.
func tlsRecord(body []byte) []byte {
	rec := make([]byte, 5+len(body))
	rec[0] = 0x16 // handshake
	rec[1] = 0x03
	rec[2] = 0x01 // legacy version TLS 1.0
	rec[3] = byte(len(body) >> 8)
	rec[4] = byte(len(body))
	copy(rec[5:], body)
	return rec
}

// Разрез на уровне TLS record даёт две валидных TLS-записи с общим header'ом.
func TestTLSRecordSplitProducesValidRecords(t *testing.T) {
	// Тело handshake: 32 байта узора.
	body := bytes.Repeat([]byte{0xaa}, 32)
	rec := tlsRecord(body)

	// Стратегия: Fragment{proto=tls_record, offset=15, order=forward}.
	// Разрез в середине handshake'а.
	s := &strategy.Strategy{
		Rules: []strategy.Rule{{
			Direction: core.DirectionOutbound,
			Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
			Action: &strategy.Action{
				Kind: core.ActionFragment,
				Params: &strategy.FragmentParams{
					Proto:  strategy.FragTLSRecord,
					Offset: 5 + 15, // внутри content после 5-байтного header'а
					Order:  strategy.FragForward,
				},
				Left:  &strategy.Action{Kind: core.ActionSend},
				Right: &strategy.Action{Kind: core.ActionSend},
			},
		}},
	}

	plan, err := BuildPlan(s, Input{
		Direction:     core.DirectionOutbound,
		Payload:       rec,
		Ordinal:       1,
		IsClientHello: true,
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Ops) != 2 {
		t.Fatalf("ops %d, ожидали 2", len(plan.Ops))
	}

	// Оба Op — SendReal (нет Tamper'ов), Frame = Segment.
	for i, op := range plan.Ops {
		if op.Kind != OpSendReal {
			t.Fatalf("op %d: kind %v, ожидали SendReal", i, op.Kind)
		}
		if op.Frame != FrameSegment {
			t.Fatalf("op %d: frame %v, ожидали FrameSegment", i, op.Frame)
		}
	}

	// Первая запись: содержимое 15 байт, header прописан.
	rec1 := plan.Ops[0].Payload
	if len(rec1) != 5+15 {
		t.Fatalf("rec1 длина %d, ожидали %d", len(rec1), 5+15)
	}
	if rec1[0] != 0x16 || rec1[1] != 0x03 || rec1[2] != 0x01 {
		t.Fatalf("rec1 header: %x, ожидали 16 03 01", rec1[:3])
	}
	gotLen1 := int(rec1[3])<<8 | int(rec1[4])
	if gotLen1 != 15 {
		t.Fatalf("rec1 заявленная длина %d, ожидали 15", gotLen1)
	}
	if !bytes.Equal(rec1[5:], bytes.Repeat([]byte{0xaa}, 15)) {
		t.Fatalf("rec1 content: %x", rec1[5:])
	}

	// Вторая запись: содержимое 17 байт.
	rec2 := plan.Ops[1].Payload
	if len(rec2) != 5+17 {
		t.Fatalf("rec2 длина %d, ожидали %d", len(rec2), 5+17)
	}
	gotLen2 := int(rec2[3])<<8 | int(rec2[4])
	if gotLen2 != 17 {
		t.Fatalf("rec2 заявленная длина %d, ожидали 17", gotLen2)
	}
	// Склеенное тело должно совпадать с исходным.
	glued := append([]byte(nil), rec1[5:]...)
	glued = append(glued, rec2[5:]...)
	if !bytes.Equal(glued, body) {
		t.Fatalf("склейка не совпадает с исходным телом")
	}
}

// Reverse order: вторая запись идёт первой.
func TestTLSRecordSplitReverseOrder(t *testing.T) {
	body := bytes.Repeat([]byte{0xbb}, 20)
	rec := tlsRecord(body)
	s := &strategy.Strategy{
		Rules: []strategy.Rule{{
			Direction: core.DirectionOutbound,
			Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
			Action: &strategy.Action{
				Kind: core.ActionFragment,
				Params: &strategy.FragmentParams{
					Proto:  strategy.FragTLSRecord,
					Offset: 5 + 8,
					Order:  strategy.FragReverse,
				},
				Left:  &strategy.Action{Kind: core.ActionSend},
				Right: &strategy.Action{Kind: core.ActionSend},
			},
		}},
	}
	plan, err := BuildPlan(s, Input{
		Direction:     core.DirectionOutbound,
		Payload:       rec,
		Ordinal:       1,
		IsClientHello: true,
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Ops) != 2 {
		t.Fatalf("ops %d, ожидали 2", len(plan.Ops))
	}
	// Первый отправленный Op — ВТОРАЯ запись (reverse): длина 12 байт.
	gotLen := int(plan.Ops[0].Payload[3])<<8 | int(plan.Ops[0].Payload[4])
	if gotLen != 12 {
		t.Fatalf("reverse: первая отправка — запись длиной %d, ожидали 12 (вторая половина)", gotLen)
	}
}

// Невалидный заголовок (не handshake) — ошибка, не молчаливый мусор.
func TestTLSRecordSplitRejectsNonHandshake(t *testing.T) {
	bogus := []byte{0x17, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5}
	s := &strategy.Strategy{
		Rules: []strategy.Rule{{
			Direction: core.DirectionOutbound,
			Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
			Action: &strategy.Action{
				Kind: core.ActionFragment,
				Params: &strategy.FragmentParams{
					Proto:  strategy.FragTLSRecord,
					Offset: 5 + 2,
					Order:  strategy.FragForward,
				},
				Left:  &strategy.Action{Kind: core.ActionSend},
				Right: &strategy.Action{Kind: core.ActionSend},
			},
		}},
	}
	_, err := BuildPlan(s, Input{
		Direction:     core.DirectionOutbound,
		Payload:       bogus,
		Ordinal:       1,
		IsClientHello: true,
	})
	if err == nil {
		t.Fatal("ожидали ошибку на не-handshake TLS record")
	}
}

// Расхождение заявленной длины — ошибка.
func TestTLSRecordSplitRejectsMismatchedLength(t *testing.T) {
	// Заявлена длина 100, а по факту 10.
	bad := []byte{0x16, 0x03, 0x01, 0x00, 0x64, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	s := &strategy.Strategy{
		Rules: []strategy.Rule{{
			Direction: core.DirectionOutbound,
			Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
			Action: &strategy.Action{
				Kind: core.ActionFragment,
				Params: &strategy.FragmentParams{
					Proto:  strategy.FragTLSRecord,
					Offset: 5 + 3,
					Order:  strategy.FragForward,
				},
				Left:  &strategy.Action{Kind: core.ActionSend},
				Right: &strategy.Action{Kind: core.ActionSend},
			},
		}},
	}
	_, err := BuildPlan(s, Input{
		Direction:     core.DirectionOutbound,
		Payload:       bad,
		Ordinal:       1,
		IsClientHello: true,
	})
	if err == nil {
		t.Fatal("ожидали ошибку на несогласованной длине TLS record")
	}
}

// Разрез в самом заголовке (offset <= 5) — ошибка, не молчаливое «что получилось».
func TestTLSRecordSplitRejectsCutInHeader(t *testing.T) {
	rec := tlsRecord(bytes.Repeat([]byte{0xcc}, 10))
	s := &strategy.Strategy{
		Rules: []strategy.Rule{{
			Direction: core.DirectionOutbound,
			Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
			Action: &strategy.Action{
				Kind: core.ActionFragment,
				Params: &strategy.FragmentParams{
					Proto:  strategy.FragTLSRecord,
					Offset: 3, // внутри заголовка
					Order:  strategy.FragForward,
				},
				Left:  &strategy.Action{Kind: core.ActionSend},
				Right: &strategy.Action{Kind: core.ActionSend},
			},
		}},
	}
	_, err := BuildPlan(s, Input{
		Direction:     core.DirectionOutbound,
		Payload:       rec,
		Ordinal:       1,
		IsClientHello: true,
	})
	if err == nil {
		t.Fatal("ожидали ошибку на разрезе внутри заголовка TLS record")
	}
}

// Токен сериализации fragProto нового значения.
func TestFragProtoTLSRecordText(t *testing.T) {
	var p strategy.FragProto = strategy.FragTLSRecord
	txt, err := p.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if string(txt) != "tls_record" {
		t.Fatalf("MarshalText = %q, ожидали tls_record", txt)
	}
	var p2 strategy.FragProto
	if err := p2.UnmarshalText([]byte("tls_record")); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if p2 != strategy.FragTLSRecord {
		t.Fatalf("UnmarshalText = %v, ожидали FragTLSRecord", p2)
	}
}
