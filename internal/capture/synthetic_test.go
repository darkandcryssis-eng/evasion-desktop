package capture

import (
	"errors"
	"io"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
)

// TestSyntheticSourceYieldsInOrderThenEOF — источник отдаёт пакеты в заданном
// порядке и завершается io.EOF, как файловый.
func TestSyntheticSourceYieldsInOrderThenEOF(t *testing.T) {
	src := NewSyntheticSource(
		Packet{Data: []byte{1}, Dir: core.DirectionOutbound},
		Packet{Data: []byte{2}, Dir: core.DirectionInbound},
	)

	p1, err := src.Recv()
	if err != nil || len(p1.Data) != 1 || p1.Data[0] != 1 || p1.Dir != core.DirectionOutbound {
		t.Fatalf("первый пакет: %+v, err=%v", p1, err)
	}
	p2, err := src.Recv()
	if err != nil || p2.Data[0] != 2 || p2.Dir != core.DirectionInbound {
		t.Fatalf("второй пакет: %+v, err=%v", p2, err)
	}
	if _, err := src.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("по исчерпании ожидался io.EOF, получено %v", err)
	}
}

// TestSyntheticSourceEmptyIsEOF — пустой источник сразу даёт io.EOF, а не
// нулевой пакет без ошибки.
func TestSyntheticSourceEmptyIsEOF(t *testing.T) {
	if _, err := NewSyntheticSource().Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("пустой источник: ожидался io.EOF, получено %v", err)
	}
}

// TestSyntheticSinkCopiesData закрепляет контракт владения: приёмник,
// удерживающий пакет, копирует Data, и позднейшая перезапись буфера источника
// записанное не искажает.
func TestSyntheticSinkCopiesData(t *testing.T) {
	var sink SyntheticSink
	buf := []byte{10, 20, 30}

	if err := sink.Send(Packet{Data: buf, Dir: core.DirectionOutbound}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Источник переиспользует буфер после Recv — имитируем перезапись.
	buf[0] = 99

	got := sink.Sent()
	if len(got) != 1 {
		t.Fatalf("ожидался один записанный пакет, получено %d", len(got))
	}
	if got[0].Data[0] != 10 {
		t.Errorf("данные не скопированы: перезапись буфера исказила запись (%d вместо 10)", got[0].Data[0])
	}
	if got[0].Dir != core.DirectionOutbound {
		t.Errorf("направление потеряно: %v", got[0].Dir)
	}
}

// TestSyntheticSinkPreservesReinject — непрозрачные данные реинъекции доходят
// до приёмника как есть.
func TestSyntheticSinkPreservesReinject(t *testing.T) {
	type addr struct{ iface int }
	var sink SyntheticSink
	if err := sink.Send(Packet{Reinject: addr{iface: 7}}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, ok := sink.Sent()[0].Reinject.(addr)
	if !ok || got.iface != 7 {
		t.Errorf("данные реинъекции не сохранены: %+v", sink.Sent()[0].Reinject)
	}
}

// TestSyntheticRoundTrip — поток из источника доходит до приёмника в порядке.
func TestSyntheticRoundTrip(t *testing.T) {
	src := NewSyntheticSource(
		Packet{Data: []byte{1}},
		Packet{Data: []byte{2}},
		Packet{Data: []byte{3}},
	)
	var sink SyntheticSink
	for {
		p, err := src.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if err := sink.Send(p); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	sent := sink.Sent()
	if len(sent) != 3 || sent[0].Data[0] != 1 || sent[2].Data[0] != 3 {
		t.Fatalf("порядок или состав потока нарушен: %+v", sent)
	}
}
