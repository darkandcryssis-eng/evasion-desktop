package socketexec

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/desync"
	"github.com/fitting-1c/evasion/internal/executor"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// recordingWriter записывает каждый вызов Write отдельной записью. Отдельные
// записи — это и есть наблюдаемая офлайн сегментация: на проводе их превращает
// в сегменты стек ОС, но порядок и границы кусков видны уже здесь.
type recordingWriter struct {
	writes [][]byte
	fail   bool
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	if w.fail {
		return 0, errors.New("сбой записи")
	}
	// Копируем: вызывающий вправе переиспользовать буфер.
	cp := make([]byte, len(p))
	copy(cp, p)
	w.writes = append(w.writes, cp)
	return len(p), nil
}

// joined склеивает все записи — для проверки, что данные дошли целиком.
func (w *recordingWriter) joined() []byte {
	return bytes.Join(w.writes, nil)
}

func sendLeaf() *strategy.Action { return &strategy.Action{Kind: core.ActionSend} }

// splitStrategy — разрезать исходящий ClientHello на границе offset.
func splitStrategy(offset int) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: offset, Order: strategy.FragForward},
			Left:   sendLeaf(),
			Right:  sendLeaf(),
		},
	}}}
}

func helloInput(payload string) desync.Input {
	return desync.Input{
		Direction:     core.DirectionOutbound,
		Payload:       []byte(payload),
		Ordinal:       1,
		IsClientHello: true,
	}
}

func TestCapabilitiesSegmentationOnly(t *testing.T) {
	caps := Capabilities()
	if !caps.Has(core.CapFragmentTCP) {
		t.Fatal("ожидалась возможность fragment_tcp")
	}
	// Никаких фейков, дублирования, порчи, IP-фрагментации, реверса.
	for _, forbidden := range []core.Capability{
		core.CapTamper, core.CapTamperChecksumCorrupt, core.CapDuplicate,
		core.CapFragmentIP, core.CapReorder, core.CapDrop,
	} {
		if caps.Has(forbidden) {
			t.Fatalf("режим прокси не должен объявлять возможность %s", forbidden)
		}
	}
}

func TestExecuteSegments(t *testing.T) {
	// Разрез на 15-м байте: SNI обычно попадает на эту границу в реальном
	// ClientHello; здесь проверяем сам факт двух записей по границе.
	payload := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	w := &recordingWriter{}
	conn := NewConn(w, helloInput(payload))

	if err := New().Execute(context.Background(), splitStrategy(15), conn); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Две записи по границе 15 — это и есть сегментация (золотая
	// последовательность уровня сокета).
	if len(w.writes) != 2 {
		t.Fatalf("ожидалось 2 записи, получено %d: %q", len(w.writes), w.writes)
	}
	if string(w.writes[0]) != payload[:15] || string(w.writes[1]) != payload[15:] {
		t.Fatalf("границы записей неверны: %q | %q", w.writes[0], w.writes[1])
	}
	// Данные обязаны дойти целиком и в исходном порядке.
	if string(w.joined()) != payload {
		t.Fatalf("склейка записей %q != %q", w.joined(), payload)
	}
}

func TestExecutePassthrough(t *testing.T) {
	// Стратегия без правил для события: сквозной пропуск — одна запись целиком.
	empty := &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionInbound, // не совпадает с исходящим событием
		Trigger:   strategy.Trigger{Match: strategy.MatchAlways},
		Action:    sendLeaf(),
	}}}
	payload := "whole-client-hello"
	w := &recordingWriter{}
	conn := NewConn(w, helloInput(payload))

	if err := New().Execute(context.Background(), empty, conn); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(w.writes) != 1 || string(w.writes[0]) != payload {
		t.Fatalf("ожидалась одна запись целиком, получено %q", w.writes)
	}
}

func TestExecuteRejectsFakeStrategy(t *testing.T) {
	// Фейк по TTL: требует CapTamper, которой у прокси нет. Должен быть
	// отвергнут до единой записи.
	fake := &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind: core.ActionDuplicate,
			Left: &strategy.Action{
				Kind:   core.ActionTamper,
				Params: &strategy.TamperParams{Field: strategy.FieldIPv4TTL, Mode: strategy.TamperReplace, Value: 3},
				Left:   sendLeaf(),
			},
			Right: sendLeaf(),
		},
	}}}
	w := &recordingWriter{}
	conn := NewConn(w, helloInput("ABCD"))

	err := New().Execute(context.Background(), fake, conn)
	var ce *executor.CapabilityError
	if !errors.As(err, &ce) {
		t.Fatalf("ожидался *executor.CapabilityError, получено %v", err)
	}
	if !ce.Missing.Has(core.CapTamper) || !ce.Missing.Has(core.CapDuplicate) {
		t.Fatalf("недостающие возможности неполны: %v", ce.Missing)
	}
	if len(w.writes) != 0 {
		t.Fatalf("при отказе не должно быть записей, получено %q", w.writes)
	}
}

func TestSendFakeAlwaysErrors(t *testing.T) {
	conn := NewConn(&recordingWriter{}, helloInput("x"))
	err := conn.SendFake(context.Background(), desync.Op{Kind: desync.OpSendFake, Payload: []byte("fake")})
	if !errors.Is(err, ErrFakeUnsupported) {
		t.Fatalf("ожидалась ErrFakeUnsupported, получено %v", err)
	}
}

func TestSendRealRejectsIPFragmentFrame(t *testing.T) {
	conn := NewConn(&recordingWriter{}, helloInput("x"))
	err := conn.SendReal(context.Background(), desync.Op{Kind: desync.OpSendReal, Payload: []byte("x"), Frame: desync.FrameIPFragment})
	if !errors.Is(err, ErrFrameUnsupported) {
		t.Fatalf("ожидалась ErrFrameUnsupported, получено %v", err)
	}
}

func TestExecuteStopsOnWriteError(t *testing.T) {
	w := &recordingWriter{fail: true}
	conn := NewConn(w, helloInput("ABCDEF"))
	if err := New().Execute(context.Background(), splitStrategy(3), conn); err == nil {
		t.Fatal("ожидалась ошибка записи")
	}
}

func TestExecuteRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := &recordingWriter{}
	conn := NewConn(w, helloInput("ABCDEF"))

	if err := New().Execute(ctx, splitStrategy(3), conn); !errors.Is(err, context.Canceled) {
		t.Fatalf("ожидалась отмена контекста, получено %v", err)
	}
	if len(w.writes) != 0 {
		t.Fatalf("при отменённом контексте записей быть не должно: %q", w.writes)
	}
}
