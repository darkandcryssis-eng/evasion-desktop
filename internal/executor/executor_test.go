package executor

import (
	"context"
	"errors"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/desync"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// recordingConn — соединение-протокол для офлайн-проверки: ничего не отправляет
// в сеть, лишь записывает порядок и содержание операций. Это синтетический
// субстрат уровня executor, аналог синтетического источника пакетов (2.5).
type recordingConn struct {
	in    desync.Input
	calls []string
	// failReal, failFake заставляют соответствующую отправку вернуть ошибку —
	// для проверки, что Run прекращает исполнение на первой ошибке.
	failReal, failFake bool
}

func (c *recordingConn) Input() desync.Input { return c.in }

func (c *recordingConn) SendReal(_ context.Context, op desync.Op) error {
	if c.failReal {
		return errors.New("сбой реальной отправки")
	}
	c.calls = append(c.calls, "real "+op.Frame.String()+" "+string(op.Payload))
	return nil
}

func (c *recordingConn) SendFake(_ context.Context, op desync.Op) error {
	if c.failFake {
		return errors.New("сбой фейка")
	}
	c.calls = append(c.calls, "fake "+op.Frame.String()+" "+string(op.Payload))
	return nil
}

// proxyCaps — возможности, которые объявит socketexec на этапе прокси: без
// обратного порядка, IP-фрагментации и порчи контрольных сумм.
var proxyCaps = core.PrimitiveSet(0).
	With(core.CapTamper).
	With(core.CapDuplicate).
	With(core.CapFragmentTCP).
	With(core.CapDrop)

func sendLeaf() *strategy.Action { return &strategy.Action{Kind: core.ActionSend} }

func clientHello(a *strategy.Action) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action:    a,
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

func TestExecuteHappyPath(t *testing.T) {
	// Дублирование: фейк с TTL плюс реальные данные.
	s := clientHello(&strategy.Action{
		Kind: core.ActionDuplicate,
		Left: &strategy.Action{
			Kind:   core.ActionTamper,
			Params: &strategy.TamperParams{Field: strategy.FieldIPv4TTL, Mode: strategy.TamperReplace, Value: 3},
			Left:   sendLeaf(),
		},
		Right: sendLeaf(),
	})

	conn := &recordingConn{in: helloInput("ABCD")}
	exec := Base{Caps: proxyCaps}

	if err := exec.Execute(context.Background(), s, conn); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	want := []string{"fake segment ABCD", "real segment ABCD"}
	if len(conn.calls) != len(want) {
		t.Fatalf("операции = %v, ожидалось %v", conn.calls, want)
	}
	for i := range want {
		if conn.calls[i] != want[i] {
			t.Fatalf("операции = %v, ожидалось %v", conn.calls, want)
		}
	}
}

func TestExecuteRejectsMissingCapability(t *testing.T) {
	// Обратный порядок требует CapReorder, которой у прокси-возможностей нет.
	s := clientHello(&strategy.Action{
		Kind:   core.ActionFragment,
		Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 2, Order: strategy.FragReverse},
		Left:   sendLeaf(),
		Right:  sendLeaf(),
	})

	conn := &recordingConn{in: helloInput("ABCD")}
	exec := Base{Caps: proxyCaps}

	err := exec.Execute(context.Background(), s, conn)
	var ce *CapabilityError
	if !errors.As(err, &ce) {
		t.Fatalf("ожидался *CapabilityError, получено %v", err)
	}
	if !ce.Missing.Has(core.CapReorder) {
		t.Fatalf("в недостающих возможностях нет reorder: %v", ce.Missing)
	}
	// Отказ обязан быть до любой отправки.
	if len(conn.calls) != 0 {
		t.Fatalf("при отказе не должно быть отправок, получено %v", conn.calls)
	}
}

func TestExecuteRejectsIPFragmentCapability(t *testing.T) {
	s := clientHello(&strategy.Action{
		Kind:   core.ActionFragment,
		Params: &strategy.FragmentParams{Proto: strategy.FragIP, Offset: 2, Order: strategy.FragForward},
		Left:   sendLeaf(),
		Right:  sendLeaf(),
	})
	conn := &recordingConn{in: helloInput("ABCD")}
	exec := Base{Caps: proxyCaps}

	err := exec.Execute(context.Background(), s, conn)
	var ce *CapabilityError
	if !errors.As(err, &ce) || !ce.Missing.Has(core.CapFragmentIP) {
		t.Fatalf("ожидался отказ по fragment_ip, получено %v", err)
	}
}

func TestRunStopsOnError(t *testing.T) {
	s := clientHello(&strategy.Action{
		Kind:   core.ActionFragment,
		Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 2, Order: strategy.FragForward},
		Left:   sendLeaf(),
		Right:  sendLeaf(),
	})
	conn := &recordingConn{in: helloInput("ABCD"), failReal: true}
	exec := Base{Caps: proxyCaps}

	if err := exec.Execute(context.Background(), s, conn); err == nil {
		t.Fatal("ожидалась ошибка отправки")
	}
	if len(conn.calls) != 0 {
		t.Fatalf("после сбоя первой отправки не должно быть следующих: %v", conn.calls)
	}
}

func TestRunRespectsContextCancellation(t *testing.T) {
	plan := desync.Plan{Ops: []desync.Op{
		{Kind: desync.OpSendReal, Payload: []byte("x")},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // отменяем до запуска

	conn := &recordingConn{}
	if err := Run(ctx, conn, plan); !errors.Is(err, context.Canceled) {
		t.Fatalf("ожидалась отмена контекста, получено %v", err)
	}
	if len(conn.calls) != 0 {
		t.Fatalf("при отменённом контексте отправок быть не должно: %v", conn.calls)
	}
}

func TestEnsureExecutable(t *testing.T) {
	// Стратегия в пределах прокси-возможностей проходит.
	ok := clientHello(&strategy.Action{
		Kind:   core.ActionTamper,
		Params: &strategy.TamperParams{Field: strategy.FieldIPv4TTL, Mode: strategy.TamperReplace, Value: 1},
		Left:   sendLeaf(),
	})
	if err := EnsureExecutable(proxyCaps, ok); err != nil {
		t.Fatalf("исполнимая стратегия отвергнута: %v", err)
	}

	// Порча контрольной суммы требует возможности, которой у прокси нет.
	bad := clientHello(&strategy.Action{
		Kind:   core.ActionTamper,
		Params: &strategy.TamperParams{Field: strategy.FieldTCPChecksum, Mode: strategy.TamperCorrupt},
		Left:   sendLeaf(),
	})
	err := EnsureExecutable(proxyCaps, bad)
	var ce *CapabilityError
	if !errors.As(err, &ce) || !ce.Missing.Has(core.CapTamperChecksumCorrupt) {
		t.Fatalf("ожидался отказ по tamper_checksum_corrupt, получено %v", err)
	}
}

func TestCapabilityErrorMessageListsMissing(t *testing.T) {
	err := &CapabilityError{Missing: core.PrimitiveSet(0).With(core.CapReorder)}
	if msg := err.Error(); msg == "" || !contains(msg, "reorder") {
		t.Fatalf("сообщение не называет недостающую возможность: %q", msg)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
