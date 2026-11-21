package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/desync"
)

// timingConn запоминает моменты отправок, чтобы проверить выдержку паузы.
type timingConn struct {
	in    desync.Input
	times []time.Time
}

func (c *timingConn) Input() desync.Input { return c.in }

func (c *timingConn) SendReal(_ context.Context, _ desync.Op) error {
	c.times = append(c.times, time.Now())
	return nil
}

func (c *timingConn) SendFake(_ context.Context, _ desync.Op) error {
	c.times = append(c.times, time.Now())
	return nil
}

func TestRunHonoursDelayBefore(t *testing.T) {
	const pause = 120 * time.Millisecond
	plan := desync.Plan{Ops: []desync.Op{
		{Kind: desync.OpSendReal, Payload: []byte("A")},
		{Kind: desync.OpSendReal, Payload: []byte("B"), DelayBefore: pause},
	}}

	c := &timingConn{}
	start := time.Now()
	if err := Run(context.Background(), c, plan); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(c.times) != 2 {
		t.Fatalf("отправок %d, ожидалось 2", len(c.times))
	}

	// Проверяем промежуток между отправками, а не общее время: общее включает
	// накладные расходы и давало бы ложные срабатывания.
	gap := c.times[1].Sub(c.times[0])
	if gap < pause {
		t.Fatalf("промежуток %v меньше заданной паузы %v", gap, pause)
	}
	// Верхняя граница свободная: планировщик может задержать пробуждение, и
	// жёсткий предел сделал бы тест неустойчивым.
	if total := time.Since(start); total > pause+2*time.Second {
		t.Fatalf("исполнение заняло %v при паузе %v", total, pause)
	}
}

func TestRunAbortsDelayOnCancel(t *testing.T) {
	// Пауза обязана прерываться отменой: иначе закрытие соединения ждало бы
	// конца задержки, которая может быть секундной.
	plan := desync.Plan{Ops: []desync.Op{
		{Kind: desync.OpSendReal, Payload: []byte("A")},
		{Kind: desync.OpSendReal, Payload: []byte("B"), DelayBefore: 10 * time.Second},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	c := &timingConn{}
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := Run(ctx, c, plan)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ожидалась отмена контекста, получено %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("отмена не прервала паузу: прошло %v", elapsed)
	}
	if len(c.times) != 1 {
		t.Fatalf("после отмены отправок %d, ожидалась 1", len(c.times))
	}
}
