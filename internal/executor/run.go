package executor

import (
	"context"
	"time"

	"github.com/fitting-1c/evasion/internal/desync"
)

// Run проводит операции плана через соединение по порядку.
//
// Порядок операций соблюдается строго: в нём закодирован порядок отправки, в
// том числе обратный порядок фрагментов. Перед каждой операцией проверяется
// отмена контекста — исполнение идёт в контуре соединения, которое может быть
// закрыто в любой момент, и продолжать слать пакеты в закрытое соединение
// бессмысленно.
//
// Run не знает о субстрате: вся работа с сокетом или пакетом — в реализации
// Conn. Это делает контур исполнения общим для обоих этапов.
func Run(ctx context.Context, c Conn, plan desync.Plan) error {
	for i := range plan.Ops {
		if err := ctx.Err(); err != nil {
			return err
		}
		op := plan.Ops[i]

		// Пауза перед операцией. Ждём через таймер с учётом отмены, а не
		// time.Sleep: соединение могут закрыть во время ожидания, и
		// просыпаться только чтобы обнаружить это — лишняя задержка закрытия.
		if op.DelayBefore > 0 {
			timer := time.NewTimer(op.DelayBefore)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}

		switch op.Kind {
		case desync.OpSendReal:
			if err := c.SendReal(ctx, op); err != nil {
				return err
			}
		case desync.OpSendFake:
			if err := c.SendFake(ctx, op); err != nil {
				return err
			}
		}
	}
	return nil
}
