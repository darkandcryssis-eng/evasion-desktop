package executor

import (
	"context"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/desync"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// Executor воплощает стратегию для одного соединения.
//
// Реализации (socketexec, packetexec) различаются доступной механикой: в
// пользовательском пространстве нет контроля над отдельными сегментами TCP,
// поэтому часть примитивов там невыразима. Именно это и сообщает Capabilities.
type Executor interface {
	// Capabilities сообщает, какие виды примитивов реализация умеет. Нужно
	// генератору, чтобы не порождать невыполнимое, и валидации, чтобы
	// отказывать явно.
	Capabilities() core.PrimitiveSet

	// Execute применяет стратегию к соединению. Обязан вернуть CapabilityError,
	// если стратегия требует недоступных возможностей, не пытаясь исполнить её
	// частично.
	Execute(ctx context.Context, s *strategy.Strategy, c Conn) error
}

// Base — общая реализация Executor, параметризованная набором возможностей.
//
// Логика исполнения одинакова для всех субстратов (проверить возможности,
// построить план, провести операции), поэтому она здесь, а различие субстратов
// живёт в реализации Conn. Конкретный исполнитель встраивает Base и задаёт свои
// возможности:
//
//	type Socket struct { executor.Base }
//	func NewSocket() Socket { return Socket{executor.Base{Caps: proxyCapabilities}} }
//
// Благодаря этому переход на этап 1 добавляет новую реализацию Conn и новое
// значение Caps, но не меняет контур исполнения.
type Base struct {
	// Caps — возможности, объявляемые исполнителем.
	Caps core.PrimitiveSet
}

// Capabilities возвращает объявленные возможности.
func (b Base) Capabilities() core.PrimitiveSet { return b.Caps }

// Execute проверяет исполнимость, строит план и проводит его через соединение.
func (b Base) Execute(ctx context.Context, s *strategy.Strategy, c Conn) error {
	if err := EnsureExecutable(b.Caps, s); err != nil {
		return err
	}
	plan, err := desync.BuildPlan(s, c.Input())
	if err != nil {
		return err
	}
	return Run(ctx, c, plan)
}

// статическая проверка, что Base удовлетворяет Executor.
var _ Executor = Base{}
