package executor

import (
	"fmt"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// CapabilityError — отказ исполнить стратегию, требующую возможностей, которых
// у исполнителя нет.
//
// Отказ обязан быть явным и называть недостающие возможности (4.7 п. 2).
// Молчаливое игнорирование непосильного примитива запрещено: стратегию оценили
// бы как нерабочую, хотя она просто не применялась, — тот же класс порчи
// измерений, что утечка по IPv6. Поля машинно-читаемы, чтобы потребитель
// (телеметрия, CLI) отличал этот отказ от сетевой ошибки.
type CapabilityError struct {
	// Required — что требует стратегия.
	Required core.PrimitiveSet
	// Available — что умеет исполнитель.
	Available core.PrimitiveSet
	// Missing — чего не хватает (Required минус Available).
	Missing core.PrimitiveSet
}

// Error удовлетворяет интерфейсу error.
func (e *CapabilityError) Error() string {
	missing, _ := e.Missing.MarshalText()
	return fmt.Sprintf("executor: стратегия требует возможностей, недоступных исполнителю: %s", missing)
}

// EnsureExecutable проверяет, что исполнитель с данными возможностями способен
// исполнить стратегию, и возвращает CapabilityError, если нет.
//
// Проверка идёт по стратегии, а не по плану: план не сохраняет сведений о
// фрагментации, обратном порядке и дублировании (см. desync.Plan), поэтому
// только дерево даёт полный набор требуемых возможностей.
func EnsureExecutable(caps core.PrimitiveSet, s *strategy.Strategy) error {
	required := strategy.RequiredCapabilities(s)
	if missing := caps.Missing(required); missing != 0 {
		return &CapabilityError{
			Required:  required,
			Available: caps,
			Missing:   missing,
		}
	}
	return nil
}
