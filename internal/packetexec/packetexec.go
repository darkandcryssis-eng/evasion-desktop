package packetexec

import (
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/executor"
)

// Capabilities возвращает возможности исполнителя перехвата.
//
// Почти полный набор этапа 1: сегментация TCP, паузы, фейки (правка полей
// заголовка и намеренная порча суммы), дублирование, отбрасывание, обратный
// порядок. Не объявлена пока лишь IP-фрагментация (CapFragmentIP): группировка
// IP-фрагментов — отдельный кусок, и объявлять её до реализации нельзя (4.7
// п. 2), иначе стратегию приняли бы и исполнили наполовину.
//
// Объявление фейков автоматически открывает их генератору (4.7 п. 3): он
// расширяет пространство поиска набором возможностей текущего исполнителя.
//
// Возвращается функцией, а не переменной, чтобы набор не мутировал из чужого
// пакета — то же решение, что в socketexec.
func Capabilities() core.PrimitiveSet {
	return core.PrimitiveSet(0).
		With(core.CapFragmentTCP).
		With(core.CapDelay).
		With(core.CapTamper).
		With(core.CapTamperChecksumCorrupt).
		With(core.CapDuplicate).
		With(core.CapDrop).
		With(core.CapReorder).
		With(core.CapTCPOverlap).
		With(core.CapMD5Sig).
		With(core.CapIPv6ExtHeader)
}

// Executor — исполнитель стратегии переписыванием пакетов. Встраивает
// executor.Base, добавляя лишь объявленный набор возможностей; вся логика
// исполнения — в Base.
type Executor struct {
	executor.Base
}

// New создаёт исполнитель перехвата.
func New() Executor {
	return Executor{Base: executor.Base{Caps: Capabilities()}}
}

// статическая проверка соответствия интерфейсу.
var _ executor.Executor = Executor{}
