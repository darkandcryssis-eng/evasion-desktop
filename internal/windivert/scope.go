package windivert

import (
	"fmt"
	"sync/atomic"
)

var excludedInterface atomic.Uint32

// SetExcludedInterface исключает интерфейс из всех перехватов, открываемых
// через Open. Нужен для стороннего TUN-VPN: пакеты внутри туннеля до DPI не
// доходят в открытом виде, а фейки в них ломают соединение на стороне VPN.
// Ноль снимает исключение. Действует на дескрипторы, открытые после вызова.
func SetExcludedInterface(index uint32) { excludedInterface.Store(index) }

func scopeFilter(filter string) string {
	index := excludedInterface.Load()
	if index == 0 || filter == "" || filter == "false" {
		return filter
	}
	return fmt.Sprintf("(%s) and ifIdx != %d", filter, index)
}
