package sandbox

import (
	"context"
	"fmt"
)

// portPool раздаёт локальные порты выделенного диапазона песочницы под пробы.
//
// Диапазон — граница изоляции (5.2): пробы песочницы инициируются с этих
// портов, и отдельный фильтр WinDivert отделяет их от пользовательского
// трафика уже на захвате. Пул следит, чтобы один порт не ушёл под две пробы
// разом: иначе их ClientHello перемешались бы в одном потоке и привязка
// «порт → кандидат» потеряла бы смысл.
//
// Реализован каналом, а не счётчиком со списком: acquire обязан уметь ждать
// освобождения порта и при этом отменяться по контексту, а это ровно семантика
// чтения из канала в select с ctx.Done().
type portPool struct {
	free chan uint16
}

// newPortPool создаёт пул на диапазон [lo, hi] включительно.
func newPortPool(lo, hi uint16) (*portPool, error) {
	if hi < lo {
		return nil, fmt.Errorf("sandbox: диапазон портов пуст: %d > %d", lo, hi)
	}
	// Ёмкость = число портов; +1 потому, что границы включительны.
	free := make(chan uint16, int(hi-lo)+1)
	// Цикл с выходом по достижении hi, а не по условию p <= hi: при hi == 65535
	// инкремент uint16 переполнился бы в 0 и условие p <= hi не кончилось бы
	// никогда.
	for p := lo; ; p++ {
		free <- p
		if p == hi {
			break
		}
	}
	return &portPool{free: free}, nil
}

// acquire берёт свободный порт, ожидая освобождения, если все заняты.
// Возвращает ошибку контекста, если ждать больше нельзя.
func (pp *portPool) acquire(ctx context.Context) (uint16, error) {
	select {
	case p := <-pp.free:
		return p, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// release возвращает порт в пул. Парен к acquire: ровно один вызов на каждый
// взятый порт.
func (pp *portPool) release(p uint16) {
	// Неблокирующе: ёмкость канала равна числу портов, и release парен к
	// acquire, поэтому место всегда есть. default — защита от двойного
	// release, который иначе заблокировал бы горутину навсегда.
	select {
	case pp.free <- p:
	default:
	}
}

// size сообщает ёмкость пула — для журнала и проверок.
func (pp *portPool) size() int { return cap(pp.free) }

// available сообщает число свободных портов прямо сейчас — для проверок.
func (pp *portPool) available() int { return len(pp.free) }
