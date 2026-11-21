package desync

import (
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// FieldSource даёт значения полей заголовка для вычисления триггеров вида
// MatchField.
//
// Это интерфейс, а не конкретный пакет, намеренно: desync не должен зависеть от
// packet, чтобы оставаться чистым и тестироваться без разбора пакетов. В режиме
// прокси полей заголовка нет (данные идут через сокет), и источник равен nil —
// тогда триггеры по полю просто не срабатывают. В режиме перехвата источник
// предоставит executor поверх разобранного пакета.
type FieldSource interface {
	// Field возвращает значение поля и признак того, что поле доступно.
	Field(f strategy.FieldID) (uint64, bool)
}

// Input описывает одно исходящее (или входящее) событие, для которого строится
// план.
//
// Это весь контекст, нужный для вычисления триггеров и обхода дерева. Намеренно
// минимален и не содержит ни сокета, ни пакета: desync работает с байтами и
// метаданными, а не с субстратом.
type Input struct {
	// Direction — направление события. Правило рассматривается, только если
	// его направление совпадает.
	Direction core.Direction
	// Payload — полезная нагрузка события (для исходящего ClientHello — байты
	// записи TLS). Операции OpSendReal возвращают срезы именно этого буфера.
	Payload []byte
	// Ordinal — порядковый номер события в своём направлении, с единицы.
	// Нужен триггеру MatchNthPacket.
	Ordinal int
	// IsClientHello — несёт ли событие ClientHello. Определяет вызывающий код
	// (через tlsparse), чтобы desync не зависел от разбора TLS.
	IsClientHello bool
	// Cuts — структурные точки разреза нагрузки, вычисленные тем, кто её
	// разобрал (в режиме прокси — пакетом proxy через tlsparse).
	//
	// Передаются готовыми, а не вычисляются здесь, по двум причинам. Во-первых,
	// desync не должен знать протоколов: иначе пропадает его главное свойство —
	// проверяемость офлайн на синтетике (4.1). Во-вторых, разбор уже выполнен
	// вызывающим, и повторный стоил бы времени прямо на горячем пути, где
	// бюджет решения 10 мкс (8.1).
	//
	// Пустой срез допустим: тогда стратегия со структурной точкой разреза
	// отвергается явной ошибкой, а не исполняется наполовину.
	Cuts []core.CutPoint
	// Fields — источник значений полей заголовка для MatchField; nil, если
	// полей нет (режим прокси).
	Fields FieldSource
}

// resolveCut возвращает абсолютное смещение структурной точки разреза.
//
// Линейный поиск по срезу, а не карта: точек единицы (сейчас не более шести),
// и перебор нескольких элементов дешевле вычисления хеша, а главное — не
// выделяет памяти, что на горячем пути обязательно (4.2, правило 1).
func (in Input) resolveCut(k core.CutKind) (int, bool) {
	for _, c := range in.Cuts {
		if c.Kind == k {
			return c.Offset, true
		}
	}
	return 0, false
}

// triggerMatches сообщает, срабатывает ли условие правила на этом событии.
//
// Проверка направления здесь не делается — её выполняет вызывающий обход по
// полю Rule.Direction. Триггер по полю при отсутствии источника полей (режим
// прокси) не срабатывает: это осознанный «не сработал», а не ошибка.
func (in Input) triggerMatches(t strategy.Trigger) bool {
	switch t.Match {
	case strategy.MatchAlways:
		return true
	case strategy.MatchClientHello:
		return in.IsClientHello
	case strategy.MatchNthPacket:
		return in.Ordinal == t.N
	case strategy.MatchField:
		if in.Fields == nil {
			return false
		}
		v, ok := in.Fields.Field(t.Field)
		if !ok {
			return false
		}
		return matchFieldValue(t.Op, v, t.Value)
	default:
		return false
	}
}

// matchFieldValue применяет операцию сравнения поля.
func matchFieldValue(op strategy.MatchOp, have, want uint64) bool {
	switch op {
	case strategy.OpEqual:
		return have == want
	case strategy.OpNotEqual:
		return have != want
	case strategy.OpHasBits:
		// Все биты маски want должны быть установлены в have.
		return have&want == want
	default:
		return false
	}
}
