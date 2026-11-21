package core

import "fmt"

// Direction — направление трафика, к которому относится правило стратегии.
//
// Направление входит в правило (strategy.Rule), а не в соединение: одно и то же
// соединение несёт пакеты в обе стороны, и правило объявляет, какую сторону оно
// рассматривает. Например, «входящий RST» — это Inbound, а разрезание
// ClientHello — Outbound.
type Direction uint8

const (
	// DirectionOutbound — пакеты, исходящие от защищаемого приложения к серверу.
	DirectionOutbound Direction = iota
	// DirectionInbound — пакеты, входящие от сервера к приложению.
	DirectionInbound
)

// Строковые метки направлений. Используются при сериализации: во внешнем
// описании стратегии направление записывается словом, а не числом, чтобы
// стратегию можно было написать и прочитать руками (требование 10.2).
const (
	directionOutboundText = "outbound"
	directionInboundText  = "inbound"
)

// String возвращает человекочитаемую метку направления.
func (d Direction) String() string {
	switch d {
	case DirectionOutbound:
		return directionOutboundText
	case DirectionInbound:
		return directionInboundText
	default:
		return fmt.Sprintf("Direction(%d)", uint8(d))
	}
}

// MarshalText сериализует направление как строковый токен для JSON и прочих
// текстовых форматов.
func (d Direction) MarshalText() ([]byte, error) {
	switch d {
	case DirectionOutbound, DirectionInbound:
		return []byte(d.String()), nil
	default:
		return nil, fmt.Errorf("core: недопустимое направление %d", uint8(d))
	}
}

// UnmarshalText разбирает строковый токен направления. Данные считаются
// недоверенными (стратегия может прийти из внешнего файла), поэтому неизвестный
// токен — это ошибка, а не молчаливое значение по умолчанию.
func (d *Direction) UnmarshalText(text []byte) error {
	switch string(text) {
	case directionOutboundText:
		*d = DirectionOutbound
	case directionInboundText:
		*d = DirectionInbound
	default:
		return fmt.Errorf("core: неизвестное направление %q", string(text))
	}
	return nil
}
