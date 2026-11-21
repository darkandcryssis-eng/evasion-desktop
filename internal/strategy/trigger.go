package strategy

import "fmt"

// MatchKind — вид условия срабатывания правила.
//
// Триггер обобщённый (как в Geneva): сопоставление по полю заголовка плюс
// предикаты позиции пакета в соединении. Чисто семантические триггеры были бы
// удобнее на этапе прокси, но зажали бы пространство поиска на этапе перехвата,
// поэтому выбрана обобщённая форма. Цена — генератор будет порождать правила,
// которые никогда не срабатывают, и ему понадобится отбраковка «мёртвых» правил.
type MatchKind uint8

const (
	// MatchAlways — срабатывает на любом пакете в направлении правила.
	// Нулевое значение, чтобы пустой триггер означал «любой пакет».
	MatchAlways MatchKind = iota
	// MatchClientHello — срабатывает на пакете, несущем TLS ClientHello.
	// Основной триггер на этапе прокси.
	MatchClientHello
	// MatchNthPacket — срабатывает на N-м пакете соединения в направлении
	// правила. Нумерация с единицы; номер хранится в Trigger.N.
	MatchNthPacket
	// MatchField — срабатывает, когда поле заголовка удовлетворяет сравнению
	// Op с Value. Поле задаётся Trigger.Field.
	MatchField
)

const (
	matchAlwaysText      = "always"
	matchClientHelloText = "client_hello"
	matchNthPacketText   = "nth_packet"
	matchFieldText       = "field"
)

// String возвращает токен вида условия.
func (m MatchKind) String() string {
	switch m {
	case MatchAlways:
		return matchAlwaysText
	case MatchClientHello:
		return matchClientHelloText
	case MatchNthPacket:
		return matchNthPacketText
	case MatchField:
		return matchFieldText
	default:
		return fmt.Sprintf("MatchKind(%d)", uint8(m))
	}
}

// MarshalText сериализует вид условия как токен.
func (m MatchKind) MarshalText() ([]byte, error) {
	switch m {
	case MatchAlways, MatchClientHello, MatchNthPacket, MatchField:
		return []byte(m.String()), nil
	default:
		return nil, fmt.Errorf("strategy: недопустимый вид условия %d", uint8(m))
	}
}

// UnmarshalText разбирает токен вида условия.
func (m *MatchKind) UnmarshalText(text []byte) error {
	switch string(text) {
	case matchAlwaysText:
		*m = MatchAlways
	case matchClientHelloText:
		*m = MatchClientHello
	case matchNthPacketText:
		*m = MatchNthPacket
	case matchFieldText:
		*m = MatchField
	default:
		return fmt.Errorf("strategy: неизвестный вид условия %q", string(text))
	}
	return nil
}

// MatchOp — операция сравнения поля в триггере MatchField.
type MatchOp uint8

const (
	// OpEqual — поле равно Value.
	OpEqual MatchOp = iota
	// OpNotEqual — поле не равно Value.
	OpNotEqual
	// OpHasBits — все биты Value установлены в поле (маска). Нужно для
	// сопоставления по отдельным флагам, например «входящий RST».
	OpHasBits
)

const (
	opEqualText    = "eq"
	opNotEqualText = "neq"
	opHasBitsText  = "has_bits"
)

// String возвращает токен операции сравнения.
func (o MatchOp) String() string {
	switch o {
	case OpEqual:
		return opEqualText
	case OpNotEqual:
		return opNotEqualText
	case OpHasBits:
		return opHasBitsText
	default:
		return fmt.Sprintf("MatchOp(%d)", uint8(o))
	}
}

// MarshalText сериализует операцию как токен.
func (o MatchOp) MarshalText() ([]byte, error) {
	switch o {
	case OpEqual, OpNotEqual, OpHasBits:
		return []byte(o.String()), nil
	default:
		return nil, fmt.Errorf("strategy: недопустимая операция %d", uint8(o))
	}
}

// UnmarshalText разбирает токен операции.
func (o *MatchOp) UnmarshalText(text []byte) error {
	switch string(text) {
	case opEqualText:
		*o = OpEqual
	case opNotEqualText:
		*o = OpNotEqual
	case opHasBitsText:
		*o = OpHasBits
	default:
		return fmt.Errorf("strategy: неизвестная операция %q", string(text))
	}
	return nil
}

// Trigger — условие, при котором правило применяет своё действие.
//
// Поля Field, Op, Value значимы только при Match == MatchField; поле N —
// только при Match == MatchNthPacket. Протокол поля не хранится отдельно: он
// определяется по FieldID (см. field.go).
type Trigger struct {
	// Match — вид условия.
	Match MatchKind `json:"match"`
	// Field — поле заголовка для сопоставления (только при MatchField).
	Field FieldID `json:"field,omitempty"`
	// Op — операция сравнения (только при MatchField).
	Op MatchOp `json:"op,omitempty"`
	// Value — эталон сравнения или битовая маска (только при MatchField).
	Value uint64 `json:"value,omitempty"`
	// N — порядковый номер пакета, с единицы (только при MatchNthPacket).
	N int `json:"n,omitempty"`
}

// validate проверяет триггер против границ. Возвращает ошибку с описанием
// нарушения; data-пригодный код ошибки навешивает вызывающая валидация дерева.
func (t Trigger) validate() error {
	switch t.Match {
	case MatchAlways, MatchClientHello:
		// Позиционные/безусловные триггеры не используют остальные поля.
		return nil
	case MatchNthPacket:
		if t.N < 1 {
			return fmt.Errorf("номер пакета N должен быть >= 1, получено %d", t.N)
		}
		return nil
	case MatchField:
		fi, ok := t.Field.info()
		if !ok {
			return fmt.Errorf("неизвестное поле триггера %d", uint8(t.Field))
		}
		if fi.isPayload {
			return fmt.Errorf("по телу (%s) сопоставление в триггере не поддерживается", t.Field)
		}
		// Эталон/маска не должны превышать ширину поля.
		if max, ok := t.Field.maxValue(); ok && t.Value > max {
			return fmt.Errorf("значение %d не умещается в поле %s (макс. %d)", t.Value, t.Field, max)
		}
		switch t.Op {
		case OpEqual, OpNotEqual, OpHasBits:
			return nil
		default:
			return fmt.Errorf("недопустимая операция сравнения %d", uint8(t.Op))
		}
	default:
		return fmt.Errorf("недопустимый вид условия %d", uint8(t.Match))
	}
}
