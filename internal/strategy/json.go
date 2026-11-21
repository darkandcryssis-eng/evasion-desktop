package strategy

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/fitting-1c/evasion/internal/core"
)

// actionWire — проводная форма узла дерева.
//
// Params вынесены в сырое сообщение, потому что это интерфейс: при разборе тип
// параметров выбирается по виду узла через реестр, при записи — сериализуется
// как есть. Порядок полей фиксирован, что и обеспечивает детерминизм
// канонической формы (canonical.go).
type actionWire struct {
	Kind   core.ActionKind `json:"kind"`
	Params json.RawMessage `json:"params,omitempty"`
	Left   *Action         `json:"left,omitempty"`
	Right  *Action         `json:"right,omitempty"`
}

// MarshalJSON сериализует узел дерева в проводную форму.
func (a *Action) MarshalJSON() ([]byte, error) {
	w := actionWire{Kind: a.Kind, Left: a.Left, Right: a.Right}
	if a.Params != nil {
		raw, err := json.Marshal(a.Params)
		if err != nil {
			return nil, fmt.Errorf("strategy: сериализация параметров %s: %w", a.Kind, err)
		}
		w.Params = raw
	}
	return json.Marshal(w)
}

// UnmarshalJSON разбирает узел дерева из проводной формы.
//
// Ввод недоверенный: неизвестные ключи отвергаются (DisallowUnknownFields),
// неизвестный вид — ошибка, параметры конструируются строго по виду. Это первый
// рубеж против мусора из конфига и из фаззинга; смысловая проверка (арность,
// границы полей) — в Validate.
func (a *Action) UnmarshalJSON(data []byte) error {
	// Строгий декодер: лишний ключ в описании — повод отказать, а не
	// проигнорировать (недоверенный ввод).
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var w actionWire
	if err := dec.Decode(&w); err != nil {
		return err
	}

	spec, ok := specFor(w.Kind)
	if !ok {
		return fmt.Errorf("strategy: неизвестный вид узла %q", w.Kind)
	}

	a.Kind = w.Kind
	a.Left = w.Left
	a.Right = w.Right
	a.Params = nil

	hasParams := len(w.Params) > 0 && !bytes.Equal(bytes.TrimSpace(w.Params), []byte("null"))
	switch {
	case spec.newParams == nil && hasParams:
		// Листья и Duplicate параметров не несут. Наличие — повод отказать, а
		// не молча отбросить: иначе ошибочное описание прошло бы незамеченным.
		return fmt.Errorf("strategy: у %s не должно быть параметров", w.Kind)
	case spec.newParams != nil && !hasParams:
		return fmt.Errorf("strategy: у %s обязательны параметры", w.Kind)
	case spec.newParams != nil:
		p := spec.newParams()
		pdec := json.NewDecoder(bytes.NewReader(w.Params))
		pdec.DisallowUnknownFields()
		if err := pdec.Decode(p); err != nil {
			return fmt.Errorf("strategy: разбор параметров %s: %w", w.Kind, err)
		}
		a.Params = p
	}
	return nil
}

// document — проводная форма всей стратегии.
type document struct {
	ID    core.StrategyID `json:"id,omitempty"`
	Rules []Rule          `json:"rules"`
}

// Marshal сериализует стратегию в каноническую JSON-форму с идентификатором.
//
// Идентификатор пересчитывается из содержимого, а не берётся из поля s.ID:
// запись всегда согласована с деревом, даже если в памяти ID почему-то устарел.
func Marshal(s *Strategy) ([]byte, error) {
	id, err := ComputeID(s)
	if err != nil {
		return nil, err
	}
	return json.Marshal(document{ID: id, Rules: s.Rules})
}

// Unmarshal разбирает стратегию из JSON, валидирует её и вычисляет
// идентификатор.
//
// Это единственный вход для недоверенного описания стратегии (конфиг, портфель,
// перенос с другой машины). Порядок строгий: разбор → проверка целостности
// идентификатора → полная валидация. Если во входе задан идентификатор, он
// обязан совпасть с вычисленным — так ловится повреждение или подмена записи.
func Unmarshal(data []byte, limits Limits) (*Strategy, error) {
	// Предохранитель по размеру и вложенности — до декодера: разбор глубокого
	// описания стоит квадратично от глубины (см. shape.go).
	limits = limits.normalized()
	if err := checkEncodedShape(data, limits); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc document
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}

	s := &Strategy{Rules: doc.Rules}
	if err := Validate(s, limits); err != nil {
		return nil, err
	}

	id, err := ComputeID(s)
	if err != nil {
		return nil, err
	}
	if doc.ID != "" && doc.ID != id {
		return nil, fmt.Errorf("strategy: идентификатор во входе %q не совпадает с вычисленным %q", doc.ID, id)
	}
	s.ID = id
	return s, nil
}
