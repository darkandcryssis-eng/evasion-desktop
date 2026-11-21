package strategy

import "github.com/fitting-1c/evasion/internal/core"

// RequiredCapabilities вычисляет набор возможностей, нужных для исполнения
// стратегии, обходом её дерева.
//
// Набор НЕ дублируется в самом дереве: иначе при мутации поле разошлось бы с
// содержимым (требование 4.7 п. 1). Генератор пересекает результат с
// возможностями исполнителя, чтобы не порождать невыполнимое; исполнитель
// сравнивает его со своими возможностями, чтобы отказать явной ошибкой, а не
// молча проигнорировать непосильный примитив.
//
// Функция тотальна и для некорректных деревьев: она не валидирует, а лишь
// собирает требования по тем узлам, что есть. Вызывать её имеет смысл после
// Validate.
func RequiredCapabilities(s *Strategy) core.PrimitiveSet {
	var set core.PrimitiveSet
	if s == nil {
		return set
	}
	for i := range s.Rules {
		set = set.Union(actionCapabilities(s.Rules[i].Action))
	}
	return set
}

// actionCapabilities собирает возможности по узлу и его ветвям.
func actionCapabilities(a *Action) core.PrimitiveSet {
	var set core.PrimitiveSet
	if a == nil {
		return set
	}
	// Базовая возможность вида. Send терминален и не требует возможностей —
	// отправка есть у любого исполнителя.
	switch a.Kind {
	case core.ActionDrop:
		set = set.With(core.CapDrop)
	case core.ActionDuplicate:
		set = set.With(core.CapDuplicate)
	case core.ActionMD5Sig:
		set = set.With(core.CapMD5Sig)
	case core.ActionIPv6Ext:
		set = set.With(core.CapIPv6ExtHeader)
	}
	// Возможности, зависящие от параметров (поле/режим/порядок).
	if a.Params != nil {
		set = set.Union(a.Params.requiredCapabilities())
	}
	// Рекурсия по ветвям.
	set = set.Union(actionCapabilities(a.Left))
	set = set.Union(actionCapabilities(a.Right))
	return set
}
