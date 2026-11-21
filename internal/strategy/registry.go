package strategy

import "github.com/fitting-1c/evasion/internal/core"

// kindSpec — описание одного вида примитива в реестре.
type kindSpec struct {
	// newParams создаёт нулевые параметры нужного типа для разбора
	// сериализованной формы. nil означает, что у вида параметров нет
	// (листья Send/Drop и Duplicate).
	newParams func() Params
}

// registry — единый источник правды о видах примитивов.
//
// Генератор НЕ содержит захардкоженного списка действий: он берёт перечень
// видов отсюда и пересекает с возможностями исполнителя (требование 10.3).
// Поэтому добавление примитива сводится к записи в этой таблице, реализации в
// desync и правилу валидации — generator при этом не меняется.
//
// Индексируется по core.ActionKind. Виды без параметров имеют newParams == nil.
var registry = map[core.ActionKind]kindSpec{
	core.ActionSend:       {newParams: nil},
	core.ActionDrop:       {newParams: nil},
	core.ActionDuplicate:  {newParams: nil},
	core.ActionTamper:     {newParams: func() Params { return &TamperParams{} }},
	core.ActionFragment:   {newParams: func() Params { return &FragmentParams{} }},
	core.ActionTCPOverlap: {newParams: func() Params { return &TCPOverlapParams{} }},
	core.ActionMD5Sig:     {newParams: nil},
	core.ActionIPv6Ext:    {newParams: nil},
}

// Kinds возвращает все известные виды примитивов. Порядок детерминирован
// (по возрастанию значения ActionKind), чтобы вывод и обход были
// воспроизводимы. Это и есть точка, из которой генератор узнаёт пространство
// действий.
func Kinds() []core.ActionKind {
	// Перечисляем явно в порядке объявления, а не обходом карты (у карты
	// порядок случаен). Список коротких видов проще держать здесь, чем
	// сортировать ключи.
	return []core.ActionKind{
		core.ActionSend,
		core.ActionDrop,
		core.ActionDuplicate,
		core.ActionTamper,
		core.ActionFragment,
		core.ActionTCPOverlap,
		core.ActionMD5Sig,
		core.ActionIPv6Ext,
	}
}

// specFor возвращает описание вида и признак того, что вид известен.
func specFor(kind core.ActionKind) (kindSpec, bool) {
	spec, ok := registry[kind]
	return spec, ok
}
