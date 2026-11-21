package strategy

import (
	"fmt"
	"strings"
)

// ValidationError — машинно-читаемая ошибка валидации стратегии.
//
// Движок headless: ошибки — это данные, а не текст для человека (требование
// 2.2). Поэтому ошибка несёт код и путь к месту нарушения, по которым потребитель
// (CLI с --json, будущий интерфейс) строит собственное представление. Поле
// Message — вспомогательное пояснение, не контракт.
type ValidationError struct {
	// Code — стабильный код причины (см. константы ниже).
	Code string
	// Path — путь к месту нарушения, например "rules[2].action.left".
	Path string
	// Message — человекочитаемое пояснение (не стабильно, для отладки).
	Message string
}

// Коды ошибок валидации. Стабильны: на них опирается потребитель.
const (
	ErrNoRules       = "no_rules"       // стратегия без правил
	ErrTooManyRules  = "too_many_rules" // превышен предел числа правил
	ErrBadDirection  = "bad_direction"  // неизвестное направление
	ErrBadTrigger    = "bad_trigger"    // некорректное условие
	ErrNoAction      = "no_action"      // у правила нет дерева действий
	ErrUnknownKind   = "unknown_kind"   // неизвестный вид узла
	ErrBadArity      = "bad_arity"      // число ветвей не соответствует виду
	ErrBadParams     = "bad_params"     // параметры узла некорректны
	ErrParamsOnLeaf  = "params_on_leaf" // у листа/дубликатора есть параметры
	ErrMissingParams = "missing_params" // у Tamper/Fragment нет параметров
	ErrTooDeep       = "too_deep"       // превышена глубина дерева
	ErrTooManyNodes  = "too_many_nodes" // превышено число узлов
	ErrInputTooLarge = "input_too_large"
	ErrInputTooDeep  = "input_too_deep"
)

// Error удовлетворяет интерфейсу error.
func (e *ValidationError) Error() string {
	var b strings.Builder
	b.WriteString("strategy: ")
	b.WriteString(e.Code)
	if e.Path != "" {
		b.WriteString(" at ")
		b.WriteString(e.Path)
	}
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	}
	return b.String()
}

// verr — краткий конструктор ошибки валидации.
func verr(code, path, format string, args ...any) *ValidationError {
	return &ValidationError{Code: code, Path: path, Message: fmt.Sprintf(format, args...)}
}

// Validate проверяет корректность стратегии против границ протоколов и лимитов.
//
// Вся проверка собрана в одном месте намеренно: раз параметры узлов — это
// интерфейс (меньше статической типизации), валидация обязана быть
// централизованной и покрытой тестами (разбор компромисса — в задании, 4.3).
// Данные считаются недоверенными: функция рассчитана и на осмысленный ввод из
// конфига, и на мусор из фаззинга.
func Validate(s *Strategy, limits Limits) error {
	if s == nil {
		return verr(ErrNoRules, "", "стратегия отсутствует")
	}
	if len(s.Rules) == 0 {
		return verr(ErrNoRules, "", "стратегия не содержит правил")
	}
	if len(s.Rules) > limits.MaxRules {
		return verr(ErrTooManyRules, "rules", "правил %d, предел %d", len(s.Rules), limits.MaxRules)
	}

	// Число узлов считаем суммарно по всем правилам: защита от дерева, где
	// каждое правило в пределах глубины, но вместе они разрастаются.
	totalNodes := 0
	for i := range s.Rules {
		path := fmt.Sprintf("rules[%d]", i)
		if err := validateRule(&s.Rules[i], path, limits, &totalNodes); err != nil {
			return err
		}
	}
	return nil
}

// validateRule проверяет одно правило.
func validateRule(r *Rule, path string, limits Limits, totalNodes *int) error {
	switch r.Direction {
	case 0, 1: // DirectionOutbound, DirectionInbound; литералы, чтобы не тянуть core в проверку диапазона
	default:
		return verr(ErrBadDirection, path+".direction", "неизвестное направление %d", uint8(r.Direction))
	}
	if err := r.Trigger.validate(); err != nil {
		return verr(ErrBadTrigger, path+".trigger", "%v", err)
	}
	if r.Action == nil {
		return verr(ErrNoAction, path+".action", "у правила нет дерева действий")
	}
	return validateAction(r.Action, path+".action", 1, limits, totalNodes)
}

// validateAction рекурсивно проверяет узел дерева и его ветви.
//
// depth — глубина текущего узла (корень = 1). totalNodes накапливает число
// узлов по всей стратегии.
func validateAction(a *Action, path string, depth int, limits Limits, totalNodes *int) error {
	if a == nil {
		// До nil-узла в допустимом дереве дойти нельзя: ветви задаёт арность, и
		// их отсутствие ловится ниже как нарушение арности. Явная проверка —
		// подстраховка на случай ручного конструирования дерева.
		return verr(ErrBadArity, path, "пустой узел")
	}
	if depth > limits.MaxDepth {
		return verr(ErrTooDeep, path, "глубина %d превышает предел %d", depth, limits.MaxDepth)
	}
	*totalNodes++
	if *totalNodes > limits.MaxNodes {
		return verr(ErrTooManyNodes, path, "узлов больше предела %d", limits.MaxNodes)
	}

	arity, known := a.Kind.Arity()
	if !known {
		return verr(ErrUnknownKind, path, "неизвестный вид узла %d", uint8(a.Kind))
	}

	// Параметры: у Tamper/Fragment обязательны и валидны; у остальных отсутствуют.
	if err := validateParams(a, path, limits); err != nil {
		return err
	}

	// Арность: сопоставляем фактические ветви с требуемыми видом.
	switch arity {
	case 0: // лист
		if a.Left != nil || a.Right != nil {
			return verr(ErrBadArity, path, "у листа %s не должно быть ветвей", a.Kind)
		}
		return nil
	case 1: // одна ветвь (Tamper): только Left
		if a.Left == nil {
			return verr(ErrBadArity, path+".left", "у %s обязательна ветвь left", a.Kind)
		}
		if a.Right != nil {
			return verr(ErrBadArity, path+".right", "у %s не должно быть ветви right", a.Kind)
		}
		return validateAction(a.Left, path+".left", depth+1, limits, totalNodes)
	case 2: // две ветви (Duplicate, Fragment)
		if a.Left == nil {
			return verr(ErrBadArity, path+".left", "у %s обязательна ветвь left", a.Kind)
		}
		if a.Right == nil {
			return verr(ErrBadArity, path+".right", "у %s обязательна ветвь right", a.Kind)
		}
		if err := validateAction(a.Left, path+".left", depth+1, limits, totalNodes); err != nil {
			return err
		}
		return validateAction(a.Right, path+".right", depth+1, limits, totalNodes)
	default:
		// Арность вне {0,1,2} означала бы рассогласование core.Arity и этого
		// обхода — ошибка разработки, а не ввода.
		return verr(ErrBadArity, path, "непредвиденная арность %d у %s", arity, a.Kind)
	}
}

// validateParams проверяет наличие/отсутствие и корректность параметров узла.
func validateParams(a *Action, path string, limits Limits) error {
	spec, ok := specFor(a.Kind)
	if !ok {
		return verr(ErrUnknownKind, path, "вид %d отсутствует в реестре", uint8(a.Kind))
	}
	needsParams := spec.newParams != nil
	switch {
	case needsParams && a.Params == nil:
		return verr(ErrMissingParams, path, "у %s обязательны параметры", a.Kind)
	case !needsParams && a.Params != nil:
		return verr(ErrParamsOnLeaf, path, "у %s не должно быть параметров", a.Kind)
	case needsParams:
		if err := a.Params.validate(limits); err != nil {
			return verr(ErrBadParams, path+".params", "%v", err)
		}
	}
	return nil
}
