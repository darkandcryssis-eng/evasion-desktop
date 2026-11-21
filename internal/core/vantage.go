package core

// VantageID — устойчивый идентификатор точки наблюдения.
//
// Выводится из её признаков (см. пакет vantage) и служит частью ключа любого
// наблюдения. Это не удобство, а требование: оценка стратегии не является её
// свойством, она свойство четвёрки «стратегия × цель × точка наблюдения ×
// время» (6.1). Поведение DPI существенно различается между операторами и
// регионами, поэтому вопрос «работает ли стратегия X» без указания, у кого
// именно, ответа не имеет.
//
// Тип живёт в core, а не в vantage, потому что на него ссылаются store и
// scoring, которым незачем знать, как точка наблюдения определяется.
type VantageID string

// String возвращает идентификатор как строку.
func (id VantageID) String() string { return string(id) }

// AccessType — тип доступа в сеть.
//
// Входит в признаки точки наблюдения, потому что мобильные и проводные сети
// часто фильтруются по-разному даже у одного оператора. Определяется не
// автоматически, а меткой из конфига: надёжного способа отличить мобильный
// доступ от проводного локальными средствами нет, а догадка здесь испортила бы
// ключ наблюдений.
type AccessType uint8

const (
	// AccessUnknown — тип доступа не указан.
	AccessUnknown AccessType = iota
	// AccessWired — проводной доступ (включая Wi-Fi домашнего провайдера).
	AccessWired
	// AccessMobile — мобильный доступ.
	AccessMobile
)

// accessTypeTokens сопоставляет тип доступа с текстовым обозначением.
var accessTypeTokens = []struct {
	access AccessType
	token  string
}{
	{AccessUnknown, "unknown"},
	{AccessWired, "wired"},
	{AccessMobile, "mobile"},
}

// String возвращает обозначение типа доступа.
func (a AccessType) String() string {
	for _, e := range accessTypeTokens {
		if e.access == a {
			return e.token
		}
	}
	return "unknown"
}

// MarshalText сериализует тип доступа.
func (a AccessType) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText разбирает обозначение типа доступа.
//
// Пустая строка допустима и означает «не указан»: тип доступа — необязательная
// часть метки, и требовать его от владельца конфига незачем.
func (a *AccessType) UnmarshalText(text []byte) error {
	s := string(text)
	if s == "" {
		*a = AccessUnknown
		return nil
	}
	for _, e := range accessTypeTokens {
		if e.token == s {
			*a = e.access
			return nil
		}
	}
	return &UnknownTokenError{Kind: "тип доступа", Token: s}
}

// UnknownTokenError — неизвестное текстовое обозначение в недоверенном вводе.
//
// Отдельный тип, чтобы потребитель мог отличить опечатку в конфиге от иных
// ошибок разбора и указать на неё внятно.
type UnknownTokenError struct {
	// Kind — что именно разбиралось.
	Kind string
	// Token — само непонятое обозначение.
	Token string
}

// Error возвращает описание ошибки.
func (e *UnknownTokenError) Error() string {
	return "core: неизвестное обозначение " + e.Kind + ": " + e.Token
}
