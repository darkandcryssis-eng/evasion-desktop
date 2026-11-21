package vantage

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/fitting-1c/evasion/internal/core"
)

// idBytes — длина идентификатора точки наблюдения до перевода в
// шестнадцатеричную запись.
const idBytes = 8

// Label — метка точки наблюдения, задаваемая владельцем в конфиге.
//
// Основной способ определения (6.2 п. 1). Автоматически эти сведения получить
// нельзя, не обращаясь наружу, а внешний запрос по умолчанию запрещён, чтобы
// определение точки наблюдения само не стало утечкой (6.6).
//
// Обозначение намеренно грубое — оператор и регион, без адресов и
// идентификаторов машины: при выносе агрегатов на хост (6.6) наверх должно
// уходить ровно столько, сколько нужно для оценки стратегий.
type Label struct {
	// Operator — оператор связи.
	Operator string `json:"operator"`
	// Region — регион.
	Region string `json:"region"`
	// Access — тип доступа.
	Access core.AccessType `json:"access,omitempty"`
}

// normalized приводит метку к канонической форме, чтобы разные записи одной и
// той же метки давали один идентификатор.
func (l Label) normalized() Label {
	l.Operator = strings.ToLower(strings.TrimSpace(l.Operator))
	l.Region = strings.ToLower(strings.TrimSpace(l.Region))
	return l
}

// Vantage — определённая точка наблюдения.
type Vantage struct {
	// Label — метка из конфига.
	Label Label
	// Fingerprint — отпечаток локальных сетевых признаков. Служит для
	// обнаружения смены сети, а не для опознания оператора.
	Fingerprint string
	// ID — устойчивый идентификатор, часть ключа любого наблюдения.
	ID core.VantageID
}

// Detect определяет точку наблюдения по метке и локальным признакам.
//
// Ошибка перечисления интерфейсов не прерывает определение: метка из конфига
// остаётся в силе, а отпечаток становится пустым. Отказываться работать из-за
// недоступности подсказки неправильно — основной способ задания точки
// наблюдения от неё не зависит. Но пустой отпечаток означает, что смену сети
// обнаружить не удастся, и это обязано быть видно потребителю, поэтому
// возвращается вместе с ошибкой.
func Detect(label Label, src InterfaceSource) (Vantage, error) {
	v := Vantage{Label: label.normalized()}

	fp, err := Fingerprint(src)
	v.Fingerprint = fp
	v.ID = computeID(v.Label, fp)
	return v, err
}

// computeID выводит идентификатор точки наблюдения из метки и отпечатка.
//
// Отпечаток входит в идентификатор наряду с меткой, и это главное решение
// пакета. Следствие: при переезде в другую сеть с той же меткой идентификатор
// меняется, и оценки прежней сети к новой не применяются. Так и нужно — DPI
// там другой, а молча считать наблюдения общими значило бы портить оценки.
//
// Цена: при поднятии виртуального адаптера идентификатор тоже сменится, и
// накопленные наблюдения окажутся привязаны к прежнему значению. Это
// неприятно, но ошибка в безопасную сторону: лучше потерять часть истории, чем
// смешать наблюдения из разных условий.
func computeID(l Label, fingerprint string) core.VantageID {
	var b strings.Builder
	b.WriteString(l.Operator)
	b.WriteString("\x00")
	b.WriteString(l.Region)
	b.WriteString("\x00")
	b.WriteString(l.Access.String())
	b.WriteString("\x00")
	b.WriteString(fingerprint)

	sum := sha256.Sum256([]byte(b.String()))
	return core.VantageID(hex.EncodeToString(sum[:idBytes]))
}

// NetworkChanged сообщает, сменилась ли сеть между двумя определениями.
//
// Сравнивается только отпечаток, а не идентификатор: смена метки в конфиге —
// это решение владельца, а не событие в сети, и путать их нельзя. Пустой
// отпечаток с любой стороны означает «сказать нечего»: сменой сети это не
// считается, иначе недоступность подсказки выглядела бы как переезд.
func NetworkChanged(prev, cur Vantage) bool {
	if prev.Fingerprint == "" || cur.Fingerprint == "" {
		return false
	}
	return prev.Fingerprint != cur.Fingerprint
}

// Describe возвращает машинно-читаемое описание точки наблюдения.
//
// Отдаёт данные, а не готовую подпись: форматирование — забота потребителя
// (2.2). Поля названы так же, как в выводе CLI, чтобы интерфейсу не пришлось
// их переименовывать.
func (v Vantage) Describe() map[string]string {
	return map[string]string{
		"id":          v.ID.String(),
		"operator":    v.Label.Operator,
		"region":      v.Label.Region,
		"access":      v.Label.Access.String(),
		"fingerprint": v.Fingerprint,
	}
}
