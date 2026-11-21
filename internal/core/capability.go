package core

import (
	"fmt"
	"sort"
	"strings"
)

// Capability — одна механическая возможность исполнителя: конкретный приём
// манипуляции пакетами, который реализация либо умеет, либо нет.
//
// Возможности описывают механику, а не намерение. Деление проходит ровно по
// границе двух этапов поставки: в пользовательском пространстве (socketexec,
// этап 0) нет контроля над отдельными сегментами TCP, поэтому часть приёмов там
// невыразима и соответствующие возможности не объявляются. Пакетный исполнитель
// (packetexec, этап 1) объявит их все.
//
// Словарь возможностей задаётся здесь целиком и заранее, чтобы при переходе на
// этап 1 не пришлось менять пакеты strategy и generator (требование 4.7 п. 4):
// переход лишь расширяет множество, которое объявляет исполнитель, но не вводит
// новых токенов.
type Capability uint32

const (
	// CapDrop — умение отбрасывать пакеты (лист Drop).
	CapDrop Capability = 1 << iota
	// CapTamper — умение править поля заголовка или тело с корректным
	// пересчётом контрольной суммы.
	CapTamper
	// CapTamperChecksumCorrupt — умение намеренно выставить неверную
	// контрольную сумму. Требует контроля над пакетами, в пользовательском
	// пространстве недоступно (1.5.1).
	CapTamperChecksumCorrupt
	// CapDuplicate — умение дублировать пакет в обе ветви дерева.
	CapDuplicate
	// CapFragmentTCP — умение разрезать поток на границе сегментов TCP.
	CapFragmentTCP
	// CapFragmentIP — умение фрагментировать на уровне IP. Требует контроля
	// над пакетами, в пользовательском пространстве недоступно.
	CapFragmentIP
	// CapReorder — умение отправлять части в порядке, отличном от
	// естественного (например, вторую часть раньше первой). Разупорядоченные
	// сегменты требуют контроля над пакетами (1.5.1).
	CapReorder
	// CapDelay — умение выдержать паузу между отправками.
	//
	// Доступно в обоих субстратах: пауза перед записью в сокет выражается так
	// же легко, как перед вбросом пакета. Отдельная возможность нужна не ради
	// ограничения, а ради честности объявления: исполнитель, который паузу
	// проигнорирует, обязан заявить её отсутствие, иначе стратегия будет
	// оценена как нерабочая, хотя исполнялась не так, как описана (4.7 п. 2).
	CapDelay
	// CapTCPOverlap — умение отправлять два TCP-сегмента с перекрытием по seq
	// (ActionTCPOverlap). Требует явного контроля над TCP sequence number
	// отдельных сегментов: сокетный исполнитель это сделать не может (ОС
	// назначает seq сама по порядку записи), поэтому возможность доступна
	// только у пакетного исполнителя.
	CapTCPOverlap
	// CapMD5Sig — умение вставить в сегмент опцию TCP MD5 Signature (RFC 2385,
	// вид 19) с заведомо неверной подписью (ActionMD5Sig). Вставка опции двигает
	// смещение данных TCP и требует перестройки пакета — в пользовательском
	// пространстве (socketexec) недоступно, объявляет только пакетный
	// исполнитель.
	CapMD5Sig
	// CapIPv6ExtHeader — умение вставить заголовок расширения IPv6 Hop-by-Hop
	// в фейк (ActionIPv6Ext). Расширяет сетевой слой и двигает нагрузку —
	// требует контроля над пакетом, объявляет только пакетный исполнитель.
	CapIPv6ExtHeader
)

// allCapabilities перечисляет все известные возможности в порядке их битов.
// Используется для разбора/печати множеств. Держать в одном месте, чтобы при
// добавлении возможности не забыть обновить сериализацию.
var allCapabilities = []struct {
	cap  Capability
	text string
}{
	{CapDrop, "drop"},
	{CapTamper, "tamper"},
	{CapTamperChecksumCorrupt, "tamper_checksum_corrupt"},
	{CapDuplicate, "duplicate"},
	{CapFragmentTCP, "fragment_tcp"},
	{CapFragmentIP, "fragment_ip"},
	{CapReorder, "reorder"},
	{CapDelay, "delay"},
	{CapTCPOverlap, "tcp_overlap"},
	{CapMD5Sig, "md5sig"},
	{CapIPv6ExtHeader, "ipv6_ext_header"},
}

// String возвращает текстовый токен одной возможности.
func (c Capability) String() string {
	for _, e := range allCapabilities {
		if e.cap == c {
			return e.text
		}
	}
	return fmt.Sprintf("Capability(0x%x)", uint32(c))
}

// PrimitiveSet — множество возможностей (битовая маска).
//
// В роли множества требуемых возможностей его вычисляет strategy, обходя дерево;
// в роли множества доступных возможностей его объявляет Executor. Соединяет их
// проверка Contains: стратегия исполнима, если требуемое — подмножество
// доступного.
type PrimitiveSet uint32

// Has сообщает, входит ли одиночная возможность во множество.
func (s PrimitiveSet) Has(c Capability) bool {
	return uint32(s)&uint32(c) != 0
}

// With возвращает множество с добавленной возможностью. Исходное не меняется:
// тип значимый, что исключает случайный общий доступ из разных горутин.
func (s PrimitiveSet) With(c Capability) PrimitiveSet {
	return s | PrimitiveSet(c)
}

// Union возвращает объединение двух множеств.
func (s PrimitiveSet) Union(other PrimitiveSet) PrimitiveSet {
	return s | other
}

// Contains сообщает, является ли other подмножеством s. Это и есть проверка
// исполнимости: Capabilities().Contains(RequiredCapabilities(strategy)).
func (s PrimitiveSet) Contains(other PrimitiveSet) bool {
	return s&other == other
}

// Missing возвращает возможности из required, которых нет в s. Пустое множество
// означает, что s покрывает required. Нужно, чтобы отказ исполнителя называл
// недостающие возможности, а не просто «не умею» (требование 4.7 п. 2).
func (s PrimitiveSet) Missing(required PrimitiveSet) PrimitiveSet {
	return required &^ s
}

// Capabilities раскладывает множество в срез отдельных возможностей в
// стабильном порядке битов. Нужно для машинно-читаемого вывода (doctor/status).
func (s PrimitiveSet) Capabilities() []Capability {
	out := make([]Capability, 0, len(allCapabilities))
	for _, e := range allCapabilities {
		if s.Has(e.cap) {
			out = append(out, e.cap)
		}
	}
	return out
}

// MarshalText сериализует множество как список токенов через запятую в
// стабильном порядке.
func (s PrimitiveSet) MarshalText() ([]byte, error) {
	caps := s.Capabilities()
	tokens := make([]string, len(caps))
	for i, c := range caps {
		tokens[i] = c.String()
	}
	return []byte(strings.Join(tokens, ",")), nil
}

// UnmarshalText разбирает список токенов возможностей через запятую. Токены
// недоверенны: неизвестный токен — ошибка.
func (s *PrimitiveSet) UnmarshalText(text []byte) error {
	var set PrimitiveSet
	raw := strings.TrimSpace(string(text))
	if raw == "" {
		*s = 0
		return nil
	}
	// Разбор без учёта порядка; дубликаты безвредны (операция идемпотентна).
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.TrimSpace(tok)
		found := false
		for _, e := range allCapabilities {
			if e.text == tok {
				set = set.With(e.cap)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("core: неизвестная возможность %q (допустимы: %s)",
				tok, strings.Join(sortedCapabilityTokens(), ", "))
		}
	}
	*s = set
	return nil
}

// sortedCapabilityTokens возвращает отсортированный список всех известных
// токенов. Используется в сообщениях об ошибках, чтобы подсказать допустимые
// значения. Вынесено, чтобы не дублировать сортировку.
func sortedCapabilityTokens() []string {
	tokens := make([]string, len(allCapabilities))
	for i, e := range allCapabilities {
		tokens[i] = e.text
	}
	sort.Strings(tokens)
	return tokens
}
