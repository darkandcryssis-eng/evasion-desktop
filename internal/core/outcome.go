package core

import "fmt"

// Словарь исходов наблюдения.
//
// Живёт в core, а не в probe, потому что это словарь всего контура управления:
// scoring взвешивает исходы, store их хранит, control по ним решает. Если бы
// словарь лежал в probe, всем этим пакетам пришлось бы импортировать машинерию
// проб, которая им не нужна (4.1).

// Outcome — исход пробы.
//
// Значения намеренно градуированы, а не двоичны: замедление — это не то же
// самое, что обрыв, и взвешиваются они по-разному (5.7). Нулевым значением
// сделано «не определено», чтобы незаполненный результат не выглядел успехом.
type Outcome uint8

const (
	// OutcomeInconclusive — измерению нельзя доверять: стратегия не
	// проверялась либо условия не позволяют судить. Вес такого наблюдения
	// равен нулю.
	OutcomeInconclusive Outcome = iota
	// OutcomeOK — рукопожатие прошло (быстрый уровень) либо полоса в норме
	// (медленный уровень).
	OutcomeOK
	// OutcomeThrottled — соединение работает, но полоса заметно ниже порога.
	// Различается только на медленном уровне.
	OutcomeThrottled
	// OutcomeFail — соединение сорвано: сброс, зависание до таймаута.
	OutcomeFail
)

// outcomeTokens сопоставляет исход с текстовым обозначением.
var outcomeTokens = []struct {
	outcome Outcome
	token   string
}{
	{OutcomeInconclusive, "inconclusive"},
	{OutcomeOK, "ok"},
	{OutcomeThrottled, "throttled"},
	{OutcomeFail, "fail"},
}

// String возвращает обозначение исхода.
func (o Outcome) String() string {
	for _, e := range outcomeTokens {
		if e.outcome == o {
			return e.token
		}
	}
	return fmt.Sprintf("Outcome(%d)", uint8(o))
}

// MarshalText сериализует исход.
func (o Outcome) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

// UnmarshalText разбирает обозначение исхода.
func (o *Outcome) UnmarshalText(text []byte) error {
	for _, e := range outcomeTokens {
		if e.token == string(text) {
			*o = e.outcome
			return nil
		}
	}
	return &UnknownTokenError{Kind: "исход пробы", Token: string(text)}
}

// Phase — уровень оценки, на котором получен исход.
type Phase uint8

const (
	// PhaseFast — быстрый уровень: только рукопожатие.
	PhaseFast Phase = iota
	// PhaseSlow — медленный уровень: форма полосы за окно.
	PhaseSlow
)

// String возвращает обозначение уровня.
func (p Phase) String() string {
	switch p {
	case PhaseFast:
		return "fast"
	case PhaseSlow:
		return "slow"
	default:
		return fmt.Sprintf("Phase(%d)", uint8(p))
	}
}

// MarshalText сериализует уровень оценки.
func (p Phase) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// UnmarshalText разбирает обозначение уровня оценки.
//
// Нужен чтению наблюдений из архива (тёплый старт): уровень хранится текстом,
// как и прочие перечисления. Неизвестное имя — ошибка, а не молчаливый
// PhaseFast: запись, сделанную другой версией кода, надо читать осознанно, а не
// отнести к быстрому уровню догадкой (то же решение, что у Outcome и Status).
func (p *Phase) UnmarshalText(text []byte) error {
	switch string(text) {
	case "fast":
		*p = PhaseFast
	case "slow":
		*p = PhaseSlow
	default:
		return &UnknownTokenError{Kind: "уровень оценки", Token: string(text)}
	}
	return nil
}

// Reason — машинно-читаемая причина исхода.
//
// Строка, а не свободный текст ошибки: по причине принимаются решения
// (эскалация требуемого объёма наблюдений при высокой доле «не определено»,
// 5.5), поэтому она обязана быть сопоставимой между прогонами. Подробности
// ошибки идут отдельным полем и только в журнал.
type Reason string

// Причины исходов. Перечень закрытый: добавление причины — осознанное
// изменение, а не побочный эффект правки кода.
const (
	// ReasonHandshakeDone — рукопожатие TLS завершено.
	ReasonHandshakeDone Reason = "handshake_done"
	// ReasonReset — соединение сброшено.
	ReasonReset Reason = "reset"
	// ReasonTimeout — ответа не было до истечения срока.
	ReasonTimeout Reason = "timeout"
	// ReasonTLSRejected — сервер ответил на уровне TLS, но отказал. Значит до
	// сервера мы дошли, и это не вердикт о DPI.
	ReasonTLSRejected Reason = "tls_rejected"
	// ReasonResolveFailed — имя не разрешилось: стратегия не проверялась.
	ReasonResolveFailed Reason = "resolve_failed"
	// ReasonConnectFailed — соединение не установилось: стратегия не
	// проверялась.
	ReasonConnectFailed Reason = "connect_failed"
	// ReasonStrategyNotApplied — стратегию не удалось применить (непосильный
	// примитив, недоступная точка разреза). Про цензора это ничего не говорит.
	ReasonStrategyNotApplied Reason = "strategy_not_applied"
	// ReasonThroughputLow — полоса ниже порога.
	ReasonThroughputLow Reason = "throughput_low"
	// ReasonCanceled — проба прервана извне.
	ReasonCanceled Reason = "canceled"
	// ReasonLocalError — местная ошибка (нехватка дескрипторов, сбой записи).
	ReasonLocalError Reason = "local_error"
)
