package strategy

import "fmt"

// FieldID — идентификатор поля заголовка или тела пакета.
//
// Один и тот же словарь полей используют и триггеры (условие срабатывания
// правила по значению поля), и примитив Tamper (какое поле править). Поэтому он
// вынесен в отдельный тип: добавление поля расширяет оба механизма сразу.
//
// Набор полей v1 охватывает хорошо определённые числовые поля заголовков IPv4,
// IPv6 и TCP плюс две однозначные опции TCP (MSS, масштаб окна) и подмену тела.
// Опции с не-числовой семантикой (SACK-permitted, timestamps) намеренно НЕ
// включены: их правка не сводится к одному целому, и половинчатая реализация
// исказила бы валидацию. Это осознанная цена ради честной проверки; поля можно
// добавить позже, не меняя generator (требование 10.3).
type FieldID uint8

const (
	// FieldNone — отсутствие поля (нулевое значение, для триггеров без
	// сопоставления поля).
	FieldNone FieldID = iota

	// --- IPv4 ---
	FieldIPv4TTL      // время жизни, 8 бит
	FieldIPv4ID       // идентификатор пакета, 16 бит
	FieldIPv4Flags    // флаги фрагментации (DF/MF), 3 бита
	FieldIPv4FragOff  // смещение фрагмента, 13 бит
	FieldIPv4TOS      // тип обслуживания / DSCP+ECN, 8 бит
	FieldIPv4Checksum // контрольная сумма заголовка, 16 бит

	// --- IPv6 ---
	FieldIPv6HopLimit     // предел переходов (аналог TTL), 8 бит
	FieldIPv6FlowLabel    // метка потока, 20 бит
	FieldIPv6TrafficClass // класс трафика, 8 бит

	// --- TCP ---
	FieldTCPSeq      // номер последовательности, 32 бита
	FieldTCPAck      // номер подтверждения, 32 бита
	FieldTCPFlags    // управляющие флаги (FIN..CWR), 8 бит
	FieldTCPWindow   // размер окна, 16 бит
	FieldTCPUrgent   // указатель срочности, 16 бит
	FieldTCPChecksum // контрольная сумма, 16 бит
	FieldTCPMSS      // опция максимального размера сегмента, 16 бит
	FieldTCPWScale   // опция масштаба окна, 8 бит

	// --- тело ---
	FieldPayload // полезная нагрузка (подмена фейковыми байтами)
)

// fieldInfo — метаданные одного поля. Это границы, вытекающие из протоколов,
// а не настраиваемые значения, поэтому им место в коде (требование 10.1).
type fieldInfo struct {
	text       string // токен для сериализации
	proto      string // протокол, которому принадлежит поле
	bitWidth   uint8  // ширина числового поля в битах; 0 для тела
	isChecksum bool   // поле контрольной суммы (влияет на возможности)
	isPayload  bool   // поле тела: правится длиной фейка, а не значением
}

// fieldTable — таблица метаданных всех известных полей. Порядок соответствует
// значениям FieldID, что позволяет индексировать напрямую.
var fieldTable = [...]fieldInfo{
	FieldNone: {text: "none", proto: ""},

	FieldIPv4TTL:      {text: "ipv4_ttl", proto: "ipv4", bitWidth: 8},
	FieldIPv4ID:       {text: "ipv4_id", proto: "ipv4", bitWidth: 16},
	FieldIPv4Flags:    {text: "ipv4_flags", proto: "ipv4", bitWidth: 3},
	FieldIPv4FragOff:  {text: "ipv4_frag_off", proto: "ipv4", bitWidth: 13},
	FieldIPv4TOS:      {text: "ipv4_tos", proto: "ipv4", bitWidth: 8},
	FieldIPv4Checksum: {text: "ipv4_checksum", proto: "ipv4", bitWidth: 16, isChecksum: true},

	FieldIPv6HopLimit:     {text: "ipv6_hop_limit", proto: "ipv6", bitWidth: 8},
	FieldIPv6FlowLabel:    {text: "ipv6_flow_label", proto: "ipv6", bitWidth: 20},
	FieldIPv6TrafficClass: {text: "ipv6_traffic_class", proto: "ipv6", bitWidth: 8},

	FieldTCPSeq:      {text: "tcp_seq", proto: "tcp", bitWidth: 32},
	FieldTCPAck:      {text: "tcp_ack", proto: "tcp", bitWidth: 32},
	FieldTCPFlags:    {text: "tcp_flags", proto: "tcp", bitWidth: 8},
	FieldTCPWindow:   {text: "tcp_window", proto: "tcp", bitWidth: 16},
	FieldTCPUrgent:   {text: "tcp_urgent", proto: "tcp", bitWidth: 16},
	FieldTCPChecksum: {text: "tcp_checksum", proto: "tcp", bitWidth: 16, isChecksum: true},
	FieldTCPMSS:      {text: "tcp_mss", proto: "tcp", bitWidth: 16},
	FieldTCPWScale:   {text: "tcp_wscale", proto: "tcp", bitWidth: 8},

	FieldPayload: {text: "payload", proto: "", isPayload: true},
}

// Fields возвращает все виды полей, пригодные для примитива Tamper, в
// детерминированном порядке (по возрастанию FieldID). FieldNone исключён — это
// признак отсутствия поля, а не поле.
//
// Это точка, из которой генератор узнаёт пространство полей (10.3): добавление
// поля в таблицу расширяет его автоматически, без правок генератора.
func Fields() []FieldID {
	out := make([]FieldID, 0, len(fieldTable))
	for id := range fieldTable {
		f := FieldID(id)
		if f == FieldNone {
			continue
		}
		if _, ok := f.info(); ok {
			out = append(out, f)
		}
	}
	return out
}

// IsPayload сообщает, что поле — это тело (правится длиной фейка, не значением).
// Нужно генератору, чтобы собрать валидные параметры Tamper: у тела иные
// правила, чем у числового поля.
func (f FieldID) IsPayload() bool {
	fi, ok := f.info()
	return ok && fi.isPayload
}

// IsIPv4 сообщает, что поле принадлежит заголовку IPv4. Нужно генератору,
// чтобы не править IPv4-поле на IPv6-трафике (там его нет), и наоборот.
func (f FieldID) IsIPv4() bool {
	fi, ok := f.info()
	return ok && fi.proto == "ipv4"
}

// IsIPv6 сообщает, что поле принадлежит заголовку IPv6.
func (f FieldID) IsIPv6() bool {
	fi, ok := f.info()
	return ok && fi.proto == "ipv6"
}

// IsChecksum сообщает, что поле — контрольная сумма: его правка требует
// возможности CapTamperChecksumCorrupt. Генератор по этому признаку не
// порождает правку суммы там, где исполнитель её не умеет (4.7).
func (f FieldID) IsChecksum() bool {
	fi, ok := f.info()
	return ok && fi.isChecksum
}

// IsTCPOption сообщает, что поле — это опция TCP (MSS, масштаб окна).
//
// Опции TCP согласуются только в сегментах SYN/SYN-ACK; в сегменте с данными
// (а ClientHello — это данные) их нет. Генератору это нужно, чтобы не править
// заведомо отсутствующее поле на ClientHello-пакете: такая правка неисполнима и
// лишь жжёт бюджет живых проб.
func (f FieldID) IsTCPOption() bool {
	return f == FieldTCPMSS || f == FieldTCPWScale
}

// MaxValue возвращает наибольшее числовое значение поля по его ширине;
// для тела и неизвестных полей — (0, false). Экспортная обёртка над внутренним
// расчётом: генератору нужна граница, чтобы константа замены умещалась в поле.
func (f FieldID) MaxValue() (uint64, bool) { return f.maxValue() }

// info возвращает метаданные поля и признак того, что поле известно.
func (f FieldID) info() (fieldInfo, bool) {
	if int(f) < 0 || int(f) >= len(fieldTable) {
		return fieldInfo{}, false
	}
	fi := fieldTable[f]
	// Пустой text означает дырку в таблице (не инициализированный элемент).
	if fi.text == "" {
		return fieldInfo{}, false
	}
	return fi, true
}

// maxValue возвращает наибольшее допустимое числовое значение поля, исходя из
// его ширины. Для поля тела и неизвестных полей возвращает 0 и false.
func (f FieldID) maxValue() (uint64, bool) {
	fi, ok := f.info()
	if !ok || fi.isPayload || fi.bitWidth == 0 {
		return 0, false
	}
	// Для ширины w наибольшее значение — это 2^w - 1. Сдвиг делаем в uint64;
	// при w == 64 сдвиг был бы некорректен, но таких полей здесь нет (максимум
	// 32 бита), поэтому формула безопасна.
	return (uint64(1) << fi.bitWidth) - 1, true
}

// String возвращает текстовый токен поля.
func (f FieldID) String() string {
	if fi, ok := f.info(); ok {
		return fi.text
	}
	return fmt.Sprintf("FieldID(%d)", uint8(f))
}

// MarshalText сериализует поле как строковый токен.
func (f FieldID) MarshalText() ([]byte, error) {
	if _, ok := f.info(); !ok {
		return nil, fmt.Errorf("strategy: недопустимое поле %d", uint8(f))
	}
	return []byte(f.String()), nil
}

// UnmarshalText разбирает токен поля. Неизвестный токен — ошибка (недоверенный
// ввод).
func (f *FieldID) UnmarshalText(text []byte) error {
	want := string(text)
	for id := range fieldTable {
		if fieldTable[id].text == want && want != "" {
			*f = FieldID(id)
			return nil
		}
	}
	return fmt.Errorf("strategy: неизвестное поле %q", want)
}
