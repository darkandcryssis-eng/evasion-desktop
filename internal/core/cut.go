package core

import "fmt"

// CutKind — вид структурной точки разреза сообщения.
//
// Зачем нужен отдельный словарь вместо числового смещения. Положение значимых
// границ внутри ClientHello зависит от конкретного соединения: длина
// legacy_session_id, размер набора шифров и порядок расширений меняются от
// клиента к клиенту и от соединения к соединению. Поэтому число «разрезать на
// 130-м байте» для одного соединения попадает внутрь имени сервера, а для
// другого — в середину списка шифров.
//
// Для генетического поиска это смертельно: мутируя числа, генератор получал бы
// функцию приспособленности, в которой один и тот же ген означает разное.
// Вид точки разреза, напротив, устойчив — «внутри имени сервера» значит одно и
// то же всегда.
//
// Словарь живёт в core, а не в tlsparse, потому что на него ссылается strategy,
// которому про TLS знать нечего (4.1). Вычисляет же точки tlsparse — он один
// понимает структуру сообщения.
type CutKind uint8

const (
	// CutNone — точка разреза не задана: смещение указано числом.
	// Нулевое значение намеренно означает «не задано», чтобы отсутствие поля в
	// сериализованном описании читалось однозначно.
	CutNone CutKind = iota
	// CutRecordHeader — сразу после заголовка записи TLS, перед телом.
	CutRecordHeader
	// CutHandshakeHeader — после заголовка сообщения рукопожатия.
	CutHandshakeHeader
	// CutExtensions — в начале списка расширений.
	CutExtensions
	// CutBeforeSNI — непосредственно перед байтами имени сервера.
	CutBeforeSNI
	// CutInsideSNI — внутри имени сервера, разделяя его на части.
	CutInsideSNI
	// CutAfterSNI — сразу после имени сервера.
	CutAfterSNI
	// CutInsideSLD splits the label immediately before the top-level domain.
	CutInsideSLD
)

// cutKindTokens сопоставляет вид точки разреза с его текстовым обозначением.
//
// Таблица, а не switch, потому что обозначения нужны в три стороны: вывод,
// разбор и перечисление доступных видов для генератора (10.3).
var cutKindTokens = []struct {
	kind  CutKind
	token string
}{
	{CutRecordHeader, "record_header"},
	{CutHandshakeHeader, "handshake_header"},
	{CutExtensions, "extensions"},
	{CutBeforeSNI, "before_sni"},
	{CutInsideSNI, "inside_sni"},
	{CutAfterSNI, "after_sni"},
	{CutInsideSLD, "inside_sld"},
}

// Valid сообщает, что вид точки разреза задан и известен.
//
// CutNone признаётся недопустимым: это не вид разреза, а признак его
// отсутствия. Проверять «задано ли» нужно сравнением с CutNone, а не через
// Valid.
func (k CutKind) Valid() bool {
	for _, e := range cutKindTokens {
		if e.kind == k {
			return true
		}
	}
	return false
}

// String возвращает текстовое обозначение вида точки разреза.
func (k CutKind) String() string {
	if k == CutNone {
		return "none"
	}
	for _, e := range cutKindTokens {
		if e.kind == k {
			return e.token
		}
	}
	return fmt.Sprintf("CutKind(%d)", uint8(k))
}

// MarshalText сериализует вид точки разреза как обозначение.
//
// CutNone в сериализацию не попадает: поле помечено omitempty, и нулевое
// значение просто отсутствует в описании. Попытка записать его явно — признак
// ошибки вызывающего, поэтому возвращается ошибка, а не пустая строка.
func (k CutKind) MarshalText() ([]byte, error) {
	if !k.Valid() {
		return nil, fmt.Errorf("core: недопустимый вид точки разреза %d", uint8(k))
	}
	return []byte(k.String()), nil
}

// UnmarshalText разбирает обозначение вида точки разреза.
//
// Ввод недоверенный (конфиг, перенос стратегии с другой машины), поэтому
// неизвестное обозначение — ошибка, а не молчаливое CutNone: иначе опечатка в
// описании превратила бы структурный разрез в отсутствие разреза.
func (k *CutKind) UnmarshalText(text []byte) error {
	s := string(text)
	for _, e := range cutKindTokens {
		if e.token == s {
			*k = e.kind
			return nil
		}
	}
	return fmt.Errorf("core: неизвестный вид точки разреза %q", s)
}

// CutKinds возвращает все известные виды точек разреза.
//
// Нужно генератору как источник пространства поиска: добавление нового вида
// расширяет его автоматически, без правок генератора (10.3). CutNone в список
// не входит — это отсутствие разреза, а не его вид.
func CutKinds() []CutKind {
	out := make([]CutKind, 0, len(cutKindTokens))
	for _, e := range cutKindTokens {
		out = append(out, e.kind)
	}
	return out
}

// CutPoint — одна структурная точка разреза: вид и смещение в буфере события.
//
// Смещение абсолютное, от начала буфера разобранного сообщения. Перевод в
// смещение внутри разрезаемой части делает desync: при вложенных разрезах части
// начинаются не с нуля.
type CutPoint struct {
	Kind   CutKind
	Offset int
}
