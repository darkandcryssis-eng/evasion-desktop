package tlsparse

import "encoding/binary"

// Слой записей TLS (RFC 8446, раздел 5.1). Заголовок записи — 5 байт:
//
//	0      тип содержимого
//	1–2    версия слоя записей
//	3–4    длина тела записи
const (
	recordHeaderLen  = 5
	recordTypeOff    = 0
	recordVersionOff = 1
	recordLengthOff  = 3
)

// ContentType — тип содержимого записи TLS.
type ContentType uint8

// Типы содержимого, которые различает разбор.
const (
	// ContentHandshake — рукопожатие; единственный интересный движку тип.
	ContentHandshake ContentType = 22
	// ContentChangeCipherSpec, ContentAlert, ContentApplicationData
	// распознаются только чтобы отличить «не то сообщение» от «не TLS».
	ContentChangeCipherSpec ContentType = 20
	ContentAlert            ContentType = 21
	ContentApplicationData  ContentType = 23
)

// Границы версии слоя записей.
//
// В записи с ClientHello версия всегда остаётся 1.0–1.2 (0x0301–0x0303) даже у
// TLS 1.3: настоящая версия согласуется расширением supported_versions, а поле
// записи оставлено для совместимости с промежуточным оборудованием. Поэтому
// проверка диапазона здесь — это именно отбраковка «не TLS», а не определение
// версии протокола.
const (
	recordVersionMin = 0x0301
	recordVersionMax = 0x0303
	// maxRecordPayload — предел длины тела записи по стандарту: 2^14 байт
	// открытого текста плюс запас на расширение шифрованием. Запись, объявившая
	// больше, не может быть корректной.
	maxRecordPayload = 1 << 14
)

// Record — разобранный заголовок записи TLS: смещения в исходном буфере.
type Record struct {
	// Type — тип содержимого.
	Type ContentType
	// Version — версия из заголовка записи.
	Version uint16
	// PayloadOff, PayloadLen — смещение и длина тела записи.
	PayloadOff, PayloadLen int
}

// End возвращает смещение первого байта за записью.
func (r Record) End() int { return r.PayloadOff + r.PayloadLen }

// ParseRecord разбирает заголовок записи TLS в начале буфера.
//
// Проверка «похоже ли это на TLS» сделана до проверки полноты намеренно: иначе
// любой короткий мусор в начале соединения выглядел бы как «подождём ещё
// байт», и движок ждал бы вечно.
func ParseRecord(buf []byte) (Record, error) {
	var r Record
	if len(buf) < recordHeaderLen {
		// Байт мало, но тип содержимого проверить уже можно: если он
		// заведомо не TLS, ждать продолжения бессмысленно.
		if len(buf) >= 1 && !knownContentType(ContentType(buf[recordTypeOff])) {
			return r, ErrNotTLS
		}
		return r, ErrIncomplete
	}

	r.Type = ContentType(buf[recordTypeOff])
	if !knownContentType(r.Type) {
		return r, ErrNotTLS
	}
	r.Version = binary.BigEndian.Uint16(buf[recordVersionOff:])
	if r.Version < recordVersionMin || r.Version > recordVersionMax {
		return r, ErrNotTLS
	}

	length := int(binary.BigEndian.Uint16(buf[recordLengthOff:]))
	if length == 0 || length > maxRecordPayload {
		return r, ErrNotTLS
	}
	r.PayloadOff = recordHeaderLen
	r.PayloadLen = length

	if len(buf) < r.End() {
		// Структура корректна, не хватает только байт тела.
		return r, ErrIncomplete
	}
	return r, nil
}

// knownContentType сообщает, относится ли байт к известным типам содержимого
// TLS. Неизвестный тип — надёжный признак того, что соединение вообще не TLS
// (например, обычный HTTP).
func knownContentType(t ContentType) bool {
	switch t {
	case ContentChangeCipherSpec, ContentAlert, ContentHandshake, ContentApplicationData:
		return true
	default:
		return false
	}
}
