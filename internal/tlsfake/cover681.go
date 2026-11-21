package tlsfake

import _ "embed"

// cover681 — встроенный 681-байтный TLS ClientHello, который используется
// приёмом ActionTCPOverlap как «прикрытие» (cover) настоящего ClientHello.
//
// Структура:
//
//	байты 0..4   — TLS Record Header (handshake, legacy_version)
//	байты 5..680 — тело handshake'а ClientHello
//
// Содержимое — валидный ClientHello со стандартным набором расширений и
// шифров из общеупотребительного браузерного образца. Это публично
// наблюдаемая форма протокола, не секретные данные.
//
// Зачем ровно 681 байт. Приём ActionTCPOverlap требует, чтобы фейковый pattern
// был КОРОЧЕ оригинальной нагрузки (M < L). 681 байт — компромисс: достаточно
// длинный, чтобы вмещать полный ClientHello с набором расширений, но
// достаточно короткий, чтобы оставаться меньше настоящего ClientHello Discord
// в 90% случаев (там около 700-900 байт из-за session_resumption ticket'ов и
// пользовательских расширений).
//
//go:embed tls_cover_681.bin
var cover681 []byte

// CoverClientHello681 возвращает КОПИЮ 681-байтного cover-ClientHello.
// Копия, не ссылка: приёмы десинка владеют своим буфером и могут его
// модифицировать (сейчас не модифицируют — это задел на будущее, например,
// случайную подстановку SNI генератором).
//
// Для присваивания в реестр пресетов (`PresetTLSCover681`) есть обёртка в
// пакете strategy — см. strategy/presets.go.
func CoverClientHello681() []byte {
	out := make([]byte, len(cover681))
	copy(out, cover681)
	return out
}

// CoverClientHello681Size возвращает размер cover-ClientHello в байтах.
// Эта константа нужна валидации стратегии: ActionTCPOverlap требует, чтобы
// pattern был короче оригинальной нагрузки (M < L); знание M на этапе
// валидации позволяет отбросить явно негодную стратегию ДО её применения.
//
// Для 681-байтного cover-ClientHello это 681.
func CoverClientHello681Size() int {
	return len(cover681)
}
