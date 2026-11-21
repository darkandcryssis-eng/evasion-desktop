package packet

import "errors"

// Ошибки разбора. Все они означают «ввод не соответствует протоколу» и
// рассчитаны на сравнение через errors.Is: вызывающий код (десинк, телеметрия)
// различает причины, чтобы отличать усечённый пакет от заведомо битого.
var (
	// ErrShortBuffer — буфер короче, чем требует уже разобранная часть
	// заголовка.
	ErrShortBuffer = errors.New("packet: буфер короче заголовка")
	// ErrBadVersion — в первых четырёх битах не 4 и не 6.
	ErrBadVersion = errors.New("packet: неизвестная версия IP")
	// ErrBadHeaderLen — длина заголовка вне допустимого диапазона или
	// противоречит общей длине пакета.
	ErrBadHeaderLen = errors.New("packet: недопустимая длина заголовка")
	// ErrExtChainTooLong — цепочка заголовков расширения IPv6 длиннее
	// разумного предела. Защита от зацикливания на враждебном вводе.
	ErrExtChainTooLong = errors.New("packet: слишком длинная цепочка расширений IPv6")
	// ErrBadOption — опция TCP объявляет длину, не умещающуюся в поле опций.
	ErrBadOption = errors.New("packet: некорректная опция TCP")
	// ErrOptionNotFound — запрошенная опция в заголовке отсутствует.
	ErrOptionNotFound = errors.New("packet: опция не найдена")
	// ErrOptionSize — найденная опция имеет неожиданную длину, и её значение
	// нельзя прочитать как число.
	ErrOptionSize = errors.New("packet: неожиданная длина опции")
)
