package tlsparse

import "encoding/binary"

// cursor — курсор чтения по буферу с проверкой границ.
//
// Зачем нужен: в разборе TLS почти каждое поле — это «прочитать длину, затем
// прочитать столько байт». Писать проверку границ при каждом обращении вручную
// означало бы десятки однотипных сравнений, в которых легко пропустить одно —
// и получить выход за границу на враждебном вводе. Курсор сводит проверку к
// одному месту.
//
// Тип значимый и не выделяет памяти: поля — срез и целое, методы работают с
// копией структуры через указатель на локальную переменную.
type cursor struct {
	buf []byte
	// pos — смещение следующего непрочитанного байта от начала buf.
	pos int
}

// remaining возвращает число непрочитанных байт.
func (c *cursor) remaining() int { return len(c.buf) - c.pos }

// skip продвигает курсор на n байт. Возвращает false, если байт не хватает.
func (c *cursor) skip(n int) bool {
	if n < 0 || c.remaining() < n {
		return false
	}
	c.pos += n
	return true
}

// u8 читает один байт.
func (c *cursor) u8() (uint8, bool) {
	if c.remaining() < 1 {
		return 0, false
	}
	v := c.buf[c.pos]
	c.pos++
	return v, true
}

// u16 читает двухбайтное значение в сетевом порядке байт.
func (c *cursor) u16() (uint16, bool) {
	if c.remaining() < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(c.buf[c.pos:])
	c.pos += 2
	return v, true
}

// u24 читает трёхбайтное значение в сетевом порядке байт.
//
// Трёхбайтные длины встречаются в заголовке сообщения рукопожатия TLS; в
// стандартной библиотеке функции для них нет, поэтому собираем вручную:
// старший байт сдвигается на 16 разрядов, средний на 8.
func (c *cursor) u24() (uint32, bool) {
	if c.remaining() < 3 {
		return 0, false
	}
	v := uint32(c.buf[c.pos])<<16 | uint32(c.buf[c.pos+1])<<8 | uint32(c.buf[c.pos+2])
	c.pos += 3
	return v, true
}

// bytes читает n байт и возвращает их как представление исходного буфера
// (без копирования).
func (c *cursor) bytes(n int) ([]byte, bool) {
	if n < 0 || c.remaining() < n {
		return nil, false
	}
	b := c.buf[c.pos : c.pos+n]
	c.pos += n
	return b, true
}

// sub возвращает курсор по следующим n байтам, продвигая исходный курсор.
//
// Нужен для вложенных структур с объявленной длиной: внутренний разбор не
// должен иметь возможности выйти за пределы своего участка, даже если
// объявленные внутри длины врут.
func (c *cursor) sub(n int) (cursor, bool) {
	b, ok := c.bytes(n)
	if !ok {
		return cursor{}, false
	}
	return cursor{buf: b}, true
}
