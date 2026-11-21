package packet

import (
	"errors"
	"fmt"
)

// hopByHopMinLen — минимальный Hop-by-Hop: 8 байт (поле «следующий заголовок»,
// поле длины и область опций на 6 байт). Длина в поле Hdr Ext Len считается в
// 8-байтных блоках СВЕРХ первых восьми, поэтому значение 0 кодирует ровно эти
// 8 байт.
const hopByHopMinLen = 8

// InsertIPv6HopByHop возвращает НОВЫЙ пакет с добавленным заголовком расширения
// IPv6 Hop-by-Hop (минимальные 8 байт, заполнитель PadN) между фиксированным
// заголовком и остальной частью.
//
// Фиксированный заголовок начинает указывать на Hop-by-Hop (следующий заголовок
// = 0), а Hop-by-Hop указывает на прежний протокол. Длина нагрузки IPv6
// увеличивается на 8. Hop-by-Hop по RFC 8200 обязан быть ПЕРВЫМ заголовком
// расширения, поэтому вставляется сразу после фиксированных 40 байт.
//
// Контрольные суммы НЕ пересчитываются — это делает вызывающий после всех
// правок. Ошибка: пакет не IPv6 или усечён. Исходный буфер не изменяется.
func (d Dissection) InsertIPv6HopByHop(buf []byte) ([]byte, Dissection, error) {
	if d.Truncated {
		return nil, Dissection{}, errors.New("packet: вставка Hop-by-Hop в усечённый пакет")
	}
	if d.Version != Version6 {
		return nil, Dissection{}, errors.New("packet: Hop-by-Hop применим только к IPv6")
	}
	if len(buf) < ipv6HeaderLen {
		return nil, Dissection{}, ErrShortBuffer
	}

	oldNext := IPv6Header(buf[:ipv6HeaderLen]).NextHeader()

	// Hop-by-Hop: [следующий заголовок, Hdr Ext Len=0, опции...]. Опции — одна
	// PadN (тип 1, длина данных 4, 4 нулевых байта), чтобы добить до 8 байт.
	ext := []byte{byte(oldNext), 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00}
	if len(ext) != hopByHopMinLen {
		return nil, Dissection{}, errors.New("packet: неверная длина Hop-by-Hop")
	}

	out := make([]byte, len(buf)+len(ext))
	copy(out, buf[:ipv6HeaderLen])
	copy(out[ipv6HeaderLen:], ext)
	copy(out[ipv6HeaderLen+len(ext):], buf[ipv6HeaderLen:])

	nh := IPv6Header(out[:ipv6HeaderLen])
	nh.SetNextHeader(ProtoHopByHop)
	nh.SetPayloadLen(uint16(len(out) - ipv6HeaderLen))

	d2, err := Dissect(out)
	if err != nil {
		return nil, Dissection{}, fmt.Errorf("packet: разбор пакета после вставки Hop-by-Hop: %w", err)
	}
	return out, d2, nil
}
