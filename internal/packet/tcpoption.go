package packet

import (
	"errors"
	"fmt"
)

// Вставка опций в заголовок TCP уже собранного пакета.
//
// В отличие от правок полей (access.go правит на месте, длина не меняется),
// добавление опции РАСШИРЯЕТ заголовок: растёт смещение данных TCP и общая
// длина сетевого слоя, нагрузка сдвигается. Поэтому операция строит новый
// буфер, а не правит исходный.

// tcpOptMD5Len — длина опции MD5 Signature (RFC 2385): вид (1) + длина (1) +
// 16 байт дайджеста.
const tcpOptMD5Len = 18

// MD5SignatureOption собирает байты опции TCP MD5 Signature с заданным
// 16-байтным дайджестом (вид 19, длина 18). Возвращает ровно 18 байт без
// выравнивания — дополнение до кратности 4 добавит InsertTCPOption.
//
// Подпись здесь не вычисляется: приём md5sig намеренно шлёт НЕВЕРНУЮ подпись
// (сервер её отбросит, DPI обычно не проверяет), поэтому дайджест задаёт
// вызывающий произвольными байтами.
func MD5SignatureOption(digest [16]byte) []byte {
	out := make([]byte, tcpOptMD5Len)
	out[0] = TCPOptMD5
	out[1] = tcpOptMD5Len
	copy(out[2:], digest[:])
	return out
}

// InsertTCPOption возвращает НОВЫЙ пакет с добавленными в область опций TCP
// байтами opt (после существующего заголовка, перед нагрузкой).
//
// opt — сырые байты одной или нескольких опций (вид, длина, значение).
// Дополняются заполнителями NOP (вид 1) до кратности 4, т.к. смещение данных
// TCP считается в 32-битных словах. Обновляются смещение данных TCP и длина
// сетевого слоя (общая длина IPv4 / длина нагрузки IPv6). Контрольные суммы
// НЕ пересчитываются — это делает вызывающий после всех правок
// (RecomputeChecksums), чтобы порядок «правки до пересчёта, порча суммы после»
// оставался в одних руках.
//
// Ошибка: пакет не TCP, усечён, или новый заголовок превышает предел смещения
// данных (60 байт). Исходный буфер не изменяется.
func (d Dissection) InsertTCPOption(buf, opt []byte) ([]byte, Dissection, error) {
	if d.Truncated {
		return nil, Dissection{}, errors.New("packet: вставка опции TCP в усечённый пакет")
	}
	if d.Protocol != ProtoTCP || d.L4Off == 0 || d.L4Len < tcpMinHeaderLen {
		return nil, Dissection{}, errors.New("packet: вставка опции TCP не в TCP-пакет")
	}
	hdrEnd := d.L4Off + d.L4Len
	if hdrEnd > len(buf) {
		return nil, Dissection{}, ErrShortBuffer
	}

	// Выравнивание до кратности 4 заполнителями NOP: смещение данных задаётся
	// в 32-битных словах, поэтому длина заголовка обязана быть кратна 4.
	pad := (4 - len(opt)%4) % 4
	padded := make([]byte, len(opt)+pad)
	copy(padded, opt)
	for i := len(opt); i < len(padded); i++ {
		padded[i] = TCPOptNop
	}

	newL4Len := d.L4Len + len(padded)
	if newL4Len > tcpMaxHeaderLen {
		return nil, Dissection{}, ErrBadHeaderLen
	}

	out := make([]byte, len(buf)+len(padded))
	copy(out, buf[:hdrEnd])                      // L3 + текущий заголовок TCP
	copy(out[hdrEnd:], padded)                   // новые опции
	copy(out[hdrEnd+len(padded):], buf[hdrEnd:]) // нагрузка

	// Смещение данных TCP — по новой длине заголовка.
	TCPHeader(out[d.L4Off : d.L4Off+newL4Len]).SetDataOffset(newL4Len)

	// Длина сетевого слоя выросла на размер вставки.
	switch d.Version {
	case Version4:
		IPv4Header(out[:d.L3Len]).SetTotalLen(uint16(len(out)))
	case Version6:
		IPv6Header(out[:ipv6HeaderLen]).SetPayloadLen(uint16(len(out) - ipv6HeaderLen))
	}

	d2, err := Dissect(out)
	if err != nil {
		return nil, Dissection{}, fmt.Errorf("packet: разбор пакета после вставки опции TCP: %w", err)
	}
	return out, d2, nil
}
