package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"sort"

	"github.com/fitting-1c/evasion/internal/tlsparse"
)

// Константы расшифровки клиентского Initial QUIC v1 (RFC 9001, раздел 5).
var (
	// initialSalt — фиксированная соль QUIC v1 для вывода начальных секретов
	// (RFC 9001, раздел 5.2). Публичная: начальная защита скрывает не
	// содержимое, а служит целостности и развязке версий, поэтому прочитать
	// Initial может любой на пути.
	initialSalt = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
)

const (
	// quicVersion1 — номер версии QUIC v1 (RFC 9000). Другие версии выводят
	// ключи иначе; их не трогаем и честно отказываемся.
	quicVersion1 = 0x00000001
	// maxCIDLen — предел длины Connection ID в QUIC v1 (RFC 9000, 17.2).
	maxCIDLen = 20
	// sampleLen — длина выборки для снятия защиты заголовка (RFC 9001, 5.4.2).
	sampleLen = 16
	// sampleSkip — отступ выборки от начала поля номера пакета: номер считается
	// максимально длинным (4 байта), и выборка берётся сразу за ним.
	sampleSkip = 4
	// aeadTagLen — длина тега AEAD (AES-128-GCM).
	aeadTagLen = 16

	// Типы кадров QUIC, которые встречаются в Initial (RFC 9000, раздел 19).
	framePadding      = 0x00
	framePing         = 0x01
	frameACK          = 0x02
	frameACKECN       = 0x03
	frameCrypto       = 0x06
	frameConnClose    = 0x1c
	frameConnCloseApp = 0x1d
)

// ExtractSNI вытаскивает SNI из клиентского QUIC-пакета Initial.
//
// datagram — полезная нагрузка UDP (одна датаграмма). Возвращает имя сервера и
// true, только если это разборный клиентский Initial QUIC v1, его начальная
// защита снята, а в собранном из CRYPTO-кадров ClientHello есть server_name.
// Во всех прочих случаях — ("", false): это «не знаю», по которому вызывающий
// обязан НЕ блокировать (переблокировать вслепую опаснее пропуска, 1.6).
//
// Буфер datagram не изменяется: снятие защиты заголовка и номер пакета считаются
// на копиях. Это живой пакет — его, возможно, ещё пропускать в сеть.
func ExtractSNI(datagram []byte) (string, bool) {
	hdr, ok := parseInitialHeader(datagram)
	if !ok {
		return "", false
	}

	key, iv, hp, ok := deriveClientKeys(hdr.dcid)
	if !ok {
		return "", false
	}

	plaintext, _, ok := unprotect(datagram, hdr, key, iv, hp)
	if !ok {
		return "", false
	}

	hello, ok := reassembleCrypto(plaintext)
	if !ok {
		return "", false
	}

	ch, err := tlsparse.ParseClientHelloMessage(hello)
	if err != nil {
		return "", false
	}
	sni, ok := ch.SNI(hello)
	if !ok {
		return "", false
	}
	return string(sni), true
}

// initialHeader — разобранный открытый заголовок клиентского Initial.
type initialHeader struct {
	dcid []byte
	// scid — Source Connection ID клиента. Сохраняется, чтобы при пересборке
	// Initial (десинк) отдать его без изменений; ключи от него не зависят.
	scid []byte
	// token — токен из заголовка (обычно пуст в первом полёте). Тоже
	// сохраняется для верной пересборки.
	token []byte
	// pnOffset — смещение поля номера пакета (оно же начало защищённой части).
	pnOffset int
	// length — объявленная длина «номер пакета + защищённая нагрузка».
	length int
}

// parseInitialHeader разбирает открытую часть заголовка клиентского Initial
// QUIC v1 (RFC 9000, 17.2 и 17.2.2). Возвращает false на всём, что не является
// таким пакетом: короткий заголовок, не v1, порча длин.
func parseInitialHeader(b []byte) (initialHeader, bool) {
	var h initialHeader
	// Нужны хотя бы первый байт, версия (4) и две длины CID (по 1).
	if len(b) < 7 {
		return h, false
	}
	first := b[0]
	// Длинный заголовок: старший бит 1. Фиксированный бит обязан быть 1.
	if first&0x80 == 0 || first&0x40 == 0 {
		return h, false
	}
	// Тип пакета в битах 5–4; Initial == 00.
	if (first&0x30)>>4 != 0 {
		return h, false
	}
	if binary.BigEndian.Uint32(b[1:5]) != quicVersion1 {
		return h, false
	}
	off := 5
	dcidLen := int(b[off])
	off++
	if dcidLen > maxCIDLen || off+dcidLen > len(b) {
		return h, false
	}
	h.dcid = b[off : off+dcidLen]
	off += dcidLen
	if off >= len(b) {
		return h, false
	}
	scidLen := int(b[off])
	off++
	if scidLen > maxCIDLen || off+scidLen > len(b) {
		return h, false
	}
	h.scid = b[off : off+scidLen]
	off += scidLen
	// Token Length (varint) и сам токен — в клиентском Initial обычно пустой.
	tokLen, n, ok := readVarint(b[off:])
	if !ok {
		return h, false
	}
	off += n
	if uint64(off)+tokLen > uint64(len(b)) {
		return h, false
	}
	h.token = b[off : off+int(tokLen)]
	off += int(tokLen)
	// Length (varint): длина «номер пакета + нагрузка».
	length, n, ok := readVarint(b[off:])
	if !ok {
		return h, false
	}
	off += n
	h.pnOffset = off
	h.length = int(length)
	// Защищённая часть обязана целиком лежать в датаграмме: AEAD проверяет весь
	// тег, по обрезку расшифровать нельзя.
	if h.pnOffset+h.length > len(b) || h.length < sampleSkip+sampleLen {
		return h, false
	}
	return h, true
}

// deriveClientKeys выводит ключ, IV и ключ защиты заголовка клиента из DCID
// (RFC 9001, 5.2). AEAD клиентского Initial — всегда AES-128-GCM.
func deriveClientKeys(dcid []byte) (key, iv, hp []byte, ok bool) {
	initialSecret, err := hkdf.Extract(sha256.New, dcid, initialSalt)
	if err != nil {
		return nil, nil, nil, false
	}
	clientSecret, err := expandLabel(initialSecret, "client in", 32)
	if err != nil {
		return nil, nil, nil, false
	}
	if key, err = expandLabel(clientSecret, "quic key", 16); err != nil {
		return nil, nil, nil, false
	}
	if iv, err = expandLabel(clientSecret, "quic iv", 12); err != nil {
		return nil, nil, nil, false
	}
	if hp, err = expandLabel(clientSecret, "quic hp", 16); err != nil {
		return nil, nil, nil, false
	}
	return key, iv, hp, true
}

// expandLabel — HKDF-Expand-Label из TLS 1.3 (RFC 8446, 7.1): info собирается
// как структура HkdfLabel с префиксом "tls13 " и пустым контекстом.
func expandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // пустой контекст
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

// unprotect снимает защиту заголовка и расшифровывает нагрузку клиентского
// Initial, возвращая открытый поток кадров QUIC (RFC 9001, 5.4 и 5.3) и
// восстановленный номер пакета. Исходный буфер b не изменяется. Номер пакета
// нужен пересборке (десинк): переписанный Initial обязан нести тот же номер,
// иначе пространства номеров клиента и сервера рассинхронизируются.
func unprotect(b []byte, h initialHeader, key, iv, hp []byte) ([]byte, uint64, bool) {
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, 0, false
	}
	// Выборка для маски берётся на 4 байта правее начала номера пакета.
	sampleOff := h.pnOffset + sampleSkip
	if sampleOff+sampleLen > len(b) {
		return nil, 0, false
	}
	var mask [sampleLen]byte
	block.Encrypt(mask[:], b[sampleOff:sampleOff+sampleLen])

	// Первый байт: у длинного заголовка маскируются младшие 4 бита.
	first := b[0] ^ (mask[0] & 0x0f)
	pnLen := int(first&0x03) + 1

	// Номер пакета — на копии: буфер не трогаем.
	pnEnd := h.pnOffset + pnLen
	if pnEnd > len(b) {
		return nil, 0, false
	}
	pn := make([]byte, pnLen)
	copy(pn, b[h.pnOffset:pnEnd])
	var pnValue uint64
	for i := 0; i < pnLen; i++ {
		pn[i] ^= mask[1+i]
		pnValue = (pnValue << 8) | uint64(pn[i])
	}

	// AAD — заголовок до конца номера пакета, уже со снятой защитой.
	aad := make([]byte, pnEnd)
	copy(aad, b[:pnEnd])
	aad[0] = first
	copy(aad[h.pnOffset:], pn)

	// Шифртекст — защищённая нагрузка после номера пакета (включая тег).
	cipherStart := pnEnd
	cipherEnd := h.pnOffset + h.length
	if cipherStart > cipherEnd || cipherEnd > len(b) || cipherEnd-cipherStart < aeadTagLen {
		return nil, 0, false
	}
	ciphertext := b[cipherStart:cipherEnd]

	// Нонс: IV XOR номер пакета, выровненный вправо по 12 байт (RFC 9001, 5.3).
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pnValue >> (8 * i))
	}

	aeadBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, false
	}
	aead, err := cipher.NewGCM(aeadBlock)
	if err != nil {
		return nil, 0, false
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, 0, false // не расшифровалось — это не наш Initial либо порча
	}
	return plaintext, pnValue, true
}

// cryptoPiece — кусок CRYPTO-данных по своему смещению в потоке рукопожатия.
type cryptoPiece struct {
	offset uint64
	data   []byte
}

// reassembleCrypto собирает CRYPTO-данные из одной открытой нагрузки и
// возвращает непрерывный префикс рукопожатия с нулевого смещения — начало
// сообщения ClientHello. Если непрерывного префикса нет, возвращает false.
func reassembleCrypto(pt []byte) ([]byte, bool) {
	pieces, ok := collectCryptoPieces(pt)
	if !ok {
		return nil, false
	}
	return stitch(pieces)
}

// collectCryptoPieces проходит кадры открытой нагрузки и возвращает CRYPTO-куски
// (смещение + данные) в порядке появления. Неизвестный кадр обрывает проход: по
// нему нельзя знать длину, а читать наугад — выйти за рамки. false означает, что
// нагрузка не разобрать (порча длин кадра, закрытие соединения) и дальше по
// этому Initial делать нечего; в отличие от «кусков нет» это твёрдый отказ.
//
// Выделено из reassembleCrypto, чтобы межпакетная сборка (Reassembler) могла
// копить куски из нескольких Initial и склеивать их уже вместе.
func collectCryptoPieces(pt []byte) ([]cryptoPiece, bool) {
	var pieces []cryptoPiece
	pos := 0
	for pos < len(pt) {
		ft, n, ok := readVarint(pt[pos:])
		if !ok {
			break
		}
		pos += n
		switch ft {
		case framePadding, framePing:
			// Без тела.
		case frameACK, frameACKECN:
			// Largest Acked, ACK Delay, Range Count, First Range — 4 varint;
			// затем Range Count пар (Gap, Length); у ECN ещё 3 счётчика.
			rangeCount, np, ok := skipVarintsReturn(pt[pos:], 3) // Largest, Delay, Count
			if !ok {
				return nil, false
			}
			pos += np
			// First ACK Range.
			if np, ok = skipVarints(pt[pos:], 1); !ok {
				return nil, false
			}
			pos += np
			if np, ok = skipVarints(pt[pos:], int(rangeCount)*2); !ok {
				return nil, false
			}
			pos += np
			if ft == frameACKECN {
				if np, ok = skipVarints(pt[pos:], 3); !ok {
					return nil, false
				}
				pos += np
			}
		case frameCrypto:
			cryptoOff, n, ok := readVarint(pt[pos:])
			if !ok {
				return nil, false
			}
			pos += n
			cryptoLen, n, ok := readVarint(pt[pos:])
			if !ok {
				return nil, false
			}
			pos += n
			if uint64(pos)+cryptoLen > uint64(len(pt)) {
				return nil, false
			}
			pieces = append(pieces, cryptoPiece{offset: cryptoOff, data: pt[pos : pos+int(cryptoLen)]})
			pos += int(cryptoLen)
		case frameConnClose, frameConnCloseApp:
			// Соединение закрывается — ClientHello здесь не соберём.
			return nil, false
		default:
			// Неизвестный кадр: дальше идти вслепую нельзя.
			pos = len(pt)
		}
	}
	return pieces, true
}

// stitch склеивает CRYPTO-куски в непрерывный префикс с нулевого смещения.
// Возвращает false, если данных с нулевого смещения нет.
func stitch(pieces []cryptoPiece) ([]byte, bool) {
	if len(pieces) == 0 {
		return nil, false
	}
	sort.SliceStable(pieces, func(i, j int) bool { return pieces[i].offset < pieces[j].offset })
	var out []byte
	var want uint64
	for _, p := range pieces {
		if p.offset > want {
			break // разрыв: дальше префикс не непрерывен
		}
		end := p.offset + uint64(len(p.data))
		if end <= want {
			continue // кусок целиком до уже собранного
		}
		out = append(out, p.data[want-p.offset:]...)
		want = end
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// readVarint читает варинт QUIC (RFC 9000, 16): два старших бита первого байта
// задают длину (1, 2, 4 или 8 байт), остальные биты — значение.
func readVarint(b []byte) (val uint64, n int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	length := 1 << (b[0] >> 6)
	if len(b) < length {
		return 0, 0, false
	}
	val = uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val, length, true
}

// skipVarints пропускает count варинтов подряд, возвращая число съеденных байт.
func skipVarints(b []byte, count int) (n int, ok bool) {
	for i := 0; i < count; i++ {
		_, m, ok := readVarint(b[n:])
		if !ok {
			return 0, false
		}
		n += m
	}
	return n, true
}

// skipVarintsReturn пропускает count варинтов и возвращает значение ПОСЛЕДНЕГО
// из них (нужно для числа диапазонов ACK) вместе с числом съеденных байт.
func skipVarintsReturn(b []byte, count int) (last uint64, n int, ok bool) {
	for i := 0; i < count; i++ {
		v, m, ok := readVarint(b[n:])
		if !ok {
			return 0, 0, false
		}
		last = v
		n += m
	}
	return last, n, true
}
