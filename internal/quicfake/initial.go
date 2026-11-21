package quicfake

import (
	"encoding/binary"
	"fmt"
)

// quicV1Version — номер версии QUIC v1 (RFC 9000). Фиксированные 4 байта в
// заголовке; DPI пользуется ими для классификации «QUIC v1 Initial».
const quicV1Version uint32 = 0x00000001

// Параметры фейка. Значения выбраны так, чтобы:
//
//   - длинный заголовок давал первый байт `0xc0` (long header=1, fixed bit=1,
//     packet type Initial=0b00, PN length=1 байт);
//   - DCID длиной 8 байт выглядел нейтральным идентификатором соединения, не
//     совпадающим с какими-либо реальными паттернами Discord;
//   - SCID был пуст — так проще и не хуже видно DPI.
const (
	flagsLongInitialPN1 byte = 0xc0 // long header, fixed, type=Initial, pn_len=1
	dcidLen                  = 8
	scidLen                  = 0
)

// benignDCID — восемь байт DCID для фейка. Произвольные байты; важно не
// повторять очевидные паттерны (все нули, все одинаковые): они опознавались бы
// примитивным DPI как подозрительные.
var benignDCID = [dcidLen]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

// BenignInitial74 возвращает 74-байтный QUIC v1 Initial, пригодный как
// нагрузка UDP decoy голоса Discord (строго 74 байта — размер шаблона IP
// discovery). Если формат когда-нибудь поменяется, подгонка под 74 байта
// локализована здесь.
//
// Структура ровно 74 байта:
//
//	[0:1]   flags = 0xc0
//	[1:5]   version = 0x00000001
//	[5:6]   DCID len = 8
//	[6:14]  DCID = benignDCID
//	[14:15] SCID len = 0
//	[15:16] token len (varint, 1 байт) = 0
//	[16:17] length (varint, 1 байт) = 57 (packet number + payload = 1 + 56)
//	        — варинт помещается в 1 байт при значении < 64 (RFC 9000 §16).
//	[17:18] packet number = 0x00
//	[18:74] payload = детерминированный узор (56 байт)
//
// payload-узор — повторяющиеся `0xa5` (не нули, чтоб DPI, который считает
// энтропию, видел непустой пакет; не рандомные, чтобы detкрэш был
// воспроизводим в золотых тестах, 8.3).
func BenignInitial74() []byte {
	out := make([]byte, 74)
	out[0] = flagsLongInitialPN1
	binary.BigEndian.PutUint32(out[1:5], quicV1Version)
	out[5] = dcidLen
	copy(out[6:14], benignDCID[:])
	out[14] = scidLen
	out[15] = 0  // token length varint = 0
	out[16] = 57 // length varint = packet number (1) + payload (56)
	out[17] = 0  // packet number (0x00)
	for i := 18; i < 74; i++ {
		out[i] = 0xa5
	}
	return out
}

// Validate — быстрая проверка «похож ли на QUIC Initial long-header».
//
// Нужна в тестах и в будущем — ранней фазе ответа DPI на такой decoy. Проверяет
// только то, что видит DPI: первый байт в маске 0xc0..0xc3 (long header, fixed,
// type Initial, любой PN length) и версия 0x00000001.
//
// Возвращает ошибку с внятным текстом, а не bool: при провале золотого теста
// хочется видеть ПОЧЕМУ пакет не прошёл, не только что не прошёл.
func Validate(buf []byte) error {
	if len(buf) < 5 {
		return fmt.Errorf("quicfake: длина %d меньше минимума заголовка (5)", len(buf))
	}
	// 0xc0..0xc3 — long header, fixed bit=1, type=Initial, любой PN length.
	if buf[0]&0xfc != 0xc0 {
		return fmt.Errorf("quicfake: первый байт 0x%02x не похож на long header Initial (ожидали 0xc0..0xc3)", buf[0])
	}
	ver := binary.BigEndian.Uint32(buf[1:5])
	if ver != quicV1Version {
		return fmt.Errorf("quicfake: версия 0x%08x, ожидали QUIC v1 (0x%08x)", ver, quicV1Version)
	}
	return nil
}
