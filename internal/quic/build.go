package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/fitting-1c/evasion/internal/tlsfake"
)

// initialDatagramSize — размер клиентской датаграммы Initial: минимум по
// RFC 9000 (раздел 14.1), ровно столько шлют браузеры.
const initialDatagramSize = 1200

// BuildClientInitial собирает настоящую клиентскую датаграмму QUIC v1 Initial с
// ClientHello для имени sni: начальная защита наложена по RFC 9001, так что
// любой разборщик (включая DPI) снимает её и видит имя. dcid — идентификатор
// соединения назначения, 8–20 байт; от него зависят ключи.
//
// Нужна как подделка «постороннего QUIC» перед началом UDP-потока, который
// DPI иначе опознал бы по первому пакету.
func BuildClientInitial(sni string, dcid []byte) ([]byte, bool) {
	if len(dcid) < 8 || len(dcid) > 20 {
		return nil, false
	}
	record := tlsfake.BuildClientHello(sni)
	if len(record) <= 5 {
		return nil, false
	}
	hello := record[5:] // без заголовка TLS-записи: в QUIC идёт само сообщение

	const pnLen = 4
	header := []byte{0xc0 | (pnLen - 1), 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}
	header = append(header, dcid...)
	header = append(header, 0x00) // SCID пуст
	header = append(header, 0x00) // токена нет
	// Поле длины — двухбайтовый varint: номер пакета + тело + метка AEAD.
	bodyLen := initialDatagramSize - len(header) - 2 - pnLen - 16
	crypto := []byte{frameCrypto, 0x00}
	crypto = binary.BigEndian.AppendUint16(crypto, 0x4000|uint16(len(hello)))
	if len(hello) >= 0x4000 || len(crypto)+len(hello) > bodyLen {
		return nil, false
	}
	plaintext := make([]byte, bodyLen) // хвост — кадры PADDING (нули)
	copy(plaintext, crypto)
	copy(plaintext[len(crypto):], hello)

	header = binary.BigEndian.AppendUint16(header, 0x4000|uint16(pnLen+bodyLen+16))
	pnOffset := len(header)
	header = append(header, 0, 0, 0, 0) // номер пакета 0

	key, iv, hp, ok := deriveClientKeys(dcid)
	if !ok {
		return nil, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	// Номер пакета 0: nonce равен iv.
	out := aead.Seal(header, iv, plaintext, header)

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, false
	}
	var mask [aes.BlockSize]byte
	hpBlock.Encrypt(mask[:], out[pnOffset+4:pnOffset+4+aes.BlockSize])
	out[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out, len(out) == initialDatagramSize
}
