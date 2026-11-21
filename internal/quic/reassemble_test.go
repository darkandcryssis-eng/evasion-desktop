package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/tlsparse"
)

// rfcClientHello расшифровывает эталонный Initial RFC 9001 и возвращает голое
// сообщение ClientHello (для example.com). На нём строятся многопакетные случаи:
// это настоящий, разбираемый tlsparse ClientHello, который мы режем на куски.
func rfcClientHello(t *testing.T) []byte {
	t.Helper()
	dgram := unhex(t, clientInitialRFC9001)
	hdr, ok := parseInitialHeader(dgram)
	if !ok {
		t.Fatal("parseInitialHeader не распознал эталон")
	}
	k, iv, hp, ok := deriveClientKeys(hdr.dcid)
	if !ok {
		t.Fatal("вывод ключей")
	}
	pt, _, ok := unprotect(dgram, hdr, k, iv, hp)
	if !ok {
		t.Fatal("расшифровка эталона")
	}
	hello, ok := reassembleCrypto(pt)
	if !ok {
		t.Fatal("сборка CRYPTO эталона")
	}
	return hello
}

// writeVarint2 кодирует значение двухбайтовым варинтом QUIC (старшие биты 01).
// Для тестовых смещений и длин (< 16384) этого достаточно.
func writeVarint2(t *testing.T, v int) []byte {
	t.Helper()
	if v < 0 || v > 16383 {
		t.Fatalf("значение %d не влезает в двухбайтовый варинт", v)
	}
	return []byte{0x40 | byte(v>>8), byte(v)}
}

// buildClientInitial собирает защищённый клиентский пакет Initial QUIC v1 с
// одним CRYPTO-кадром (смещение + данные) и заданным DCID. Это точная инверсия
// parseInitialHeader+unprotect: нужен, чтобы в тесте разложить один ClientHello
// по нескольким Initial с общим DCID и проверить межпакетную сборку.
func buildClientInitial(t *testing.T, dcid []byte, pn byte, cryptoOffset int, cryptoData []byte) []byte {
	t.Helper()
	key, iv, hp, ok := deriveClientKeys(dcid)
	if !ok {
		t.Fatal("вывод ключей для сборки")
	}

	// Открытая нагрузка: один CRYPTO-кадр.
	plaintext := []byte{frameCrypto}
	plaintext = append(plaintext, writeVarint2(t, cryptoOffset)...)
	plaintext = append(plaintext, writeVarint2(t, len(cryptoData))...)
	plaintext = append(plaintext, cryptoData...)

	// Незащищённый заголовок. Первый байт: длинный заголовок, фиксированный бит,
	// тип Initial (00), длина номера пакета 1 (младшие биты 00).
	const pnLen = 1
	hdr := []byte{0xC0 | (pnLen - 1), 0x00, 0x00, 0x00, 0x01}
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00) // SCID длиной 0
	hdr = append(hdr, 0x00) // Token Length 0

	ctLen := len(plaintext) + aeadTagLen
	hdr = append(hdr, writeVarint2(t, pnLen+ctLen)...) // Length

	pnOffset := len(hdr)
	hdr = append(hdr, pn) // номер пакета (1 байт)
	pnEnd := len(hdr)

	// AAD — заголовок до конца номера пакета, в открытом виде.
	aad := make([]byte, pnEnd)
	copy(aad, hdr)

	// Нонс: IV XOR номер пакета, выровненный вправо.
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	nonce[len(nonce)-1] ^= pn

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	packet := append(hdr, ciphertext...)

	// Защита заголовка: маска из выборки шифртекста на 4 байта правее номера.
	sampleOff := pnOffset + sampleSkip
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatalf("aes hp: %v", err)
	}
	var mask [sampleLen]byte
	hpBlock.Encrypt(mask[:], packet[sampleOff:sampleOff+sampleLen])
	packet[0] ^= mask[0] & 0x0f
	packet[pnOffset] ^= mask[1]

	return packet
}

// TestReassemblerSingleDatagram — однопакетный ClientHello (эталон) собирается
// за один Offer, как и раньше ExtractSNI.
func TestReassemblerSingleDatagram(t *testing.T) {
	r := NewReassembler()
	sni, ok := r.Offer(unhex(t, clientInitialRFC9001), time.Now())
	if !ok || sni != "example.com" {
		t.Fatalf("ожидался example.com за один пакет, получено %q ok=%v", sni, ok)
	}
}

// TestReassemblerSplitAcrossInitials — ClientHello, разложенный по двум Initial
// с общим DCID, собирается: первый кусок даёт «ещё не готово», второй — SNI.
// Это и есть случай современного Chrome (постквантовый ClientHello на несколько
// Initial), который ExtractSNI в одиночку не берёт.
func TestReassemblerSplitAcrossInitials(t *testing.T) {
	hello := rfcClientHello(t)
	if _, err := tlsparse.ParseClientHelloMessage(hello); err != nil {
		t.Fatalf("эталонный ClientHello сам по себе должен разбираться: %v", err)
	}
	mid := len(hello) / 2
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	p1 := buildClientInitial(t, dcid, 0, 0, hello[:mid])
	p2 := buildClientInitial(t, dcid, 1, mid, hello[mid:])

	r := NewReassembler()
	now := time.Now()
	if sni, ok := r.Offer(p1, now); ok {
		t.Fatalf("первый из двух кусков не должен давать SNI, получено %q", sni)
	}
	if sni, ok := r.Offer(p2, now); !ok || sni != "example.com" {
		t.Fatalf("после второго куска ожидался example.com, получено %q ok=%v", sni, ok)
	}
	// Повтор завершающего пакета — тот же вердикт из кэша, без повторной сборки.
	if sni, ok := r.Offer(p2, now); !ok || sni != "example.com" {
		t.Fatalf("повтор должен давать тот же SNI из кэша, получено %q ok=%v", sni, ok)
	}
}

// TestReassemblerCoalesced — два Initial одного DCID склеены в одну датаграмму
// (RFC 9000, 12.2): собирается за один Offer. Без разбора склейки хвост
// ClientHello во втором пакете был бы потерян.
func TestReassemblerCoalesced(t *testing.T) {
	hello := rfcClientHello(t)
	mid := len(hello) / 2
	dcid := []byte{7, 7, 7, 7, 2, 2, 2, 2}
	p1 := buildClientInitial(t, dcid, 0, 0, hello[:mid])
	p2 := buildClientInitial(t, dcid, 1, mid, hello[mid:])
	coalesced := append(append([]byte{}, p1...), p2...)

	r := NewReassembler()
	if sni, ok := r.Offer(coalesced, time.Now()); !ok || sni != "example.com" {
		t.Fatalf("склеенные в одну датаграмму Initial должны собраться, получено %q ok=%v", sni, ok)
	}
}

// TestReassemblerStats — счётчики наблюдаемости отражают исход: распознанный
// Initial и собранный SNI.
func TestReassemblerStats(t *testing.T) {
	r := NewReassembler()
	r.Offer(unhex(t, clientInitialRFC9001), time.Now()) // один Initial → SNI
	r.Offer([]byte("not quic at all......"), time.Now()) // не Initial
	s := r.Snapshot()
	if s.Datagrams != 2 {
		t.Errorf("датаграмм: ожидалось 2, получено %d", s.Datagrams)
	}
	if s.Initials != 1 {
		t.Errorf("initial: ожидалось 1, получено %d", s.Initials)
	}
	if s.Resolved != 1 {
		t.Errorf("собран SNI: ожидалось 1, получено %d", s.Resolved)
	}
}

// TestReassemblerOutOfOrder — куски пришли в обратном порядке (середина раньше
// начала): пока нет префикса с нуля — молчим, после начального куска собираем.
func TestReassemblerOutOfOrder(t *testing.T) {
	hello := rfcClientHello(t)
	mid := len(hello) / 2
	dcid := []byte{9, 9, 9, 9, 1, 1, 1, 1}
	p1 := buildClientInitial(t, dcid, 0, 0, hello[:mid])
	p2 := buildClientInitial(t, dcid, 1, mid, hello[mid:])

	r := NewReassembler()
	now := time.Now()
	if sni, ok := r.Offer(p2, now); ok {
		t.Fatalf("кусок из середины без начала давать SNI не должен, получено %q", sni)
	}
	if sni, ok := r.Offer(p1, now); !ok || sni != "example.com" {
		t.Fatalf("после начального куска ожидался example.com, получено %q ok=%v", sni, ok)
	}
}

// TestReassemblerSeparatesDCIDs — куски от разных DCID не смешиваются: половина
// одного рукопожатия и половина другого вместе ClientHello не образуют.
func TestReassemblerSeparatesDCIDs(t *testing.T) {
	hello := rfcClientHello(t)
	mid := len(hello) / 2
	dcidA := []byte{0xAA, 0xAA, 0xAA, 0xAA, 0, 0, 0, 1}
	dcidB := []byte{0xBB, 0xBB, 0xBB, 0xBB, 0, 0, 0, 2}
	a1 := buildClientInitial(t, dcidA, 0, 0, hello[:mid])
	b2 := buildClientInitial(t, dcidB, 0, mid, hello[mid:])

	r := NewReassembler()
	now := time.Now()
	if _, ok := r.Offer(a1, now); ok {
		t.Fatal("половина рукопожатия A не должна собираться")
	}
	if _, ok := r.Offer(b2, now); ok {
		t.Fatal("кусок другого DCID не должен достраивать чужое рукопожатие")
	}
}

// FuzzReassemblerOffer — произвольный ввод не должен ронять сборщик (8.2: данные
// из сети враждебны всегда). Проверяется только отсутствие паники.
func FuzzReassemblerOffer(f *testing.F) {
	seed, _ := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(clientInitialRFC9001))
	f.Add(seed)
	f.Add([]byte{0xc0, 0, 0, 0, 1})
	f.Add([]byte(nil))

	f.Fuzz(func(_ *testing.T, data []byte) {
		r := NewReassembler()
		r.Offer(data, time.Now())
	})
}
