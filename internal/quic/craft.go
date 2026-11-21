package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/fitting-1c/evasion/internal/tlsparse"
)

// Крафт клиентских QUIC Initial — основа десинка QUIC (3.3): вместо блокировки
// QUIC мы сможем переписать исходящий Initial так, чтобы DPI не собрал из него
// SNI, а сервер — собрал. Здесь пока только офлайн-примитив и его проверка; его
// подключение к перехвату — отдельный слайс (8.3: примитив строится против
// синтетики с золотыми тестами ДО интеграции).
//
// Ключи защиты Initial выводятся из открытого DCID (RFC 9001, 5.2), поэтому мы
// можем не только расшифровать чужой Initial, но и собрать валидный свой: тот
// же DCID → те же ключи → сервер примет наши пакеты как часть того же
// рукопожатия.

// minInitialDatagram — минимальный размер датаграммы, несущей клиентский
// Initial (RFC 9000, 14.1): клиент ОБЯЗАН добить такую датаграмму до 1200 байт.
// Сервер вправе отбросить более короткую, поэтому каждую часть добиваем
// PADDING-кадрами (нулевыми байтами) до этого размера.
const minInitialDatagram = 1200

// SplitClientInitial переписывает один клиентский Initial в НЕСКОЛЬКО Initial с
// тем же DCID, разложив CRYPTO (ClientHello) по смещению at: первая часть несёт
// рукопожатие [0:at], вторая — [at:]. Это десинк-приём «фрагментация QUIC
// Initial»: DPI, осматривающий только первый пакет, не увидит целого SNI, а
// сервер соберёт рукопожатие из обеих частей по стандартным правилам QUIC.
//
// Возвращает датаграммы к отправке и true. ok=false (и ничего не трогаем,
// 1.6), если datagram — не клиентский Initial v1, его не расшифровать, в нём не
// целый ClientHello (частичный разложен по нескольким исходным Initial — его
// пересборку делает вызывающий), или at вне (0, len(ClientHello)). Исходный
// буфер не изменяется.
//
// Эффективность — вопрос измерения, а не гарантии: приём помогает против DPI,
// который НЕ пересобирает Initial по DCID (как это делает наш Reassembler).
// Поэтому примитив даётся как механика, а работает он или нет — решает живая
// оценка (2.5), как и для TCP-примитивов.
func SplitClientInitial(datagram []byte, at int) ([][]byte, bool) {
	hdr, hello, _, ok := prepareSplit(datagram)
	if !ok {
		return nil, false
	}
	return splitAt(hdr, hello, at)
}

// SplitClientInitialInSNI разрезает ClientHello ВНУТРИ имени сервера, деля его
// пополам. Это нацеленный приём против DPI, который ищет SNI в первом пакете:
// ни одна из частей не содержит имени целиком, а сервер собирает рукопожатие по
// общему DCID. Выбор места по структуре, а не числом, нужен потому, что
// положение SNI в ClientHello плавает от соединения к соединению (та же причина,
// что у core.CutKind для TCP-примитивов).
//
// ok=false, если это не разбираемый целый клиентский Initial v1 или в
// ClientHello нет имени (делить нечего). Исходный буфер не изменяется.
func SplitClientInitialInSNI(datagram []byte) ([][]byte, bool) {
	hdr, hello, ch, ok := prepareSplit(datagram)
	if !ok {
		return nil, false
	}
	// Нужно имя длиной хотя бы 2 байта, чтобы разрез пришёлся строго внутри.
	if ch.SNILen < 2 {
		return nil, false
	}
	at := ch.SNIOff + ch.SNILen/2
	return splitAt(hdr, hello, at)
}

// prepareSplit расшифровывает один клиентский Initial и собирает из него ЦЕЛЫЙ
// ClientHello. Возвращает заголовок (для DCID/SCID/token при пересборке), байты
// сообщения и его разбор. ok=false на не-Initial, нерасшифруемом или неполном
// ClientHello: частичный (исходное рукопожатие само разложено по нескольким
// Initial) здесь делить нельзя — его пересобирает вызывающий через Reassembler.
func prepareSplit(datagram []byte) (initialHeader, []byte, tlsparse.ClientHello, bool) {
	hdr, ok := parseInitialHeader(datagram)
	if !ok {
		return hdr, nil, tlsparse.ClientHello{}, false
	}
	key, iv, hp, ok := deriveClientKeys(hdr.dcid)
	if !ok {
		return hdr, nil, tlsparse.ClientHello{}, false
	}
	pt, _, ok := unprotect(datagram, hdr, key, iv, hp)
	if !ok {
		return hdr, nil, tlsparse.ClientHello{}, false
	}
	hello, ok := reassembleCrypto(pt)
	if !ok {
		return hdr, nil, tlsparse.ClientHello{}, false
	}
	ch, err := tlsparse.ParseClientHelloMessage(hello)
	if err != nil {
		return hdr, nil, tlsparse.ClientHello{}, false
	}
	return hdr, hello, ch, true
}

// splitAt собирает две части из готового ClientHello по смещению at: первая
// несёт CRYPTO [0:at], вторая [at:], обе с тем же DCID. Нужен настоящий разрез
// (0 < at < len): пустая часть означала бы «не разрезали».
func splitAt(hdr initialHeader, hello []byte, at int) ([][]byte, bool) {
	if at <= 0 || at >= len(hello) {
		return nil, false
	}
	first, err := sealClientInitial(hdr.dcid, hdr.scid, hdr.token, 0, cryptoFrame(0, hello[:at]), minInitialDatagram)
	if err != nil {
		return nil, false
	}
	second, err := sealClientInitial(hdr.dcid, hdr.scid, hdr.token, 1, cryptoFrame(at, hello[at:]), minInitialDatagram)
	if err != nil {
		return nil, false
	}
	return [][]byte{first, second}, true
}

// PeekSNI достаёт имя сервера из ОДНОГО клиентского Initial, не требуя целого
// ClientHello. Начало рукопожатия (и server_name в нём) лежит в первом Initial,
// поэтому по первому же пакету видно, к какому имени идёт соединение — это нужно
// десинку, чтобы решить, трогать ли пакет (радиус), ещё до сборки всего
// ClientHello. Пакет-продолжение (CRYPTO не с нулевого смещения) имени не несёт
// и даёт ("", false). Исходный буфер не изменяется.
func PeekSNI(datagram []byte) (string, bool) {
	hdr, ok := parseInitialHeader(datagram)
	if !ok {
		return "", false
	}
	key, iv, hp, ok := deriveClientKeys(hdr.dcid)
	if !ok {
		return "", false
	}
	pt, _, ok := unprotect(datagram, hdr, key, iv, hp)
	if !ok {
		return "", false
	}
	pieces, ok := collectCryptoPieces(pt)
	if !ok {
		return "", false
	}
	prefix, ok := stitch(pieces) // смежный CRYPTO с нулевого смещения
	if !ok {
		return "", false
	}
	sni, ok := tlsparse.ScanSNI(prefix)
	if !ok {
		return "", false
	}
	return string(sni), true
}

// RewriteInitialReorder переписывает один клиентский Initial как пакет с ТЕМ ЖЕ
// номером пакета и DCID, но с CRYPTO, разбитым на два кадра в обратном порядке
// (сначала второй кусок, затем первый). Имя сервера лежит в начале рукопожатия
// и оказывается во втором кадре; DPI, читающий первый CRYPTO-кадр как начало
// ClientHello, его не находит, а сервер собирает поток по смещениям (QUIC
// обязывает принимать CRYPTO в любом порядке).
//
// Главное свойство — безопасность: один пакет → один пакет той же длины и того
// же номера. Пространства номеров клиента и сервера не рассинхронизируются
// (сервер не подтвердит номер, которого клиент не слал), а датаграмму можно
// заменить на месте без пересчёта длин IP/UDP. Это осознанно слабее разбиения
// на несколько датаграмм, зато не рвёт соединение (1.6).
//
// ok=false (не трогаем пакет), если это не клиентский Initial с единственным
// CRYPTO-кадром от нуля, номер пакета не однобайтовый (не первый полёт), либо
// кадры не умещаются в исходную длину. Длина результата равна len(datagram).
func RewriteInitialReorder(datagram []byte) ([]byte, bool) {
	hdr, ok := parseInitialHeader(datagram)
	if !ok {
		return nil, false
	}
	key, iv, hp, ok := deriveClientKeys(hdr.dcid)
	if !ok {
		return nil, false
	}
	pt, pn, ok := unprotect(datagram, hdr, key, iv, hp)
	if !ok {
		return nil, false
	}
	// Держим однобайтовый номер: первый полёт клиента нумеруется с нуля, и
	// однобайтовая кодировка номера совпадает с ожиданием сервера. Повторы с
	// большим номером не переписываем (вернём false — пройдут как есть).
	if pn > 255 {
		return nil, false
	}
	pieces, ok := collectCryptoPieces(pt)
	if !ok {
		return nil, false
	}
	// Требуем единственный CRYPTO-кадр от нуля: тогда переписав его, мы точно
	// не теряем и не дублируем данные рукопожатия этого пакета.
	if len(pieces) != 1 || pieces[0].offset != 0 {
		return nil, false
	}
	data := pieces[0].data
	if len(data) < 2 {
		return nil, false
	}

	mid := len(data) / 2
	frames := cryptoFrame(mid, data[mid:])
	frames = append(frames, cryptoFrame(0, data[:mid])...)

	out, err := sealClientInitial(hdr.dcid, hdr.scid, hdr.token, byte(pn), frames, len(datagram))
	if err != nil {
		return nil, false
	}
	return out, true
}

// cryptoFrame собирает CRYPTO-кадр QUIC (RFC 9000, 19.6): тип, смещение в
// потоке рукопожатия, длина, данные.
func cryptoFrame(offset int, data []byte) []byte {
	f := []byte{frameCrypto}
	f = appendVarint(f, uint64(offset))
	f = appendVarint(f, uint64(len(data)))
	return append(f, data...)
}

// sealClientInitial собирает защищённый клиентский пакет Initial QUIC v1 с
// заданной открытой нагрузкой (кадрами) и номером пакета pn, добивая датаграмму
// PADDING до minInitialDatagram. Это инверсия parseInitialHeader+unprotect:
// шифрование AES-128-GCM и защита заголовка по ключам, выведенным из DCID.
//
// Номер пакета берём однобайтовым: в первом полёте клиента их единицы, 256
// значений с запасом хватает, а короткий номер упрощает защиту заголовка.
func sealClientInitial(dcid, scid, token []byte, pn byte, frames []byte, target int) ([]byte, error) {
	key, iv, hp, ok := deriveClientKeys(dcid)
	if !ok {
		return nil, errors.New("quic: вывод ключей для сборки Initial не удался")
	}

	// Заголовок фиксированного размера: Length кодируем всегда двухбайтовым
	// варинтом, чтобы его величина (растёт от добивки) не меняла размер
	// заголовка и не создавала обратной связи при расчёте добивки.
	header := func(length int) []byte {
		// Первый байт (до защиты): длинный заголовок (0x80), фиксированный бит
		// (0x40), тип Initial (00), длина номера пакета 1 (младшие биты 00).
		h := []byte{0xC0, 0x00, 0x00, 0x00, 0x01}
		h = append(h, byte(len(dcid)))
		h = append(h, dcid...)
		h = append(h, byte(len(scid)))
		h = append(h, scid...)
		h = appendVarint(h, uint64(len(token)))
		h = append(h, token...)
		// Length двухбайтовым варинтом (старшие биты 01). length ≤ 16383.
		h = append(h, byte(0x40|(length>>8)), byte(length))
		return h
	}

	const pnLen = 1
	plaintext := frames
	headerLen := len(header(0)) // величина Length размер заголовка не меняет

	// Добиваем PADDING-кадрами (нулевые байты) до ТОЧНО target байт. Точная
	// длина нужна пересборке на месте (десинк): переписанная датаграмма
	// заменяет оригинал, и равенство длин избавляет от пересчёта длин IP/UDP.
	overhead := headerLen + pnLen + aeadTagLen
	if overhead+len(plaintext) > target {
		return nil, errors.New("quic: кадры не умещаются в заданную длину датаграммы")
	}
	if pad := target - overhead - len(plaintext); pad > 0 {
		plaintext = append(plaintext, make([]byte, pad)...)
	}

	length := pnLen + len(plaintext) + aeadTagLen
	if length > 16383 {
		return nil, errors.New("quic: Initial слишком велик для двухбайтового Length")
	}

	hdr := header(length)
	pnOffset := len(hdr)
	hdr = append(hdr, pn) // номер пакета (1 байт, до защиты)
	pnEnd := len(hdr)

	// AAD — заголовок до конца номера пакета, в открытом виде.
	aad := append([]byte(nil), hdr[:pnEnd]...)

	// Нонс: IV XOR номер пакета, выровненный вправо (RFC 9001, 5.3). Номер
	// однобайтовый, поэтому меняется только младший байт.
	nonce := append([]byte(nil), iv...)
	nonce[len(nonce)-1] ^= pn

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	pkt := append(hdr, ciphertext...)

	// Защита заголовка: маска из выборки шифртекста на 4 байта правее номера.
	sampleOff := pnOffset + sampleSkip
	if sampleOff+sampleLen > len(pkt) {
		return nil, errors.New("quic: пакет короче выборки для защиты заголовка")
	}
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	var mask [sampleLen]byte
	hpBlock.Encrypt(mask[:], pkt[sampleOff:sampleOff+sampleLen])
	pkt[0] ^= mask[0] & 0x0f // у длинного заголовка маскируются младшие 4 бита
	pkt[pnOffset] ^= mask[1] // единственный байт номера пакета

	return pkt, nil
}

// appendVarint дописывает значение варинтом QUIC (RFC 9000, 16) минимальной
// длины: два старших бита первого байта задают длину (1, 2, 4 или 8 байт).
func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(0x40|(v>>8)), byte(v))
	case v <= 1073741823:
		return append(b, byte(0x80|(v>>24)), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b,
			byte(0xc0|(v>>56)), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}
