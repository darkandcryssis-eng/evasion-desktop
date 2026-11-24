// Package tlsfake собирает безобидные TLS-записи для фейковых пакетов десинка.
//
// Назначение одно: дать фейку (поддельному пакету, который видит только DPI, а
// сервер отбрасывает) содержимое БЕЗОБИДНОГО ClientHello — с SNI на нейтральный
// домен (google/cloudflare/apple/microsoft). В этом вся суть приёма «fake»:
// когда DPI разбирает фейк, он видит имя сервера нейтрального домена и относит
// соединение к нему; а настоящий ClientHello к discord.media, идущий следом
// (и, как правило, разрезанный), DPI собрать по имени уже не может — соединение
// проходит.
//
// Зачем несколько пресетов. Один и тот же google-пресет на миллионе соединений
// — это сам по себе признак обхода: продвинутый DPI может классифицировать
// «одинаковый ClientHello всех клиентов провайдера = скорее всего, инструмент
// обхода». Разные пресеты (google/cloudflare/apple/microsoft/vk/yandex)
// размывают эту сигнатуру и выглядят как разные браузеры разных пользователей
// на разных сайтах. Плюс часть провайдеров агрессивнее душит именно google
// (как «популярный флаг обхода»), а на cloudflare/apple смотрит менее
// подозрительно — и наоборот. Выбор под провайдера — работа конфига.
package tlsfake

// fakeCipherSuites — список шифронаборов фейкового ClientHello. Набор в духе
// современных браузеров (TLS 1.3 + распространённые ECDHE): фейк должен выглядеть
// обычным клиентским приветствием, иначе придирчивый разбор DPI его отбросит и
// приём не сработает.
var fakeCipherSuites = []uint16{
	0x1301, 0x1302, 0x1303, // TLS_AES_128_GCM_SHA256 и соседи (TLS 1.3)
	0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDHE-ECDSA/RSA с AES-GCM
	0xcca9, 0xcca8, // ECDHE с ChaCha20-Poly1305
	0xc013, 0xc014, // ECDHE-RSA с AES-CBC
	0x009c, 0x009d, // RSA с AES-GCM
	0x002f, 0x0035, // RSA с AES-CBC
}

// BuildClientHello собирает безобидный TLS ClientHello с заданным SNI как
// полную TLS-запись рукопожатия (тип 0x16).
//
// Результат детерминирован: случайные поля (random, session_id) заполнены
// фиксированным узором. Детерминизм обязателен золотым тестам и воспроизведению
// записи (replay); криптографическая стойкость тут не нужна — пакет всё равно
// отбрасывается, до настоящего рукопожатия дело не доходит.
//
// Каждый вызов возвращает новый срез: вызывающий волен его менять.
func BuildClientHello(sniHost string) []byte {
	return buildClientHello(sniHost)
}

// GoogleClientHello возвращает ClientHello с SNI www.google.com.
func GoogleClientHello() []byte { return copyBytes(googleClientHello) }

// CloudflareClientHello — ClientHello с SNI www.cloudflare.com.
// Используется, когда провайдер агрессивнее душит google-сигнатуру.
func CloudflareClientHello() []byte { return copyBytes(cloudflareClientHello) }

// AppleClientHello — ClientHello с SNI www.apple.com. Нейтральный домен,
// обычный Safari/iOS-трафик.
func AppleClientHello() []byte { return copyBytes(appleClientHello) }

// MicrosoftClientHello — ClientHello с SNI www.microsoft.com. Нейтральный,
// обычный Edge/Windows-трафик, часто проходит там, где google задушен.
func MicrosoftClientHello() []byte { return copyBytes(microsoftClientHello) }

// YandexClientHello — ClientHello с SNI ya.ru. Пригодится, если провайдер
// жёстче смотрит на зарубежные SNI; российский домен «своей» классификации не
// вызывает.
func YandexClientHello() []byte { return copyBytes(yandexClientHello) }

// VKClientHello — ClientHello с SNI vk.com. Та же мотивация, что у яндекса.
func VKClientHello() []byte { return copyBytes(vkClientHello) }

// Кэшированные формы: собираются один раз при инициализации пакета. Через
// copyBytes в каждом геттере защищены от правок вызывающими.
var (
	googleClientHello     = buildClientHello("www.google.com")
	cloudflareClientHello = buildClientHello("www.cloudflare.com")
	appleClientHello      = buildClientHello("www.apple.com")
	microsoftClientHello  = buildClientHello("www.microsoft.com")
	yandexClientHello     = buildClientHello("ya.ru")
	vkClientHello         = buildClientHello("vk.com")
)

// copyBytes возвращает независимую копию буфера.
func copyBytes(src []byte) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

// u16 кодирует число как два байта (big-endian) — ширина большинства длин в TLS.
func u16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }

// u24 кодирует число как три байта (big-endian) — ширина длины рукопожатия.
func u24(v int) []byte { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} }

// tlsExtension обрамляет данные расширения его типом и длиной (RFC 8446 §4.2).
func tlsExtension(typ int, data []byte) []byte {
	out := make([]byte, 0, 4+len(data))
	out = append(out, u16(typ)...)
	out = append(out, u16(len(data))...)
	return append(out, data...)
}

// buildClientHello собирает ClientHello по RFC 8446 §4.1.2: тело приветствия,
// рукопожатие, затем TLS-запись. Длины всех вложенных секций проставляются по
// факту — поэтому запись самосогласованна, и разбор (в т.ч. тестовый,
// имитирующий DPI) доходит до SNI.
//
// sniHost — имя сервера, которое попадёт в расширение server_name. Если
// пустая строка — расширение не вставляется (валидный ClientHello без SNI,
// но для фейка смысла мало: мы прячем настоящий SNI, подставляя фейковый).
func buildClientHello(sniHost string) []byte {
	return buildClientHelloExt(sniHost, nil)
}

// buildClientHelloExt — то же, что buildClientHello, но дописывает extraExt
// в конец блока расширений (после стандартного набора). Нужно, чтобы собрать
// cover-пресет фиксированного размера: туда добавляется расширение padding
// (RFC 7685), доводящее запись до нужной длины. extraExt уже должно быть
// оформлено как цепочка готовых TLS-расширений (type+len+data); nil — обычный
// ClientHello без добавок.
func buildClientHelloExt(sniHost string, extraExt []byte) []byte {
	// Набор и порядок расширений — в духе Chromium: GREASE первым и последним,
	// ALPN, status_request, SCT, key_share с x25519, compress_certificate.
	// DPI, сверяющий «похоже ли на браузер», минимальный ClientHello из пяти
	// расширений отличает сразу.
	var extensions []byte
	add := func(typ int, data []byte) { extensions = append(extensions, tlsExtension(typ, data)...) }

	add(greaseA, nil)
	if sniHost != "" {
		// server_name: список из одной записи host_name (0x00) с именем.
		name := []byte(sniHost)
		entry := append([]byte{0x00}, u16(len(name))...)
		entry = append(entry, name...)
		add(0x0000, append(u16(len(entry)), entry...))
	}
	add(0x0017, nil)          // extended_master_secret
	add(0xff01, []byte{0x00}) // renegotiation_info
	groups := concatU16(greaseA, 0x001d, 0x0017, 0x0018)
	add(0x000a, append(u16(len(groups)), groups...))
	add(0x000b, []byte{0x01, 0x00}) // ec_point_formats: uncompressed
	add(0x0023, nil)                // session_ticket
	alpn := []byte("\x02h2\x08http/1.1")
	add(0x0010, append(u16(len(alpn)), alpn...))
	add(0x0005, []byte{0x01, 0x00, 0x00, 0x00, 0x00}) // status_request: OCSP
	sigs := concatU16(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)
	add(0x000d, append(u16(len(sigs)), sigs...))
	add(0x0012, nil) // signed_certificate_timestamp
	// key_share: GREASE-запись в один байт и x25519 (32 байта; содержимое
	// перезаписывает Refresh на каждом соединении).
	shares := append(u16(greaseA), 0x00, 0x01, 0x00)
	shares = append(shares, u16(0x001d)...)
	shares = append(shares, u16(32)...)
	shares = append(shares, fixedBytes(32, 0x33)...)
	add(0x0033, append(u16(len(shares)), shares...))
	add(0x002d, []byte{0x01, 0x01}) // psk_key_exchange_modes: psk_dhe_ke
	vers := concatU16(greaseB, 0x0304, 0x0303)
	add(0x002b, append([]byte{byte(len(vers))}, vers...))
	add(0x001b, []byte{0x02, 0x00, 0x02}) // compress_certificate: brotli
	add(greaseB, []byte{0x00})
	// Дополнительные расширения (padding cover-пресета) идут последними.
	extensions = append(extensions, extraExt...)

	// --- тело ClientHello ---
	var body []byte
	body = append(body, u16(0x0303)...)          // legacy_version: TLS 1.2
	body = append(body, fixedBytes(32, 0x42)...) // random: перезаписывает Refresh
	body = append(body, 32)                      // session_id length
	body = append(body, fixedBytes(32, 0x24)...) // session_id: перезаписывает Refresh

	ciphers := u16(greaseA)
	for _, c := range fakeCipherSuites {
		ciphers = append(ciphers, u16(int(c))...)
	}
	body = append(body, u16(len(ciphers))...)
	body = append(body, ciphers...)

	body = append(body, 0x01, 0x00) // compression_methods: длина 1, null

	body = append(body, u16(len(extensions))...)
	body = append(body, extensions...)

	// --- рукопожатие и запись ---
	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01) // тип: ClientHello
	handshake = append(handshake, u24(len(body))...)
	handshake = append(handshake, body...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16)           // content_type: handshake
	record = append(record, u16(0x0301)...) // legacy record version
	record = append(record, u16(len(handshake))...)
	record = append(record, handshake...)
	return record
}

// Значения GREASE (RFC 8701): клиент вставляет их, чтобы серверы не ломались
// на неизвестных кодах. Два разных значения, как у Chromium.
const (
	greaseA = 0x0a0a
	greaseB = 0x1a1a
)

// concatU16 собирает последовательность 16-битных значений в байты (big-endian).
func concatU16(vs ...int) []byte {
	out := make([]byte, 0, 2*len(vs))
	for _, v := range vs {
		out = append(out, u16(v)...)
	}
	return out
}

// fixedBytes возвращает n байт одного значения — детерминированная заглушка для
// полей, где содержимое не важно (random, session_id фейка).
func fixedBytes(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
