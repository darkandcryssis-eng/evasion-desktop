package tlsfake

import (
	"crypto/rand"
	"fmt"
)

// Варианты cover-ClientHello фиксированного размера 681 байт с РАЗНЫМИ SNI.
//
// Зачем. Приём ActionTCPOverlap прикрывает настоящий ClientHello безобидным
// cover-пакетом; DPI классифицирует соединение по SNI этого cover'а и
// пропускает. Базовый cover (PresetTLSCover681, встроенный tls_cover_681.bin)
// несёт SNI www.google.com. Если на всех соединениях провайдера летит один и
// тот же 681-байтный google-cover, этот паттерн сам становится сигнатурой
// обхода: продвинутый DPI может выучить «ровно 681 байт + google-SNI +
// фиксированный набор расширений = инструмент». Варианты с другими SNI
// (apple, microsoft, yandex) размывают сигнатуру — соединения выглядят как
// разные браузеры разных пользователей на разных сайтах. Плюс часть
// провайдеров мягче смотрит на отечественные SNI (yandex), часть — на
// microsoft/apple, когда google уже под подозрением.
//
// Инвариант размера. Для TCP overlap критично, чтобы все cover-пресеты были
// РОВНО 681 байт (M в walkTCPOverlap): смещение cover-пакета считается как
// L - M, и смена M сломала бы overlap-зону. Поэтому варианты собираются не
// вручную, а генератором buildCover681, который доводит запись до 681 байт
// расширением padding (RFC 7685) — так SNI любой длины укладывается в один и
// тот же размер.

const cover681Size = 681

// buildCover681 собирает валидный ClientHello с заданным SNI, добитый до
// ровно cover681Size байт расширением padding (RFC 7685, тип 21). Тело
// padding — нули (как и предписывает RFC). Размер padding вычисляется из
// длины «голого» ClientHello, поэтому результат детерминирован и не зависит
// от длины SNI, пока она оставляет место под 4-байтовый заголовок расширения.
//
// Паникует при сборке пакета, если SNI настолько длинный, что голый
// ClientHello уже не влезает в целевой размер: это ошибка разработчика в
// списке вариантов (все имена тут короткие), а не внешних данных, и всплыть
// она должна на инициализации пакета, а не в поле.
func buildCover681(sniHost string) []byte {
	bare := len(buildClientHelloExt(sniHost, nil))
	// Запись padding стоит 4 байта заголовка (type+len) плюс тело.
	padBody := cover681Size - bare - 4
	if padBody < 0 {
		panic(fmt.Sprintf("tlsfake: cover для %q = %d байт, не влезает в %d даже с пустым padding",
			sniHost, bare, cover681Size))
	}
	padExt := tlsExtension(0x0015, make([]byte, padBody))
	out := buildClientHelloExt(sniHost, padExt)
	if len(out) != cover681Size {
		panic(fmt.Sprintf("tlsfake: cover для %q вышел %d байт, ожидали %d",
			sniHost, len(out), cover681Size))
	}
	return out
}

// Кэшированные варианты cover'а: собираются один раз при инициализации пакета.
// Через copyBytes в каждом геттере защищены от правок вызывающими.
var (
	coverApple     = buildCover681("www.apple.com")
	coverMicrosoft = buildCover681("www.microsoft.com")
	coverYandex    = buildCover681("ya.ru")
)

// CoverClientHello681Apple возвращает КОПИЮ 681-байтного cover-ClientHello с
// SNI www.apple.com.
func CoverClientHello681Apple() []byte { return copyBytes(coverApple) }

// CoverClientHello681Microsoft возвращает КОПИЮ 681-байтного cover-ClientHello
// с SNI www.microsoft.com.
func CoverClientHello681Microsoft() []byte { return copyBytes(coverMicrosoft) }

// CoverClientHello681Yandex возвращает КОПИЮ 681-байтного cover-ClientHello с
// SNI ya.ru.
func CoverClientHello681Yandex() []byte { return copyBytes(coverYandex) }

// MinCoverSize — наименьший размер cover-ClientHello с этим SNI: голый
// ClientHello плюс пустое расширение padding.
func MinCoverSize(sniHost string) int { return len(buildClientHelloExt(sniHost, nil)) + 4 }

// BuildCoverSized собирает cover-ClientHello с SNI sniHost ровно size байт
// (добивкой padding) со свежими случайными полями. Нужен tcp_overlap для
// ClientHello короче стандартного 681-байтного cover'а: прежде такие hello
// уходили на запасной разрез внутри имени, который ломает Cloudflare.
// false — если size меньше MinCoverSize.
func BuildCoverSized(sniHost string, size int) ([]byte, bool) {
	padBody := size - MinCoverSize(sniHost)
	if padBody < 0 {
		return nil, false
	}
	out := buildClientHelloExt(sniHost, tlsExtension(0x0015, make([]byte, padBody)))
	Refresh(out, func(p []byte) { _, _ = rand.Read(p) })
	return out, len(out) == size
}
