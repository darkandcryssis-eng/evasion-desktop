package strategy

import "github.com/fitting-1c/evasion/internal/tlsfake"

// Имена пресетов фейковой нагрузки. Каждый — полный безобидный TLS ClientHello
// с конкретным SNI. Кладётся в фейковый пакет приёма «fake», чтобы DPI отнёс
// соединение к безобидному домену, а настоящий SNI (например discord.media)
// собрать не смог.
//
// Разные пресеты существуют, чтобы:
//   - размывать сигнатуру «одинаковый ClientHello у всех клиентов провайдера»
//     (один статичный пресет сам становится маркером обхода);
//   - подбирать нейтральный домен под провайдера: часть DPI агрессивнее душат
//     google (популярный флаг), часть — зарубежные SNI (российские домены
//     обходят классификацию «иностранный трафик»).
const (
	PresetTLSGoogle     = "tls_clienthello_google"
	PresetTLSCloudflare = "tls_clienthello_cloudflare"
	PresetTLSApple      = "tls_clienthello_apple"
	PresetTLSMicrosoft  = "tls_clienthello_microsoft"
	PresetTLSYandex     = "tls_clienthello_yandex"
	PresetTLSVK         = "tls_clienthello_vk"
	// PresetTLSCover681 — 681-байтный ClientHello фиксированного размера,
	// используется приёмом ActionTCPOverlap как «прикрытие» (cover) настоящего
	// ClientHello. Содержит стандартный браузерный набор расширений и шифров
	// — валидная форма протокола, пропускаемая обычными DPI без претензий.
	//
	// Отличается от прочих TLS-пресетов (PresetTLSGoogle, PresetTLSApple,
	// ...) тем, что имеет ФИКСИРОВАННЫЙ размер 681 байт. Для TCP overlap
	// это критично: смещение второго пакета вычисляется как L - M, где
	// M — длина cover-пресета, L — длина настоящего ClientHello. При
	// изменении размера пресета сервер начнёт получать неверные байты в
	// overlap-зоне и рукопожатие сорвётся.
	PresetTLSCover681 = "tls_cover_681"
	// Варианты cover-пресета того же фиксированного размера 681 байт, но с
	// другими SNI. Нужны, чтобы один google-cover на всех соединениях не стал
	// сам по себе сигнатурой обхода (см. tlsfake/cover681_variants.go). Для
	// ActionTCPOverlap взаимозаменяемы с PresetTLSCover681: размер тот же,
	// меняется только имя в SNI, под которое DPI классифицирует соединение.
	PresetTLSCover681Apple     = "tls_cover_681_apple"
	PresetTLSCover681Microsoft = "tls_cover_681_microsoft"
	PresetTLSCover681Yandex    = "tls_cover_681_yandex"
)

// fakePresets — реестр именованных нагрузок фейка. Это не настройка, а свойства
// приёма: содержимое собрано в коде (tlsfake), а конфиг ссылается на него по
// имени, чтобы не нести base64-блоб и не расходиться с единственным источником.
// Добавление пресета — одна строка здесь; всё остальное (валидация, сборка
// плана) работает по этому реестру.
var fakePresets = map[string][]byte{
	PresetTLSGoogle:     tlsfake.GoogleClientHello(),
	PresetTLSCloudflare: tlsfake.CloudflareClientHello(),
	PresetTLSApple:      tlsfake.AppleClientHello(),
	PresetTLSMicrosoft:  tlsfake.MicrosoftClientHello(),
	PresetTLSYandex:     tlsfake.YandexClientHello(),
	PresetTLSVK:         tlsfake.VKClientHello(),
	PresetTLSCover681:   tlsfake.CoverClientHello681(),

	PresetTLSCover681Apple:     tlsfake.CoverClientHello681Apple(),
	PresetTLSCover681Microsoft: tlsfake.CoverClientHello681Microsoft(),
	PresetTLSCover681Yandex:    tlsfake.CoverClientHello681Yandex(),
}

// FakePresetNames возвращает имена всех зарегистрированных пресетов в
// детерминированном порядке. Нужно для диагностики (`evasion doctor`) и для
// генератора стратегий — чтобы перебор был воспроизводим.
func FakePresetNames() []string {
	names := []string{
		PresetTLSGoogle,
		PresetTLSCloudflare,
		PresetTLSApple,
		PresetTLSMicrosoft,
		PresetTLSYandex,
		PresetTLSVK,
		PresetTLSCover681,
		PresetTLSCover681Apple,
		PresetTLSCover681Microsoft,
		PresetTLSCover681Yandex,
	}
	return names
}

// coverPresetNames — cover-пресеты фиксированного размера (681 байт),
// пригодные как прикрытие для ActionTCPOverlap. Отличаются от обычных
// TLS-пресетов (google/apple/...) тем, что имеют ЕДИНЫЙ фиксированный размер,
// от которого зависит механика overlap (смещение cover = L - M). Порядок
// детерминирован — от него зависит воспроизводимость перебора генератором.
var coverPresetNames = []string{
	PresetTLSCover681,
	PresetTLSCover681Apple,
	PresetTLSCover681Microsoft,
	PresetTLSCover681Yandex,
}

// CoverPresetNames возвращает имена cover-пресетов фиксированного размера для
// ActionTCPOverlap в детерминированном порядке. Нужно генератору стратегий:
// при мутации tcp_overlap перебирается именно этот набор (а не все пресеты
// фейка), потому что только фиксированный размер сохраняет корректность
// overlap-перекрытия. Возвращается копия — реестр неизменяем.
func CoverPresetNames() []string {
	out := make([]string, len(coverPresetNames))
	copy(out, coverPresetNames)
	return out
}

// FakePreset возвращает нагрузку пресета по имени и признак, что имя известно.
// Срез — копия: реестр неизменяем, а план (desync) волен владеть своей копией.
func FakePreset(name string) ([]byte, bool) {
	b, ok := fakePresets[name]
	if !ok {
		return nil, false
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, true
}
