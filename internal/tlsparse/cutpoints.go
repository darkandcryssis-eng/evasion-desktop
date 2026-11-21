package tlsparse

import (
	"bytes"
	"github.com/fitting-1c/evasion/internal/core"
)

// CutPointsWithSNI also splits the domain label hidden behind long CDN prefixes.
func (ch ClientHello) CutPointsWithSNI(dst []core.CutPoint, name []byte) []core.CutPoint {
	start := len(dst)
	dst = ch.CutPoints(dst)
	if len(name) != ch.SNILen {
		return dst
	}
	name = bytes.TrimSuffix(name, []byte("."))
	end := bytes.LastIndexByte(name, '.')
	if end < 0 {
		end = len(name)
	}
	first := bytes.LastIndexByte(name[:end], '.') + 1
	if end-first < 2 {
		return dst
	}
	dst = append(dst, core.CutPoint{Kind: core.CutInsideSLD, Offset: ch.SNIOff + first + (end-first)/2})
	for i := len(dst) - 1; i > start && dst[i-1].Offset > dst[i].Offset; i-- {
		dst[i-1], dst[i] = dst[i], dst[i-1]
	}
	return dst
}

// Вычисление структурных точек разреза записи.
//
// Пакет отдаёт границы как данные и не решает, какую из них использовать: выбор
// — дело стратегии, а исполнение — дело desync. Такое разделение нужно потому,
// что множество осмысленных точек задаётся структурой сообщения (её знает
// только этот пакет), а предпочтение между ними выводит генетический поиск, не
// знающий о TLS ничего.
//
// Сам словарь видов точек живёт в core: на него ссылается strategy, которому
// про TLS знать нечего.

// CutPoints добавляет в dst структурные точки разреза разобранного сообщения и
// возвращает расширенный срез.
//
// Срез передаётся вызывающим, а не выделяется здесь: вызов происходит на
// горячем пути, где бюджет аллокаций нулевой, и переиспользуемый буфер снимает
// этот расход полностью. Цена — наружу торчит неудобство в виде параметра dst.
//
// Точки возвращаются по возрастанию смещения. Точка внутри имени добавляется
// только если имя достаточно длинное, чтобы разрез дал две непустые части:
// разрез по нулевой границе ничего не разделяет и лишь зря расходует бюджет
// живых прогонов.
func (ch ClientHello) CutPoints(dst []core.CutPoint) []core.CutPoint {
	dst = append(dst, core.CutPoint{Kind: core.CutRecordHeader, Offset: ch.Record.PayloadOff})

	if ch.HandshakeOff > 0 {
		dst = append(dst, core.CutPoint{Kind: core.CutHandshakeHeader, Offset: ch.HandshakeOff})
	}
	if ch.ExtensionsOff > 0 {
		dst = append(dst, core.CutPoint{Kind: core.CutExtensions, Offset: ch.ExtensionsOff})
	}
	if ch.SNILen > 0 {
		dst = append(dst, core.CutPoint{Kind: core.CutBeforeSNI, Offset: ch.SNIOff})
		if ch.SNILen >= 2 {
			// Середина имени. Деление пополам, а не на фиксированном
			// расстоянии от начала: при коротком имени фиксированный отступ
			// вышел бы за его пределы.
			dst = append(dst, core.CutPoint{Kind: core.CutInsideSNI, Offset: ch.SNIOff + ch.SNILen/2})
		}
		dst = append(dst, core.CutPoint{Kind: core.CutAfterSNI, Offset: ch.SNIOff + ch.SNILen})
	}
	return dst
}
