package intercept

import (
	"errors"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/tlsparse"
)

// TLSHelloDetector — детектор ClientHello для flow.Table на основе tlsparse.
//
// Распознаёт ClientHello в полезной нагрузке и сообщает таблице потоков,
// применять ли десинк. Таблица зовёт его как на одном сегменте, так и на
// склейке нескольких (при сборке многосегментного ClientHello) — для детектора
// это просто буфер байт, разницы он не видит:
//
//   - целый ClientHello в сегменте — применяем (complete=true);
//   - первый сегмент многосегментного ClientHello, в котором расширение
//     server_name уже целиком присутствует, — ТОЖЕ применяем: имя лежит в
//     начале рукопожатия, то есть в первом сегменте, и десинк по нему режет
//     ровно то, что видит DPI. Крупный постквантовый ClientHello не влезает в
//     один сегмент, и без этой ветки цель (например, googlevideo) уходила бы
//     мимо десинка с сырым SNI. Собирать всё сообщение не нужно и вредно: к
//     моменту склейки первый сегмент уже ушёл бы в сеть;
//   - TLS-рукопожатие, в котором имени ещё не видно (сегмент обрезан до
//     server_name), — не применяем (complete=false), поток уходит сырым;
//   - не-TLS — не TLS.
//
// Решение строится в два шага. Сначала — попытка применить: если имя сервера
// уже видно (строгим разбором либо, если строгий споткнулся, нестрогим), десинк
// применим немедленно. Нестрогий разбор доверяем при ЛЮБОЙ ошибке строгого:
// server_name лежит в начале расширений, и если нестрогий его там нашёл — это
// ClientHello, даже когда строгий отказал на более позднем поле (редкое/
// нестандартное расширение после server_name, рукопожатие на несколько записей
// и т.п.). Нестрогий разбор не выдаёт имя на мусоре — он требует корректной
// структуры server_name, поэтому ложный десинк не-ClientHello исключён.
//
// Если имени ещё нет, второй шаг решает — ждать или пропустить: при
// «данных пока мало» (ErrIncomplete) и «рукопожатие растянуто на записи»
// (ErrFragmentedHandshake) ждём следующий сегмент; иначе это не наш ClientHello.
func TLSHelloDetector(payload []byte) (hello []byte, complete bool, isTLS bool) {
	_, err := tlsparse.ParseClientHello(payload)
	if err == nil {
		// A TCP segment may also contain CCS or early data. Dropping that tail
		// leaves a permanent sequence gap after the modified ClientHello.
		return payload, true, true
	}
	// Строгий разбор не удался. Имя всё же может быть видно — доверяем
	// нестрогому разбору (он валидирует структуру server_name, ложного
	// срабатывания на мусоре не даёт). Крупный ClientHello Chrome, у которого
	// строгий разбор спотыкается (растянут на TLS-записи или несёт расширение,
	// которое строгий разбор не принимает), иначе уходил бы мимо десинка с
	// открытым SNI — и TSPU рвал загрузку (картинки cdn.discordapp.com,
	// net_error -101).
	if _, ok := tlsparse.ParseClientHelloLenient(payload); ok {
		return payload, true, true
	}
	// Имени нет. Ждём ещё байт, только если причина — неполнота записи или
	// растянутое на записи рукопожатие (продолжение придёт). Остальное — не
	// наш ClientHello: уходим с пути.
	if errors.Is(err, tlsparse.ErrIncomplete) || errors.Is(err, tlsparse.ErrFragmentedHandshake) {
		return nil, false, true
	}
	return nil, false, false
}

// TLSHelloParser — разбор ClientHello для контура: имя сервера и структурные
// точки разреза. Разбор идёт по тем же правилам, что в пакете proxy, чтобы оба
// этапа одинаково понимали одно сообщение.
//
// Если строгий разбор отказывает (первый сегмент многосегментного ClientHello),
// пробуем нестрогий: он находит SNI и смещения в пределах этого сегмента. Точки
// разреза при этом лежат внутри сегмента (имя целиком присутствует), поэтому
// десинк применим к нему без склейки.
func TLSHelloParser(hello []byte) (sni string, cuts []core.CutPoint, ok bool) {
	ch, err := tlsparse.ParseClientHello(hello)
	if err != nil {
		lenient, lok := tlsparse.ParseClientHelloLenient(hello)
		if !lok {
			return "", nil, false
		}
		ch = lenient
	}
	name, has := ch.SNI(hello)
	if has {
		sni = string(name)
	}
	cuts = ch.CutPointsWithSNI(make([]core.CutPoint, 0, 8), name)
	return sni, cuts, true
}

// статическая проверка, что детектор годится таблице потоков.
var _ flow.HelloDetector = TLSHelloDetector
