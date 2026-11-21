package quic

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/fitting-1c/evasion/internal/tlsparse"
)

// Параметры межпакетной сборки. Магических чисел в коде быть не должно (10.1),
// но это внутренний порог без второго потребителя и без настройки снаружи —
// значения консервативны и задаются здесь.
const (
	// reasmTTL — сколько держать незавершённую сборку без новых пакетов.
	// Рукопожатие QUIC укладывается в доли секунды; десять секунд с запасом
	// переживают переповтор (PTO) и не держат память долго.
	reasmTTL = 10 * time.Second
	// reasmMaxConns — предел числа одновременно отслеживаемых DCID. При
	// переполнении новые сборки не заводятся, а разбор идёт разово по одному
	// пакету (деградация в пропуск, как таблица потоков при переполнении, 4.4).
	reasmMaxConns = 4096
	// reasmMaxBytes — предел CRYPTO-данных на один DCID. Защита от враждебного
	// потока кусков, который никогда не сложится в ClientHello (8.2): при
	// превышении сборка помечается несобираемой.
	reasmMaxBytes = 65536
	// reasmSweepEvery — не чаще этого срока проходим карту и чистим стухшее.
	// Иначе удаление по возрасту стоило бы O(n) на каждый пакет QUIC.
	reasmSweepEvery = time.Second
)

// assembly — накопленное по одному клиентскому рукопожатию (один DCID).
type assembly struct {
	pieces []cryptoPiece
	bytes  int
	sni    string
	// solved — ClientHello уже разобран: sni проставлен (возможно, пустой, если
	// имени в нём нет). Дальше по этому DCID не расшифровываем, отвечаем кэшем.
	solved bool
	// failed — датаграммы этого DCID не разобрать (ключи/расшифровка/порча или
	// превышен предел байт). Больше не пытаемся.
	failed bool
	seen   time.Time
}

// Reassembler собирает клиентский ClientHello QUIC v1 из одного или нескольких
// пакетов Initial с общим DCID и достаёт из него SNI.
//
// Зачем он нужен сверх ExtractSNI. Постквантовый ClientHello современных
// браузеров (X25519MLKEM768) не помещается в один Initial и разбивается на
// несколько CRYPTO-кадров в разных датаграммах. ExtractSNI смотрит одну
// датаграмму и на таком рукопожатии честно отказывает; без межпакетной сборки
// блокировка QUIC (3.3) и детект QUIC-only не сработали бы против такого
// клиента. Пакеты одного первого полёта несут общий DCID, а ключи защиты
// Initial выводятся именно из DCID, поэтому их можно расшифровать и склеить
// CRYPTO по смещению.
//
// НЕ потокобезопасен: предназначен для единственного цикла блокировки QUIC,
// который обрабатывает пакеты последовательно. Второй реализации синхронизации
// заводить не нужно — её отсутствие это требование к вызывающему, а не недосмотр.
type Reassembler struct {
	conns     map[string]*assembly
	lastSweep time.Time
	stats     Stats
}

// Stats — накопленные счётчики для наблюдаемости (7): по ним видно, идёт ли
// распознаваемый QUIC вообще. Молчание блокировщика без этих чисел нельзя было
// отличить от «QUIC не шлётся» (например, браузер ушёл в QUIC-broken backoff) —
// именно эта слепота мешала диагностике на живой машине.
type Stats struct {
	// Datagrams — всего предложено датаграмм (на фильтре это исходящий UDP/443).
	Datagrams int
	// Initials — из них распознан клиентский Initial QUIC v1 (хотя бы первый
	// пакет датаграммы). Малое число при большом Datagrams — QUIC идёт, но не
	// в виде клиентского Initial (короткий заголовок уже установленной сессии).
	Initials int
	// Resolved — вызовов, где ClientHello собран и SNI извлечён.
	Resolved int
	// NoSNI — ClientHello собран, но имени в нём нет.
	NoSNI int
	// Failed — не разобрать (ключи/расшифровка/порча/превышен лимит байт).
	Failed int
	// Pending — возвращено «ещё не готово» (ждём остальные Initial).
	Pending int
}

// NewReassembler создаёт пустой сборщик.
func NewReassembler() *Reassembler {
	return &Reassembler{conns: make(map[string]*assembly)}
}

// Snapshot возвращает копию накопленных счётчиков.
func (r *Reassembler) Snapshot() Stats { return r.stats }

// Offer скармливает одну UDP-датаграмму и возвращает имя сервера (SNI) с true,
// если клиентский ClientHello QUIC v1 собран и SNI из него извлечён — сразу из
// одного Initial или по накоплению нескольких с общим DCID. Во всех прочих
// случаях — ("", false): не клиентский Initial, не v1, ещё не собрано, не
// разобрать или имени нет. По false блокировать нельзя (1.6): пакет, который
// только часть рукопожатия, пропускается, и решение принимается, когда (и если)
// рукопожатие сложится целиком.
func (r *Reassembler) Offer(datagram []byte, now time.Time) (string, bool) {
	r.stats.Datagrams++

	hdr, ok := parseInitialHeader(datagram)
	if !ok {
		return "", false // не клиентский Initial v1 — не наш пакет
	}
	r.stats.Initials++

	r.sweep(now)

	key := hex.EncodeToString(hdr.dcid)
	a := r.conns[key]
	if a == nil {
		// Переполнение карты: не заводим новую сборку, пробуем разобрать пакет
		// разово (сработает для однопакетного ClientHello). Это деградация в
		// пропуск для многопакетных, а не слепая блокировка (4.4, 1.6).
		if len(r.conns) >= reasmMaxConns {
			sni, ok := ExtractSNI(datagram)
			if ok {
				r.stats.Resolved++
			} else {
				r.stats.Pending++
			}
			return sni, ok
		}
		a = &assembly{seen: now}
		r.conns[key] = a
	}
	a.seen = now

	// По уже принятому решению отвечаем кэшем, не расшифровывая повторно. Так
	// повторы и продолжение того же рукопожатия получают тот же вердикт, а
	// чужой (не из радиуса) QUIC не дешифруется на каждом пакете.
	if a.solved {
		r.tally(a.sni)
		return a.sni, a.sni != ""
	}
	if a.failed {
		r.stats.Failed++
		return "", false
	}

	k, iv, hp, ok := deriveClientKeys(hdr.dcid)
	if !ok {
		a.failed = true
		r.stats.Failed++
		return "", false
	}

	// Пройти все склеенные (coalesced) клиентские Initial того же DCID в одной
	// датаграмме. Клиент может как слать части рукопожатия отдельными
	// датаграммами (их копит сборка между вызовами), так и склеивать несколько
	// Initial в одну датаграмму (RFC 9000, 12.2). Без разбора склейки второй
	// пакет с хвостом ClientHello был бы пропущен, и рукопожатие не собралось
	// бы — та же слепота, что к многопакетному ClientHello.
	off := 0
	for off < len(datagram) {
		h, ok := parseInitialHeader(datagram[off:])
		if !ok {
			break // дальше не Initial v1 (паддинг/другой тип/хвост) — выходим
		}
		if hex.EncodeToString(h.dcid) != key {
			break // чужой DCID в склейке — не часть этого рукопожатия
		}
		pt, _, ok := unprotect(datagram[off:], h, k, iv, hp)
		if !ok {
			a.failed = true
			r.stats.Failed++
			return "", false
		}
		pieces, ok := collectCryptoPieces(pt)
		if !ok {
			a.failed = true
			r.stats.Failed++
			return "", false
		}
		// Куски копируем: pt — временный буфер этого вызова, а сборка живёт
		// между вызовами. Параллельно сторожим предел байт против
		// враждебного потока.
		for _, p := range pieces {
			if a.bytes+len(p.data) > reasmMaxBytes {
				a.failed = true
				a.pieces = nil
				r.stats.Failed++
				return "", false
			}
			cp := make([]byte, len(p.data))
			copy(cp, p.data)
			a.pieces = append(a.pieces, cryptoPiece{offset: p.offset, data: cp})
			a.bytes += len(cp)
		}
		off += h.pnOffset + h.length
	}

	hello, ok := stitch(a.pieces)
	if !ok {
		r.stats.Pending++
		return "", false // непрерывного префикса с нуля пока нет — ждём ещё
	}
	ch, err := tlsparse.ParseClientHelloMessage(hello)
	if err != nil {
		// Обрезанное сообщение (ClientHello ещё не весь) — штатное ожидание
		// следующих Initial. Прочие ошибки — это не разбираемый ClientHello,
		// дальше по DCID делать нечего.
		if errors.Is(err, tlsparse.ErrFragmentedHandshake) || errors.Is(err, tlsparse.ErrIncomplete) {
			r.stats.Pending++
			return "", false
		}
		a.failed = true
		a.pieces = nil
		r.stats.Failed++
		return "", false
	}

	// ClientHello собран целиком — фиксируем вердикт и освобождаем буфер.
	a.solved = true
	a.pieces = nil
	if sni, ok := ch.SNI(hello); ok {
		a.sni = string(sni)
	}
	r.tally(a.sni)
	return a.sni, a.sni != ""
}

// tally учитывает исход собранного ClientHello: имя найдено или его нет.
// Считается исход каждого вызова (включая повторы из кэша) — это показывает
// активность на проводе, а не число уникальных соединений.
func (r *Reassembler) tally(sni string) {
	if sni != "" {
		r.stats.Resolved++
	} else {
		r.stats.NoSNI++
	}
}

// sweep удаляет стухшие сборки, но не чаще reasmSweepEvery: иначе проход по
// карте стоил бы O(n) на каждый пакет QUIC.
func (r *Reassembler) sweep(now time.Time) {
	if now.Sub(r.lastSweep) < reasmSweepEvery {
		return
	}
	r.lastSweep = now
	for key, a := range r.conns {
		if now.Sub(a.seen) > reasmTTL {
			delete(r.conns, key)
		}
	}
}
