package tlsfake

import "crypto/rand"

// Refresh перезаписывает на месте все «случайные» поля ClientHello в buf
// свежими байтами из fill: random, session_id, тела key_share и нагрузку ECH.
// Длина и структура записи не меняются, поэтому приём tcp_overlap, завязанный
// на размер cover'а, работает как прежде.
//
// Зачем. Пресет с одним и тем же random на каждом соединении — готовая
// сигнатура инструмента обхода: настоящий клиент никогда не повторяет random.
// Refresh делает каждый фейк уникальным, оставляя SNI и набор расширений.
//
// Возвращает false, если buf не разобрался как ClientHello; buf при этом не
// тронут. fill обязан заполнить срез целиком (как crypto/rand.Read).
func Refresh(buf []byte, fill func([]byte)) bool {
	if fill == nil {
		return false
	}
	spans, ok := randomSpans(buf)
	if !ok {
		return false
	}
	for _, s := range spans {
		fill(buf[s.from:s.to])
	}
	return true
}

type span struct{ from, to int }

const (
	extKeyShare = 0x0033
	extECH      = 0xfe0d
	// groupSecp256r1 и соседние кривые NIST: первый байт ключа — формат точки
	// (0x04, uncompressed), его сохраняем.
	groupSecp256r1 = 0x0017
	groupSecp384r1 = 0x0018
	groupSecp521r1 = 0x0019
)

// randomSpans находит диапазоны случайных полей. Разбор строгий по длинам:
// любой выход за границу — отказ, без частичного результата.
func randomSpans(buf []byte) ([]span, bool) {
	// Запись: тип(1) версия(2) длина(2); рукопожатие: тип(1) длина(3).
	if len(buf) < 9 || buf[0] != 0x16 || buf[5] != 0x01 {
		return nil, false
	}
	end := 5 + (int(buf[3])<<8 | int(buf[4]))
	if end > len(buf) {
		return nil, false
	}
	p := 9 + 2 // версия клиента
	if p+32+1 > end {
		return nil, false
	}
	spans := []span{{p, p + 32}}
	p += 32
	sid := int(buf[p])
	p++
	if p+sid > end {
		return nil, false
	}
	if sid > 0 {
		spans = append(spans, span{p, p + sid})
	}
	p += sid
	if p+2 > end {
		return nil, false
	}
	p += 2 + (int(buf[p])<<8 | int(buf[p+1])) // шифронаборы
	if p+1 > end {
		return nil, false
	}
	p += 1 + int(buf[p]) // методы сжатия
	if p == end {
		return spans, true // без расширений
	}
	if p+2 > end {
		return nil, false
	}
	extEnd := p + 2 + (int(buf[p])<<8 | int(buf[p+1]))
	p += 2
	if extEnd > end {
		return nil, false
	}
	for p < extEnd {
		if p+4 > extEnd {
			return nil, false
		}
		typ := int(buf[p])<<8 | int(buf[p+1])
		n := int(buf[p+2])<<8 | int(buf[p+3])
		p += 4
		if p+n > extEnd {
			return nil, false
		}
		switch typ {
		case extKeyShare:
			ks, ok := keyShareSpans(buf, p, p+n)
			if !ok {
				return nil, false
			}
			spans = append(spans, ks...)
		case extECH:
			// type(1) kdf(2) aead(2) config_id(1) enc_len(2) enc payload_len(2) payload
			q := p + 6
			if q+2 <= p+n {
				encLen := int(buf[q])<<8 | int(buf[q+1])
				q += 2
				if q+encLen+2 <= p+n {
					if encLen > 0 {
						spans = append(spans, span{q, q + encLen})
					}
					q += encLen
					pl := int(buf[q])<<8 | int(buf[q+1])
					q += 2
					if q+pl <= p+n && pl > 0 {
						spans = append(spans, span{q, q + pl})
					}
				}
			}
		}
		p += n
	}
	return spans, true
}

func keyShareSpans(buf []byte, p, end int) ([]span, bool) {
	if p+2 > end {
		return nil, false
	}
	listEnd := p + 2 + (int(buf[p])<<8 | int(buf[p+1]))
	p += 2
	if listEnd > end {
		return nil, false
	}
	var out []span
	for p < listEnd {
		if p+4 > listEnd {
			return nil, false
		}
		group := int(buf[p])<<8 | int(buf[p+1])
		n := int(buf[p+2])<<8 | int(buf[p+3])
		p += 4
		if p+n > listEnd {
			return nil, false
		}
		from := p
		switch group {
		case groupSecp256r1, groupSecp384r1, groupSecp521r1:
			from++ // байт формата точки
		}
		if from < p+n {
			out = append(out, span{from, p + n})
		}
		p += n
	}
	return out, true
}

// FreshGoogleClientHello — GoogleClientHello со свежими случайными полями.
func FreshGoogleClientHello() []byte {
	b := GoogleClientHello()
	Refresh(b, func(p []byte) { _, _ = rand.Read(p) })
	return b
}

// EqualIgnoringRandom сообщает, совпадают ли два ClientHello во всём, кроме
// полей, которые перезаписывает Refresh. Нужен проверкам, сверяющим фейк
// с пресетом: после Refresh побайтовое равенство уже не выполняется.
func EqualIgnoringRandom(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	sa, okA := randomSpans(a)
	sb, okB := randomSpans(b)
	if !okA || !okB || len(sa) != len(sb) {
		return string(a) == string(b)
	}
	a, b = copyBytes(a), copyBytes(b)
	zero := func(p []byte) { clear(p) }
	Refresh(a, zero)
	Refresh(b, zero)
	return string(a) == string(b)
}
