package quic

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// TestSplitClientInitialInSNI — нацеленный разрез делит имя сервера пополам:
// место попадает строго внутрь SNI, ни одна часть не несёт имени целиком, а обе
// с общим DCID собираются обратно в example.com.
func TestSplitClientInitialInSNI(t *testing.T) {
	orig := unhex(t, clientInitialRFC9001)

	// Куда приём обязан целиться: середина имени сервера.
	hdr, hello, ch, ok := prepareSplit(orig)
	if !ok {
		t.Fatal("prepareSplit не удался на эталоне")
	}
	if ch.SNILen < 2 {
		t.Fatalf("у эталона слишком короткий SNI: %d", ch.SNILen)
	}
	at := ch.SNIOff + ch.SNILen/2
	if at <= ch.SNIOff || at >= ch.SNIOff+ch.SNILen {
		t.Fatalf("разрез %d не попал строго внутрь имени [%d,%d)", at, ch.SNIOff, ch.SNIOff+ch.SNILen)
	}

	parts, ok := SplitClientInitialInSNI(orig)
	if !ok || len(parts) != 2 {
		t.Fatalf("разрез по SNI не удался: ok=%v частей=%d", ok, len(parts))
	}

	// Должно совпасть байт в байт с разрезом ровно в середину имени.
	want, ok := splitAt(hdr, hello, at)
	if !ok || !bytes.Equal(parts[0], want[0]) || !bytes.Equal(parts[1], want[1]) {
		t.Fatal("SplitClientInitialInSNI разрезал не в середине имени")
	}

	// Первая часть одна имени не выдаёт; обе вместе собираются в example.com.
	if sni, ok := NewReassembler().Offer(parts[0], time.Now()); ok {
		t.Fatalf("первая часть не должна давать SNI, получено %q", sni)
	}
	r := NewReassembler()
	now := time.Now()
	r.Offer(parts[0], now)
	if sni, ok := r.Offer(parts[1], now); !ok || sni != "example.com" {
		t.Fatalf("обе части должны собраться в example.com, получено %q ok=%v", sni, ok)
	}
}

// TestSplitClientInitialRoundTrip — переписанный Initial разложен на две части:
// по отдельности первая часть SNI не выдаёт (DPI, читающий только первый пакет,
// имени не соберёт), а вместе с общим DCID они собираются в исходный SNI, как
// это сделает и сервер. Каждая часть — валидный клиентский Initial, добитый до
// 1200 байт.
func TestSplitClientInitialRoundTrip(t *testing.T) {
	orig := unhex(t, clientInitialRFC9001)
	hello := rfcClientHello(t)
	at := len(hello) / 2

	parts, ok := SplitClientInitial(orig, at)
	if !ok {
		t.Fatal("разрез не удался на эталонном Initial")
	}
	if len(parts) != 2 {
		t.Fatalf("ожидалось 2 части, получено %d", len(parts))
	}
	for i, p := range parts {
		if len(p) < minInitialDatagram {
			t.Errorf("часть %d не добита до %d байт: %d", i, minInitialDatagram, len(p))
		}
		if _, ok := parseInitialHeader(p); !ok {
			t.Errorf("часть %d не разбирается как клиентский Initial", i)
		}
	}

	// Первая часть сама по себе целого ClientHello не несёт — SNI недоступен.
	if sni, ok := NewReassembler().Offer(parts[0], time.Now()); ok {
		t.Fatalf("первая часть одна не должна давать SNI, получено %q", sni)
	}

	// Обе части с общим DCID собираются обратно в тот же SNI.
	r := NewReassembler()
	now := time.Now()
	r.Offer(parts[0], now)
	if sni, ok := r.Offer(parts[1], now); !ok || sni != "example.com" {
		t.Fatalf("после обеих частей ожидался example.com, получено %q ok=%v", sni, ok)
	}
}

// TestSplitClientInitialRejects — разрез отвергается там, где он невозможен или
// бессмыслен: негодное место, не клиентский Initial, усечённая датаграмма.
// Отказ означает «не трогаем пакет» (1.6).
func TestSplitClientInitialRejects(t *testing.T) {
	orig := unhex(t, clientInitialRFC9001)
	hello := rfcClientHello(t)

	cases := []struct {
		name string
		data []byte
		at   int
	}{
		{"место разреза 0", orig, 0},
		{"место разреза = длине", orig, len(hello)},
		{"место разреза за пределами", orig, len(hello) + 100},
		{"не QUIC", []byte("this is not a quic initial at all!!!"), 10},
		{"усечённый Initial", orig[:len(orig)-100], 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := SplitClientInitial(tc.data, tc.at); ok {
				t.Errorf("ожидался отказ, получено согласие на разрез")
			}
		})
	}
}

// TestPeekSNI — имя достаётся из одного Initial; пакет-продолжение (CRYPTO не с
// нуля) имени не несёт.
func TestPeekSNI(t *testing.T) {
	orig := unhex(t, clientInitialRFC9001)
	if sni, ok := PeekSNI(orig); !ok || sni != "example.com" {
		t.Fatalf("PeekSNI на эталоне: ожидался example.com, получено %q ok=%v", sni, ok)
	}
	cont := buildClientInitial(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, 1, 100, []byte("continuation crypto, not a hello"))
	if sni, ok := PeekSNI(cont); ok {
		t.Fatalf("на пакете-продолжении имени быть не должно, получено %q", sni)
	}
}

// TestRewriteInitialReorder — переписанный пакет той же длины, с тем же номером,
// собирается сервером (и нашим сборщиком) в тот же SNI, но его первый CRYPTO-кадр
// идёт НЕ с нулевого смещения (в этом и десинк).
func TestRewriteInitialReorder(t *testing.T) {
	orig := unhex(t, clientInitialRFC9001)
	out, ok := RewriteInitialReorder(orig)
	if !ok {
		t.Fatal("переписать эталон не удалось")
	}
	if len(out) != len(orig) {
		t.Fatalf("длина датаграммы изменилась: было %d, стало %d", len(orig), len(out))
	}
	if sni, ok := NewReassembler().Offer(out, time.Now()); !ok || sni != "example.com" {
		t.Fatalf("переписанный Initial должен собираться в example.com, получено %q ok=%v", sni, ok)
	}
	// Первый CRYPTO-кадр переписанного пакета — не с нуля.
	hdr, okh := parseInitialHeader(out)
	if !okh {
		t.Fatal("переписанный пакет не разбирается как Initial")
	}
	k, iv, hp, _ := deriveClientKeys(hdr.dcid)
	pt, _, oku := unprotect(out, hdr, k, iv, hp)
	if !oku {
		t.Fatal("переписанный пакет не расшифровался")
	}
	pieces, _ := collectCryptoPieces(pt)
	if len(pieces) < 2 || pieces[0].offset == 0 {
		t.Fatalf("ожидался первый кадр не с нуля; кадров %d", len(pieces))
	}
}

// FuzzRewriteInitialReorder — произвольный ввод не роняет переписывание; если
// переписали, длина сохранена и результат разбирается как Initial.
func FuzzRewriteInitialReorder(f *testing.F) {
	seed, _ := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(clientInitialRFC9001))
	f.Add(seed)
	f.Add([]byte{0xc0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		out, ok := RewriteInitialReorder(data)
		if !ok {
			return
		}
		if len(out) != len(data) {
			t.Fatalf("длина изменилась при переписывании")
		}
		if _, pok := parseInitialHeader(out); !pok {
			t.Fatalf("переписанный пакет не разбирается как Initial")
		}
	})
}

// FuzzSplitClientInitial — произвольный ввод не роняет крафт (8.2); а если
// разрез согласован, его части обязаны быть разбираемыми клиентскими Initial.
func FuzzSplitClientInitial(f *testing.F) {
	seed, _ := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(clientInitialRFC9001))
	f.Add(seed, 50)
	f.Add([]byte{0xc0, 0, 0, 0, 1}, 1)
	f.Add([]byte(nil), 0)

	f.Fuzz(func(t *testing.T, data []byte, at int) {
		parts, ok := SplitClientInitial(data, at)
		if !ok {
			return
		}
		for _, p := range parts {
			if _, pok := parseInitialHeader(p); !pok {
				t.Fatalf("разрез вернул неразбираемую как Initial часть")
			}
		}
	})
}
