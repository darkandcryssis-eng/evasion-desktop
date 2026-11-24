package tlsfake

import (
	"bytes"
	"testing"

	"github.com/fitting-1c/evasion/internal/tlsparse"
)

func fillWith(b byte) func([]byte) {
	return func(p []byte) {
		for i := range p {
			p[i] = b
		}
	}
}

func TestRefreshKeepsStructureAndSNI(t *testing.T) {
	cases := map[string][]byte{
		"google":   GoogleClientHello(),
		"cover681": CoverClientHello681(),
		"apple681": CoverClientHello681Apple(),
	}
	for name, orig := range cases {
		t.Run(name, func(t *testing.T) {
			before, err := tlsparse.ParseClientHello(orig)
			if err != nil {
				t.Fatalf("пресет не разбирается: %v", err)
			}
			wantSNI, _ := before.SNI(orig)

			got := copyBytes(orig)
			if !Refresh(got, fillWith(0xEE)) {
				t.Fatal("Refresh отказал на валидном ClientHello")
			}
			if len(got) != len(orig) {
				t.Fatalf("длина изменилась: %d → %d", len(orig), len(got))
			}
			if bytes.Equal(got, orig) {
				t.Fatal("Refresh ничего не изменил")
			}
			after, err := tlsparse.ParseClientHello(got)
			if err != nil {
				t.Fatalf("после Refresh запись не разбирается: %v", err)
			}
			if sni, _ := after.SNI(got); !bytes.Equal(sni, wantSNI) {
				t.Fatalf("SNI изменился: %q → %q", wantSNI, sni)
			}
			// random — байты 11..43.
			if !bytes.Equal(got[11:43], bytes.Repeat([]byte{0xEE}, 32)) {
				t.Fatal("random не перезаписан")
			}
			// Вне случайных полей байты прежние: считаем изменённые диапазоны.
			spans, _ := randomSpans(orig)
			mask := make([]bool, len(orig))
			for _, s := range spans {
				for i := s.from; i < s.to; i++ {
					mask[i] = true
				}
			}
			for i := range orig {
				if !mask[i] && orig[i] != got[i] {
					t.Fatalf("байт %d вне случайных полей изменён", i)
				}
			}
			if len(spans) < 3 {
				t.Fatalf("найдено %d случайных полей, ожидали random, session_id и key_share", len(spans))
			}
		})
	}
}

func TestRefreshRejectsGarbage(t *testing.T) {
	for _, buf := range [][]byte{nil, {0x16}, bytes.Repeat([]byte{0x17}, 64), GoogleClientHello()[:40]} {
		cp := copyBytes(buf)
		if Refresh(cp, fillWith(0xEE)) {
			t.Fatalf("Refresh принял мусор длиной %d", len(buf))
		}
		if !bytes.Equal(cp, buf) {
			t.Fatal("Refresh изменил буфер, который отверг")
		}
	}
}

func FuzzRefresh(f *testing.F) {
	f.Add(GoogleClientHello())
	f.Add(CoverClientHello681())
	f.Fuzz(func(t *testing.T, buf []byte) {
		cp := copyBytes(buf)
		Refresh(cp, fillWith(0xEE))
		if len(cp) != len(buf) {
			t.Fatal("длина изменилась")
		}
	})
}
