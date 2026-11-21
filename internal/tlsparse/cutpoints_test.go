package tlsparse

import (
	"strings"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
)

func TestDomainCutSplitsBlockedLabelBehindCDNPrefix(t *testing.T) {
	for _, name := range []string{"rr5---sn-oj5hn5-5t.googlevideo.com", "rr1---sn-jvhnu5g-n8vk.googlevideo.com", "www.youtube.com", "i.ytimg.com", "example.org."} {
		data := realClientHello(t, name)
		ch, e := ParseClientHello(data)
		if e != nil {
			t.Fatal(e)
		}
		for _, partial := range []bool{false, true} {
			if partial {
				var ok bool
				ch, ok = ParseClientHelloLenient(data[:ch.SNIOff+ch.SNILen])
				if !ok {
					t.Fatal("partial hello lost complete SNI")
				}
			}
			host, _ := ch.SNI(data)
			points := ch.CutPointsWithSNI(nil, host)
			found := false
			prev := -1
			for _, p := range points {
				if p.Offset < prev {
					t.Fatal("unordered cuts")
				}
				prev = p.Offset
				if p.Kind == core.CutInsideSLD {
					found = true
					left, right := string(data[ch.SNIOff:p.Offset]), string(data[p.Offset:ch.SNIOff+ch.SNILen])
					if left == "" || right == "" || left+right != strings.TrimSuffix(name, ".") {
						t.Fatal("corrupted split")
					}
					if strings.HasSuffix(name, "googlevideo.com") && (strings.Contains(left, "googlevideo") || strings.Contains(right, "googlevideo")) {
						t.Fatal("blocked label remained in one segment")
					}
				}
			}
			if !found {
				t.Fatal("domain cut missing", name, partial)
			}
		}
	}
}

func TestDomainCutKeepsCallerPrefixAndReusesBuffer(t *testing.T) {
	data := realClientHello(t, "rr5---sn-oj5hn5-5t.googlevideo.com")
	ch, _ := ParseClientHello(data)
	host, _ := ch.SNI(data)
	buf := make([]core.CutPoint, 1, 16)
	buf[0] = core.CutPoint{Kind: core.CutAfterSNI, Offset: 99999}
	points := ch.CutPointsWithSNI(buf, host)
	if points[0] != buf[0] {
		t.Fatal("caller prefix moved")
	}
	if n := testing.AllocsPerRun(100, func() { ch.CutPointsWithSNI(buf[:0], host) }); n != 0 {
		t.Fatalf("hot path allocates: %v", n)
	}
	for _, name := range []string{"a.com", "", "x"} {
		ch.SNILen = len(name)
		for _, p := range ch.CutPointsWithSNI(buf[:0], []byte(name)) {
			if p.Kind == core.CutInsideSLD {
				t.Fatal("unsplittable label has a cut")
			}
		}
	}
}

func TestCutPointsOnRealHello(t *testing.T) {
	const name = "www.example.com"
	data := realClientHello(t, name)

	ch, err := ParseClientHello(data)
	if err != nil {
		t.Fatal(err)
	}

	points := ch.CutPoints(nil)
	if len(points) == 0 {
		t.Fatal("точек разреза не найдено")
	}

	// Все точки обязаны лежать внутри буфера и идти по возрастанию: иначе
	// desync, резавший по ним поток, вышел бы за границы или перепутал порядок
	// частей.
	prev := -1
	seen := make(map[core.CutKind]int)
	for _, p := range points {
		if p.Offset < 0 || p.Offset > len(data) {
			t.Fatalf("точка %s со смещением %d вне буфера длиной %d",
				p.Kind, p.Offset, len(data))
		}
		if p.Offset < prev {
			t.Fatalf("точки не упорядочены: %s на %d после %d", p.Kind, p.Offset, prev)
		}
		prev = p.Offset
		seen[p.Kind] = p.Offset
	}

	// Для сообщения с SNI обязаны присутствовать все виды точек.
	for _, want := range []core.CutKind{
		core.CutRecordHeader, core.CutHandshakeHeader, core.CutExtensions,
		core.CutBeforeSNI, core.CutInsideSNI, core.CutAfterSNI,
	} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("точка разреза %s не найдена", want)
		}
	}

	// Проверяем смысл точек по содержимому: до core.CutBeforeSNI имени ещё нет,
	// после core.CutAfterSNI — уже нет, а разрез внутри делит имя на две непустые
	// части.
	if got := string(data[seen[core.CutBeforeSNI]:seen[core.CutAfterSNI]]); got != name {
		t.Fatalf("между before_sni и after_sni лежит %q, ожидалось %q", got, name)
	}
	inside := seen[core.CutInsideSNI]
	left := string(data[seen[core.CutBeforeSNI]:inside])
	right := string(data[inside:seen[core.CutAfterSNI]])
	if left == "" || right == "" {
		t.Fatalf("разрез внутри имени дал пустую часть: %q | %q", left, right)
	}
	if left+right != name {
		t.Fatalf("части имени %q + %q не дают %q", left, right, name)
	}
}

func TestCutPointsWithoutSNI(t *testing.T) {
	data := realClientHello(t, "")
	ch, err := ParseClientHello(data)
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range ch.CutPoints(nil) {
		switch p.Kind {
		case core.CutBeforeSNI, core.CutInsideSNI, core.CutAfterSNI:
			t.Fatalf("точка %s не должна существовать без SNI", p.Kind)
		}
	}
}

// TestCutPointsAppendsToProvidedSlice фиксирует контракт: функция добавляет к
// переданному срезу, а не создаёт свой. Именно это позволяет переиспользовать
// буфер на горячем пути.
func TestCutPointsAppendsToProvidedSlice(t *testing.T) {
	data := realClientHello(t, "example.org")
	ch, err := ParseClientHello(data)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]core.CutPoint, 0, 16)
	first := ch.CutPoints(buf)
	second := ch.CutPoints(first)
	if len(second) != 2*len(first) {
		t.Fatalf("повторный вызов дал %d точек, ожидалось %d", len(second), 2*len(first))
	}
}

func TestCutKindStringsAreDistinct(t *testing.T) {
	kinds := []core.CutKind{
		core.CutRecordHeader, core.CutHandshakeHeader, core.CutBeforeSNI,
		core.CutInsideSNI, core.CutAfterSNI, core.CutExtensions,
	}
	seen := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		s := k.String()
		if s == "" || s == "unknown" {
			t.Fatalf("вид %d не имеет метки", uint8(k))
		}
		if seen[s] {
			t.Fatalf("метка %q повторяется", s)
		}
		seen[s] = true
	}
}

// TestCutPointsShortSNI проверяет, что для имени из одного байта точка внутри
// не создаётся: разрез по нулевой границе ничего не разделяет и лишь расходует
// бюджет живых прогонов.
func TestCutPointsShortSNI(t *testing.T) {
	ch := ClientHello{
		Record:       Record{PayloadOff: recordHeaderLen, PayloadLen: 100},
		HandshakeOff: recordHeaderLen + handshakeHeaderLen,
		SNIOff:       50,
		SNILen:       1,
	}
	for _, p := range ch.CutPoints(nil) {
		if p.Kind == core.CutInsideSNI {
			t.Fatal("для односимвольного имени точка inside_sni не нужна")
		}
	}
}
