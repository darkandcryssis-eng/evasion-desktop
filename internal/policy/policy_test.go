package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
)

const testVantage = core.VantageID("vtest")

// splitStrategy — стратегия с разрезом по смещению. Нужна только как
// отличимое по идентификатору значение: сам разрез здесь не исполняется.
func splitStrategy(offset int) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: offset, Order: strategy.FragForward},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right:  &strategy.Action{Kind: core.ActionSend},
		},
	}}}
}

func mustSnapshot(t *testing.T, entries ...Entry) *Snapshot {
	t.Helper()
	s, err := NewSnapshot(testVantage, 1, entries)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	return s
}

func TestSnapshotMatchesDomainAndSubdomain(t *testing.T) {
	snap := mustSnapshot(t, Entry{Domain: "youtube.com", Strategy: splitStrategy(5)})

	for _, host := range []string{"youtube.com", "www.youtube.com", "a.b.youtube.com"} {
		sel, ok := snap.Lookup(host, "")
		if !ok || sel.Strategy == nil {
			t.Fatalf("имя %q должно попадать в радиус", host)
		}
	}
}

// TestSnapshotDoesNotMatchSiblingName закрепляет границу суффикса: совпадение
// только по границе метки. Без этого "notyoutube.com" попал бы в радиус
// "youtube.com", и стратегия применялась бы к чужому сайту.
func TestSnapshotDoesNotMatchSiblingName(t *testing.T) {
	snap := mustSnapshot(t, Entry{Domain: "youtube.com", Strategy: splitStrategy(5)})

	for _, host := range []string{"notyoutube.com", "youtube.com.evil.net", "xyoutube.com", "com"} {
		if _, ok := snap.Lookup(host, ""); ok {
			t.Fatalf("имя %q не должно попадать в радиус", host)
		}
	}
}

// TestSnapshotMostSpecificRecordWins проверяет, что итог задан точностью
// записи, а не порядком записей: иначе решение зависело бы от того, в каком
// порядке control перечислил радиус.
func TestSnapshotMostSpecificRecordWins(t *testing.T) {
	broad := splitStrategy(5)
	narrow := splitStrategy(77)

	// Порядок записей намеренно обратный ожидаемому приоритету.
	snap := mustSnapshot(t,
		Entry{Domain: "www.youtube.com", Strategy: narrow},
		Entry{Domain: "youtube.com", Strategy: broad},
	)

	sel, ok := snap.Lookup("www.youtube.com", "")
	if !ok {
		t.Fatal("имя должно попадать в радиус")
	}
	if sel.Strategy != narrow {
		t.Fatal("должна выигрывать более точная запись www.youtube.com")
	}

	// Поддомен более точной записи наследует её же.
	if sel, _ := snap.Lookup("m.www.youtube.com", ""); sel.Strategy != narrow {
		t.Fatal("поддомен точной записи должен наследовать её стратегию")
	}
	// Соседний поддомен остаётся за общей записью.
	if sel, _ := snap.Lookup("music.youtube.com", ""); sel.Strategy != broad {
		t.Fatal("music.youtube.com должен попасть под общую запись")
	}
}

// TestSnapshotExclusionOverridesBroaderRecord проверяет исключение:
// запись с nil-стратегией перекрывает более общую запись и при этом
// отличается от «записи нет» вторым результатом Lookup.
func TestSnapshotExclusionOverridesBroaderRecord(t *testing.T) {
	snap := mustSnapshot(t,
		Entry{Domain: "youtube.com", Strategy: splitStrategy(5)},
		Entry{Domain: "api.youtube.com"},
	)

	sel, ok := snap.Lookup("api.youtube.com", "")
	if !ok {
		t.Fatal("исключение обязано считаться попаданием в таблицу")
	}
	if sel.Strategy != nil {
		t.Fatal("к исключённому имени стратегия применяться не должна")
	}
	if sel.ID != "" {
		t.Fatalf("у пустого выбора не должно быть идентификатора, получено %q", sel.ID)
	}

	// Поддомен исключения тоже исключён.
	if sel, ok := snap.Lookup("v1.api.youtube.com", ""); !ok || sel.Strategy != nil {
		t.Fatal("поддомен исключения должен наследовать исключение")
	}
	// Вне исключения общая запись продолжает действовать.
	if sel, _ := snap.Lookup("www.youtube.com", ""); sel.Strategy == nil {
		t.Fatal("общая запись должна действовать за пределами исключения")
	}
	// А имени вне радиуса не соответствует вообще ничего.
	if _, ok := snap.Lookup("example.com", ""); ok {
		t.Fatal("имя вне радиуса не должно считаться попаданием")
	}
}

// TestSnapshotSNIBeatsHost закрепляет приоритет SNI: DPI судит по имени из
// ClientHello, значит и стратегия выбирается по нему.
func TestSnapshotSNIBeatsHost(t *testing.T) {
	byHost := splitStrategy(5)
	bySNI := splitStrategy(77)
	snap := mustSnapshot(t,
		Entry{Domain: "front.example.net", Strategy: byHost},
		Entry{Domain: "youtube.com", Strategy: bySNI},
	)

	sel, ok := snap.Lookup("front.example.net", "www.youtube.com")
	if !ok {
		t.Fatal("соединение должно попадать в радиус")
	}
	if sel.Strategy != bySNI {
		t.Fatal("при расхождении имён должна выигрывать запись по SNI")
	}
}

func TestSnapshotFallsBackToHostWithoutSNI(t *testing.T) {
	snap := mustSnapshot(t, Entry{Domain: "youtube.com", Strategy: splitStrategy(5)})

	// Не-TLS соединение: SNI пуст, остаётся host.
	if sel, ok := snap.Lookup("www.youtube.com", ""); !ok || sel.Strategy == nil {
		t.Fatal("без SNI решение должно приниматься по host")
	}
	// SNI есть, но вне радиуса — host всё равно проверяется.
	if sel, ok := snap.Lookup("www.youtube.com", "cdn.example.net"); !ok || sel.Strategy == nil {
		t.Fatal("несовпадение по SNI не должно отменять проверку host")
	}
}

// TestSnapshotCaseAndTrailingDot проверяет, что форма записи имени не влияет
// на решение: регистр и завершающая точка в DNS незначащи, а приходят они из
// запроса приложения, то есть как угодно.
func TestSnapshotCaseAndTrailingDot(t *testing.T) {
	snap := mustSnapshot(t, Entry{Domain: "YouTube.COM.", Strategy: splitStrategy(5)})

	for _, host := range []string{
		"youtube.com", "YOUTUBE.COM", "WwW.YouTube.Com", "www.youtube.com.", " www.youtube.com ",
	} {
		if sel, ok := snap.Lookup(host, ""); !ok || sel.Strategy == nil {
			t.Fatalf("имя %q должно совпадать независимо от формы записи", host)
		}
	}
}

// TestAddressRecordsRejected запирает инвариант, на котором держится
// отсутствие сопоставления по IP: запись, похожая на адрес, в снимок не
// попадает.
//
// Это проверка именно инварианта, а не поведения. Поведение («адрес не
// совпадает с радиусом») из инварианта следует: всякий суффикс IPv4 состоит
// из цифр и точек, а IPv6 содержит двоеточие, и ни то, ни другое записью быть
// не может. Поэтому горячий путь адреса не проверяет, а падать при поломке
// обязан этот тест: ослабь кто-нибудь canonicalDomain — и сопоставление по
// адресам появится молча.
func TestAddressRecordsRejected(t *testing.T) {
	for _, domain := range []string{
		"142.250.185.78", "250.185.78", "185.78", "78", "1.1", "127.0.0.1",
		"2a00:1450:4010:c0f::8a", "::ffff:192.168.1.1",
	} {
		if _, err := NewSnapshot(testVantage, 1, []Entry{{Domain: domain, Strategy: splitStrategy(6)}}); err == nil {
			t.Fatalf("запись %q похожа на адрес и должна быть отвергнута", domain)
		}
	}

	// Следствие инварианта: адрес не попадает в радиус, заданный именами.
	snap := mustSnapshot(t, Entry{Domain: "youtube.com", Strategy: splitStrategy(5)})
	for _, host := range []string{"142.250.185.78", "2a00:1450:4010:c0f::8a", "127.0.0.1", "::ffff:192.168.1.1"} {
		if _, ok := snap.Lookup(host, ""); ok {
			t.Fatalf("адрес %q не должен сопоставляться с радиусом", host)
		}
	}
}

func TestSnapshotEmptyMatchesNothing(t *testing.T) {
	snap := mustSnapshot(t)
	if _, ok := snap.Lookup("youtube.com", "www.youtube.com"); ok {
		t.Fatal("пустой снимок не должен совпадать ни с чем")
	}
	if snap.Len() != 0 {
		t.Fatalf("длина пустого снимка = %d", snap.Len())
	}
}

func TestNilSnapshotIsSafe(t *testing.T) {
	var snap *Snapshot
	if sel, ok := snap.Lookup("youtube.com", ""); ok || sel.Strategy != nil {
		t.Fatal("нулевой снимок не должен ничего применять")
	}
	if snap.Rev() != 0 || snap.Len() != 0 || snap.VantageID() != "" || snap.Domains() != nil {
		t.Fatal("нулевой снимок должен отвечать нулевыми значениями, а не паниковать")
	}
}

// TestSnapshotIDMatchesComputeID: идентификатор в выборе обязан совпадать с
// тем, что вычисляет strategy.ComputeID, иначе телеметрия приписала бы исход
// другой стратегии.
func TestSnapshotIDMatchesComputeID(t *testing.T) {
	s := splitStrategy(5)
	want, err := strategy.ComputeID(s)
	if err != nil {
		t.Fatalf("ComputeID: %v", err)
	}

	snap := mustSnapshot(t, Entry{Domain: "youtube.com", Strategy: s})
	sel, _ := snap.Lookup("youtube.com", "")
	if sel.ID != want {
		t.Fatalf("идентификатор = %q, ожидался %q", sel.ID, want)
	}
}

// TestSnapshotSharedStrategyKeepsOneID: общая стратегия у нескольких записей
// даёт один и тот же идентификатор (хеш считается один раз).
func TestSnapshotSharedStrategyKeepsOneID(t *testing.T) {
	s := splitStrategy(5)
	snap := mustSnapshot(t,
		Entry{Domain: "youtube.com", Strategy: s},
		Entry{Domain: "discord.com", Strategy: s},
	)
	a, _ := snap.Lookup("youtube.com", "")
	b, _ := snap.Lookup("discord.com", "")
	if a.ID == "" || a.ID != b.ID {
		t.Fatalf("идентификаторы общей стратегии разошлись: %q и %q", a.ID, b.ID)
	}
}

func TestNewSnapshotRejectsBadEntries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		domain string
	}{
		{"пустой", ""},
		{"только точки", "..."},
		{"пустая метка", "www..youtube.com"},
		{"не ASCII", "ютуб.рф"},
		{"звёздочка", "*.youtube.com"},
		{"с портом", "youtube.com:443"},
		{"ссылка", "https://youtube.com"},
		{"адрес IPv4", "142.250.185.78"},
		{"адрес IPv6", "2a00:1450:4010:c0f::8a"},
		{"слишком длинный", strings.Repeat("a.", 130) + "com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSnapshot(testVantage, 1, []Entry{{Domain: tc.domain, Strategy: splitStrategy(5)}}); err == nil {
				t.Fatalf("домен %q должен быть отвергнут", tc.domain)
			}
		})
	}
}

func TestNewSnapshotRejectsDuplicateDomain(t *testing.T) {
	// Дубликат неочевиден: записан он в разной форме, а домен один и тот же.
	_, err := NewSnapshot(testVantage, 1, []Entry{
		{Domain: "youtube.com", Strategy: splitStrategy(5)},
		{Domain: "YouTube.com.", Strategy: splitStrategy(77)},
	})
	if err == nil {
		t.Fatal("повторный домен должен быть отвергнут")
	}
	if !strings.Contains(err.Error(), "дважды") {
		t.Fatalf("ошибка должна называть причину, получено: %v", err)
	}
}

func TestNewSnapshotRequiresVantageAndRev(t *testing.T) {
	if _, err := NewSnapshot("", 1, nil); !errors.Is(err, errNoVantage) {
		t.Fatalf("ошибка = %v, ожидалась errNoVantage", err)
	}
	if _, err := NewSnapshot(testVantage, 0, nil); !errors.Is(err, errZeroRev) {
		t.Fatalf("ошибка = %v, ожидалась errZeroRev", err)
	}
}

func TestSnapshotKeepsVantageAndRev(t *testing.T) {
	snap, err := NewSnapshot("vantage-7", 42, []Entry{{Domain: "youtube.com", Strategy: splitStrategy(5)}})
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	if snap.VantageID() != "vantage-7" || snap.Rev() != 42 {
		t.Fatalf("снимок = (%q, %d), ожидалось (vantage-7, 42)", snap.VantageID(), snap.Rev())
	}
}

func TestSnapshotDomainsSortedAndNormalized(t *testing.T) {
	snap := mustSnapshot(t,
		Entry{Domain: "YouTube.com", Strategy: splitStrategy(5)},
		Entry{Domain: ".discord.com.", Strategy: splitStrategy(6)},
	)
	got := snap.Domains()
	want := []string{"discord.com", "youtube.com"}
	if len(got) != len(want) {
		t.Fatalf("домены = %v, ожидались %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("домены = %v, ожидались %v", got, want)
		}
	}
}

// TestCanonicalDomainAgreesWithFoldName — предусловие работы таблицы: ключи
// строятся canonicalDomain, а ищутся foldName. Разойдись эти две функции в
// приведении регистра или в отрезании точек, таблица молча перестала бы
// совпадать, и радиус выглядел бы настроенным, ничего не делая.
func TestCanonicalDomainAgreesWithFoldName(t *testing.T) {
	for _, name := range []string{
		"youtube.com", "YouTube.Com", "WWW.YOUTUBE.COM", "youtube.com.",
		".youtube.com", " youtube.com ", "a-b_c.example.org", "xn--80aswg.xn--p1ai",
	} {
		canon, err := canonicalDomain(name)
		if err != nil {
			t.Fatalf("canonicalDomain(%q): %v", name, err)
		}
		var buf [maxNameLen]byte
		n, ok := foldName(buf[:], name)
		if !ok {
			t.Fatalf("foldName(%q) отказал", name)
		}
		// foldName ведущую точку не отрезает: имя ".youtube.com" обходится по
		// меткам и доходит до "youtube.com" уже в цикле поиска.
		folded := strings.TrimPrefix(string(buf[:n]), ".")
		if folded != canon {
			t.Fatalf("для %q canonicalDomain = %q, foldName = %q", name, canon, folded)
		}
	}
}

// TestTableSatisfiesProvider: policy подставляется прокси вместо
// StaticProvider, и сам proxy при этом не меняется.
func TestTableSatisfiesProvider(t *testing.T) {
	var prov proxy.StrategyProvider = NewTable()
	if sel := prov.Select(proxy.ConnMeta{Host: "youtube.com"}); sel.Strategy != nil {
		t.Fatal("пустая таблица должна пропускать соединение без изменений")
	}
}
