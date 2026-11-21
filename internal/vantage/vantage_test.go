package vantage

import (
	"errors"
	"net"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
)

// fakeSource — заданный набор интерфейсов. Нужен, чтобы отпечаток проверялся на
// известных данных: источник на основе стандартной библиотеки давал бы разный
// результат в песочнице и на рабочей машине, и тест ничего бы не доказывал.
type fakeSource struct {
	ifaces []Iface
	err    error
}

func (s fakeSource) Interfaces() ([]Iface, error) { return s.ifaces, s.err }

// ipnet собирает адрес с маской из записи вида "192.168.0.10/24".
func ipnet(t *testing.T, cidr string) net.IPNet {
	t.Helper()
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("разбор %q: %v", cidr, err)
	}
	return net.IPNet{IP: ip, Mask: n.Mask}
}

// mac собирает аппаратный адрес.
func mac(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	h, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("разбор MAC %q: %v", s, err)
	}
	return h
}

// homeNetwork — типовой набор: петлевой интерфейс, ДВА поднятых и один
// опущенный.
//
// Двух поднятых интерфейсов требует проверка независимости от порядка: при
// одном сортировать нечего, и проверка проходила бы, даже если сортировку
// убрать. Это выяснилось проверкой теста на способность провалиться.
func homeNetwork(t *testing.T) fakeSource {
	t.Helper()
	return fakeSource{ifaces: []Iface{
		{Name: "lo", Up: true, Loopback: true, Addrs: []net.IPNet{ipnet(t, "127.0.0.1/8")}},
		{Name: "eth0", Up: true, HardwareAddr: mac(t, "a8:a1:59:ed:73:4c"),
			Addrs: []net.IPNet{ipnet(t, "192.168.0.180/24")}},
		{Name: "tap0", Up: true, HardwareAddr: mac(t, "02:00:4c:4f:4f:50"),
			Addrs: []net.IPNet{ipnet(t, "172.16.3.2/16")}},
		{Name: "wlan0", Up: false, HardwareAddr: mac(t, "aa:bb:cc:dd:ee:ff"),
			Addrs: []net.IPNet{ipnet(t, "10.0.0.5/24")}},
	}}
}

func TestFingerprintStableAcrossCalls(t *testing.T) {
	src := homeNetwork(t)
	first, err := Fingerprint(src)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	second, err := Fingerprint(src)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if first != second {
		t.Fatalf("отпечаток нестабилен: %q и %q", first, second)
	}
	if first == "" {
		t.Fatal("отпечаток пуст при наличии поднятого интерфейса")
	}
}

func TestFingerprintIgnoresInterfaceOrder(t *testing.T) {
	// Порядок перечисления интерфейсов операционная система не гарантирует.
	// Если бы отпечаток от него зависел, смена сети обнаруживалась бы ложно
	// при каждом перезапуске.
	src := homeNetwork(t)
	want, err := Fingerprint(src)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}

	rev := make([]Iface, len(src.ifaces))
	for i, f := range src.ifaces {
		rev[len(src.ifaces)-1-i] = f
	}
	reversed := fakeSource{ifaces: rev}
	got, err := Fingerprint(reversed)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if got != want {
		t.Fatalf("отпечаток зависит от порядка интерфейсов: %q против %q", got, want)
	}
}

func TestFingerprintIgnoresAddressWithinSameNetwork(t *testing.T) {
	// Главное свойство: при повторном получении адреса по DHCP конкретный
	// адрес меняется, а сеть остаётся той же. Отпечаток по адресам давал бы
	// ложную смену сети при каждом продлении аренды.
	src := homeNetwork(t)
	want, err := Fingerprint(src)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}

	moved := homeNetwork(t)
	moved.ifaces[1].Addrs = []net.IPNet{ipnet(t, "192.168.0.57/24")}
	got, err := Fingerprint(moved)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if got != want {
		t.Fatalf("смена адреса внутри сети изменила отпечаток: %q против %q", got, want)
	}
}

func TestFingerprintChangesWithNetwork(t *testing.T) {
	src := homeNetwork(t)
	home, err := Fingerprint(src)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}

	other := homeNetwork(t)
	other.ifaces[1].Addrs = []net.IPNet{ipnet(t, "10.100.7.3/24")}
	away, err := Fingerprint(other)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if home == away {
		t.Fatal("переезд в другую сеть не изменил отпечаток")
	}
}

func TestFingerprintIgnoresDownAndLoopback(t *testing.T) {
	// Опущенный интерфейс и петля условий наблюдения не задают.
	src := homeNetwork(t)
	want, err := Fingerprint(src)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}

	// Оставляем только поднятые непетлевые — отпечаток обязан не измениться.
	trimmed := fakeSource{ifaces: []Iface{src.ifaces[1], src.ifaces[2]}}
	got, err := Fingerprint(trimmed)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if got != want {
		t.Fatalf("опущенный или петлевой интерфейс попал в отпечаток: %q против %q", got, want)
	}
}

func TestDetectKeepsLabelWhenInterfacesFail(t *testing.T) {
	// Недоступность подсказки не должна отменять основной способ задания точки
	// наблюдения. Но отпечаток при этом пуст, и об этом надо сообщить ошибкой.
	label := Label{Operator: "ОпСвязи", Region: "Регион", Access: core.AccessWired}
	v, err := Detect(label, fakeSource{err: errors.New("перечисление не удалось")})
	if err == nil {
		t.Fatal("ожидалась ошибка перечисления интерфейсов")
	}
	if v.Fingerprint != "" {
		t.Fatalf("отпечаток %q при неудачном перечислении", v.Fingerprint)
	}
	if v.Label.Operator != "опсвязи" {
		t.Fatalf("метка потеряна или не нормализована: %q", v.Label.Operator)
	}
	if v.ID == "" {
		t.Fatal("идентификатор не вычислен")
	}
}

func TestLabelNormalizationGivesSameID(t *testing.T) {
	// Разные записи одной метки обязаны давать один идентификатор, иначе
	// наблюдения одной точки разошлись бы по двум ключам из-за регистра.
	src := homeNetwork(t)
	a, err := Detect(Label{Operator: "  ОпСвязи ", Region: "Регион"}, src)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	b, err := Detect(Label{Operator: "опсвязи", Region: "регион"}, src)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if a.ID != b.ID {
		t.Fatalf("идентификаторы разошлись: %q и %q", a.ID, b.ID)
	}
}

func TestIDDependsOnLabelAndFingerprint(t *testing.T) {
	src := homeNetwork(t)
	base, err := Detect(Label{Operator: "a", Region: "r"}, src)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	// Другой оператор — другая точка наблюдения.
	other, err := Detect(Label{Operator: "b", Region: "r"}, src)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if base.ID == other.ID {
		t.Fatal("смена оператора не изменила идентификатор")
	}

	// Другой тип доступа — тоже: мобильные сети фильтруются иначе.
	mobile, err := Detect(Label{Operator: "a", Region: "r", Access: core.AccessMobile}, src)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if base.ID == mobile.ID {
		t.Fatal("смена типа доступа не изменила идентификатор")
	}

	// Другая сеть при той же метке — тоже, иначе оценки чужой сети
	// применялись бы как свои.
	moved := homeNetwork(t)
	moved.ifaces[1].Addrs = []net.IPNet{ipnet(t, "10.100.7.3/24")}
	elsewhere, err := Detect(Label{Operator: "a", Region: "r"}, moved)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if base.ID == elsewhere.ID {
		t.Fatal("переезд в другую сеть не изменил идентификатор")
	}
}

func TestNetworkChanged(t *testing.T) {
	cases := []struct {
		name     string
		prev     string
		cur      string
		expected bool
	}{
		{"та же сеть", "aaaa", "aaaa", false},
		{"другая сеть", "aaaa", "bbbb", true},
		{"прежний отпечаток неизвестен", "", "bbbb", false},
		{"текущий отпечаток неизвестен", "aaaa", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NetworkChanged(Vantage{Fingerprint: c.prev}, Vantage{Fingerprint: c.cur})
			if got != c.expected {
				t.Fatalf("NetworkChanged(%q,%q)=%t, ожидалось %t", c.prev, c.cur, got, c.expected)
			}
		})
	}
}

func TestNetworkChangedIgnoresLabel(t *testing.T) {
	// Смена метки — решение владельца, а не событие в сети. Путать их нельзя:
	// иначе правка конфига выглядела бы как переезд.
	prev := Vantage{Label: Label{Operator: "a"}, Fingerprint: "same"}
	cur := Vantage{Label: Label{Operator: "b"}, Fingerprint: "same"}
	if NetworkChanged(prev, cur) {
		t.Fatal("смена метки принята за смену сети")
	}
}

func TestDescribeIsData(t *testing.T) {
	// Пакет отдаёт данные, а не готовые подписи (2.2).
	src := homeNetwork(t)
	v, err := Detect(Label{Operator: "опсвязи", Region: "регион", Access: core.AccessMobile}, src)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	d := v.Describe()
	for _, k := range []string{"id", "operator", "region", "access", "fingerprint"} {
		if d[k] == "" {
			t.Fatalf("поле %q пусто: %+v", k, d)
		}
	}
	if d["access"] != "mobile" {
		t.Fatalf("тип доступа %q", d["access"])
	}
}

func TestSystemInterfacesWorks(t *testing.T) {
	// Проверка на настоящей машине, а не на поддельном источнике.
	//
	// Нужна потому, что все остальные тесты отпечатка работают на заданном
	// наборе интерфейсов и потому ничего не говорят о том, что получится на
	// рабочем компьютере. Если перечисление там отдаст интерфейсы без
	// аппаратных адресов или все поднятые окажутся отфильтрованы, отпечаток
	// выйдет пустым — и обнаружение смены сети молча перестанет работать.
	list, err := SystemInterfaces().Interfaces()
	if err != nil {
		t.Skipf("перечисление интерфейсов недоступно в этой среде: %v", err)
	}
	if len(list) == 0 {
		t.Skip("интерфейсов нет: вероятно, изолированная среда")
	}

	// Считаем интерфейсы, которые вообще попадают в отпечаток.
	active := 0
	for _, f := range list {
		if f.Up && !f.Loopback {
			active++
		}
	}
	t.Logf("интерфейсов всего: %d, участвуют в отпечатке: %d", len(list), active)

	fp, err := Fingerprint(SystemInterfaces())
	if err != nil {
		t.Fatalf("отпечаток по настоящим интерфейсам: %v", err)
	}
	t.Logf("отпечаток этой машины: %q", fp)

	if active == 0 {
		t.Skip("поднятых непетлевых интерфейсов нет: сравнивать нечего")
	}
	// Отпечаток не обязан быть каким-то определённым, но обязан быть
	// непустым: пустое значение означает, что смену сети не заметить.
	if fp == "" {
		t.Fatalf("отпечаток пуст при %d участвующих интерфейсах", active)
	}

	v, err := Detect(Label{Operator: "проверка", Region: "проверка"}, SystemInterfaces())
	if err != nil {
		t.Fatalf("Detect на настоящих интерфейсах: %v", err)
	}
	t.Logf("точка наблюдения: %+v", v.Describe())
	if v.ID == "" {
		t.Fatal("идентификатор точки наблюдения пуст")
	}
}
