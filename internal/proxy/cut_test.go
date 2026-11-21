package proxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// cutStrategy — разрезать исходящий ClientHello по структурной точке.
func cutStrategy(at core.CutKind) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, At: at},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right:  &strategy.Action{Kind: core.ActionSend},
		},
	}}}
}

// TestProxySplitsInsideServerName — главная проверка M3c.
//
// Проверяет не просто факт разреза, а то, что имя сервера оказалось РАЗОРВАНО
// между сегментами. Это и есть смысл структурной точки: числовое смещение для
// другого соединения попало бы в другое место, и ровно из-за этого перебор
// абсолютных смещений вслепую ничего не доказывал.
func TestProxySplitsInsideServerName(t *testing.T) {
	const name = "example.com"

	prov, err := NewStaticProvider(cutStrategy(core.CutInsideSNI))
	if err != nil {
		t.Fatalf("NewStaticProvider: %v", err)
	}
	addr, up := startServer(t, Config{Provider: prov})

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	socksConnect(t, client, name, 443)

	hello := fakeClientHello(name)
	go func() { _, _ = client.Write(hello) }()

	// net.Pipe передаёт каждую запись отдельно, поэтому первый Read — это
	// ровно первый сегмент.
	first := readUntilShort(t, up.serverSide, len(hello))
	if len(first) == 0 || len(first) >= len(hello) {
		t.Fatalf("первый сегмент %d байт при ClientHello %d байт: разрез не состоялся",
			len(first), len(hello))
	}

	second := readWithTimeout(t, up.serverSide, len(hello)-len(first))
	if !bytes.Equal(append(append([]byte{}, first...), second...), hello) {
		t.Fatal("склейка частей не равна исходному ClientHello")
	}

	// Ключевое: целого имени нет ни в одной части, а обрывки есть в обеих.
	nameBytes := []byte(name)
	if bytes.Contains(first, nameBytes) {
		t.Fatal("имя целиком попало в первый сегмент: разрез лёг не внутрь имени")
	}
	if bytes.Contains(second, nameBytes) {
		t.Fatal("имя целиком попало во второй сегмент: разрез лёг не внутрь имени")
	}
	// Имя разорвано: конец первой части и начало второй вместе дают имя.
	if !bytes.Contains(append(append([]byte{}, first...), second...), nameBytes) {
		t.Fatal("имя не восстанавливается из частей — нагрузка искажена")
	}
}

// TestProxyMissingCutPointPassesThrough проверяет, что при недоступной точке
// разреза соединение не рвётся.
//
// Стратегия требует разреза внутри имени сервера, а ClientHello имени не несёт.
// Исполнение обрывается до первой записи, и начало потока обязано уйти как
// есть: ломать соединение из-за непригодной стратегии недопустимо (1.6).
func TestProxyMissingCutPointPassesThrough(t *testing.T) {
	prov, err := NewStaticProvider(cutStrategy(core.CutInsideSNI))
	if err != nil {
		t.Fatalf("NewStaticProvider: %v", err)
	}
	addr, up := startServer(t, Config{Provider: prov})

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	socksConnect(t, client, "no-sni.test", 443)

	hello := fakeClientHelloNoSNI()
	go func() { _, _ = client.Write(hello) }()

	got := readWithTimeout(t, up.serverSide, len(hello))
	if !bytes.Equal(got, hello) {
		t.Fatal("ClientHello без имени искажён или не доставлен")
	}
}

// readUntilShort читает одну порцию данных, не больше max байт.
//
// Нужен там, где размер первого сегмента заранее неизвестен: именно его
// величину тест и выясняет.
func readUntilShort(t *testing.T, c net.Conn, max int) []byte {
	t.Helper()
	buf := make([]byte, max)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("чтение первого сегмента: %v", err)
	}
	return buf[:n]
}

// fakeClientHelloNoSNI собирает корректный ClientHello без расширения
// server_name. Нужен, чтобы проверить поведение при недоступной структурной
// точке разреза.
func fakeClientHelloNoSNI() []byte {
	body := binary.BigEndian.AppendUint16(nil, 0x0303) // legacy_version
	body = append(body, make([]byte, 32)...)           // random
	body = append(body, 0x00)                          // session_id: пусто
	body = binary.BigEndian.AppendUint16(body, 2)      // cipher_suites len
	body = append(body, 0x13, 0x01)                    // один набор
	body = append(body, 0x01, 0x00)                    // compression: [0]
	// Расширений нет вовсе: список пуст, значит и имени сервера нет.
	body = binary.BigEndian.AppendUint16(body, 0)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01} // handshake, версия записи 1.0
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	return rec
}
