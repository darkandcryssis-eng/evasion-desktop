package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// Тесты гоняют настоящий протокол SOCKS5 через сервер по localhost, но
// соединение с «сервером» подменяют на канал в памяти. Так проверяется весь
// прокси без выхода в сеть.

// fakeUpstream — подставное соединение с сервером: одна сторона отдаётся
// прокси, другую читает тест.
type fakeUpstream struct {
	serverSide net.Conn // то, что видит «сервер назначения» (читает тест)
	proxySide  net.Conn // то, что получает прокси как upstream
}

func newFakeUpstream() *fakeUpstream {
	p, s := net.Pipe()
	return &fakeUpstream{serverSide: s, proxySide: p}
}

// startServer поднимает прокси на localhost с инъектированным диалером,
// возвращающим подставной апстрим, и возвращает адрес и созданный апстрим.
func startServer(t *testing.T, cfg Config) (addr string, up *fakeUpstream) {
	t.Helper()
	up = newFakeUpstream()
	cfg.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return up.proxySide, nil
	}
	if cfg.Logger == nil {
		// Тихий журнал, чтобы не засорять вывод тестов.
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, ln) }()
	return ln.Addr().String(), up
}

// socksConnect проводит клиентскую сторону SOCKS5 до успешного ответа на
// CONNECT к заданной цели.
func socksConnect(t *testing.T, c net.Conn, host string, port uint16) {
	t.Helper()
	// Приветствие: версия 5, один метод — без аутентификации.
	if _, err := c.Write([]byte{socksVersion5, 1, socksMethodNoAuth}); err != nil {
		t.Fatalf("приветствие: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("ответ на приветствие: %v", err)
	}
	if reply[0] != socksVersion5 || reply[1] != socksMethodNoAuth {
		t.Fatalf("метод не согласован: %v", reply)
	}

	// Запрос CONNECT к доменному имени.
	req := []byte{socksVersion5, socksCmdConnect, 0x00, socksAddrDomain, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("запрос CONNECT: %v", err)
	}

	resp := make([]byte, 10) // ответ с IPv4-адресом фиксирован 10 байт
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("ответ на CONNECT: %v", err)
	}
	if resp[1] != socksReplySuccess {
		t.Fatalf("CONNECT не успешен: код %d", resp[1])
	}
}

// readWithTimeout читает n байт с таймаутом, чтобы тест не завис при ошибке.
func readWithTimeout(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("чтение %d байт: %v", n, err)
	}
	_ = c.SetReadDeadline(time.Time{})
	return buf
}

// splitStrategy — разрезать исходящий ClientHello на границе offset.
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

func TestProxyPassthroughNonTLS(t *testing.T) {
	prov, _ := NewStaticProvider(splitStrategy(5))
	addr, up := startServer(t, Config{Provider: prov})

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	socksConnect(t, client, "example.com", 80)

	// Шлём не-TLS данные: прокси должен переслать их серверу как есть.
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	go func() { _, _ = client.Write(payload) }()

	got := readWithTimeout(t, up.serverSide, len(payload))
	if string(got) != string(payload) {
		t.Fatalf("сервер получил %q, ожидалось %q", got, payload)
	}
}

func TestProxySegmentsClientHello(t *testing.T) {
	// Разрез на 15-м байте: сервер должен получить ClientHello целиком, но
	// первый приход — ровно первые 15 байт (сегментация видна по границе
	// первого Read на стороне сервера, так как net.Pipe не склеивает записи).
	prov, _ := NewStaticProvider(splitStrategy(15))
	addr, up := startServer(t, Config{Provider: prov})

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	socksConnect(t, client, "example.com", 443)

	hello := fakeClientHello("example.com")
	go func() { _, _ = client.Write(hello) }()

	// net.Pipe передаёт каждую запись отдельно: первый Read вернёт первую часть.
	first := readWithTimeout(t, up.serverSide, 15)
	if string(first) != string(hello[:15]) {
		t.Fatalf("первая часть неверна")
	}
	second := readWithTimeout(t, up.serverSide, len(hello)-15)
	if string(second) != string(hello[15:]) {
		t.Fatalf("вторая часть неверна")
	}
}

func TestProxyObserveMode(t *testing.T) {
	// В режиме наблюдения стратегия не применяется: ClientHello уходит целиком
	// одной записью, несмотря на стратегию разреза.
	prov, _ := NewStaticProvider(splitStrategy(15))
	addr, up := startServer(t, Config{Provider: prov, Observe: true})

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	socksConnect(t, client, "example.com", 443)

	hello := fakeClientHello("example.com")
	go func() { _, _ = client.Write(hello) }()

	// Весь ClientHello приходит одной записью (разрез не применён).
	got := readWithTimeout(t, up.serverSide, len(hello))
	if string(got) != string(hello) {
		t.Fatalf("в режиме наблюдения ClientHello искажён")
	}
}

func TestProxyRelayBidirectional(t *testing.T) {
	prov, _ := NewStaticProvider(nil) // без стратегии: чистый пропуск
	addr, up := startServer(t, Config{Provider: prov})

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	socksConnect(t, client, "example.com", 80)

	// Клиент -> сервер.
	req := []byte("ping")
	go func() { _, _ = client.Write(req) }()
	if got := readWithTimeout(t, up.serverSide, len(req)); string(got) != "ping" {
		t.Fatalf("сервер получил %q", got)
	}

	// Сервер -> клиент.
	resp := []byte("pong")
	go func() { _, _ = up.serverSide.Write(resp) }()
	if got := readWithTimeout(t, client, len(resp)); string(got) != "pong" {
		t.Fatalf("клиент получил %q", got)
	}
}

func TestProxyRejectsNonSocks(t *testing.T) {
	prov, _ := NewStaticProvider(nil)
	addr, _ := startServer(t, Config{Provider: prov})

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	// Шлём мусор вместо приветствия SOCKS: сервер должен закрыть соединение.
	_, _ = client.Write([]byte("not socks at all"))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := client.Read(buf); err == nil {
		t.Fatal("ожидалось закрытие соединения на не-SOCKS вводе")
	}
}

func TestNewServerRequiresProvider(t *testing.T) {
	if _, err := NewServer(Config{}); err == nil {
		t.Fatal("ожидалась ошибка при отсутствии провайдера")
	}
}

// fakeClientHello собирает минимальный корректный ClientHello с заданным именем
// сервера. Нужен тестам прокси, чтобы проверять вычленение и сегментацию без
// зависимости от crypto/tls. Длина заведомо больше 15 байт, чтобы граница
// разреза в тестах попадала внутрь сообщения.
func fakeClientHello(name string) []byte {
	// Расширение server_name.
	entry := []byte{0x00} // тип host_name
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(name)))
	entry = append(entry, name...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	list = append(list, entry...)
	ext := binary.BigEndian.AppendUint16(nil, 0x0000) // server_name
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(list)))
	ext = append(ext, list...)

	body := binary.BigEndian.AppendUint16(nil, 0x0303) // legacy_version
	body = append(body, make([]byte, 32)...)           // random
	body = append(body, 0x00)                          // session_id: пусто
	body = binary.BigEndian.AppendUint16(body, 2)      // cipher_suites len
	body = append(body, 0x13, 0x01)                    // один набор
	body = append(body, 0x01, 0x00)                    // compression: [0]
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01} // handshake, версия записи 1.0
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	return rec
}
