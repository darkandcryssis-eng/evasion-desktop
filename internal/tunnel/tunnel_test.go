package tunnel

import (
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/warp"
)

// goodAccount — тестовый account с валидными ключами. Генерируем на лету,
// чтобы не хранить в репозитории даже тестовые приватные ключи.
func goodAccount(t *testing.T) *warp.Account {
	t.Helper()
	kp, err := warp.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	// Публичный ключ peer-а — тестовая заглушка (32 нулевых байта в base64).
	peerPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return &warp.Account{
		Keypair:       *kp,
		DeviceID:      "test-device",
		Token:         "test-token",
		IPv4:          netip.MustParseAddr("172.16.0.2"),
		IPv6:          netip.MustParseAddr("2606:4700:110::2"),
		PeerPublicKey: peerPub,
		// Невалидный endpoint — туннель не поднимется в сеть, но Open не
		// должен падать на этапе конфигурации: сетевая часть ленивая.
		PeerEndpoint: "127.0.0.1:65535",
	}
}

func TestBuildUAPI(t *testing.T) {
	acc := goodAccount(t)
	cfg, err := buildUAPI(acc, acc.PeerEndpoint)
	if err != nil {
		t.Fatalf("buildUAPI: %v", err)
	}
	// В UAPI ключи в HEX; длина 32 байта → 64 hex-символа.
	for _, want := range []string{
		"private_key=",
		"public_key=",
		"endpoint=" + acc.PeerEndpoint,
		"persistent_keepalive_interval=25",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("в UAPI нет строки %q:\n%s", want, cfg)
		}
	}
	// Приватный ключ в HEX длиной 64 символа (без переводов строк).
	for _, line := range strings.Split(cfg, "\n") {
		if strings.HasPrefix(line, "private_key=") {
			hexPart := strings.TrimPrefix(line, "private_key=")
			if len(hexPart) != 64 {
				t.Fatalf("приватный ключ в hex: длина %d, ожидалось 64", len(hexPart))
			}
		}
	}
}

func TestB64ToHex(t *testing.T) {
	kp, err := warp.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	hexKey, err := b64ToHex(kp.Private)
	if err != nil {
		t.Fatalf("b64ToHex: %v", err)
	}
	if len(hexKey) != 64 {
		t.Fatalf("длина hex %d, ожидалось 64", len(hexKey))
	}
	// Негодные входы.
	cases := map[string]string{
		"пустой":            "",
		"не base64":         "zzz***",
		"короткий":          base64.StdEncoding.EncodeToString(make([]byte, 10)),
		"длинный":           base64.StdEncoding.EncodeToString(make([]byte, 50)),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := b64ToHex(in); err == nil {
				t.Fatalf("ожидалась ошибка на %q", in)
			}
		})
	}
}

func TestOpenRejectsNilAccount(t *testing.T) {
	if _, err := Open(Options{}); err == nil {
		t.Fatal("Open с nil account должен возвращать ошибку")
	}
}

func TestOpenRejectsInvalidAccount(t *testing.T) {
	bad := goodAccount(t)
	bad.PeerPublicKey = "" // ломаем валидацию
	if _, err := Open(Options{Account: bad}); err == nil {
		t.Fatal("Open с битым account должен возвращать ошибку")
	}
}

// TestOpenRejectsBadKey проверяет, что битый ключ (не 32 байта в base64)
// отвергается на этапе UAPI, а не позже с невнятной ошибкой wireguard-go.
func TestOpenRejectsBadKey(t *testing.T) {
	bad := goodAccount(t)
	// Валидный base64, но не 32 байта. Validate account пропустит (он
	// проверяет длину только у PeerPublicKey), а buildUAPI поймает.
	bad.Keypair.Private = base64.StdEncoding.EncodeToString(make([]byte, 10))
	_, err := Open(Options{Account: bad})
	if err == nil {
		t.Fatal("Open с коротким ключом должен возвращать ошибку")
	}
}

// TestOpenCreatesTunnelAndClosesCleanly открывает туннель с заведомо
// недостижимым peer-ом (127.0.0.1:65535) и сразу закрывает. Проверяет, что
// открытие не падает на этапе конфигурации (сеть лениво) и что Close
// корректно освобождает ресурсы.
//
// Это smoke-тест: он НЕ проверяет сетевую работу (нужен настоящий
// WireGuard-peer), но ловит регрессии в UAPI-формате и netstack-инициализации.
func TestOpenCreatesTunnelAndClosesCleanly(t *testing.T) {
	acc := goodAccount(t)
	tun, err := Open(Options{Account: acc})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestDialContextRejectsUDP: DialContext для udp должен отвечать ясной
// ошибкой, а не странной от netstack. UDP добавим в Phase 2.3+ если
// понадобится.
func TestDialContextRejectsUDP(t *testing.T) {
	acc := goodAccount(t)
	tun, err := Open(Options{Account: acc})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tun.Close()

	_, err = tun.DialContext(context.Background(), "udp", "1.2.3.4:443")
	if err == nil {
		t.Fatal("DialContext для udp должен возвращать ошибку")
	}
}

func TestListenUDP(t *testing.T) {
	acc := goodAccount(t)
	tun, err := Open(Options{Account: acc})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tun.Close()

	pc4, err := tun.ListenUDP(false)
	if err != nil {
		t.Fatalf("ListenUDP(false): %v", err)
	}
	defer pc4.Close()
	if pc4.LocalAddr() == nil {
		t.Fatal("ListenUDP(false) returned nil LocalAddr")
	}

	pc6, err := tun.ListenUDP(true)
	if err != nil {
		t.Fatalf("ListenUDP(true): %v", err)
	}
	defer pc6.Close()
	if pc6.LocalAddr() == nil {
		t.Fatal("ListenUDP(true) returned nil LocalAddr")
	}
}

// TestDialContextTimesOutWithUnreachablePeer: с заведомо недостижимым
// peer-ом (localhost порт 65535), DialContext с коротким контекстом обязан
// честно отваливаться по таймауту. Это проверка, что netstack реагирует на
// контекст, а не висит бесконечно.
func TestDialContextTimesOutWithUnreachablePeer(t *testing.T) {
	acc := goodAccount(t)
	tun, err := Open(Options{Account: acc})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tun.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err = tun.DialContext(ctx, "tcp", "162.159.130.235:443")
	if err == nil {
		t.Fatal("DialContext к недостижимому peer-у должен был упасть по контексту")
	}
	// Ошибка может быть любой (netstack выдаёт разные), главное — что она
	// есть за разумное время, а не вис.
}

// TestResolveEndpointIPPassthrough: IP:port возвращается как есть.
func TestResolveEndpointIPPassthrough(t *testing.T) {
	got, err := resolveEndpoint("1.2.3.4:2408")
	if err != nil {
		t.Fatalf("resolveEndpoint: %v", err)
	}
	if got != "1.2.3.4:2408" {
		t.Fatalf("ожидалось 1.2.3.4:2408, получено %q", got)
	}
}

// TestResolveEndpointBadFormat: мусор на входе — ясная ошибка.
func TestResolveEndpointBadFormat(t *testing.T) {
	if _, err := resolveEndpoint("не endpoint"); err == nil {
		t.Fatal("ожидалась ошибка на мусоре")
	}
}

// TestResolveEndpointFallback: имя `engage.cloudflareclient.com` возвращает
// IP из fallback-таблицы если DNS не отвечает. На тесте DNS может быть,
// может не быть — тест допускает оба исхода, но проверяет что результат
// это IP:port, а не имя.
func TestResolveEndpointFallback(t *testing.T) {
	got, err := resolveEndpoint("engage.cloudflareclient.com:2408")
	if err != nil {
		t.Fatalf("resolveEndpoint для known-host должен работать (DNS или fallback): %v", err)
	}
	if !strings.Contains(got, ":2408") {
		t.Fatalf("порт потерян: %q", got)
	}
	host, _, _ := net.SplitHostPort(got)
	if net.ParseIP(host) == nil {
		t.Fatalf("ожидался IP на выходе, получен %q", host)
	}
}
