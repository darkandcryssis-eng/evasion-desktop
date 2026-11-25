package tunnel

import (
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

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

func TestOpenWithFallbackParallel(t *testing.T) {
	acc := goodAccount(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 4 unreachable loopback ports probed in one parallel batch of 4 should
	// finish in ~1 per-port timeout rather than 4x sequential.
	start := time.Now()
	tn, err := OpenWithFallbackParallel(ctx, Options{Account: acc}, []int{65531, 65532, 65533, 65534}, 150*time.Millisecond, 4)
	if tn != nil {
		_ = tn.Close()
	}
	if err == nil {
		t.Fatal("expected error when no peer responds")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("parallel batch probe took %v, expected well under 2s", elapsed)
	}

	// Cancelled context aborts immediately without waiting for perPortTimeout.
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if _, err := OpenWithFallbackParallel(cctx, Options{Account: acc}, []int{65531, 65532}, 5*time.Second, 2); err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

type recordingBind struct {
	conn.Bind
	sent [][]byte
}

func (r *recordingBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, b := range bufs {
		cp := append([]byte(nil), b...)
		r.sent = append(r.sent, cp)
	}
	return nil
}

func TestJunkBindPrependsJunkOnlyOnHandshakeInitiation(t *testing.T) {
	rec := &recordingBind{}
	jb := newJunkBind(rec, 4)

	// Non-handshake transport data (type 4) must pass through untouched.
	dataPkt := make([]byte, 64)
	dataPkt[0] = 4
	if err := jb.Send([][]byte{dataPkt}, nil); err != nil {
		t.Fatalf("Send data: %v", err)
	}
	if len(rec.sent) != 1 {
		t.Fatalf("data packet should send 1 packet, got %d", len(rec.sent))
	}

	// WireGuard Handshake Initiation (148 bytes, type 1 0 0 0) must be preceded
	// by 4 random junk packets whose first byte is outside 0x01..0x04.
	rec.sent = nil
	initPkt := make([]byte, 148)
	initPkt[0] = 1
	if err := jb.Send([][]byte{initPkt}, nil); err != nil {
		t.Fatalf("Send handshake: %v", err)
	}
	if len(rec.sent) != 5 {
		t.Fatalf("handshake should emit 4 junk + 1 init = 5 packets, got %d", len(rec.sent))
	}
	for i := 0; i < 4; i++ {
		j := rec.sent[i]
		if len(j) < wgJunkMinLen || len(j) > wgJunkMaxLen {
			t.Fatalf("junk[%d] len=%d outside [%d,%d]", i, len(j), wgJunkMinLen, wgJunkMaxLen)
		}
		if j[0] <= 4 {
			t.Fatalf("junk[%d][0]=%d must not collide with WireGuard message types 1..4", i, j[0])
		}
	}
	if len(rec.sent[4]) != 148 || rec.sent[4][0] != 1 {
		t.Fatalf("last packet must be the original 148B handshake initiation")
	}
}
