package warp

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
)

// genTestKeypair — настоящая пара ключей для тестов. Генерируем, а не
// захардкоживаем: это убеждает что GenerateKeypair вообще работает, и
// избавляет от соблазна положить реальный ключ в репозиторий.
func genTestKeypair(t *testing.T) Keypair {
	t.Helper()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return *kp
}

// goodAccount — заготовленный валидный account для тестов валидации.
func goodAccount(t *testing.T) *Account {
	t.Helper()
	kp := genTestKeypair(t)
	peerPub := base64.StdEncoding.EncodeToString(make([]byte, 32)) // 32 нулевых байта — валидный base64/длина
	return &Account{
		Keypair:       kp,
		DeviceID:      "dev-123",
		Token:         "tok-abc",
		IPv4:          netip.MustParseAddr("172.16.0.2"),
		IPv6:          netip.MustParseAddr("2606:4700:110::1"),
		PeerPublicKey: peerPub,
		PeerEndpoint:  "engage.cloudflareclient.com:2408",
	}
}

func TestGenerateKeypairProducesValidX25519(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	// Разбор каждый из ключей должен проходить длинy и формат.
	if _, err := ParseKeypair(kp.Private, kp.Public); err != nil {
		t.Fatalf("ParseKeypair: %v", err)
	}
	// Разные вызовы должны давать разные ключи — это и есть смысл
	// генерации. Иначе RNG не крутится.
	kp2, _ := GenerateKeypair()
	if kp.Private == kp2.Private {
		t.Fatal("два вызова GenerateKeypair вернули одинаковый приватный ключ")
	}
}

func TestParseKeypairRejectsBadInput(t *testing.T) {
	cases := map[string]struct{ priv, pub string }{
		"пустой приватный": {"", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		"пустой публичный": {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ""},
		"не base64":        {"not-base64!!!", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		"короткий":         {base64.StdEncoding.EncodeToString(make([]byte, 10)), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		"длинный":          {base64.StdEncoding.EncodeToString(make([]byte, 50)), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKeypair(c.priv, c.pub); err == nil {
				t.Fatal("ожидалась ошибка парсинга")
			}
		})
	}
}

func TestAccountValidate(t *testing.T) {
	// Валидный account проходит.
	if err := goodAccount(t).Validate(); err != nil {
		t.Fatalf("валидный account отвергнут: %v", err)
	}

	// Каждое поле отдельно — обязательно.
	cases := map[string]func(*Account){
		"nil keypair private": func(a *Account) { a.Keypair.Private = "" },
		"nil device id":       func(a *Account) { a.DeviceID = "" },
		"nil token":           func(a *Account) { a.Token = "" },
		"zero ipv4":           func(a *Account) { a.IPv4 = netip.Addr{} },
		"zero ipv6":           func(a *Account) { a.IPv6 = netip.Addr{} },
		"empty peer key":      func(a *Account) { a.PeerPublicKey = "" },
		"empty peer endpoint": func(a *Account) { a.PeerEndpoint = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := goodAccount(t)
			mutate(a)
			if err := a.Validate(); err == nil {
				t.Fatal("ожидалась ошибка валидации")
			}
		})
	}
}

func TestAccountMarshalRoundtrip(t *testing.T) {
	orig := goodAccount(t)
	data, err := orig.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := UnmarshalAccount(data)
	if err != nil {
		t.Fatalf("UnmarshalAccount: %v", err)
	}
	if got.DeviceID != orig.DeviceID || got.Token != orig.Token {
		t.Fatalf("device_id/token разошлись: %+v vs %+v", got, orig)
	}
	if got.IPv4 != orig.IPv4 || got.IPv6 != orig.IPv6 {
		t.Fatalf("адреса разошлись: %v/%v vs %v/%v", got.IPv4, got.IPv6, orig.IPv4, orig.IPv6)
	}
	if got.PeerPublicKey != orig.PeerPublicKey || got.PeerEndpoint != orig.PeerEndpoint {
		t.Fatalf("peer разошёлся")
	}
}

func TestUnmarshalRejectsBadJSON(t *testing.T) {
	cases := map[string][]byte{
		"пустой":            []byte(""),
		"не JSON":           []byte("not json"),
		"неполный":          []byte(`{"device_id": "x"}`),
		"неизвестное поле":  []byte(`{"unknown_field": 1}`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := UnmarshalAccount(data); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
}

func TestWireGuardConfigShape(t *testing.T) {
	a := goodAccount(t)
	// Радиус — узкий: диапазон Cloudflare Spectrum для голоса Discord
	// (`162.159.*.0/24` упрощённо).
	prefix := netip.MustParsePrefix("162.159.128.0/19")
	cfg, err := a.WireGuardConfig([]netip.Prefix{prefix})
	if err != nil {
		t.Fatalf("WireGuardConfig: %v", err)
	}
	// Проверяем структуру конфигурации, а не точную строку — слишком хрупко.
	wants := []string{
		"[Interface]",
		"PrivateKey = " + a.Keypair.Private,
		"Address = " + a.IPv4.String() + "/32, " + a.IPv6.String() + "/128",
		"[Peer]",
		"PublicKey = " + a.PeerPublicKey,
		"Endpoint = " + a.PeerEndpoint,
		"AllowedIPs = 162.159.128.0/19",
		"PersistentKeepalive = 25",
	}
	for _, w := range wants {
		if !strings.Contains(cfg, w) {
			t.Fatalf("в конфиге нет строки %q:\n%s", w, cfg)
		}
	}
}

func TestWireGuardConfigRejectsEmptyAllowed(t *testing.T) {
	a := goodAccount(t)
	if _, err := a.WireGuardConfig(nil); err == nil {
		t.Fatal("ожидалась ошибка на пустом allowed-ips")
	}
}
