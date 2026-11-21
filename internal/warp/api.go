package warp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// APIBase — базовый URL API Cloudflare WARP для клиентов.
//
// Это публичный, но не задокументированный официально endpoint. Его шапка
// версии (`v0a2483`) периодически обновляется в клиенте Cloudflare; поэтому
// держим его константой, а не вшиваем в код. Если API сломается, здесь ищем.
const APIBase = "https://api.cloudflareclient.com/v0a2483"

// Клиентские заголовки, подделывающие официальный Android-клиент Cloudflare.
// Так регистрация проходит ровно так же, как у обычного пользователя, и ни
// одна сторона не отличает. Числа взяты из последней стабильной версии клиента
// на момент написания; если API начнёт их валидировать строже, обновляем.
const (
	ClientVersion = "a-6.11-2223"
	ClientUA      = "okhttp/3.12.1"
	ClientType    = "Android"
	ClientLocale  = "en_US"
	ClientModel   = "PC"
)

// Register регистрирует новое устройство в WARP и возвращает Account.
//
// Пара ключей генерируется здесь же, затем публичный ключ отправляется в
// Cloudflare; приватный никогда не покидает нашей машины. Это обычное
// WireGuard-поведение, но нужно явно оговорить — особенно для документации,
// которую будет читать владелец.
//
// httpc — инъекция для тестов (можно передать клиент с httptest.Server в
// качестве транспорта). Если nil, используется http.DefaultClient с 30-с
// таймаутом; производственный путь (команда CLI) передаёт настроенный клиент.
func Register(ctx context.Context, httpc *http.Client) (*Account, error) {
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}

	kp, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}

	reqBody, err := json.Marshal(registerRequest{
		InstallID: "",
		TOS:       time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Key:       kp.Public,
		FCMToken:  "",
		Type:      ClientType,
		Locale:    ClientLocale,
		Model:     ClientModel,
	})
	if err != nil {
		return nil, fmt.Errorf("warp: сборка запроса регистрации: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, APIBase+"/reg", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("warp: сборка HTTP-запроса: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", ClientUA)
	req.Header.Set("CF-Client-Version", ClientVersion)
	req.Header.Set("Accept", "application/json")

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("warp: запрос регистрации не доехал: %w — "+
			"возможно, провайдер режет api.cloudflareclient.com", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("warp: чтение ответа: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("warp: регистрация отвергнута Cloudflare: HTTP %d: %s",
			resp.StatusCode, truncate(string(body), 200))
	}

	var rr registerResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		return nil, fmt.Errorf("warp: ответ не разбирается: %w: %s", err, truncate(string(body), 200))
	}

	acc, err := accountFromResponse(kp, &rr)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

// registerRequest — тело запроса регистрации. Поля в оригинальном (snake_case)
// формате API, иначе Cloudflare их не узнает.
type registerRequest struct {
	InstallID string `json:"install_id"`
	TOS       string `json:"tos"`
	Key       string `json:"key"`
	FCMToken  string `json:"fcm_token"`
	Type      string `json:"type"`
	Locale    string `json:"locale"`
	Model     string `json:"model"`
}

// registerResponse — ответ API регистрации.
//
// Берём ровно те поля, что нужны. Остальные (account.*, warp_plus, …) есть,
// но нас не касаются и игнорируются (без DisallowUnknownFields: Cloudflare
// добавляет поля без предупреждения, строгий разбор здесь ломался бы при
// каждом рефакторинге их API).
type registerResponse struct {
	ID     string               `json:"id"`
	Type   string               `json:"type"`
	Model  string               `json:"model"`
	Token  string               `json:"token"`
	Config registerConfigPacket `json:"config"`
}

type registerConfigPacket struct {
	Interface registerInterfacePacket `json:"interface"`
	Peers     []registerPeerPacket    `json:"peers"`
}

type registerInterfacePacket struct {
	Addresses registerAddresses `json:"addresses"`
}

type registerAddresses struct {
	V4 string `json:"v4"`
	V6 string `json:"v6"`
}

type registerPeerPacket struct {
	PublicKey string                `json:"public_key"`
	Endpoint  registerPeerEndpoints `json:"endpoint"`
}

type registerPeerEndpoints struct {
	V4   string `json:"v4"`
	V6   string `json:"v6"`
	Host string `json:"host"`
}

// accountFromResponse собирает Account из нашей пары ключей и ответа API.
func accountFromResponse(kp *Keypair, r *registerResponse) (*Account, error) {
	if r.ID == "" || r.Token == "" {
		return nil, fmt.Errorf("warp: ответ без id/token: %+v", r)
	}
	if len(r.Config.Peers) == 0 {
		return nil, fmt.Errorf("warp: ответ без peers")
	}
	peer := r.Config.Peers[0]
	if peer.PublicKey == "" {
		return nil, fmt.Errorf("warp: peer без публичного ключа")
	}
	// Хост выбираем в порядке: явный host (DNS-имя), v4-адрес, v6-адрес.
	// Явный host удобнее — DNS-резолвинг сработает при изменении IP; но
	// если его нет (ранние версии API могут не отдавать), берём адрес.
	endpoint := peer.Endpoint.Host
	if endpoint == "" {
		endpoint = peer.Endpoint.V4
	}
	if endpoint == "" {
		endpoint = peer.Endpoint.V6
	}
	if endpoint == "" {
		return nil, fmt.Errorf("warp: peer без endpoint-а")
	}

	v4, err := netip.ParseAddr(r.Config.Interface.Addresses.V4)
	if err != nil {
		return nil, fmt.Errorf("warp: негодный v4-адрес интерфейса %q: %w", r.Config.Interface.Addresses.V4, err)
	}
	v6, err := netip.ParseAddr(r.Config.Interface.Addresses.V6)
	if err != nil {
		return nil, fmt.Errorf("warp: негодный v6-адрес интерфейса %q: %w", r.Config.Interface.Addresses.V6, err)
	}

	return &Account{
		Keypair:       *kp,
		DeviceID:      r.ID,
		Token:         r.Token,
		IPv4:          v4,
		IPv6:          v6,
		PeerPublicKey: peer.PublicKey,
		PeerEndpoint:  endpoint,
	}, nil
}

// truncate обрезает строку для вывода в сообщение об ошибке. Длинное тело
// ответа Cloudflare засоряет лог.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// WireGuardConfig собирает конфигурацию WireGuard-клиента по account.
// Возвращает текст в стандартном формате wg-quick, пригодном и для нашего
// встроенного туннеля (Phase 2.2), и для импорта в сторонний клиент на случай
// отладки руками.
//
// Allowed-IPs подобраны минималистично: только диапазон Cloudflare Spectrum
// (voice-гейтвеи Discord). Весь прочий трафик через туннель НЕ идёт — это
// требование владельца «основной трафик не трогаем». Фактический радиус
// задаётся вызывающим через `allowedPrefixes`; тут только сериализация.
func (a *Account) WireGuardConfig(allowedPrefixes []netip.Prefix) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	if len(allowedPrefixes) == 0 {
		return "", fmt.Errorf("warp: allowed-ips пуст — тогда через туннель вообще нечего пускать")
	}
	var b strings.Builder
	fmt.Fprintln(&b, "[Interface]")
	fmt.Fprintf(&b, "PrivateKey = %s\n", a.Keypair.Private)
	fmt.Fprintf(&b, "Address = %s/32, %s/128\n", a.IPv4, a.IPv6)
	// MTU и DNS не ставим: туннель userspace, DNS через свой DoH-резолвер (2.3).
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "[Peer]")
	fmt.Fprintf(&b, "PublicKey = %s\n", a.PeerPublicKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", a.PeerEndpoint)
	parts := make([]string, 0, len(allowedPrefixes))
	for _, p := range allowedPrefixes {
		parts = append(parts, p.String())
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(parts, ", "))
	// PersistentKeepalive нужен для NAT: без него роутер пользователя через
	// минуту закрывает UDP-сессию, туннель умирает. 25 секунд — рекомендованное
	// значение из документации WireGuard, достаточно консервативное для
	// большинства NAT-таблиц.
	fmt.Fprintln(&b, "PersistentKeepalive = 25")
	return b.String(), nil
}
