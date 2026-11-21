package warp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeWARPServer эмулирует Cloudflare WARP API /reg для тестов.
//
// Отдаёт детерминированный ответ, в котором фигурируют заметные значения —
// так в тесте легко отличить реальные данные от артефактов разбора.
func fakeWARPServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0a2483/reg" {
			t.Errorf("неожиданный путь: %q", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("метод не POST: %q", r.Method)
			http.Error(w, "method", 405)
			return
		}
		// Заголовки обязаны присутствовать — иначе Cloudflare не даст регистрации.
		for key, want := range map[string]string{
			"Content-Type":      "application/json; charset=UTF-8",
			"User-Agent":        ClientUA,
			"CF-Client-Version": ClientVersion,
		} {
			if got := r.Header.Get(key); got != want {
				t.Errorf("заголовок %s: получено %q, ожидалось %q", key, got, want)
			}
		}
		body, _ := io.ReadAll(r.Body)
		var req registerRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("тело запроса не JSON: %v", err)
			http.Error(w, "bad json", 400)
			return
		}
		if req.Type != ClientType {
			t.Errorf("Type: %q", req.Type)
		}
		if req.Key == "" {
			t.Errorf("Key пуст")
		}

		// Отдаём минимальный, но валидный ответ.
		resp := registerResponse{
			ID:    "test-device-id",
			Type:  "Android",
			Model: "PC",
			Token: "test-token-abc",
			Config: registerConfigPacket{
				Interface: registerInterfacePacket{
					Addresses: registerAddresses{V4: "172.16.0.42", V6: "2606:4700:110::42"},
				},
				Peers: []registerPeerPacket{{
					PublicKey: "bmNqNqMvl8e3IE3DcPSmTx6AZu1OYtK4XJUZeqxx+Dc=", // любой валидный 32-байт base64
					Endpoint: registerPeerEndpoints{
						V4:   "162.159.192.1:2408",
						V6:   "[2606:4700:d0::a29f:c001]:2408",
						Host: "engage.cloudflareclient.com:2408",
					},
				}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	return srv
}

// clientFor делает http.Client, который перенаправляет запросы к `api.cloudflareclient.com`
// на тестовый httptest-сервер. Так мы не меняем URL в коде, а подменяем транспорт.
func clientFor(srv *httptest.Server) *http.Client {
	return &http.Client{
		Transport: &rewritingTransport{dest: srv.URL, delegate: srv.Client().Transport},
		Timeout:   5 * time.Second,
	}
}

type rewritingTransport struct {
	dest     string
	delegate http.RoundTripper
}

func (r *rewritingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Перенаправляем все запросы к api.cloudflareclient.com на локальный сервер,
	// сохраняя путь и тело.
	req2 := req.Clone(req.Context())
	req2.URL.Scheme = "https"
	req2.URL.Host = strings.TrimPrefix(r.dest, "https://")
	req2.Host = req2.URL.Host
	return r.delegate.RoundTrip(req2)
}

func TestRegisterHappyPath(t *testing.T) {
	srv := fakeWARPServer(t)
	defer srv.Close()

	acc, err := Register(context.Background(), clientFor(srv))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if acc.DeviceID != "test-device-id" {
		t.Fatalf("DeviceID: %q", acc.DeviceID)
	}
	if acc.Token != "test-token-abc" {
		t.Fatalf("Token: %q", acc.Token)
	}
	if acc.IPv4.String() != "172.16.0.42" {
		t.Fatalf("IPv4: %s", acc.IPv4)
	}
	if acc.PeerEndpoint != "engage.cloudflareclient.com:2408" {
		t.Fatalf("PeerEndpoint: %q", acc.PeerEndpoint)
	}
	// Приватный ключ — ОЖИДАЕМО новый при каждой регистрации.
	if acc.Keypair.Private == "" || acc.Keypair.Public == "" {
		t.Fatal("ключи не заполнены")
	}
	if err := acc.Validate(); err != nil {
		t.Fatalf("после регистрации Validate: %v", err)
	}
}

func TestRegisterRejects5xx(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", 503)
	}))
	defer srv.Close()

	_, err := Register(context.Background(), clientFor(srv))
	if err == nil {
		t.Fatal("ожидалась ошибка на 5xx")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("в ошибке нет кода: %v", err)
	}
}

func TestRegisterRejectsBadResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Пустой peers — обязан отвергаться.
		resp := registerResponse{
			ID: "x", Token: "y",
			Config: registerConfigPacket{
				Interface: registerInterfacePacket{Addresses: registerAddresses{V4: "1.2.3.4", V6: "::1"}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	_, err := Register(context.Background(), clientFor(srv))
	if err == nil {
		t.Fatal("ожидалась ошибка на ответе без peers")
	}
}

func TestRegisterTimeoutCancels(t *testing.T) {
	// Сервер висит дольше контекста — Register должен сдаться по ctx.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := Register(ctx, clientFor(srv))
	if err == nil {
		t.Fatal("ожидалась ошибка по контексту")
	}
}
