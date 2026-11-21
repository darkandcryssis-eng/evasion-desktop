package netcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/websocket"
)

func TestEndpointStagesWithLocalTLS(t *testing.T) {
	for _, tt := range []struct {
		name       string
		gateway    bool
		status     int
		body, code string
	}{
		{"api", false, 200, `{"url":"wss://gateway.discord.gg"}`, "https_ok"},
		{"restricted", false, 403, "denied", "http_403"},
		{"invalid-api", false, 200, `{"url":"https://wrong.example"}`, "https_error"},
		{"gateway", true, 200, `{"op":10,"d":{"heartbeat_interval":45000}}`, "gateway_ok"},
		{"invalid-gateway", true, 200, `{"op":1,"d":{"heartbeat_interval":45000}}`, "gateway_error"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.gateway {
					conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
					if err != nil {
						return
					}
					defer conn.Close()
					_ = conn.WriteMessage(websocket.TextMessage, []byte(tt.body))
					return
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			network := probeNetwork{lookup: func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
			}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}, tlsConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
			result := check(context.Background(), Endpoint{ID: "discord-api", Host: "127.0.0.1", Path: "/", Gateway: tt.gateway}, network)
			if len(result.Steps) != 4 || result.Steps[3].Code != tt.code {
				t.Fatalf("unexpected stages: %+v", result)
			}
		})
	}
}

func TestFailureReasonsDoNotExposeRawErrors(t *testing.T) {
	for _, tt := range []struct {
		stage string
		err   error
		code  string
	}{
		{"dns", &net.DNSError{Err: "private-dns-host", Name: "private-name"}, "dns_error"},
		{"tcp", context.DeadlineExceeded, "tcp_timeout"},
		{"tls", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, "tls_certificate"},
		{"gateway", errors.New("private-account-token"), "gateway_error"},
		{"tcp", context.Canceled, "cancelled"},
	} {
		code, _, _ := Failure(tt.stage, tt.err)
		if code != tt.code {
			t.Errorf("%s: got %s want %s", tt.stage, code, tt.code)
		}
	}
}

func TestCancelledCheckStopsAtDNS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Check(ctx, DiscordAPI)
	if r.Status != "fail" || len(r.Steps) > 2 {
		t.Fatalf("unexpected result: %+v", r)
	}
}

func TestLiveServiceEndpoints(t *testing.T) {
	if os.Getenv("EVASION_SERVICES_LIVE") != "1" {
		t.Skip("opt-in public service probes")
	}
	for _, endpoint := range []Endpoint{TelegramWeb, DiscordAPI, DiscordGateway} {
		t.Run(endpoint.ID, func(t *testing.T) {
			r := Check(context.Background(), endpoint)
			t.Logf("%s: %s; %+v", r.Name, r.Summary, r.Steps)
			if len(r.Steps) == 0 {
				t.Fatal("no checks")
			}
		})
	}
}
