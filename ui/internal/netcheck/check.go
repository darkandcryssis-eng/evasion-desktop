package netcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

type Step struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	MS     int64  `json:"ms"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
	Advice string `json:"advice"`
}

type Result struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Summary   string `json:"summary"`
	Advice    string `json:"advice"`
	CheckedAt string `json:"checkedAt"`
	Steps     []Step `json:"steps"`
}

type Endpoint struct {
	ID, Name, Host, Path string
	Gateway              bool
}

var DiscordAPI = Endpoint{ID: "discord-api", Name: "Discord · API", Host: "discord.com", Path: "/api/v10/gateway"}
var DiscordGateway = Endpoint{ID: "discord-gateway", Name: "Discord · события", Host: "gateway.discord.gg", Path: "/?v=10&encoding=json", Gateway: true}
var TelegramWeb = Endpoint{ID: "telegram-web", Name: "Telegram · веб-доступ", Host: "web.telegram.org", Path: "/"}

func Failure(stage string, err error) (string, string, string) {
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var host x509.HostnameError
	var timeout net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled", "Проверка отменена", "Запустите проверку повторно."
	case errors.As(err, &dns):
		return "dns_error", "DNS не смог определить адрес сервиса", "Проверьте DNS в Windows и повторите проверку."
	case errors.As(err, &cert), errors.As(err, &unknown), errors.As(err, &invalid), errors.As(err, &host):
		return "tls_certificate", "Сертификат сервиса не прошёл проверку", "Проверьте дату компьютера, антивирус и HTTPS-фильтрацию."
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &timeout) && timeout.Timeout():
		return stage + "_timeout", "Сервис не ответил на этапе «" + stageName(stage) + "»", "Включите обход и повторите. Причиной может быть фильтрация или недоступность маршрута."
	default:
		return stage + "_error", "Сбой на этапе «" + stageName(stage) + "»", "Проверьте подключение и повторите с включённым обходом."
	}
}

func stageName(id string) string {
	switch id {
	case "dns":
		return "DNS"
	case "tcp":
		return "TCP"
	case "tls":
		return "TLS"
	case "https":
		return "HTTPS"
	case "gateway":
		return "WebSocket"
	default:
		return "MTProto"
	}
}

// Check validates public endpoints without credentials, cookies or account access.
func Check(parent context.Context, endpoint Endpoint) Result {
	return check(parent, endpoint, probeNetwork{lookup: net.DefaultResolver.LookupIPAddr, dial: (&net.Dialer{}).DialContext, tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12}})
}

type probeNetwork struct {
	lookup    func(context.Context, string) ([]net.IPAddr, error)
	dial      func(context.Context, string, string) (net.Conn, error)
	tlsConfig *tls.Config
}

func check(parent context.Context, endpoint Endpoint, network probeNetwork) Result {
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	result := Result{ID: endpoint.ID, Name: endpoint.Name, Status: "ok", Summary: "Сервис отвечает", CheckedAt: time.Now().Format(time.RFC3339Nano), Steps: []Step{}}
	run := func(id string, operation func() error) bool {
		start := time.Now()
		err := operation()
		step := Step{ID: id, Status: "ok", MS: time.Since(start).Milliseconds(), Code: id + "_ok", Detail: stageName(id) + ": ответ получен"}
		if err != nil {
			step.Status = "fail"
			step.Code, step.Detail, step.Advice = Failure(id, err)
			result.Status, result.Summary, result.Advice = "fail", step.Detail, step.Advice
		}
		result.Steps = append(result.Steps, step)
		return err == nil
	}
	if !run("dns", func() error { _, err := network.lookup(ctx, endpoint.Host); return err }) {
		return result
	}
	var raw net.Conn
	if !run("tcp", func() error {
		var err error
		raw, err = network.dial(ctx, "tcp", net.JoinHostPort(endpoint.Host, "443"))
		return err
	}) {
		return result
	}
	defer raw.Close()
	tlsConfig := network.tlsConfig.Clone()
	tlsConfig.ServerName = endpoint.Host
	secure := tls.Client(raw, tlsConfig)
	if !run("tls", func() error { return secure.HandshakeContext(ctx) }) {
		return result
	}
	stop := context.AfterFunc(ctx, func() { _ = secure.Close() })
	defer stop()
	if endpoint.Gateway {
		if !run("gateway", func() error {
			dialer := websocket.Dialer{NetDialTLSContext: func(context.Context, string, string) (net.Conn, error) { return secure, nil }, HandshakeTimeout: 5 * time.Second}
			conn, response, err := dialer.DialContext(ctx, "wss://"+endpoint.Host+endpoint.Path, nil)
			if response != nil && response.Body != nil {
				defer response.Body.Close()
			}
			if err != nil {
				return err
			}
			defer conn.Close()
			conn.SetReadLimit(16 << 10)
			var hello struct {
				Op int `json:"op"`
				D  struct {
					Heartbeat float64 `json:"heartbeat_interval"`
				} `json:"d"`
			}
			if err := conn.ReadJSON(&hello); err != nil {
				return err
			}
			if hello.Op != 10 || hello.D.Heartbeat <= 0 {
				return errors.New("unexpected gateway hello")
			}
			return nil
		}) {
			return result
		}
		result.Summary = "Канал событий Discord отвечает"
		result.Advice = "Вход в аккаунт и голосовой UDP-канал этой проверкой не проверяются."
		return result
	}
	var status int
	if !run("https", func() error {
		transport := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return secure, nil }, DisableKeepAlives: true, ForceAttemptHTTP2: false}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+endpoint.Host+endpoint.Path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "Evasion-Diagnostics/1")
		response, err := client.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		status = response.StatusCode
		if status < 200 || status >= 400 {
			return errors.New("http status")
		}
		if endpoint.ID == "discord-api" {
			var payload struct {
				URL string `json:"url"`
			}
			if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&payload); err != nil {
				return err
			}
			if payload.URL != "wss://gateway.discord.gg" && payload.URL != "wss://gateway.discord.gg/" {
				return errors.New("unexpected gateway endpoint")
			}
		}
		return nil
	}) {
		if status != 0 && (status < 200 || status >= 400) {
			last := &result.Steps[len(result.Steps)-1]
			last.Code = "http_" + strconv.Itoa(status)
			last.Detail = "Сервис ответил HTTP " + strconv.Itoa(status)
			last.Advice = "Связь установлена, но сервер ограничил запрос. Повторите позже; это не означает сбой DPI."
			result.Summary, result.Advice = last.Detail, last.Advice
		}
		return result
	}
	return result
}
