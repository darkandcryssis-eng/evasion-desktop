package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/fitting-1c/evasion-ui/internal/netcheck"
	"github.com/fitting-1c/evasion-ui/internal/tgproxy"
)

type ServiceStep struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	MS     int64  `json:"ms"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
	Advice string `json:"advice"`
}
type ServiceDiagnostic struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Status    string        `json:"status"`
	Summary   string        `json:"summary"`
	Advice    string        `json:"advice"`
	CheckedAt string        `json:"checkedAt"`
	Steps     []ServiceStep `json:"steps"`
}
type TelegramRoute struct {
	Code      string `json:"code"`
	Reason    string `json:"reason"`
	ID        string `json:"id"`
	Host      string `json:"host"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
	LatencyMS int64  `json:"latencyMs"`
	Failures  int    `json:"failures"`
	Stability int    `json:"stability"`
	Drops     int    `json:"drops"`
	CheckedAt string `json:"checkedAt"`
	RetryAt   string `json:"retryAt"`
}
type SpeedSample struct {
	At   string  `json:"at"`
	Up   float64 `json:"up"`
	Down float64 `json:"down"`
}

func routeViews(routes []tgproxy.RouteStatus) []TelegramRoute {
	out := make([]TelegramRoute, 0, len(routes))
	for _, r := range routes {
		out = append(out, TelegramRoute{Code: r.Code, Reason: r.Reason, ID: r.ID, Host: r.Host, Kind: r.Kind, Status: r.Status, LatencyMS: r.LatencyMS, Failures: r.Failures, Stability: r.Stability, Drops: r.Drops, CheckedAt: r.CheckedAt, RetryAt: r.RetryAt})
	}
	return out
}

func serviceView(r netcheck.Result) ServiceDiagnostic {
	out := ServiceDiagnostic{ID: r.ID, Name: r.Name, Status: r.Status, Summary: r.Summary, Advice: r.Advice, CheckedAt: r.CheckedAt, Steps: []ServiceStep{}}
	for _, s := range r.Steps {
		out.Steps = append(out.Steps, ServiceStep{ID: s.ID, Status: s.Status, MS: s.MS, Code: s.Code, Detail: s.Detail, Advice: s.Advice})
	}
	return out
}

func (a *App) serviceContext() (context.Context, context.CancelFunc) {
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, 16*time.Second)
}

func (a *App) checkRoutes(ctx context.Context) []TelegramRoute {
	a.telegramMu.Lock()
	server := a.telegram
	cfg, err := readTelegramSettings(telegramSettingsPath())
	a.telegramMu.Unlock()
	if err != nil {
		return []TelegramRoute{}
	}
	var routes []tgproxy.RouteStatus
	if server != nil && server.Running() {
		routes = server.CheckRoutes(ctx)
	} else {
		routes = tgproxy.CheckRoutes(ctx, cfg.Community)
	}
	views := routeViews(routes)
	a.reportMu.Lock()
	a.routeResults = views
	a.reportMu.Unlock()
	return views
}

func (a *App) GetTelegramRoutes() []TelegramRoute {
	a.telegramMu.Lock()
	server := a.telegram
	a.telegramMu.Unlock()
	if server != nil && server.Running() {
		return routeViews(server.Routes())
	}
	a.reportMu.Lock()
	defer a.reportMu.Unlock()
	return append([]TelegramRoute{}, a.routeResults...)
}

func (a *App) CheckTelegramRoutes() ([]TelegramRoute, error) {
	if !a.serviceMu.TryLock() {
		return nil, errors.New("проверка уже выполняется")
	}
	defer a.serviceMu.Unlock()
	ctx, cancel := a.serviceContext()
	defer cancel()
	return a.checkRoutes(ctx), nil
}

func (a *App) GetServiceDiagnostics() []ServiceDiagnostic {
	a.reportMu.Lock()
	defer a.reportMu.Unlock()
	return append([]ServiceDiagnostic{}, a.serviceResults...)
}

func (a *App) RunServiceDiagnostics() ([]ServiceDiagnostic, error) {
	if !a.serviceMu.TryLock() {
		return nil, errors.New("проверка уже выполняется")
	}
	defer a.serviceMu.Unlock()
	ctx, cancel := a.serviceContext()
	defer cancel()
	endpoints := []netcheck.Endpoint{netcheck.TelegramWeb, netcheck.DiscordAPI, netcheck.DiscordGateway}
	results := make([]ServiceDiagnostic, len(endpoints)+1)
	var wg sync.WaitGroup
	for i, endpoint := range endpoints {
		wg.Add(1)
		go func(i int, endpoint netcheck.Endpoint) {
			defer wg.Done()
			results[i+1] = serviceView(netcheck.Check(ctx, endpoint))
		}(i, endpoint)
	}
	started := time.Now()
	routes := a.checkRoutes(ctx)
	telegram := ServiceDiagnostic{ID: "telegram", Name: "Telegram · протокол", Status: "fail", Summary: "Проверенные маршруты не ответили Telegram", Advice: "Включите обход, разрешите резервные узлы и повторите. Остальные дата-центры могут иметь другое состояние.", CheckedAt: time.Now().Format(time.RFC3339Nano), Steps: []ServiceStep{{ID: "mtproto", Status: "fail", Code: "mtproto_unavailable", Detail: "Нет подтверждённого ответа MTProto"}}}
	for _, r := range routes {
		checked, _ := time.Parse(time.RFC3339Nano, r.CheckedAt)
		if r.Status == "verified" && (strings.HasPrefix(r.Host, "kws2.") || r.ID == "tcp:dc2") && !checked.Before(started) {
			telegram.Status, telegram.Summary = "ok", "Получен корректный ответ Telegram"
			telegram.Advice = "Проверен DC2 без входа в аккаунт. Другие дата-центры, медиа и звонки проверяются отдельно."
			telegram.Steps = []ServiceStep{{ID: "mtproto", Status: "ok", Code: "mtproto_ok", MS: r.LatencyMS, Detail: "Ответ resPQ и nonce проверены"}}
			break
		}
	}
	results[0] = telegram
	wg.Wait()
	a.reportMu.Lock()
	a.serviceResults = results
	a.reportMu.Unlock()
	return results, nil
}
