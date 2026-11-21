package main

import (
	"fmt"
	"strings"
	"sync"

	wr "github.com/wailsapp/wails/v2/pkg/runtime"
)

type trayControl struct {
	mu                          sync.Mutex
	dark                        bool
	natural                     bool
	options                     StartOptions
	busy                        string
	diagnosing                  bool
	result                      string
	error                       string
	resultsReady                bool
	closed                      bool
	toggle, refresh, hide, quit func()
}

type trayView struct {
	Dark, Natural, DPIOn, TelegramOn, DPIBusy, TelegramBusy, Diagnosing, ResultsReady bool
	DPI, Telegram, Diagnostic, Error                                                  string
}

func newTrayControl() *trayControl {
	return &trayControl{options: StartOptions{Voice: "ttl", Quic: "off", RestartDiscord: true, Boost: true}}
}

func (a *App) SetTrayPreferences(theme string, options StartOptions, skin string) error {
	if theme != "light" && theme != "black" {
		return fmt.Errorf("неизвестная тема")
	}
	if err := options.validate(); err != nil {
		return err
	}
	a.setTraySkinIcon(skin)
	if a.tray == nil {
		return nil
	}
	a.tray.mu.Lock()
	a.tray.dark = theme == "black"
	a.tray.natural = skin == "natural"
	a.tray.options = options
	refresh := a.tray.refresh
	a.tray.mu.Unlock()
	if refresh != nil {
		refresh()
	}
	return nil
}

func (c *trayControl) attach(toggle, refresh, hide, quit func()) {
	c.mu.Lock()
	c.toggle, c.refresh, c.hide, c.quit = toggle, refresh, hide, quit
	closed := c.closed
	c.mu.Unlock()
	if closed {
		quit()
	}
}

func (c *trayControl) detach() {
	c.mu.Lock()
	c.toggle, c.refresh, c.hide, c.quit = nil, nil, nil, nil
	c.mu.Unlock()
}

func (c *trayControl) show() bool {
	c.mu.Lock()
	toggle, closed := c.toggle, c.closed
	c.mu.Unlock()
	if toggle == nil || closed {
		return false
	}
	toggle()
	return true
}

func (c *trayControl) dismiss() {
	c.mu.Lock()
	hide := c.hide
	c.mu.Unlock()
	if hide != nil {
		hide()
	}
}

func (c *trayControl) close() {
	c.mu.Lock()
	c.closed = true
	quit := c.quit
	c.mu.Unlock()
	if quit != nil {
		quit()
	}
}

func (a *App) trayView() trayView {
	c := a.tray
	c.mu.Lock()
	v := trayView{Dark: c.dark, Natural: c.natural, DPIBusy: c.busy == "dpi", TelegramBusy: c.busy == "telegram", Diagnosing: c.diagnosing, Diagnostic: c.result, Error: c.error, ResultsReady: c.resultsReady}
	busy := c.busy
	c.mu.Unlock()
	e := a.engine.snapshot()
	tg := a.GetTelegramState()
	v.DPIOn = e.Phase == phaseRunning
	v.DPIBusy = v.DPIBusy || busy != "" || e.Phase == phaseStarting || e.Phase == phaseStopping
	v.TelegramBusy = v.TelegramBusy || busy != ""
	v.TelegramOn = tg.Running
	v.DPI = map[string]string{phaseStopped: "Подключение выключено", phaseStarting: "Запускаем обход…", phaseRunning: "Обход работает", phaseStopping: "Останавливаем…", phaseFailed: "Не удалось подключиться"}[e.Phase]
	v.Telegram = "Прокси выключен"
	if tg.Running {
		v.Telegram = map[string]string{"waiting": "Ожидает Telegram", "connecting": "Открываем канал…", "online": "Есть обмен данными", "degraded": "Возобновление"}[tg.Phase]
	}
	if v.Diagnostic == "" {
		v.Diagnostic = "Telegram и Discord · без входа в аккаунт"
	}
	if v.Diagnosing {
		v.Diagnostic = "Проверяем соединение, до 16 секунд…"
	}
	return v
}

func trayDiagnosticSummary(results []ServiceDiagnostic) string {
	telegram, discord := "Telegram: нет ответа", "Discord: не проверен"
	discordChecks := 0
	discordFailure := ""
	for _, r := range results {
		if r.ID == "telegram" && r.Status == "ok" {
			telegram = "Telegram отвечает"
		}
		if strings.HasPrefix(r.ID, "discord-") {
			discordChecks++
		}
		if strings.HasPrefix(r.ID, "discord-") && r.Status != "ok" {
			stage := "нет ответа"
			for _, s := range r.Steps {
				if s.Status != "ok" {
					stage = map[string]string{"dns": "DNS", "tcp": "TCP", "tls": "TLS", "https": "HTTPS", "gateway": "WebSocket"}[s.ID]
					break
				}
			}
			if stage == "" {
				stage = "нет ответа"
			}
			discordFailure = "Discord: " + stage
		}
	}
	if discordChecks == 2 {
		discord = "Discord отвечает"
	}
	if discordFailure != "" {
		discord = discordFailure
	}
	return telegram + " · " + discord
}

func (a *App) trayAction(kind string) {
	c := a.tray
	if kind == "open" {
		c.dismiss()
		a.showWindow()
		c.mu.Lock()
		results := c.resultsReady
		c.mu.Unlock()
		if results && a.ctx != nil {
			wr.EventsEmit(a.ctx, "evasion:navigate", "Диагностика")
		}
		return
	}
	if kind == "quit" {
		c.dismiss()
		a.ExitApplication()
		return
	}
	c.mu.Lock()
	if c.closed || (kind == "diagnose" && c.diagnosing) || (kind != "diagnose" && c.busy != "") {
		c.mu.Unlock()
		return
	}
	if kind != "dpi" && kind != "telegram" && kind != "diagnose" {
		c.mu.Unlock()
		return
	}
	if kind == "diagnose" {
		c.diagnosing = true
	} else {
		c.busy = kind
	}
	c.error = ""
	options := c.options
	refresh := c.refresh
	c.mu.Unlock()
	if refresh != nil {
		refresh()
	}
	go func() {
		var err error
		var results []ServiceDiagnostic
		switch kind {
		case "dpi":
			phase := a.engine.snapshot().Phase
			if phase == phaseRunning {
				err = a.StopEngine()
			} else if phase != phaseStarting && phase != phaseStopping {
				err = a.StartEngine(options)
			}
		case "telegram":
			if a.GetTelegramState().Running {
				err = a.StopTelegramProxy()
			} else {
				err = a.StartTelegramProxy(0)
				if err == nil {
					err = a.OpenTelegramProxy()
				}
			}
		case "diagnose":
			results, err = a.RunServiceDiagnostics()
		}
		c.mu.Lock()
		if kind == "diagnose" {
			c.diagnosing = false
			if err == nil {
				c.result = trayDiagnosticSummary(results)
				c.resultsReady = true
			}
		} else {
			c.busy = ""
		}
		if err != nil {
			c.error = strings.Join(strings.Fields(err.Error()), " ")
		}
		refresh = c.refresh
		c.mu.Unlock()
		if refresh != nil {
			refresh()
		}
	}()
}

type trayRect struct{ Left, Top, Right, Bottom int32 }

func placeTrayPanel(x, y, width, height, margin int32, work trayRect) trayRect {
	width = min(width, max(1, work.Right-work.Left-2*margin))
	height = min(height, max(1, work.Bottom-work.Top-2*margin))
	left := x - width + 24
	top := y - height - margin
	if top < work.Top+margin {
		top = y + margin
	}
	left = max(work.Left+margin, min(left, work.Right-margin-width))
	top = max(work.Top+margin, min(top, work.Bottom-margin-height))
	return trayRect{left, top, left + width, top + height}
}
