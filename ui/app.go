package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fitting-1c/evasion-ui/internal/tgproxy"
	"github.com/wailsapp/wails/v2/pkg/options"
	wr "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App — Go-API оболочки, привязанное к фронтенду через Wails.
//
// Движок запускается подпроцессом (runtime\evasion.exe run --mode intercept),
// а не импортируется: его пакеты лежат в internal/ корневого модуля, горячий
// путь проверен в поле именно в виде CLI, а падение движка не роняет окно.
// Управление — через stdin (--stop-on-stdin-eof), наблюдение — через stdout
// (строка запуска) и stderr (slog JSON), плюс файлы state\.
type App struct {
	gameMu          sync.Mutex
	tuner           networkTuner
	quitRequested   atomic.Bool
	trayAvailable   atomic.Bool
	previousUnclean bool
	sessionPath     string
	lifecycle       sync.Mutex
	settingsMu      sync.Mutex
	cancelAutoStart context.CancelFunc
	shuttingDown    bool
	ctx             context.Context
	engine          *engineManager
	games           *engineManager
	telegramMu      sync.Mutex
	telegram        *tgproxy.Server
	telegramErr     string
	tray            *trayControl
	serviceMu       sync.Mutex
	reportMu        sync.Mutex
	serviceResults  []ServiceDiagnostic
	routeResults    []TelegramRoute
	ruRemoved       []string
	gameArmed       atomic.Bool
}

func NewApp() *App {
	return &App{engine: newEngineManager(), games: newEngineManager(), tray: newTrayControl()}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.startReliabilityLog()
	// Подчистить оставшийся подпроцесс этой установки Evasion.
	// В фоне, чтобы не тормозить появление окна.
	go func() {
		a.lifecycle.Lock()
		defer a.lifecycle.Unlock()
		a.tuner.mu.Lock()
		tuning := a.tuner.busy
		a.tuner.mu.Unlock()
		if a.engine.snapshot().Phase == phaseStopped && !tuning {
			killStrayEngines()
		}
	}()
	a.startTray()
	go a.superviseEngine(ctx)
	go a.watchGames(ctx)
	go a.restoreTelegramProxy()
	for _, arg := range os.Args[1:] {
		if arg == "--autostart" {
			var autoCtx context.Context
			autoCtx, a.cancelAutoStart = context.WithCancel(ctx)
			go a.connectAtLogin(autoCtx)
			break
		}
	}
}

// shutdown останавливает движок штатно при закрытии окна. Если оболочку
// убили, движок остановится сам: закроется его stdin.
func (a *App) shutdown(context.Context) {
	a.lifecycle.Lock()
	a.shuttingDown = true
	a.lifecycle.Unlock()
	if a.cancelAutoStart != nil {
		a.cancelAutoStart()
	}
	_ = a.StopGameFilter()
	_ = a.StopEngine()
	a.telegramMu.Lock()
	if a.telegram != nil {
		_ = a.telegram.Close()
	}
	a.telegramMu.Unlock()
	a.trayQuit()
	if a.sessionPath != "" {
		_ = markSession(a.sessionPath, true)
	}
}

// onSecondInstance — вторая копия оболочки завершается, а эта поднимает своё
// окно из трея/свёрнутого состояния на передний план (см. SingleInstanceLock).
func (a *App) onSecondInstance(options.SecondInstanceData) { a.showWindow() }

// MinimiseToTray прячет окно в системный трей (значок остаётся; вернуть —
// клик по значку или пункт «Открыть»). Отдельно от обычной кнопки сворачивания
// в панель задач.
func (a *App) MinimiseToTray() {
	if a.ctx != nil {
		// Фронтенд глушит WebGL-фон и фоновые видео, пока окна нет: скрытое
		// окно WebView2 продолжает гонять GPU-декодер и со временем падает,
		// унося всё приложение из трея.
		wr.EventsEmit(a.ctx, "evasion:window", "hidden")
		wr.WindowHide(a.ctx)
	}
}

// OpenDataFolder открывает папку данных (state\, runtime\, конфиг) в
// Проводнике — доступ из «Настроек» в один клик. Возвращает путь к папке.
func (a *App) OpenDataFolder() (string, error) {
	l, err := resolveLayout()
	if err != nil {
		return "", err
	}
	if err := openPath(l.Base); err != nil {
		return l.Base, err
	}
	return l.Base, nil
}

// AppState — всё, что нужно экранам «Обзор» и строке состояния.
type AppState struct {
	Telegram   TelegramState `json:"telegram"`
	Engine     EngineState   `json:"engine"`
	Elevated   bool          `json:"elevated"`
	Payload    payloadInfo   `json:"payload"`
	BaseDir    string        `json:"baseDir"`
	ConfigPath string        `json:"configPath"`
	UserConfig bool          `json:"userConfig"`
	RuGuard    []string      `json:"ruGuard"`
}

func (a *App) GetState() AppState {
	st := AppState{Engine: a.engine.snapshot(), Payload: embeddedPayload(), Telegram: a.GetTelegramState()}
	st.Elevated, _ = isElevated()
	if l, err := resolveLayout(); err == nil {
		st.BaseDir, st.ConfigPath, st.UserConfig = l.Base, l.Config, l.UserConfig
	}
	a.settingsMu.Lock()
	st.RuGuard = append([]string{}, a.ruRemoved...)
	a.settingsMu.Unlock()
	return st
}

// StartEngine распаковывает встроенный пакет и поднимает движок. Если
// включён перезапуск Discord, он выполняется после строки запуска движка
// (перехват уже стоит), в фоне.
func (a *App) StartEngine(opts StartOptions) error {
	if a.cancelAutoStart != nil {
		a.cancelAutoStart()
	}
	return a.startEngine(opts)
}

func (a *App) startEngine(opts StartOptions) error {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	a.engine.resetGuard()
	return a.startEngineLocked(opts, false)
}

func (a *App) startEngineLocked(opts StartOptions, suppressDiscordRestart bool) error {
	if a.shuttingDown {
		return errors.New("приложение закрывается")
	}
	a.tuner.mu.Lock()
	tuning := a.tuner.busy
	a.tuner.mu.Unlock()
	if tuning {
		return errors.New("дождитесь окончания подбора YouTube или отмените его")
	}
	if err := opts.validate(); err != nil {
		return err
	}
	phase := a.engine.snapshot().Phase
	if phase == phaseStarting || phase == phaseRunning || phase == phaseStopping {
		return errors.New("движок уже запущен")
	}
	if elev, checked := isElevated(); checked && !elev {
		return errors.New("нет прав администратора: WinDivert без них не поднимется. Запустите Evasion.exe от имени администратора")
	}
	l, err := resolveLayout()
	if err != nil {
		return err
	}
	// Снять любые конкурирующие evasion.exe перед запуском: два движка дерутся
	// за WinDivert handle и не дают обновить runtime. Свой процесс ещё не поднят.
	killStrayEngines()
	if err := extractPayload(l); err != nil {
		return err
	}
	beforeEngineStart()
	l = a.adaptiveLayout(l, opts)
	var removed []string
	l, removed = guardLayout(l)
	a.settingsMu.Lock()
	a.ruRemoved = removed
	a.settingsMu.Unlock()
	if err := a.engine.start(l, opts); err != nil {
		return err
	}
	a.rememberLaunchOptions(opts)
	if opts.RestartDiscord && !suppressDiscordRestart {
		go func() {
			if !a.engine.waitReady() {
				a.engine.setDiscord("Discord не перезапущен: движок не поднялся")
				return
			}
			a.engine.setDiscord("Перезапускаю Discord…")
			a.engine.setDiscord(discordResult(restartDiscord(a.engine.discordProxyAddress())))
		}()
	}
	return nil
}

func (a *App) StopEngine() error {
	a.CancelYouTubeTuning()
	if a.cancelAutoStart != nil {
		a.cancelAutoStart()
	}
	return a.stopEngine()
}

func (a *App) stopEngine() error {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	return a.engine.stop()
}

// RestartDiscord — ручной перезапуск клиента с выключенным DoH.
func (a *App) RestartDiscord() string {
	msg := discordResult(restartDiscord(a.engine.discordProxyAddress()))
	a.engine.setDiscord(msg)
	return msg
}

type discordStartResult struct {
	Version string
	Tunnel  bool
}

func discordResult(result discordStartResult, err error) string {
	if err != nil {
		return err.Error()
	}
	message := "Discord запущен: " + result.Version + " (DoH выключен"
	if result.Tunnel {
		message += "; резервный маршрут"
	}
	return message + ")"
}

// TargetGroup — группа доменов из конфига и действующая на неё стратегия.
type TargetGroup struct {
	Name        string   `json:"name"`
	Domains     []string `json:"domains"`
	OwnStrategy bool     `json:"ownStrategy"`
	Active      string   `json:"active"`
}

type configShape struct {
	Groups     map[string][]string        `json:"groups"`
	Strategies map[string]json.RawMessage `json:"strategies"`
	Strategy   json.RawMessage            `json:"strategy"`
}

func readConfig(path string) (configShape, error) {
	var c configShape
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// configForView — конфиг, который будет (или был) передан движку: до
// первого запуска runtime\config.json ещё не распакован, тогда читаем
// встроенный эталон.
func configForView(l layout) (configShape, error) {
	if _, err := os.Stat(l.Config); err == nil {
		return readConfig(l.Config)
	}
	b, ok := payloadFile(payloadConfig)
	if !ok {
		return configShape{}, errors.New("конфиг не найден: нет ни config.json рядом с Evasion.exe, ни встроенного")
	}
	var c configShape
	return c, json.Unmarshal(b, &c)
}

func (a *App) GetTargets() ([]TargetGroup, error) {
	l, err := resolveLayout()
	if err != nil {
		return nil, err
	}
	c, err := configForView(l)
	if err != nil {
		return nil, err
	}
	active := map[string]string{}
	for _, s := range a.engine.snapshot().Strategies {
		active[s.Group] = s.Strategy
	}
	out := make([]TargetGroup, 0, len(c.Groups))
	for name, domains := range c.Groups {
		_, own := c.Strategies[name]
		out = append(out, TargetGroup{Name: name, Domains: domains, OwnStrategy: own, Active: active[name]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DiagnosticItem — одна проверка экрана «Диагностика».
type DiagnosticItem struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Tone   string `json:"tone"`
	Detail string `json:"detail"`
}

func (a *App) GetDiagnostics() []DiagnosticItem {
	var items []DiagnosticItem
	add := func(name, status, tone, detail string) {
		items = append(items, DiagnosticItem{name, status, tone, detail})
	}

	switch elev, checked := isElevated(); {
	case !checked:
		add("Права администратора", "Недоступно", "warning", "Перехват работает только в Windows.")
	case elev:
		add("Права администратора", "Есть", "success", "Есть разрешение запросить загрузку сетевого драйвера. Его состояние проверяется отдельно.")
	default:
		add("Права администратора", "Нет", "warning", "Запустите Evasion.exe от имени администратора.")
	}

	p := embeddedPayload()
	if a.previousUnclean {
		add("Предыдущий сеанс", "Завершился неожиданно", "warning", "Windows не сообщил точную причину. При повторном сбое аварийная трассировка сохраняется локально в crash.log; в экспорт отчёта она не включается.")
	}
	l, lerr := resolveLayout()
	if p.Engine {
		add("Встроенный движок", "Есть", "success", "evasion.exe распаковывается в "+l.Runtime+" при запуске.")
	} else {
		add("Встроенный движок", "Нет", "warning", errNoEngine.Error())
	}

	if lerr == nil {
		dll := fileExists(filepath.Join(l.Runtime, payloadDivertDLL)) && fileExists(filepath.Join(l.Runtime, payloadDivertSys))
		switch {
		case dll:
			add("Файлы WinDivert", "На месте", "success", "WinDivert.dll и WinDivert64.sys лежат в "+l.Runtime+".")
		case p.WinDivert:
			add("Файлы WinDivert", "Встроены", "success", "Будет распакован при первом запуске.")
		default:
			add("Файлы WinDivert", "Нет", "warning", "Положите WinDivert.dll и WinDivert64.sys в "+l.Runtime+".")
		}

		if c, err := configForView(l); err != nil {
			add("Конфигурация", "Ошибка", "warning", err.Error())
		} else {
			src := "встроенный эталон (examples/config.json на момент сборки)"
			if l.UserConfig {
				src = "свой файл " + l.Config
			}
			add("Конфигурация", "Готово", "success", fmt.Sprintf("%s; групп: %d, своих стратегий: %d.", src, len(c.Groups), len(c.Strategies)))
		}

		items = append(items, driverDiagnosticItem(a.driverDiagnostic()))
		add(rtcTrackItem(l))
		add(lockItem(l, a.engine.snapshot().PID))
		add(hostsItem())
	}
	return items
}

func rtcTrackItem(l layout) (string, string, string, string) {
	const name = "Память голоса (rtctrack)"
	path := filepath.Join(l.State, "rtctrack.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return name, "Пусто", "neutral", "Файла " + path + " нет. Память наберётся за 10–15 минут голоса. Чтобы взять уже прогретую, скопируйте rtctrack.json из прежней папки state в " + l.State + "."
	}
	var snap struct {
		SavedAt time.Time         `json:"saved_at"`
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(b, &snap); err != nil {
		return name, "Не читается", "warning", path + ": " + err.Error()
	}
	return name, fmt.Sprintf("%d пар", len(snap.Entries)), "success",
		fmt.Sprintf("%s, сохранено %s. Не удаляйте этот файл.", path, snap.SavedAt.Local().Format("02.01 15:04"))
}

func lockItem(l layout, ownPID int) (string, string, string, string) {
	const name = "Другие копии движка"
	b, err := os.ReadFile(filepath.Join(l.State, "engine.lock"))
	if err != nil {
		return name, "Нет", "success", "Конфликтов за WinDivert не будет."
	}
	var entries []struct {
		PID int `json:"pid"`
	}
	_ = json.Unmarshal(b, &entries)
	var others []string
	for _, e := range entries {
		if e.PID != ownPID && pidAlive(e.PID) {
			others = append(others, fmt.Sprint(e.PID))
		}
	}
	if len(others) == 0 {
		return name, "Нет", "success", "Конфликтов за WinDivert не будет."
	}
	return name, "Найдены", "warning", "Запущен другой evasion.exe (PID " + strings.Join(others, ", ") + "), например из start-discord.bat. Закройте его окно перед запуском отсюда."
}

func hostsItem() (string, string, string, string) {
	const name = "hosts-подмена"
	b, err := os.ReadFile(hostsFilePath())
	if err != nil {
		return name, "Не читается", "neutral", err.Error()
	}
	if bytes.Contains(b, []byte("cloudflare-fallback")) {
		return name, "Применена", "success", "Блок cloudflare-fallback есть в hosts. Движок его не снимает при остановке; снять: evasion.exe hosts clean."
	}
	return name, "Нет", "neutral", "Блок появится при запуске движка, если transport_fallback включён в конфиге."
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// DoctorCheck — сводная строка отчёта `evasion doctor --json`.
type DoctorCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// RunDoctor запускает `evasion.exe doctor --json` и возвращает сводку проверок.
func (a *App) RunDoctor() ([]DoctorCheck, error) {
	l, err := resolveLayout()
	if err != nil {
		return nil, err
	}
	if err := extractPayload(l); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.Engine, "doctor", "--json", "--config", l.Config)
	cmd.Dir = l.Base
	hideConsole(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run() // код 1 при вердикте fail — отчёт всё равно на stdout
	var rep struct {
		Checks []DoctorCheck `json:"checks"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("doctor: %v: %s", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("doctor: не удалось разобрать отчёт: %w", err)
	}
	d := a.driverDiagnostic()
	status := "warn"
	if d.Status == "ok" {
		status = "ok"
	}
	for i := range rep.Checks {
		if rep.Checks[i].ID == "windivert_driver" {
			rep.Checks[i] = DoctorCheck{ID: "windivert_driver", Status: status, Reason: d.Summary + ". " + d.Advice}
		}
	}
	return rep.Checks, nil
}

// PortfolioView — содержимое state\status.json (пишется только в режиме
// автопилота --auto; в повседневном фиксированном режиме файла нет).
type PortfolioView struct {
	Found     bool              `json:"found"`
	UpdatedAt string            `json:"updatedAt"`
	Holdings  []PortfolioHolder `json:"holdings"`
}

type PortfolioHolder struct {
	StrategyID   string `json:"strategy_id"`
	Status       string `json:"status"`
	Observations int64  `json:"observations"`
	Targets      int    `json:"targets"`
}

func (a *App) GetPortfolio() (PortfolioView, error) {
	l, err := resolveLayout()
	if err != nil {
		return PortfolioView{}, err
	}
	b, err := os.ReadFile(filepath.Join(l.State, "status.json"))
	if errors.Is(err, os.ErrNotExist) {
		return PortfolioView{}, nil
	}
	if err != nil {
		return PortfolioView{}, err
	}
	var raw struct {
		UpdatedAt time.Time `json:"updated_at"`
		Portfolio []struct {
			StrategyID   string          `json:"strategy_id"`
			Status       json.RawMessage `json:"status"`
			Observations int64           `json:"observations"`
			Targets      int             `json:"targets"`
		} `json:"portfolio"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return PortfolioView{}, fmt.Errorf("status.json: %w", err)
	}
	v := PortfolioView{Found: true, UpdatedAt: raw.UpdatedAt.Format(time.RFC3339)}
	for _, h := range raw.Portfolio {
		v.Holdings = append(v.Holdings, PortfolioHolder{
			StrategyID:   h.StrategyID,
			Status:       strings.Trim(string(h.Status), `"`),
			Observations: h.Observations,
			Targets:      h.Targets,
		})
	}
	return v, nil
}
