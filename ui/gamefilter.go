package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	wr "github.com/wailsapp/wails/v2/pkg/runtime"
)

type GameTransportState struct {
	Stage      string `json:"stage"`
	Connecting int    `json:"connecting"`
	TLSWaiting int    `json:"tlsWaiting"`
	Responding int    `json:"responding"`
	NoTCPReply int    `json:"noTCPReply"`
	NoTLSReply int    `json:"noTLSReply"`
	TLSClosed  int    `json:"tlsClosed"`
	TCPClosed  int    `json:"tcpClosed"`
}

type GameFilterSettings struct {
	Mode        string   `json:"mode"`
	Protocol    string   `json:"protocol"`
	Executables []string `json:"executables"`
	// OnDemand — поднимать фильтр только пока запущена выбранная игра.
	OnDemand bool `json:"onDemand"`
	Adaptive bool `json:"adaptive"`
}
type GameFilterStats struct {
	Tunnel         bool   `json:"tunnel"`
	TunnelReceived uint64 `json:"tunnelReceived"`
	TunnelSent     uint64 `json:"tunnelSent"`
	TLSApplied     uint64 `json:"tlsApplied"`
	TLSFailed      uint64 `json:"tlsFailed"`
	TLSPrepared    uint64 `json:"preparedTLSIPs"`
	Connections    uint64 `json:"connections"`
	UDP            uint64 `json:"udp"`
	TCP            uint64 `json:"tcp"`
	Decoys         uint64 `json:"decoys"`
	Errors         uint64 `json:"errors"`
	Limited        uint64 `json:"limited"`
}
type GameProcessState struct {
	Family    string `json:"family"`
	Launchers int    `json:"launchers"`
	Clients   int    `json:"clients"`
	Helpers   int    `json:"helpers"`
}
type gameSnapshot struct {
	Transport GameTransportState `json:"transport"`
	Processes []GameProcessState `json:"processes"`
	PID       int                `json:"pid"`
	At        string             `json:"at"`
	Mode      string             `json:"mode"`
	Protocol  string             `json:"protocol"`
	Targets   []string           `json:"targets"`
	Stats     GameFilterStats    `json:"stats"`
	Adaptive  GameAdaptiveState  `json:"adaptive"`
	Error     string             `json:"error"`
}
type GameAdaptiveState struct {
	Stage      string `json:"stage"`
	Watching   int    `json:"watching"`
	Helping    int    `json:"helping"`
	Responsive int    `json:"responsive"`
}
type GameFilterView struct {
	// Armed — фильтр включён «по требованию» и ждёт запуска выбранной игры.
	Armed          bool               `json:"armed"`
	Route          GameRouteView      `json:"route"`
	Transport      GameTransportState `json:"transport"`
	Processes      []GameProcessState `json:"processes"`
	Adaptive       GameAdaptiveState  `json:"adaptive"`
	Settings       GameFilterSettings `json:"settings"`
	ActiveMode     string             `json:"activeMode"`
	ActiveProtocol string             `json:"activeProtocol"`
	Pending        bool               `json:"pending"`
	EngineRunning  bool               `json:"engineRunning"`
	Fresh          bool               `json:"fresh"`
	Targets        []string           `json:"targets"`
	Stats          GameFilterStats    `json:"stats"`
	Error          string             `json:"error"`
}

func defaultGameSettings() GameFilterSettings {
	return GameFilterSettings{Mode: "off", Adaptive: true, Protocol: "both", Executables: []string{}, OnDemand: true}
}
func (s GameFilterSettings) validate() error {
	if s.Mode != "off" && s.Mode != "auto" && s.Mode != "gentle" && s.Mode != "balanced" && s.Mode != "strong" {
		return errors.New("неизвестный игровой режим")
	}
	if s.Protocol != "both" && s.Protocol != "tcp" && s.Protocol != "udp" {
		return errors.New("неизвестный игровой протокол")
	}
	if len(s.Executables) > 16 {
		return errors.New("можно добавить не более 16 файлов игр")
	}
	for _, path := range s.Executables {
		if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") {
			return errors.New("выберите полный путь к .exe игры")
		}
		switch strings.ToLower(filepath.Base(path)) {
		case "steam.exe", "steamwebhelper.exe", "epicgameslauncher.exe", "epicwebhelper.exe", "beservice.exe", "beservice_x64.exe", "easyanticheat.exe", "easyanticheat_eos.exe", "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe", "csrss.exe", "explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "browser.exe", "msedgewebview2.exe", "discord.exe", "telegram.exe", "evasion.exe", "evasionv2.exe":
			return errors.New("выберите игру, а не системную программу или браузер")
		}
		if strings.Contains(strings.ToLower(filepath.Clean(path)), "\\windows\\") {
			return errors.New("системные программы нельзя добавить как игру")
		}
	}
	if s.Mode != "off" && len(s.Executables) == 0 {
		return errors.New("выберите хотя бы одну игру")
	}
	return nil
}
func readGameSettings(base string) (GameFilterSettings, error) {
	s := defaultGameSettings()
	b, err := os.ReadFile(filepath.Join(base, "game-filter.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return defaultGameSettings(), err
	}
	if len(b) > 65536 || json.Unmarshal(b, &s) != nil {
		return defaultGameSettings(), errors.New("настройки игр повреждены; игровой фильтр выключен")
	}
	if s.Executables == nil {
		s.Executables = []string{}
	}
	// Settings saved before games were added by file had built-in targets only.
	if len(s.Executables) == 0 && slices.Contains([]string{"auto", "gentle", "balanced", "strong"}, s.Mode) {
		s.Mode = "off"
	}
	if err = s.validate(); err != nil {
		return defaultGameSettings(), err
	}
	return s, nil
}
func gameArgs(s GameFilterSettings) []string {
	if s.Mode == "off" {
		return nil
	}
	args := []string{"--game-adaptive=" + strconv.FormatBool(s.Adaptive), "--game-mode", s.Mode, "--game-protocol", s.Protocol}
	for _, path := range s.Executables {
		args = append(args, "--game-exe", path)
	}
	return args
}
func (a *App) GetGameFilter() GameFilterView {
	v := GameFilterView{Settings: defaultGameSettings(), ActiveMode: "off", ActiveProtocol: "both", Targets: []string{}, Processes: []GameProcessState{}}
	l, err := resolveLayout()
	if err != nil {
		v.Error = err.Error()
		return v
	}
	v.Route = gameRouteView(l.Base)
	v.Armed = a.gameArmed.Load()
	a.gameMu.Lock()
	v.Settings, err = readGameSettings(l.Base)
	a.gameMu.Unlock()
	if err != nil {
		v.Error = err.Error()
	}
	state := a.games.snapshot()
	var activeArgs []string
	if state.Phase == phaseFailed && v.Settings.Mode != "off" {
		v.Error = "Движок не запустился: " + state.Error
	}
	v.EngineRunning = state.Phase == phaseRunning

	a.games.mu.Lock()
	if v.EngineRunning && a.games.cmd != nil {
		args := a.games.cmd.Args
		for i := 0; i < len(args); i++ {
			if args[i] == "--game-vless-profile" {
				i++
				continue
			}
			if strings.HasPrefix(args[i], "--game-") && args[i] != "--game-only" {
				activeArgs = append(activeArgs, args[i])
				if !strings.Contains(args[i], "=") && i+1 < len(args) {
					i++
					activeArgs = append(activeArgs, args[i])
				}
			}
		}

		for i, arg := range args {
			if i+1 < len(args) {
				switch arg {
				case "--game-mode":
					v.ActiveMode = args[i+1]
				case "--game-protocol":
					v.ActiveProtocol = args[i+1]
				}
			}
		}
	}
	a.games.mu.Unlock()
	v.Pending = !slices.Equal(activeArgs, gameArgs(v.Settings))
	if !v.EngineRunning || v.ActiveMode == "off" {
		return v
	}
	b, err := os.ReadFile(filepath.Join(l.Base, "game-runtime", "state", "gamefilter.json"))
	if err != nil || len(b) > 16384 {
		return v
	}
	var snap gameSnapshot
	if json.Unmarshal(b, &snap) != nil || snap.PID != state.PID || snap.Mode != v.ActiveMode || snap.Protocol != v.ActiveProtocol {
		return v
	}
	at, err := time.Parse(time.RFC3339Nano, snap.At)
	if err != nil || time.Since(at) > 5*time.Second || at.After(time.Now().Add(time.Minute)) {
		return v
	}
	v.Fresh = true
	v.Stats = snap.Stats
	v.Adaptive = snap.Adaptive
	v.Transport = snap.Transport
	v.Targets = snap.Targets
	v.Processes = snap.Processes
	if snap.Error != "" {
		v.Error = snap.Error
	}
	return v
}
func (a *App) SetGameFilter(s GameFilterSettings) error {
	if err := s.validate(); err != nil {
		return err
	}
	l, err := resolveLayout()
	if err != nil {
		return err
	}
	a.gameMu.Lock()
	defer a.gameMu.Unlock()
	b, _ := json.Marshal(s)
	return writeAtomic(filepath.Join(l.Base, "game-filter.json"), b)
}
func (a *App) SelectGameExecutable() (string, error) {
	if a.ctx == nil {
		return "", errors.New("окно приложения ещё не готово")
	}
	return wr.OpenFileDialog(a.ctx, wr.OpenDialogOptions{Title: "Выберите исполняемый файл игры", Filters: []wr.FileFilter{{DisplayName: "Игры Windows", Pattern: "*.exe"}}})
}
func (a *App) ApplyGameFilter(opts StartOptions) error {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	if a.shuttingDown {
		return errors.New("приложение закрывается")
	}
	a.tuner.mu.Lock()
	tuning := a.tuner.busy
	a.tuner.mu.Unlock()
	if tuning {
		return errors.New("дождитесь окончания подбора YouTube")
	}
	if a.games.snapshot().Phase == phaseStarting || a.games.snapshot().Phase == phaseStopping {
		return errors.New("дождитесь переключения игрового фильтра")
	}
	l, err := resolveLayout()
	if err != nil {
		return err
	}
	a.gameMu.Lock()
	settings, err := readGameSettings(l.Base)
	a.gameMu.Unlock()
	if err != nil {
		return err
	}
	if settings.Mode == "off" {
		a.gameArmed.Store(false)
		return a.games.stop()
	}
	if elev, checked := isElevated(); checked && !elev {
		return errors.New("запустите Evasion от имени администратора")
	}
	if settings.OnDemand {
		// Взвести сторожа; сам фильтр поднимается только при запущенной игре.
		a.gameArmed.Store(true)
		names, perr := runningProcessNames()
		if perr == nil && !anyGameRunning(settings, names) {
			return a.games.stop()
		}
	} else {
		a.gameArmed.Store(false)
	}
	return a.startGameFilterLocked()
}

// startGameFilterLocked перезапускает игровой движок с текущими настройками.
// Вызывать под a.lifecycle.
func (a *App) startGameFilterLocked() error {
	l, err := resolveLayout()
	if err != nil {
		return err
	}
	a.gameMu.Lock()
	settings, err := readGameSettings(l.Base)
	a.gameMu.Unlock()
	if err != nil {
		return err
	}
	if settings.Mode == "off" {
		return a.games.stop()
	}
	if err = a.games.stop(); err != nil {
		return err
	}
	gameStartArgs := gameArgs(settings)
	if gameRouteView(l.Base).Configured {
		gameStartArgs = append(gameStartArgs, "--game-vless-profile", filepath.Join(l.Base, gameRouteFile))
	}
	l.Base = filepath.Join(l.Base, "game-runtime")
	l.Runtime = l.Base
	l.Engine = filepath.Join(l.Base, payloadEngine)
	if err = extractPayload(l); err != nil {
		return err
	}
	if err = a.games.start(l, StartOptions{Voice: "off", Quic: "off"}, gameStartArgs...); err != nil {
		return err
	}
	return a.games.awaitStartup()
}
func (a *App) StopGameFilter() error {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	a.gameArmed.Store(false)
	return a.games.stop()
}
