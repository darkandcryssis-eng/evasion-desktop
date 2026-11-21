package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/fitting-1c/evasion-ui/internal/tgproxy"
	wr "github.com/wailsapp/wails/v2/pkg/runtime"
)

const defaultTelegramPort = 17655
const defaultTelegramTunnelAddress = "127.0.0.1:17659"

type telegramSettings struct {
	Community bool   `json:"community"`
	Enabled   bool   `json:"enabled"`
	Port      int    `json:"port"`
	Secret    string `json:"secret"`
}

type TelegramState struct {
	Speeds      []SpeedSample `json:"speeds"`
	Running     bool          `json:"running"`
	Phase       string        `json:"phase"`
	Address     string        `json:"address"`
	Active      int64         `json:"active"`
	Connections uint64        `json:"connections"`
	BytesUp     uint64        `json:"bytesUp"`
	BytesDown   uint64        `json:"bytesDown"`
	Failures    uint64        `json:"failures"`
	Rejected    uint64        `json:"rejected"`
	Route       string        `json:"route"`
	DialMS      int64         `json:"dialMs"`
	LastDataAt  string        `json:"lastDataAt"`
	Error       string        `json:"error"`
	Logs        []LogLine     `json:"logs"`
	Community   bool          `json:"community"`
	Enabled     bool          `json:"enabled"`
	Port        int           `json:"port"`
	Link        string        `json:"link"`
}

func telegramSettingsPath() string { return filepath.Join(dataDir(), "telegram-proxy.json") }

func readTelegramSettings(path string) (telegramSettings, error) {
	cfg := telegramSettings{Port: defaultTelegramPort, Community: true}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if len(b) > 4096 {
		return cfg, errors.New("настройки Telegram слишком большие")
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("настройки Telegram повреждены: %w", err)
	}
	if cfg.Port < 1024 || cfg.Port > 65535 {
		return cfg, errors.New("порт Telegram должен быть от 1024 до 65535")
	}
	if cfg.Secret != "" {
		decoded, err := hex.DecodeString(cfg.Secret)
		if err != nil || len(decoded) != 16 {
			return cfg, errors.New("секрет Telegram повреждён")
		}
	}
	return cfg, nil
}

func writeTelegramSettings(path string, cfg telegramSettings) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func telegramLink(cfg telegramSettings) string {
	if cfg.Secret == "" {
		return ""
	}
	q := url.Values{"server": {"127.0.0.1"}, "port": {strconv.Itoa(cfg.Port)}, "secret": {"dd" + cfg.Secret}}
	return "tg://proxy?" + q.Encode()
}

func (a *App) GetTelegramState() TelegramState {
	a.telegramMu.Lock()
	defer a.telegramMu.Unlock()
	cfg, err := readTelegramSettings(telegramSettingsPath())
	snapshot := tgproxy.Snapshot{Phase: "stopped"}
	if a.telegram != nil {
		snapshot = a.telegram.Snapshot()
	}
	state := TelegramState{Running: snapshot.Running, Phase: snapshot.Phase, Address: snapshot.Address, Active: snapshot.Active, Connections: snapshot.Connections, BytesUp: snapshot.BytesUp, BytesDown: snapshot.BytesDown, Failures: snapshot.Failures, Rejected: snapshot.Rejected, Route: snapshot.Route, DialMS: snapshot.DialMS, LastDataAt: snapshot.LastDataAt, Error: snapshot.Error, Logs: []LogLine{}, Enabled: cfg.Enabled, Port: cfg.Port, Link: telegramLink(cfg), Community: cfg.Community}
	for _, line := range snapshot.Logs {
		state.Logs = append(state.Logs, LogLine{At: line.At, Level: line.Level, Msg: line.Msg, Attrs: line.Attrs})
	}
	state.Speeds = make([]SpeedSample, 0, len(snapshot.Speeds))
	for _, sample := range snapshot.Speeds {
		state.Speeds = append(state.Speeds, SpeedSample{At: sample.At, Up: sample.Up, Down: sample.Down})
	}
	if a.telegramErr != "" {
		state.Error = a.telegramErr
	}
	if err != nil {
		state.Error = err.Error()
	}
	return state
}

func (a *App) StartTelegramProxy(port int) error {
	a.telegramMu.Lock()
	defer a.telegramMu.Unlock()
	return a.startTelegramProxyLocked(port)
}

func (a *App) startTelegramProxyLocked(port int) error {
	a.lifecycle.Lock()
	closing := a.shuttingDown
	a.lifecycle.Unlock()
	if closing {
		return errors.New("приложение закрывается")
	}
	cfg, err := readTelegramSettings(telegramSettingsPath())
	if err != nil {
		a.telegramErr = err.Error()
		return err
	}
	if port == 0 {
		port = cfg.Port
	}
	if port < 1024 || port > 65535 {
		return errors.New("порт Telegram должен быть от 1024 до 65535")
	}
	if a.telegram != nil && a.telegram.Snapshot().Running {
		if port == cfg.Port {
			return nil
		}
		return errors.New("остановите Telegram-прокси перед изменением порта")
	}
	if cfg.Secret == "" {
		secret := make([]byte, 16)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
		cfg.Secret = hex.EncodeToString(secret)
	}
	secret, _ := hex.DecodeString(cfg.Secret)
	cachePath, networkKey := telegramRouteCache(dataDir())
	opts := tgproxy.Options{Secret: secret, Community: cfg.Community, CachePath: cachePath, NetworkKey: networkKey}
	if gameRouteView(dataDir()).Configured {
		opts.Tunnel = tgproxy.CONNECTDialer(defaultTelegramTunnelAddress)
	}
	server, err := tgproxy.New(opts)
	if err != nil {
		return err
	}
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err = server.Start(ctx, port); err != nil {
		a.telegramErr = err.Error()
		return err
	}
	cfg.Enabled = true
	cfg.Port = port
	if err = writeTelegramSettings(telegramSettingsPath(), cfg); err != nil {
		_ = server.Close()
		a.telegramErr = err.Error()
		return err
	}
	a.telegram = server
	a.telegramErr = ""
	return nil
}

func (a *App) StopTelegramProxy() error {
	a.telegramMu.Lock()
	defer a.telegramMu.Unlock()
	if a.telegram != nil {
		_ = a.telegram.Close()
	}
	cfg, err := readTelegramSettings(telegramSettingsPath())
	if err != nil {
		return err
	}
	cfg.Enabled = false
	if err = writeTelegramSettings(telegramSettingsPath(), cfg); err != nil {
		a.telegramErr = err.Error()
		return err
	}
	a.telegramErr = ""
	return nil
}

func (a *App) restoreTelegramProxy() {
	a.telegramMu.Lock()
	defer a.telegramMu.Unlock()
	cfg, err := readTelegramSettings(telegramSettingsPath())
	if err == nil && cfg.Enabled {
		_ = a.startTelegramProxyLocked(cfg.Port)
	}
}

func (a *App) ConnectWithTelegram(opts StartOptions, telegram bool) error {
	if err := a.StartEngine(opts); err != nil {
		return err
	}
	if telegram {
		if err := a.StartTelegramProxy(0); err != nil {
			return fmt.Errorf("обход включён, но Telegram-прокси не запустился: %w", err)
		}
	} else {
		state := a.GetTelegramState()
		if state.Running || state.Enabled {
			if err := a.StopTelegramProxy(); err != nil {
				return fmt.Errorf("обход включён, но Telegram-прокси не удалось остановить: %w", err)
			}
		}
	}
	return nil
}

func (a *App) StopConnection() error {
	engineErr := a.StopEngine()
	state := a.GetTelegramState()
	var telegramErr error
	if state.Running || state.Enabled {
		telegramErr = a.StopTelegramProxy()
	}
	return errors.Join(engineErr, telegramErr)
}

func (a *App) OpenTelegramProxy() error {
	state := a.GetTelegramState()
	if !state.Running || state.Link == "" {
		return errors.New("сначала включите Telegram-прокси")
	}
	if a.ctx == nil {
		return errors.New("окно приложения недоступно")
	}
	wr.BrowserOpenURL(a.ctx, state.Link)
	return nil
}

func (a *App) TelegramProxyLicense() string { return tgproxy.License }

func (a *App) SetTelegramOptions(port int, community bool) error {
	a.telegramMu.Lock()
	defer a.telegramMu.Unlock()
	if port < 1024 || port > 65535 {
		return errors.New("порт Telegram должен быть от 1024 до 65535")
	}
	if a.telegram != nil && a.telegram.Snapshot().Running {
		return errors.New("остановите Telegram-прокси перед изменением параметров")
	}
	cfg, err := readTelegramSettings(telegramSettingsPath())
	if err != nil {
		return err
	}
	cfg.Port = port
	cfg.Community = community
	return writeTelegramSettings(telegramSettingsPath(), cfg)
}
