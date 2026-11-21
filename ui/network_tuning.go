package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type tuningSettings struct {
	YouTube  bool `json:"youtube"`
	Telegram bool `json:"telegram"`
}

type youtubeProfile struct {
	Schema   int       `json:"schema"`
	Network  string    `json:"network"`
	Config   string    `json:"config"`
	Profile  string    `json:"profile"`
	QUIC     string    `json:"quic"`
	At       time.Time `json:"at"`
	Verified bool      `json:"verified"`
}

type NetworkTuningView struct {
	Health    YouTubeHealthView `json:"health"`
	YouTube   bool              `json:"youtube"`
	Telegram  bool              `json:"telegram"`
	Busy      bool              `json:"busy"`
	Phase     string            `json:"phase"`
	Profile   string            `json:"profile"`
	QUIC      string            `json:"quic"`
	CheckedAt string            `json:"checkedAt"`
	Error     string            `json:"error"`
}

type networkTuner struct {
	mu               sync.Mutex
	busy             bool
	phase, lastError string
	cancel           context.CancelFunc
}

func readTuningSettings(base string) tuningSettings {
	defaults := tuningSettings{Telegram: true}
	b, err := os.ReadFile(filepath.Join(base, "network-settings.json"))
	if err != nil || len(b) > 4096 {
		return defaults
	}
	v := defaults
	if json.Unmarshal(b, &v) != nil {
		return defaults
	}
	return v
}

// Only a hash of active adapters and network prefixes is persisted.
func networkFingerprint() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var parts []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, subnet, err := net.ParseCIDR(address.String())
			if err != nil || !ip.IsGlobalUnicast() {
				continue
			}
			parts = append(parts, iface.Name+"|"+iface.HardwareAddr.String()+"|"+subnet.String())
		}
	}
	return fingerprintParts(parts)
}

func fingerprintParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	h := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(h[:])
}

func tuningConfigHash(path string, opts StartOptions) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 2<<20 {
		return ""
	}
	h := sha256.Sum256(append(b, []byte("\nquic:"+opts.Quic)...))
	return hex.EncodeToString(h[:])
}

func profilePath(base, network string) string {
	return filepath.Join(base, "youtube-profile-"+network+".json")
}

func validYouTubeProfile(p youtubeProfile, network, config string, now time.Time) bool {
	return p.Schema == 1 && len(network) == 64 && len(config) == 64 && p.Network == network && p.Config == config && p.Verified &&
		(allowed(p.Profile, "current", "split", "overlap", "split-forward", "fake-split", "fake-overlap", "fake-forward", "split-sld", "fake-sld") != "unknown") && allowedQuic[p.QUIC] &&
		!p.At.After(now.Add(time.Minute)) && now.Sub(p.At) <= 6*time.Hour
}

func readYouTubeProfile(base, network, config string) (youtubeProfile, bool) {
	var p youtubeProfile
	if len(network) != 64 || len(config) != 64 {
		return p, false
	}
	b, err := os.ReadFile(profilePath(base, network))
	if err != nil || len(b) > 4096 || json.Unmarshal(b, &p) != nil {
		return p, false
	}
	return p, validYouTubeProfile(p, network, config, time.Now())
}

func (a *App) GetNetworkTuning(opts StartOptions) NetworkTuningView {
	l, err := resolveLayout()
	v := NetworkTuningView{Telegram: true}
	if err != nil {
		v.Error = err.Error()
		return v
	}
	s := readTuningSettings(l.Base)
	v.YouTube, v.Telegram = s.YouTube, s.Telegram
	if p, ok := readYouTubeProfile(l.Base, networkFingerprint(), tuningConfigHash(l.Config, opts)); ok {
		v.Profile, v.QUIC, v.CheckedAt = p.Profile, p.QUIC, p.At.Format(time.RFC3339)
	}
	a.tuner.mu.Lock()
	v.Busy, v.Phase, v.Error = a.tuner.busy, a.tuner.phase, a.tuner.lastError
	a.tuner.mu.Unlock()
	v.Health = a.youTubeHealth()
	v.YouTube = true
	if v.Health.Fresh {
		v.Profile = v.Health.Profile
		v.QUIC = "block"
		v.CheckedAt = v.Health.CheckedAt
		v.Error = ""
	}
	return v
}

func (a *App) SetNetworkTuningSettings(youtube, telegram bool) error {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	a.tuner.mu.Lock()
	defer a.tuner.mu.Unlock()
	if a.tuner.busy {
		return errors.New("дождитесь окончания подбора или отмените его")
	}
	l, err := resolveLayout()
	if err != nil {
		return err
	}
	b, _ := json.Marshal(tuningSettings{YouTube: youtube, Telegram: telegram})
	return writeAtomic(filepath.Join(l.Base, "network-settings.json"), b)
}

func (a *App) CancelYouTubeTuning() {
	a.tuner.mu.Lock()
	if a.tuner.cancel != nil {
		a.tuner.cancel()
	}
	a.tuner.mu.Unlock()
}

var tuningPhases = map[string]string{
	"tcp:current": "Проверяем текущую стратегию",
	"tcp:split":   "Проверяем разделение TLS",
	"tcp:overlap": "Проверяем альтернативную стратегию",
	"quic:native": "Проверяем прямой HTTP/3",
	"quic:desync": "Проверяем обход для HTTP/3",
	"verify":      "Повторно проверяем результат",
}

func (a *App) RunYouTubeTuning(opts StartOptions) (resultErr error) {
	if err := opts.validate(); err != nil {
		return err
	}
	if opts.Observe {
		return errors.New("выключите режим наблюдения перед подбором")
	}
	a.lifecycle.Lock()
	phase := a.engine.snapshot().Phase
	a.tuner.mu.Lock()
	if a.shuttingDown || a.tuner.busy || phase != phaseStopped && phase != phaseFailed {
		a.tuner.mu.Unlock()
		a.lifecycle.Unlock()
		return errors.New("для подбора остановите обход; Telegram можно оставить включённым")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 95*time.Second)
	a.tuner.busy, a.tuner.cancel, a.tuner.phase, a.tuner.lastError = true, cancel, "Подготовка проверки", ""
	a.tuner.mu.Unlock()
	a.lifecycle.Unlock()
	defer func() {
		cancel()
		a.tuner.mu.Lock()
		defer a.tuner.mu.Unlock()
		a.tuner.busy = false
		a.tuner.cancel = nil
		if resultErr != nil {
			a.tuner.lastError = resultErr.Error()
			a.tuner.phase = ""
		} else {
			a.tuner.phase = "Профиль проверен. Применится при следующем включении обхода"
		}
	}()
	l, err := resolveLayout()
	if err != nil {
		return err
	}
	network := networkFingerprint()
	if network == "" {
		return errors.New("не удалось определить текущую сеть")
	}
	if elev, checked := isElevated(); checked && !elev {
		return errors.New("для проверки запустите Evasion от имени администратора")
	}
	if err = extractPayload(l); err != nil {
		return err
	}
	hash := tuningConfigHash(l.Config, opts)
	if hash == "" {
		return errors.New("не удалось прочитать конфигурацию")
	}
	cmd := exec.CommandContext(ctx, l.Engine, "youtube-tune", "--config", l.Config)
	cmd.Dir = l.Base
	hideConsole(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer stdin.Close()
	cmd.Cancel = stdin.Close
	cmd.WaitDelay = 3 * time.Second
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	if err = cmd.Start(); err != nil {
		return errors.New("не удалось запустить проверку YouTube")
	}
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		if text, ok := tuningPhases[scanner.Text()]; ok {
			a.tuner.mu.Lock()
			a.tuner.phase = text
			a.tuner.mu.Unlock()
		}
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return errors.New("подбор отменён или превышено время ожидания; настройки сохранены")
	}
	if err != nil {
		return errors.New("не удалось подтвердить подходящий вариант. Прежние настройки сохранены; проверьте сеть и отсутствие другого DPI-движка")
	}
	var p youtubeProfile
	if output.Len() > 1<<20 || json.Unmarshal(output.Bytes(), &p) != nil {
		return errors.New("движок вернул некорректный результат; настройки сохранены")
	}
	p.Schema, p.Network, p.Config, p.At = 1, network, hash, time.Now().UTC()
	if !validYouTubeProfile(p, network, hash, time.Now()) || networkFingerprint() != network || tuningConfigHash(l.Config, opts) != hash {
		return errors.New("сеть или конфигурация изменились во время проверки; повторите подбор")
	}
	// Serialize commit with cancellation and settings changes.
	a.tuner.mu.Lock()
	defer a.tuner.mu.Unlock()
	if ctx.Err() != nil {
		return errors.New("подбор отменён; настройки сохранены")
	}
	return commitYouTubeProfile(ctx, l.Base, p)
}

func commitYouTubeProfile(ctx context.Context, base string, p youtubeProfile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := profilePath(base, p.Network)
	previous, readErr := os.ReadFile(path)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	b, _ := json.Marshal(p)
	if err := writeAtomic(path, b); err != nil {
		return err
	}
	s := readTuningSettings(base)
	s.YouTube = true
	b, _ = json.Marshal(s)
	err := ctx.Err()
	if err == nil {
		err = writeAtomic(filepath.Join(base, "network-settings.json"), b)
	}
	if err != nil {
		var rollback error
		if readErr == nil {
			rollback = writeAtomic(path, previous)
		} else {
			rollback = os.Remove(path)
		}
		return errors.Join(err, rollback)
	}
	return nil
}

// The original config is never rewritten. A failed/stale profile uses the baseline.
func (a *App) adaptiveLayout(l layout, opts StartOptions) layout {
	if opts.Observe || !readTuningSettings(l.Base).YouTube {
		return l
	}
	network := networkFingerprint()
	p, ok := readYouTubeProfile(l.Base, network, tuningConfigHash(l.Config, opts))
	if !ok {
		return l
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.Engine, "youtube-profile", "--config", l.Config, "--profile", p.Profile, "--quic", p.QUIC)
	cmd.Dir = l.Base
	hideConsole(cmd)
	b, err := cmd.Output()
	if err != nil || len(b) > 2<<20 {
		return l
	}
	path := filepath.Join(l.Runtime, "config-youtube.json")
	if writeAtomic(path, b) != nil {
		return l
	}
	l.Config = path
	return l
}

func telegramRouteCache(base string) (string, string) {
	if !readTuningSettings(base).Telegram {
		return "", ""
	}
	network := networkFingerprint()
	if network == "" {
		return "", ""
	}
	return filepath.Join(base, "telegram-routes-"+network+".json"), network
}
