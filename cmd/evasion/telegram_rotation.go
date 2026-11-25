package main

import (
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/rotationstore"
	"github.com/fitting-1c/evasion/internal/telegramtune"
	"github.com/fitting-1c/evasion/internal/vantage"
)

// startTelegramRotationPersistence saves and restores the auto-fitted Telegram
// bypass strategy per network/ISP fingerprint so the optimal profile is
// remembered across restarts and refit automatically when switching ISPs.
func startTelegramRotationPersistence(provider *telegramtune.Provider, logger *slog.Logger) func() {
	if provider == nil {
		return func() {}
	}
	store := rotationstore.New(filepath.Join(defaultStateDir, "telegram_rotation.json"))
	currentFingerprint := func() string {
		fp, err := vantage.Fingerprint(vantage.SystemInterfaces())
		if err != nil {
			return ""
		}
		return fp
	}
	restore := func(fp string) {
		if fp == "" {
			return
		}
		active, err := store.Load(fp)
		if err != nil {
			logger.Warn("не удалось загрузить профиль обхода Telegram", "ошибка", err)
			return
		}
		if id := active[telegramtune.GroupName]; id != "" && provider.SetActiveByID(id) {
			name, _ := provider.ActiveProfile()
			logger.Info("восстановлен профиль обхода Telegram для провайдера", "профиль", name, "стратегия", id)
		}
	}
	save := func(fp string, id core.StrategyID) bool {
		if fp == "" || id == "" {
			return false
		}
		err := store.Save(fp, map[string]core.StrategyID{telegramtune.GroupName: id}, time.Now())
		if err != nil {
			logger.Warn("не удалось сохранить профиль обхода Telegram", "ошибка", err)
			return false
		}
		return true
	}

	fingerprint := currentFingerprint()
	restore(fingerprint)
	_, lastSaved := provider.ActiveProfile()

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		saveTicker := time.NewTicker(rotationSaveInterval)
		networkTicker := time.NewTicker(rotationNetworkInterval)
		defer saveTicker.Stop()
		defer networkTicker.Stop()

		for {
			select {
			case <-saveTicker.C:
				_, cur := provider.ActiveProfile()
				if cur != lastSaved && save(fingerprint, cur) {
					lastSaved = cur
				}
			case <-networkTicker.C:
				next := currentFingerprint()
				if next == fingerprint {
					continue
				}
				_, cur := provider.ActiveProfile()
				save(fingerprint, cur)
				fingerprint = next
				provider.Reset()
				restore(fingerprint)
				_, lastSaved = provider.ActiveProfile()
			case <-stop:
				_, cur := provider.ActiveProfile()
				save(fingerprint, cur)
				return
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() { close(stop) })
		<-done
	}
}
