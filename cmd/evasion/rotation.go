package main

import (
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/rotationstore"
	"github.com/fitting-1c/evasion/internal/vantage"
)

const (
	rotationSaveInterval    = 2 * time.Second
	rotationNetworkInterval = 30 * time.Second
)

func startRotationPersistence(provider proxy.MultiGroupProvider, logger *slog.Logger) func() {
	store := rotationstore.New(filepath.Join(defaultStateDir, "rotation.json"))
	var emptyFingerprintLogged sync.Once
	currentFingerprint := func() (string, bool) {
		fingerprint, err := vantage.Fingerprint(vantage.SystemInterfaces())
		if err == nil && fingerprint != "" {
			return fingerprint, true
		}
		emptyFingerprintLogged.Do(func() {
			logger.Info("сохранение стратегий отключено: отпечаток сети пуст")
		})
		return "", false
	}
	fingerprint, ok := currentFingerprint()
	if ok {
		restoreRotation(provider, store, fingerprint, logger)
	}
	lastSaved := provider.ActiveStrategies()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		saveTicker := time.NewTicker(rotationSaveInterval)
		networkTicker := time.NewTicker(rotationNetworkInterval)
		defer saveTicker.Stop()
		defer networkTicker.Stop()

		save := func(fp string) bool {
			if fp == "" {
				return false
			}
			if err := store.Save(fp, provider.ActiveStrategies(), time.Now()); err != nil {
				logger.Warn("не удалось сохранить активные стратегии", "ошибка", err)
				return false
			}
			return true
		}
		for {
			select {
			case <-saveTicker.C:
				active := provider.ActiveStrategies()
				if !sameStrategies(active, lastSaved) && save(fingerprint) {
					lastSaved = active
				}
			case <-networkTicker.C:
				next, enabled := currentFingerprint()
				nextFingerprint := ""
				if enabled {
					nextFingerprint = next
				}
				if nextFingerprint == fingerprint {
					continue
				}
				save(fingerprint)
				fingerprint = nextFingerprint
				resetRotation(provider)
				if fingerprint != "" {
					restoreRotation(provider, store, fingerprint, logger)
				}
				lastSaved = provider.ActiveStrategies()
			case <-stop:
				save(fingerprint)
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

func restoreRotation(provider proxy.MultiGroupProvider, store *rotationstore.Store, fingerprint string, logger *slog.Logger) {
	active, err := store.Load(fingerprint)
	if err != nil {
		logger.Warn("не удалось загрузить активные стратегии", "ошибка", err)
		return
	}
	for group, id := range active {
		provider.SetActive(group, id)
	}
}

func resetRotation(provider proxy.MultiGroupProvider) {
	for _, rule := range provider.Rules() {
		if len(rule.StrategyIDs) > 0 {
			provider.SetActive(rule.Name, rule.StrategyIDs[0])
		}
	}
}

func sameStrategies(a, b map[string]core.StrategyID) bool {
	if len(a) != len(b) {
		return false
	}
	for group, id := range a {
		if b[group] != id {
			return false
		}
	}
	return true
}
