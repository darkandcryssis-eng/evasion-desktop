package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type internetSettings struct {
	AutoConfigURL string
	ProxyEnable   uint32
	ProxyServer   string
	ProxyOverride string
}

type pacSettings interface {
	Snapshot() (internetSettings, error)
	SetAutoConfigURL(string) error
	Notify() error
}

type youtubePACBackup struct {
	URL      string
	Settings internetSettings
}

func installYouTubePAC(settings pacSettings, backupPath, url string) (func(), error) {
	current, err := settings.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать настройки прокси Windows: %w", err)
	}
	original := current
	if current.AutoConfigURL == url {
		backup, loadErr := loadYouTubePACBackup(backupPath, url)
		if loadErr == nil {
			original = backup.Settings
		} else {
			original.AutoConfigURL = ""
		}
	} else if current.AutoConfigURL != "" || (current.ProxyEnable != 0 && current.ProxyServer != "") {
		return nil, errors.New("в Windows уже настроен свой прокси или PAC; автоматический резерв YouTube не включён")
	}
	if err = saveYouTubePACBackup(backupPath, youtubePACBackup{URL: url, Settings: original}); err != nil {
		return nil, err
	}
	if err = settings.SetAutoConfigURL(url); err != nil {
		_ = os.Remove(backupPath)
		return nil, fmt.Errorf("не удалось установить PAC YouTube: %w", err)
	}
	if err = settings.Notify(); err != nil {
		_ = settings.SetAutoConfigURL(original.AutoConfigURL)
		_ = os.Remove(backupPath)
		return nil, fmt.Errorf("не удалось обновить настройки прокси Windows: %w", err)
	}
	var restored bool
	return func() {
		if restored {
			return
		}
		restored = true
		if latest, e := settings.Snapshot(); e == nil && latest.AutoConfigURL == url {
			_ = settings.SetAutoConfigURL(original.AutoConfigURL)
			_ = settings.Notify()
		}
		_ = os.Remove(backupPath)
	}, nil
}

func saveYouTubePACBackup(path string, backup youtubePACBackup) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(backup)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func loadYouTubePACBackup(path, url string) (youtubePACBackup, error) {
	var backup youtubePACBackup
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 16384 {
		return backup, errors.New("резервная копия настроек PAC недоступна")
	}
	if err = json.Unmarshal(data, &backup); err != nil || backup.URL != url {
		return backup, errors.New("резервная копия настроек PAC повреждена")
	}
	return backup, nil
}
