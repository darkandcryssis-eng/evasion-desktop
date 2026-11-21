package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakePACSettings struct {
	current   internetSettings
	set       []string
	notified  int
	snapshotE error
}

func (f *fakePACSettings) Snapshot() (internetSettings, error) {
	return f.current, f.snapshotE
}
func (f *fakePACSettings) SetAutoConfigURL(url string) error {
	f.set = append(f.set, url)
	f.current.AutoConfigURL = url
	return nil
}
func (f *fakePACSettings) Notify() error {
	f.notified++
	return nil
}

func TestYouTubePACInstallAndRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "youtube-pac.json")
	settings := &fakePACSettings{current: internetSettings{ProxyServer: "unused-while-disabled", ProxyOverride: "local"}}
	restore, err := installYouTubePAC(settings, path, "http://127.0.0.1:17658/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	if settings.current.AutoConfigURL != "http://127.0.0.1:17658/proxy.pac" || settings.notified != 1 {
		t.Fatalf("settings=%+v notifications=%d", settings.current, settings.notified)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("original settings were not persisted", err)
	}
	restore()
	restore()
	if settings.current.AutoConfigURL != "" || settings.current.ProxyServer != "unused-while-disabled" || settings.current.ProxyOverride != "local" {
		t.Fatalf("settings not restored: %+v", settings.current)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("backup was not removed")
	}
}

func TestYouTubePACRefusesExistingUserConfiguration(t *testing.T) {
	for _, current := range []internetSettings{{AutoConfigURL: "http://proxy.example/custom.pac"}, {ProxyEnable: 1, ProxyServer: "127.0.0.1:8080"}} {
		settings := &fakePACSettings{current: current}
		restore, err := installYouTubePAC(settings, filepath.Join(t.TempDir(), "backup.json"), "http://127.0.0.1:17658/proxy.pac")
		if err == nil || restore != nil {
			t.Fatal("existing configuration was accepted")
		}
		if len(settings.set) != 0 {
			t.Fatal("existing configuration was overwritten")
		}
	}
}

func TestYouTubePACRecoversOriginalSettingsAfterCrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "youtube-pac.json")
	url := "http://127.0.0.1:17658/proxy.pac"
	first := &fakePACSettings{}
	_, err := installYouTubePAC(first, path, url)
	if err != nil {
		t.Fatal(err)
	}
	second := &fakePACSettings{current: first.current}
	restore, err := installYouTubePAC(second, path, url)
	if err != nil {
		t.Fatal(err)
	}
	restore()
	if second.current.AutoConfigURL != "" {
		t.Fatalf("stale PAC was not restored: %+v", second.current)
	}
}

func TestYouTubePACDoesNotOverwriteNewUserPACOnRestore(t *testing.T) {
	settings := &fakePACSettings{}
	restore, err := installYouTubePAC(settings, filepath.Join(t.TempDir(), "backup.json"), "http://127.0.0.1:17658/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	settings.current.AutoConfigURL = "http://proxy.example/new.pac"
	restore()
	if settings.current.AutoConfigURL != "http://proxy.example/new.pac" {
		t.Fatal("user PAC was overwritten during restore")
	}
}

func TestYouTubePACAllowsEmptyEnabledProxyPlaceholder(t *testing.T) {
	settings := &fakePACSettings{current: internetSettings{ProxyEnable: 1}}
	restore, err := installYouTubePAC(settings, filepath.Join(t.TempDir(), "backup.json"), "http://127.0.0.1:17658/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	restore()
	if settings.current.ProxyEnable != 1 {
		t.Fatal("unrelated proxy flag was changed")
	}
}
