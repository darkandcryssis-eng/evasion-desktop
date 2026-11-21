package main

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestTelegramSettingsAndLocalDeepLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telegram.json")
	cfg, err := readTelegramSettings(path)
	if err != nil || cfg.Enabled || cfg.Secret != "" || cfg.Port != 17655 {
		t.Fatalf("incorrect safe defaults: %+v %v", cfg, err)
	}
	cfg.Enabled = true
	cfg.Secret = "000102030405060708090a0b0c0d0e0f"
	if err := writeTelegramSettings(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := readTelegramSettings(path)
	if err != nil || loaded != cfg {
		t.Fatal("settings did not survive reload")
	}
	u, err := url.Parse(telegramLink(loaded))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "tg" || u.Host != "proxy" || u.Query().Get("server") != "127.0.0.1" || u.Query().Get("port") != "17655" || u.Query().Get("secret") != "dd"+cfg.Secret {
		t.Fatal("invalid local padded MTProto link")
	}
}

func TestInvalidTelegramSettingsCannotEnableAProxy(t *testing.T) {
	for _, source := range []string{`{"port":1}`, `{"port":99999}`, `{"secret":"bad"}`, `{broken`} {
		path := filepath.Join(t.TempDir(), "telegram.json")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readTelegramSettings(path); err == nil {
			t.Fatalf("invalid settings accepted: %s", source)
		}
	}
}
