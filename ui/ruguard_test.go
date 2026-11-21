package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIsRussianDomain(t *testing.T) {
	ru := []string{"gosuslugi.ru", "*.sberbank.ru", "online.sberbank.ru.", "VK.com", "st.vk.com", "yandex.net", "кто.рф", "xn--80aswg.xn--p1ai", "mail.ru", "example.su", "userapi.com"}
	for _, d := range ru {
		if !isRussianDomain(d) {
			t.Errorf("%q должен считаться российским", d)
		}
	}
	foreign := []string{"discord.com", "googlevideo.com", "youtube.com", "truvk.com", "ru.example.com", "rutracker.org", "", "notvk.com.example", "cyandex.com"}
	for _, d := range foreign {
		if isRussianDomain(d) {
			t.Errorf("%q не должен считаться российским", d)
		}
	}
}

func TestEmbeddedConfigHasNoRussianDomains(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("payload", "config.json"))
	if err != nil {
		t.Skip("payload/config.json недоступен")
	}
	out, removed, err := sanitizeConfig(raw)
	if err != nil || len(removed) != 0 || string(out) != string(raw) {
		t.Fatalf("встроенный конфиг должен проходить защиту без изменений: removed=%v err=%v", removed, err)
	}
}

func TestSanitizeConfigRemovesRussianDomainsAndEmptyGroups(t *testing.T) {
	raw := []byte(`{"version":3,"groups":{"video":["youtube.com","rutube.ru"],"bank":["sberbank.ru","vk.com"]},"strategies":{"video":{"a":1},"bank":{"b":2}},"strategy":{"x":"<&>"}}`)
	out, removed, err := sanitizeConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Fatalf("removed=%v", removed)
	}
	var c struct {
		Version    int                        `json:"version"`
		Groups     map[string][]string        `json:"groups"`
		Strategies map[string]json.RawMessage `json:"strategies"`
		Strategy   map[string]string          `json:"strategy"`
	}
	if err := json.Unmarshal(out, &c); err != nil {
		t.Fatal(err)
	}
	if c.Version != 3 || len(c.Groups) != 1 || len(c.Groups["video"]) != 1 || c.Groups["video"][0] != "youtube.com" {
		t.Fatalf("groups=%v", c.Groups)
	}
	if _, ok := c.Strategies["bank"]; ok || len(c.Strategies) != 1 {
		t.Fatalf("strategies=%v", c.Strategies)
	}
	if c.Strategy["x"] != "<&>" {
		t.Fatalf("прочие поля должны сохраняться: %v", c.Strategy)
	}
}

func TestGuardLayoutWritesCleanCopyOnlyWhenNeeded(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"groups":{"a":["discord.com"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, removed := guardLayout(layout{Config: cfg}); l.Config != cfg || removed != nil {
		t.Fatalf("чистый конфиг не должен подменяться: %v %v", l.Config, removed)
	}
	if err := os.WriteFile(cfg, []byte(`{"groups":{"a":["discord.com","ok.ru"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	l, removed := guardLayout(layout{Config: cfg})
	if l.Config == cfg || len(removed) != 1 || removed[0] != "ok.ru" {
		t.Fatalf("ожидалась очищенная копия: %v %v", l.Config, removed)
	}
	if l2, _ := guardLayout(layout{Config: filepath.Join(dir, "missing.json")}); l2.Config != filepath.Join(dir, "missing.json") {
		t.Fatal("отсутствующий конфиг должен остаться как есть")
	}
}
