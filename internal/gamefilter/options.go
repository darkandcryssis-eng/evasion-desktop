package gamefilter

import (
	"errors"
	"path/filepath"
	"strings"
)

type Options struct {
	Mode        string   `json:"mode"`
	Protocol    string   `json:"protocol"`
	Executables []string `json:"executables"`
}

func Default() Options {
	return Options{Mode: "off", Protocol: "both", Executables: []string{}}
}
func (o Options) Enabled() bool { return o.Mode != "" && o.Mode != "off" }
func (o Options) TCP() bool     { return o.Enabled() && (o.Protocol == "tcp" || o.Protocol == "both") }
func (o Options) UDP() bool     { return o.Enabled() && (o.Protocol == "udp" || o.Protocol == "both") }
func (o Options) Limits() (packets, repeats int) {
	switch o.Mode {
	case "gentle":
		return 1, 1
	case "balanced":
		return 2, 3
	case "auto", "strong":
		return 3, 6
	}
	return 0, 0
}
func (o Options) Validate() error {
	if o.Mode != "off" && o.Mode != "auto" && o.Mode != "gentle" && o.Mode != "balanced" && o.Mode != "strong" {
		return errors.New("неизвестный игровой режим")
	}
	if o.Protocol != "tcp" && o.Protocol != "udp" && o.Protocol != "both" {
		return errors.New("неизвестный игровой протокол")
	}
	if len(o.Executables) > 16 {
		return errors.New("можно выбрать не более 16 исполняемых файлов")
	}
	for _, p := range o.Executables {
		if !filepath.IsAbs(p) || !strings.EqualFold(filepath.Ext(p), ".exe") || Protected(filepath.Base(p)) {
			return errors.New("выберите исполняемый файл игры (.exe)")
		}
	}
	if o.Enabled() && len(o.Executables) == 0 {
		return errors.New("выберите хотя бы одну игру")
	}
	return nil
}

func Protected(name string) bool {
	switch strings.ToLower(name) {
	case "steam.exe", "steamwebhelper.exe", "epicgameslauncher.exe", "epicwebhelper.exe", "beservice.exe", "beservice_x64.exe", "easyanticheat.exe", "easyanticheat_eos.exe", "system", "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe", "csrss.exe", "explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "browser.exe", "msedgewebview2.exe", "discord.exe", "telegram.exe", "evasion.exe", "evasionv2.exe", "xray.exe":
		return true
	}
	return false
}

// Targets are the user-added executables, matched by full path.
func (o Options) Match(image string) string {
	image = strings.ReplaceAll(strings.ToLower(image), "\\", "/")
	name := image[strings.LastIndex(image, "/")+1:]
	if Protected(name) || strings.Contains(image, "/windows/") {
		return ""
	}
	for _, p := range o.Executables {
		if strings.ReplaceAll(strings.ToLower(p), "\\", "/") == image {
			return "custom"
		}
	}
	return ""
}
