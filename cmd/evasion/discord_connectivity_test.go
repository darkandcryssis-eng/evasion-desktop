package main

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/proxy"
)

func TestDiscordWebProfilePreservesSpecializedStrategies(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "examples", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Groups["discord"]; ok {
		t.Fatal("duplicate discord group must be removed in favor of discord_web")
	}
	radius, err := cfg.DomainSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := buildInterceptProvider(cfg, radius, nil, cfg.Strategy, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ host, group string }{
		{"discord.com", "discord_web"}, {"canary.discord.com", "discord_web"}, {"discord.gg", "discord_web"},
		{"gateway.discord.gg", "discord_gateway"}, {"updates.discord.com", "discord_updates"},
		{"cdn.discordapp.com", "discord_cdn"}, {"media.discordapp.net", "discord_cdn"},
		{"c-hel01.example.discord.media", "discord_voice"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			got := p.Select(proxy.ConnMeta{SNI: tc.host, IsClientHello: true})
			if got.Strategy == nil || got.ID != cfg.Strategies[tc.group].ID {
				t.Fatalf("wrong strategy for %s", tc.host)
			}
		})
	}
	for _, host := range []string{"youtube.com", "r1.googlevideo.com", "i.ytimg.com"} {
		if got := p.Select(proxy.ConnMeta{SNI: host, IsClientHello: true}); got.ID != cfg.Strategy.ID {
			t.Fatalf("YouTube changed: %s", host)
		}
	}
	for _, host := range []string{"example.com", "evildiscord.com", "discord.com.example.com"} {
		if p.Select(proxy.ConnMeta{SNI: host, IsClientHello: true}).Strategy != nil {
			t.Fatalf("out-of-scope strategy: %s", host)
		}
	}
	reps, _ := sandboxCoverage(cfg.Groups, radius.Domains(), []string{"discord.com"})
	if len(reps) != 1 || reps[0] != "discord.com" {
		t.Fatalf("autopilot should probe the duplicate Discord radius once: %v", reps)
	}
	// Selecting only video must not activate any Discord rule.
	video, _ := cfg.DomainSet([]string{"video"})
	p, _, err = buildInterceptProvider(cfg, video, []string{"video"}, cfg.Strategy, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if p.Select(proxy.ConnMeta{SNI: "discord.com", IsClientHello: true}).Strategy != nil {
		t.Fatal("group selection ignored")
	}
}
