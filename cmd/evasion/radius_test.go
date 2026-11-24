package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
)

func TestAllRadiusMatcherExcludesRussianAndConfiguredSuffixes(t *testing.T) {
	matcher := newAllRadiusMatcher([]string{"example.org"})
	for _, sni := range []string{"vk.com", "mail.yandex.net", "api.example.org", "EXAMPLE.ORG."} {
		if matcher.Matches("", sni) {
			t.Errorf("%q unexpectedly matched the all-radius fallback", sni)
		}
	}
	for _, sni := range []string{"discord.com", "truvk.com", "ru.example.com"} {
		if !matcher.Matches("", sni) {
			t.Errorf("%q should match the all-radius fallback", sni)
		}
	}
}

func TestBuildInterceptProviderUsesSafeAllRadiusFallback(t *testing.T) {
	cfg := config.Default()
	cfg.Radius.Mode = config.RadiusAll
	cfg.Radius.Exclude = []string{"example.org"}
	cfg.Groups = map[string][]string{"video": {"youtube.com"}}
	cfg.Strategy = &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action:    &strategy.Action{Kind: core.ActionSend},
	}}}
	radius, err := cfg.DomainSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	provider, _, err := buildInterceptProvider(cfg, radius, nil, cfg.Strategy, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	multi, ok := provider.(proxy.MultiGroupProvider)
	if !ok {
		t.Fatalf("all-radius provider has type %T", provider)
	}
	for _, sni := range []string{"google.com", "discord.com"} {
		if sel := multi.Select(proxy.ConnMeta{SNI: sni, IsClientHello: true}); sel.Strategy == nil {
			t.Errorf("fallback strategy missing for %q", sni)
		}
	}
	for _, sni := range []string{"mail.ru", "api.example.org"} {
		if sel := multi.Select(proxy.ConnMeta{SNI: sni, IsClientHello: true}); sel.Strategy != nil {
			t.Errorf("fallback strategy should be excluded for %q", sni)
		}
	}
}

func TestRadiusFlagOverridesConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Radius.Mode = config.RadiusAll
	if err := applyRadiusOverride(cfg, "groups"); err != nil {
		t.Fatal(err)
	}
	if cfg.Radius.Mode != config.RadiusGroups {
		t.Fatalf("flag did not override config: %q", cfg.Radius.Mode)
	}
	if err := applyRadiusOverride(cfg, "all"); err != nil {
		t.Fatal(err)
	}
	if cfg.Radius.Mode != config.RadiusAll {
		t.Fatalf("radius override = %q", cfg.Radius.Mode)
	}
	if err := applyRadiusOverride(cfg, "unknown"); err == nil {
		t.Fatal("unknown radius flag must be rejected")
	}
}
