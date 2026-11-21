package main

import (
	"context"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/gamefilter"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
)

type gameTestOwner bool

func (o gameTestOwner) Owns(string, uint16) bool { return bool(o) }

func TestGameStrategiesValidateAndHaveShortHelloFallback(t *testing.T) {
	for _, mode := range []string{"gentle", "balanced", "strong"} {
		large, err := gameStrategy(mode)
		if err != nil {
			t.Fatal(err)
		}
		small, err := gameStrategy(mode, true)
		if err != nil {
			t.Fatal(err)
		}
		if strategy.RequiredCapabilities(small).Has(core.CapTCPOverlap) {
			t.Fatal("short hello still requires overlap")
		}
		if mode != "gentle" && !strategy.RequiredCapabilities(large).Has(core.CapTCPOverlap) {
			t.Fatal("large hello lost overlap")
		}
	}
}
func TestGameProviderPreservesBaselineAndProcessScope(t *testing.T) {
	baseline, _ := gameStrategy("gentle")
	base, _ := proxy.NewGroupProvider(baseline, domainSetFor(t, "discord.com"))
	large, _ := gameStrategy("balanced")
	small, _ := gameStrategy("balanced", true)
	largeStatic, _ := proxy.NewStaticProvider(large)
	smallStatic, _ := proxy.NewStaticProvider(small)
	for _, tc := range []struct {
		name, host, sni string
		local, port     uint16
		size            int
		owned           bool
		want            string
	}{
		{"selected-game", "1.1.1.1", "game.example", 45000, 443, 1200, true, "large"},
		{"short-game", "1.1.1.1", "game.example", 45000, 443, 500, true, "small"},
		{"discord-kept", "1.1.1.1", "discord.com", 45000, 443, 1200, true, "base"},
		{"browser", "1.1.1.1", "game.example", 45000, 443, 1200, false, "none"},
		{"private-game", "192.168.1.1", "game.example", 45000, 443, 1200, true, "none"},
		{"unselected-high-port", "1.1.1.1", "discord.com", 45000, 12345, 1200, false, "none"},
		{"passive-observer", "", "discord.com", 0, 0, 0, false, "base"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := gamefilter.Default()
			opts.Mode = "balanced"
			processor := gamefilter.New(opts, gameTestOwner(tc.owned))
			p := gameProvider{base: base, processor: processor, selection: largeStatic.Select(proxy.ConnMeta{}), smallSelection: smallStatic.Select(proxy.ConnMeta{})}
			meta := proxy.ConnMeta{Host: tc.host, SNI: tc.sni, LocalPort: tc.local, Port: tc.port, PayloadLength: tc.size, IsClientHello: true}
			got := p.Select(meta)
			if tc.want == "none" {
				if got.Strategy != nil {
					t.Fatal("out-of-scope game strategy")
				}
				return
			}
			want := map[string]*strategy.Strategy{"base": baseline, "large": large, "small": small}[tc.want]
			id, _ := strategy.ComputeID(want)
			if got.ID != id {
				t.Fatal("wrong strategy priority")
			}
			if tc.want == "base" && processor.Stats().Connections != 0 {
				t.Fatal("baseline traffic counted as game")
			}
		})
	}
}
func TestGameFlagsRejectUnsafeCombinationsBeforeStarting(t *testing.T) {
	for _, args := range [][]string{
		{"--game-mode", "unknown"},
		{"--game-mode", "balanced"},
		{"--mode", "intercept", "--game-mode", "balanced", "--auto"},
		{"--mode", "intercept", "--game-mode", "balanced", "--rtc-redirect"},
		{"--mode", "intercept", "--game-mode", "balanced", "--voice", "probe"},
		{"--mode", "intercept", "--game-mode", "balanced", "--game-albion=false", "--game-ubisoft=false"},
	} {
		if err := runCommand(context.Background(), args); err == nil {
			t.Fatal("unsafe flags accepted", args)
		}
	}
}
