package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/tlsfake"
)

type suffixMatcher string

func (m suffixMatcher) Matches(host, sni string) bool { return sni == string(m) || host == string(m) }

func evolveTestProvider(t *testing.T) proxy.MultiGroupProvider {
	t.Helper()
	cfg, err := loadConfig(filepath.Join("..", "..", "examples", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := proxy.NewMultiGroupProvider([]proxy.GroupRule{
		{Name: "discord_cdn", Matcher: suffixMatcher("stable.dl2.discordapp.net"), Strategies: cfg.StrategiesRotation["discord_cdn"]},
		{Name: "discord_web", Matcher: suffixMatcher("web.test"), Strategies: cfg.StrategiesRotation["discord_web"]},
	}, nil, suffixMatcher("none.test"))
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

// Потомки поставляемых стратегий обязаны исполняться движком и переживать
// сохранение: иначе отбор тратил бы загрузки на неприменимое, а выведенное
// терялось бы при перезапуске.
func TestEvolvedChildrenExecuteAndSurviveStorage(t *testing.T) {
	provider := evolveTestProvider(t)
	evolver := newDiscordEvolver(provider, nil, slog.New(slog.DiscardHandler))
	if evolver == nil {
		t.Fatal("отбор не создан для поставляемых групп Discord")
	}
	parents := provider.Strategies("discord_cdn")
	hello := tlsfake.FreshGoogleClientHello()
	bred := 0
	for i := 0; i < 60; i++ {
		child, err := evolver.breed(parents[i%len(parents)].Strategy, parents[(i+1)%len(parents)].Strategy, i)
		if err != nil {
			continue
		}
		bred++
		id, err := strategy.ComputeID(child)
		if err != nil {
			t.Fatalf("потомок %d: %v", i, err)
		}
		raw, err := strategy.Marshal(child)
		if err != nil {
			t.Fatalf("потомок %d не сохраняется: %v", i, err)
		}
		restored, err := strategy.Unmarshal(raw, strategy.DefaultLimits())
		if err != nil {
			t.Fatalf("потомок %d не читается обратно: %v\n%s", i, err, raw)
		}
		if got, _ := strategy.ComputeID(restored); got != id {
			t.Fatalf("потомок %d сменил id после сохранения", i)
		}
		static, err := proxy.NewStaticProvider(child)
		if err != nil {
			t.Fatal(err)
		}
		observer := &rotationBuildObserver{}
		engine, err := intercept.New(intercept.Options{
			ShortHelloFallback: true,
			Source: capture.NewSyntheticSource(capture.Packet{
				Data: rotationClientHelloPacket(t, false, hello),
				Dir:  core.DirectionOutbound,
			}),
			Sink:     &capture.SyntheticSink{},
			Flows:    flow.NewTable(16, time.Minute, intercept.TLSHelloDetector),
			Provider: static,
			Exec:     packetexec.New(),
			Parse:    intercept.TLSHelloParser,
			Observer: observer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.Run(context.Background()); err != nil {
			t.Fatalf("потомок %d: %v\n%s", i, err, raw)
		}
		if len(observer.failed) != 0 {
			t.Fatalf("потомок %d не исполнился: %v\n%s", i, observer.failed, raw)
		}
	}
	if bred < 30 {
		t.Fatalf("выведено только %d потомков из 60", bred)
	}
}

func TestEvolverPromotesAndPrunes(t *testing.T) {
	provider := evolveTestProvider(t)
	evolver := newDiscordEvolver(provider, nil, slog.New(slog.DiscardHandler))
	evolver.path = filepath.Join(t.TempDir(), "evolved.json")
	parents := provider.Strategies("discord_cdn")
	results := []evolveResult{
		{sel: parents[3], passed: 3, trials: 3},
		{sel: parents[0], passed: 1, trials: 3},
	}
	evolver.promote(results)
	for group, id := range provider.ActiveStrategies() {
		if id != parents[3].ID {
			t.Fatalf("группа %s осталась на %s, ждали лучшую %s", group, id, parents[3].ID)
		}
	}
	before := len(provider.Strategies("discord_cdn"))
	for i := 0; len(evolver.evolved) < evolveKeep+2 && i < 200; i++ {
		child, err := evolver.breed(parents[0].Strategy, parents[1].Strategy, i)
		if err != nil {
			continue
		}
		if id, ok := evolver.admit(child); ok {
			evolver.evolved[id] = child
		}
	}
	evolver.prune()
	if got := len(provider.Strategies("discord_cdn")); got != before+evolveKeep {
		t.Fatalf("после чистки в группе %d стратегий, ждали %d", got, before+evolveKeep)
	}
	evolver.save()
	fresh := newDiscordEvolver(evolveTestProvider(t), nil, slog.New(slog.DiscardHandler))
	fresh.path = evolver.path
	fresh.restore()
	if networkFingerprint() != "" && len(fresh.evolved) != evolveKeep {
		t.Fatalf("восстановлено %d стратегий, ждали %d", len(fresh.evolved), evolveKeep)
	}
}
