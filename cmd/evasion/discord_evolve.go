package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/generator"
	"github.com/fitting-1c/evasion/internal/netbind"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/vantage"
)

// Отбор стратегий Discord живой загрузкой.
//
// Пакет обновления Discord лежит на узле, которым сам клиент пользуется только
// при обновлении, а фильтр провайдера замораживает его так же, как остальные
// узлы Discord. На этом узле каждая стратегия получает назначение в обход
// группы и проверяется настоящей загрузкой: счёт удач решает, какую стратегию
// держать, а из лучших мутацией и скрещиванием выводятся новые. Потомок входит
// в ротацию, только если прошёл все свои загрузки.
const (
	evolveStartDelay    = 40 * time.Second
	evolvePause         = 15 * time.Minute
	evolveTrials        = 3
	evolveChildTrials   = 5
	evolveControlTrials = 4
	evolveChildren      = 6
	evolveKeep          = 6
	evolveTrialBytes    = 256 << 10
	evolveTrialTimeout  = 4 * time.Second
	evolveTrialGap      = 300 * time.Millisecond
	evolveFile          = "evolved.json"
	evolveReferenceGrp  = "discord_cdn"
)

type evolveDocument struct {
	Networks map[string]evolveNetwork `json:"networks"`
}

type evolveNetwork struct {
	Updated    time.Time                       `json:"updated"`
	Strategies []json.RawMessage               `json:"strategies"`
	Scores     map[core.StrategyID]proxy.Score `json:"scores"`
}

type discordEvolver struct {
	provider proxy.MultiGroupProvider
	dial     netbind.DialContextFunc
	log      *slog.Logger
	gen      *generator.Generator
	groups   []string
	evolved  map[core.StrategyID]*strategy.Strategy
	path     string
}

func discordGroups(provider proxy.MultiGroupProvider) []string {
	var out []string
	for _, rule := range provider.Rules() {
		if strings.HasPrefix(rule.Name, "discord_") && len(rule.StrategyIDs) > 1 {
			out = append(out, rule.Name)
		}
	}
	return out
}

func networkFingerprint() string {
	fingerprint, err := vantage.Fingerprint(vantage.SystemInterfaces())
	if err != nil {
		return ""
	}
	return fingerprint
}

func newDiscordEvolver(provider proxy.MultiGroupProvider, dial netbind.DialContextFunc, logger *slog.Logger) *discordEvolver {
	groups := discordGroups(provider)
	if len(groups) == 0 || len(provider.Strategies(evolveReferenceGrp)) < 2 {
		return nil
	}
	gen, err := generator.New(generator.Config{
		Caps:      packetexec.New().Capabilities(),
		Limits:    strategy.DefaultLimits(),
		IPVersion: 4,
		Rand:      rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
	})
	if err != nil {
		logger.Warn("отбор стратегий Discord не запущен", "err", err)
		return nil
	}
	return &discordEvolver{
		provider: provider,
		dial:     dial,
		log:      logger,
		gen:      gen,
		groups:   groups,
		evolved:  make(map[core.StrategyID]*strategy.Strategy),
		path:     filepath.Join(defaultStateDir, evolveFile),
	}
}

// restore возвращает в ротацию выведенные ранее стратегии этой сети и их счёт.
// Вызывается до восстановления действующих стратегий, чтобы выбранный потомок
// нашёлся в группе.
func (e *discordEvolver) restore() {
	fingerprint := networkFingerprint()
	if fingerprint == "" {
		return
	}
	network, ok := e.readDocument().Networks[fingerprint]
	if !ok {
		return
	}
	for _, raw := range network.Strategies {
		s, err := strategy.Unmarshal(raw, strategy.DefaultLimits())
		if err != nil {
			continue
		}
		if id, ok := e.admit(s); ok {
			e.evolved[id] = s
		}
	}
	for id, score := range network.Scores {
		for _, group := range e.groups {
			e.provider.SetScore(group, id, score)
		}
	}
	if len(e.evolved) > 0 {
		e.log.Info("отбор стратегий Discord: восстановлены выведенные для этой сети", "стратегий", len(e.evolved))
	}
}

func (e *discordEvolver) admit(s *strategy.Strategy) (core.StrategyID, bool) {
	var id core.StrategyID
	added := false
	for _, group := range e.groups {
		if got, ok := e.provider.AddStrategy(group, s); ok {
			id, added = got, true
		}
	}
	return id, added
}

func (e *discordEvolver) readDocument() evolveDocument {
	doc := evolveDocument{Networks: map[string]evolveNetwork{}}
	data, err := os.ReadFile(e.path)
	if err != nil {
		return doc
	}
	if json.Unmarshal(data, &doc) != nil || doc.Networks == nil {
		return evolveDocument{Networks: map[string]evolveNetwork{}}
	}
	return doc
}

func (e *discordEvolver) save() {
	fingerprint := networkFingerprint()
	if fingerprint == "" {
		return
	}
	network := evolveNetwork{Updated: time.Now().UTC(), Scores: e.provider.Scores(evolveReferenceGrp)}
	ids := make([]core.StrategyID, 0, len(e.evolved))
	for id := range e.evolved {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if raw, err := strategy.Marshal(e.evolved[id]); err == nil {
			network.Strategies = append(network.Strategies, raw)
		}
	}
	doc := e.readDocument()
	doc.Networks[fingerprint] = network
	for len(doc.Networks) > 16 {
		oldest := ""
		for name, item := range doc.Networks {
			if oldest == "" || item.Updated.Before(doc.Networks[oldest].Updated) {
				oldest = name
			}
		}
		delete(doc.Networks, oldest)
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(e.path), 0o755); err != nil {
		return
	}
	tmp := e.path + ".tmp"
	if os.WriteFile(tmp, data, 0o644) == nil {
		if err := os.Rename(tmp, e.path); err != nil {
			e.log.Warn("отбор стратегий Discord: не удалось сохранить", "err", err)
		}
	}
}

func (e *discordEvolver) run(ctx context.Context) {
	if !sleepContext(ctx, evolveStartDelay) {
		return
	}
	for {
		if err := e.cycle(ctx); err != nil && ctx.Err() == nil {
			e.log.Info("отбор стратегий Discord: круг пропущен", "причина", err.Error())
		}
		if !sleepContext(ctx, evolvePause) {
			return
		}
	}
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

type evolveResult struct {
	sel    proxy.Selection
	passed int
	trials int
	spent  time.Duration
}

func (r evolveResult) better(other evolveResult) bool {
	if r.passed*other.trials != other.passed*r.trials {
		return r.passed*other.trials > other.passed*r.trials
	}
	return r.spent < other.spent
}

func (e *discordEvolver) cycle(ctx context.Context) error {
	// Через сторонний VPN проходит любая стратегия, и счёт ничего не значит.
	if route, err := netbind.Detect(); err != nil || route.Tunnel {
		return errors.New("маршрут по умолчанию занят VPN или не определён")
	}
	target, err := e.target(ctx)
	if err != nil {
		return err
	}
	host := target.Hostname()
	defer e.provider.ClearHostOverride(host)

	// Контроль: загрузка без приёма. Если она проходит, фильтр сейчас узлу не
	// мешает, и прошедший потомок ничего не доказал бы.
	parents := e.provider.Strategies(evolveReferenceGrp)
	control := e.measureScored(ctx, target, plainStrategy(parents[0].Strategy), evolveControlTrials, false, false)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Одиночный срыв бывает и на чистой линии; фильтр считается действующим,
	// когда без приёма срывается большинство загрузок.
	filtered := control.passed*2 < control.trials

	// Круг 1: счёт каждой стратегии ротации по живым загрузкам.
	var results []evolveResult
	for _, sel := range parents {
		result := e.measure(ctx, target, sel.Strategy, evolveTrials, false)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		results = append(results, result)
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].better(results[j]) })
	if len(results) == 0 || results[0].passed == 0 {
		return fmt.Errorf("ни одна стратегия не прошла загрузку с %s", host)
	}
	e.log.Info("отбор стратегий Discord: счёт по загрузкам", "узел", host,
		"без_приёма", fmt.Sprintf("%d/%d", control.passed, control.trials), "итог", describeResults(results))
	if !filtered {
		e.promote(results)
		e.save()
		e.log.Info("отбор стратегий Discord: без приёма проходит большинство загрузок, потомки не выводятся")
		return nil
	}

	// Круг 2: потомки двух лучших. Принимается только прошедший все загрузки.
	best, second := results[0], results[0]
	if len(results) > 1 && results[1].passed > 0 {
		second = results[1]
	}
	accepted := 0
	seen := map[core.StrategyID]bool{}
	for _, result := range results {
		seen[result.sel.ID] = true
	}
	tested := 0
	for i := 0; i < evolveChildren*5 && tested < evolveChildren; i++ {
		child, err := e.breed(best.sel.Strategy, second.sel.Strategy, i)
		if err != nil {
			continue
		}
		id, err := strategy.ComputeID(child)
		if err != nil || seen[id] || !desyncs(child) {
			continue
		}
		seen[id] = true
		tested++
		result := e.measure(ctx, target, child, evolveChildTrials, true)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if result.passed < evolveChildTrials {
			continue
		}
		if route, err := netbind.Detect(); err != nil || route.Tunnel {
			return errors.New("маршрут сменился во время проверки")
		}
		if _, ok := e.admit(child); !ok {
			continue
		}
		e.evolved[id] = child
		for range result.passed {
			e.record(id, true)
		}
		accepted++
		results = append(results, result)
		e.log.Info("отбор стратегий Discord: потомок принят в ротацию",
			"strategy", id, "загрузок", result.passed, "среднее_мс", result.spent.Milliseconds()/int64(result.trials))
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].better(results[j]) })
	e.promote(results)
	e.prune()
	e.save()
	e.log.Info("отбор стратегий Discord: круг завершён", "проверено_потомков", tested, "принято", accepted, "лучшая", results[0].sel.ID)
	return nil
}

// plainStrategy — стратегия с теми же правилами, но без приёма: пакет уходит
// как есть.
func plainStrategy(like *strategy.Strategy) *strategy.Strategy {
	out := &strategy.Strategy{Rules: make([]strategy.Rule, len(like.Rules))}
	for i, rule := range like.Rules {
		rule.Action = &strategy.Action{Kind: core.ActionSend}
		out.Rules[i] = rule
	}
	return out
}

// desyncs сообщает, остался ли в стратегии сам приём: мутация способна
// выродить дерево в простую отправку, а она проходит лишь пока фильтр молчит.
func desyncs(s *strategy.Strategy) bool {
	var walk func(a *strategy.Action) bool
	walk = func(a *strategy.Action) bool {
		if a == nil {
			return false
		}
		switch a.Kind {
		case core.ActionFragment, core.ActionDuplicate, core.ActionTCPOverlap:
			return true
		}
		return walk(a.Left) || walk(a.Right)
	}
	for _, rule := range s.Rules {
		if walk(rule.Action) {
			return true
		}
	}
	return false
}

func describeResults(results []evolveResult) string {
	parts := make([]string, 0, len(results))
	for _, r := range results {
		parts = append(parts, fmt.Sprintf("%.8s %d/%d", r.sel.ID.String(), r.passed, r.trials))
	}
	return strings.Join(parts, ", ")
}

func (e *discordEvolver) breed(best, second *strategy.Strategy, i int) (*strategy.Strategy, error) {
	switch i % 3 {
	case 0:
		return e.gen.Mutate(best)
	case 1:
		if best != second {
			return e.gen.Crossover(best, second)
		}
		return e.gen.Mutate(best)
	default:
		return e.gen.Mutate(second)
	}
}

func (e *discordEvolver) record(id core.StrategyID, ok bool) {
	for _, group := range e.groups {
		e.provider.Record(group, id, ok)
	}
}

// promote ставит лучшую по загрузкам стратегию действующей там, где нынешняя
// прошла хуже. Действующую, прошедшую все загрузки, не трогает: смена без
// причины лишь сбивает то, что работает.
func (e *discordEvolver) promote(results []evolveResult) {
	best := results[0]
	if best.passed < best.trials {
		return
	}
	byID := make(map[core.StrategyID]evolveResult, len(results))
	for _, r := range results {
		byID[r.sel.ID] = r
	}
	active := e.provider.ActiveStrategies()
	for _, group := range e.groups {
		current, measured := byID[active[group]]
		if measured && current.passed == current.trials {
			continue
		}
		if active[group] != best.sel.ID && e.provider.SetActive(group, best.sel.ID) {
			e.log.Info("отбор стратегий Discord: действующая заменена лучшей по загрузкам",
				"группа", group, "было", active[group], "стало", best.sel.ID)
		}
	}
}

// prune оставляет не больше evolveKeep выведенных стратегий, убирая худшие.
func (e *discordEvolver) prune() {
	if len(e.evolved) <= evolveKeep {
		return
	}
	scores := e.provider.Scores(evolveReferenceGrp)
	ids := make([]core.StrategyID, 0, len(e.evolved))
	for id := range e.evolved {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if a, b := scores[ids[i]].Rate(), scores[ids[j]].Rate(); a != b {
			return a < b
		}
		return ids[i] < ids[j]
	})
	for _, id := range ids[:len(ids)-evolveKeep] {
		removed := true
		for _, group := range e.groups {
			if !e.provider.RemoveStrategy(group, id) {
				removed = false
			}
		}
		if removed {
			delete(e.evolved, id)
		}
	}
}

// measure проверяет стратегию загрузками с узла target. stopOnFail прекращает
// проверку на первом срыве: потомку нужен безупречный счёт.
func (e *discordEvolver) measure(ctx context.Context, target *url.URL, s *strategy.Strategy, trials int, stopOnFail bool) evolveResult {
	return e.measureScored(ctx, target, s, trials, stopOnFail, !stopOnFail)
}

func (e *discordEvolver) measureScored(ctx context.Context, target *url.URL, s *strategy.Strategy, trials int, stopOnFail, record bool) evolveResult {
	host := target.Hostname()
	id, ok := e.provider.SetHostOverride(host, s)
	result := evolveResult{sel: proxy.Selection{Strategy: s, ID: id}}
	if !ok {
		return result
	}
	for range trials {
		start := time.Now()
		passed := e.download(ctx, target)
		if ctx.Err() != nil {
			return result
		}
		result.trials++
		result.spent += time.Since(start)
		if passed {
			result.passed++
		}
		if record {
			e.record(id, passed)
		}
		if !passed && stopOnFail {
			break
		}
		if !sleepContext(ctx, evolveTrialGap) {
			return result
		}
	}
	return result
}

func (e *discordEvolver) download(ctx context.Context, target *url.URL) bool {
	transport := &http.Transport{Proxy: nil, DialContext: e.dial, ForceAttemptHTTP2: true, DisableCompression: true}
	defer transport.CloseIdleConnections()
	requestCtx, cancel := context.WithTimeout(ctx, evolveTrialTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, target.String(), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", evolveTrialBytes-1))
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false
	}
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, evolveTrialBytes))
	return n >= discordUpdateMinBytes
}

// target возвращает адрес пакета обновления. Узел обязан быть под обходом, а
// манифест — прийти: без него проверять нечем.
func (e *discordEvolver) target(ctx context.Context) (*url.URL, error) {
	transport := &http.Transport{Proxy: nil, DialContext: e.dial, ForceAttemptHTTP2: true, DisableCompression: true}
	defer transport.CloseIdleConnections()
	requestCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, discordUpdateManifestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("манифест обновления не получен: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("манифест обновления не дочитан: %w", err)
	}
	raw, err := discordUpdateURL(body)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	host := target.Hostname()
	sel := e.provider.Select(proxy.ConnMeta{Host: host, SNI: host, Port: 443, IsClientHello: true})
	if sel.Strategy == nil {
		return nil, fmt.Errorf("узел %s вне обхода", host)
	}
	return target, nil
}
