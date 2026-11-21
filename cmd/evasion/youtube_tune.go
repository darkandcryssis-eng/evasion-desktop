package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/windivert"
	"github.com/fitting-1c/evasion/internal/youtubetune"
	quicgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var youtubeProbeURLs = map[string]string{"site": "https://www.youtube.com/generate_204", "cdn": "https://i.ytimg.com/generate_204"}

func probeYouTubeHTTP(ctx context.Context, target, protocol string, tlsConfig *tls.Config) youtubetune.Check {
	result := youtubetune.Check{Target: target, Protocol: protocol}
	url, ok := youtubeProbeURLs[target]
	if !ok {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var roundTripper http.RoundTripper
	if protocol == "h3" {
		t := &http3.Transport{TLSClientConfig: tlsConfig, QUICConfig: &quicgo.Config{Versions: []quicgo.Version{quicgo.Version1}, HandshakeIdleTimeout: 4 * time.Second, MaxIdleTimeout: 5 * time.Second}}
		defer t.Close()
		roundTripper = t
	} else {
		t := &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 4 * time.Second}).DialContext, TLSHandshakeTimeout: 4 * time.Second}
		defer t.CloseIdleConnections()
		roundTripper = t
	}
	client := &http.Client{Transport: roundTripper, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result
	}
	req.Header.Set("User-Agent", "Evasion-YouTube-Check/1")
	req.Header.Set("Cache-Control", "no-cache")
	start := time.Now()
	response, err := client.Do(req)
	result.MS = time.Since(start).Milliseconds()
	if err != nil {
		return result
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	result.OK = (response.StatusCode == 204 || target == "cdn" && response.StatusCode == 404) && (protocol != "h3" || response.ProtoMajor == 3)
	return result
}

func youtubeProbeCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("youtube-probe", flag.ContinueOnError)
	target := fs.String("target", "site", "")
	protocol := fs.String("protocol", "tcp", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, ok := youtubeProbeURLs[*target]; !ok || (*protocol != "tcp" && *protocol != "h3") {
		return errors.New("invalid probe")
	}
	return json.NewEncoder(os.Stdout).Encode(probeYouTubeHTTP(ctx, *target, *protocol, &tls.Config{MinVersion: tls.VersionTLS12}))
}

func childYouTubeProbe(ctx context.Context, target, protocol string) youtubetune.Check {
	failed := youtubetune.Check{Target: target, Protocol: protocol}
	exe, err := os.Executable()
	if err != nil {
		return failed
	}
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "youtube-probe", "--target", target, "--protocol", protocol)
	hideCommandWindow(cmd)
	data, err := cmd.Output()
	if err != nil || len(data) > 4096 {
		return failed
	}
	var result youtubetune.Check
	if json.Unmarshal(data, &result) != nil || result.Target != target || result.Protocol != protocol {
		return failed
	}
	return result
}

func youtubeScore(ctx context.Context, name, protocol string) youtubetune.Score {
	score := youtubetune.Score{Name: name, Checks: []youtubetune.Check{}}
	for range 2 {
		checks := make(chan youtubetune.Check, 2)
		for _, target := range []string{"site", "cdn"} {
			go func(target string) { checks <- childYouTubeProbe(ctx, target, protocol) }(target)
		}
		for range 2 {
			score.Checks = append(score.Checks, <-checks)
		}
		if ctx.Err() != nil {
			return score
		}
	}
	return score
}

// Only the YouTube radius receives the candidate. Other TCP/UDP is forwarded.
func withYouTubeCandidate(ctx context.Context, strat *strategy.Strategy, mode config.QUICMode, run func(context.Context) youtubetune.Score) (youtubetune.Score, error) {
	scope := config.Default()
	scope.Groups = map[string][]string{"video": youtubetune.Domains}
	domains, _ := scope.DomainSet([]string{"video"})
	provider, err := proxy.NewGroupProvider(strat, domains)
	if err != nil {
		return youtubetune.Score{}, err
	}
	h, err := windivert.Open(interceptFilter)
	if err != nil {
		return youtubetune.Score{}, err
	}
	engine, err := intercept.New(intercept.Options{Source: h, Sink: h, DesyncSink: func(sni string) capture.PacketSink {
		if youtubetune.IsYouTube(sni) {
			return youtubePacketSink{h}
		}
		return nil
	}, Flows: flow.NewTable(flowCapacity, flowTTL, intercept.TLSHelloDetector), Provider: provider, Exec: packetexec.New(), Parse: intercept.TLSHelloParser})
	if err != nil {
		h.Close()
		return youtubetune.Score{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var engineErr error
	go func() { defer close(done); engineErr = engine.Run(ctx) }()
	scope.QUICMode = mode
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir, err := os.MkdirTemp("", "evasion-youtube-*")
	if err != nil {
		cancel()
		h.Close()
		<-done
		return youtubetune.Score{}, err
	}
	defer os.RemoveAll(dir)
	stop, _, _, err := startQUICBlock(ctx, scope, domains, dir, logger)
	if err != nil {
		cancel()
		h.Close()
		<-done
		return youtubetune.Score{}, err
	}
	defer func() { cancel(); stop(); h.Close(); <-done }()
	score := run(ctx)
	select {
	case <-done:
		if engineErr != nil {
			return youtubetune.Score{}, engineErr
		}
		return youtubetune.Score{}, errors.New("проверочный движок остановился")
	default:
	}
	return score, nil
}

func youtubeTuneCommand(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("youtube-tune", flag.ContinueOnError)
	path := fs.String("config", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	if cfg.Observe {
		return errors.New("режим наблюдения не поддерживает подбор")
	}
	if err := youtubetune.ValidateVideoGroup(cfg); err != nil {
		return err
	}
	lock, err := acquireEngineLock(interceptFilter)
	if err != nil {
		return err
	}
	defer lock.Release()
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); cancel() }()
	current := cfg.Strategies["video"]
	if current == nil {
		current = cfg.Strategy
	}
	result, err := youtubetune.Run(ctx, func(ctx context.Context, name, mode, protocol string) (youtubetune.Score, error) {
		candidate, err := youtubetune.Profile(name, current)
		if err != nil {
			return youtubetune.Score{}, err
		}
		parsed, err := config.ParseQUICMode(mode)
		if err != nil {
			return youtubetune.Score{}, err
		}
		return withYouTubeCandidate(ctx, candidate, parsed, func(ctx context.Context) youtubetune.Score { return youtubeScore(ctx, name, protocol) })
	}, func(stage string) { fmt.Fprintln(os.Stderr, stage) })
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func youtubeProfileCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("youtube-profile", flag.ContinueOnError)
	path := fs.String("config", "", "")
	profile := fs.String("profile", "current", "")
	mode := fs.String("quic", "off", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	if err := youtubetune.ValidateVideoGroup(cfg); err != nil {
		return err
	}
	b, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	if len(b) > 2<<20 {
		return errors.New("configuration too large")
	}
	b, err = youtubetune.Overlay(b, *profile, *mode)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(b)
	return err
}
