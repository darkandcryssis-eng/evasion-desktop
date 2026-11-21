package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fitting-1c/evasion/internal/tunnel"
	"github.com/fitting-1c/evasion/internal/warp"
)

// tunnelUsage собирается в рантайме.
var tunnelUsage = `evasion tunnel — WireGuard-туннель к Cloudflare WARP (Phase 2.2)

  evasion tunnel ping [--target host:port]  открыть туннель, попробовать
                                            TCP-соединение, замерить RTT

Проверяет что сохранённый warp account (` + warpStateFile + `) живой и
peer отвечает. Для фактического использования туннеля (Phase 2.3+) будет
отдельная оркестровка; команда tunnel ping — чисто диагностическая.

Нужен уже зарегистрированный account:
  evasion warp register --state-dir state
` + "\n"

// tunnelCommand — точка входа.
func tunnelCommand(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("укажите подкоманду: ping\n\n%s", tunnelUsage)
	}
	switch args[0] {
	case "ping":
		return tunnelPingCommand(ctx, args[1:])
	case "-h", "--help":
		fmt.Fprint(os.Stdout, tunnelUsage)
		return nil
	default:
		return fmt.Errorf("неизвестная подкоманда %q\n\n%s", args[0], tunnelUsage)
	}
}

// tunnelPingCommand проверяет туннель живым TCP-соединением.
//
// Это smoke-тест Phase 2.2: открыть туннель, дотянуться до доступной цели
// (по умолчанию `1.1.1.1:443` — Cloudflare DNS, точно принимает TCP),
// доложить RTT и успех/неудачу. По нему увидим, что wireguard-handshake
// реально прошёл с WARP-peer-ом.
func tunnelPingCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("tunnel ping", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir, "каталог состояния")
	target := fs.String("target", "1.1.1.1:443", "цель TCP-пинга через туннель")
	ptimeout := fs.Duration("timeout", 10*time.Second, "таймаут соединения")
	verbose := fs.Bool("verbose", false, "подробные логи WireGuard (хендшейки)")
	jsonOut := fs.Bool("json", false, "машинно-читаемый вывод")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Загружаем account.
	path := filepath.Join(*stateDir, warpStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("account не зарегистрирован: сначала evasion warp register --state-dir %s", *stateDir)
		}
		return fmt.Errorf("чтение account: %w", err)
	}
	acc, err := warp.UnmarshalAccount(data)
	if err != nil {
		return err
	}

	logger := newLogger(os.Stderr, *jsonOut)
	level := "silent"
	if *verbose {
		level = "verbose"
	}

	logger.Info("tunnel.ping: подбор порта WARP (41 порт, по 3с на попытку)",
		"портов", len(tunnel.WARPFallbackPorts))

	tStart := time.Now()
	tn, err := tunnel.OpenWithFallback(tunnel.Options{
		Account:  acc,
		Logger:   logger,
		LogLevel: level,
	}, tunnel.WARPFallbackPorts, 3*time.Second)
	if err != nil {
		return fmt.Errorf("открытие туннеля (все порты): %w", err)
	}
	defer tn.Close()
	tOpen := time.Since(tStart)

	// Пробуем соединение. Это и есть «ping» на уровне TCP: handshake
	// SYN+SYNACK через туннель = peer принял наши пакеты.
	dctx, cancel := context.WithTimeout(ctx, *ptimeout)
	defer cancel()

	dialStart := time.Now()
	c, err := tn.DialContext(dctx, "tcp", *target)
	rtt := time.Since(dialStart)
	if err != nil {
		if *jsonOut {
			return writeJSON(os.Stdout, struct {
				OK         bool   `json:"ok"`
				OpenMs     int64  `json:"open_ms"`
				Target     string `json:"target"`
				Error      string `json:"error"`
				PeerPublic string `json:"peer_public"`
				PeerEnd    string `json:"peer_endpoint"`
			}{false, tOpen.Milliseconds(), *target, err.Error(), acc.PeerPublicKey, acc.PeerEndpoint})
		}
		return fmt.Errorf("TCP-соединение через туннель к %s не поднялось за %v: %w",
			*target, *ptimeout, err)
	}
	_ = c.Close()

	if *jsonOut {
		return writeJSON(os.Stdout, struct {
			OK         bool   `json:"ok"`
			OpenMs     int64  `json:"open_ms"`
			RTTMs      int64  `json:"rtt_ms"`
			Target     string `json:"target"`
			PeerEnd    string `json:"peer_endpoint"`
			PeerPublic string `json:"peer_public"`
			OurIPv4    string `json:"our_ipv4"`
		}{true, tOpen.Milliseconds(), rtt.Milliseconds(), *target, acc.PeerEndpoint, acc.PeerPublicKey, acc.IPv4.String()})
	}
	fmt.Fprintln(os.Stdout, "туннель работает:")
	fmt.Fprintf(os.Stdout, "  открытие туннеля: %v\n", tOpen.Round(time.Millisecond))
	fmt.Fprintf(os.Stdout, "  RTT до %s через туннель: %v\n", *target, rtt.Round(time.Millisecond))
	fmt.Fprintf(os.Stdout, "  peer: %s\n", acc.PeerEndpoint)
	fmt.Fprintf(os.Stdout, "  наш IPv4 в WARP: %s\n", acc.IPv4)
	return nil
}
