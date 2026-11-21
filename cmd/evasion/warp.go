package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fitting-1c/evasion/internal/warp"
)

// warpStateFile — имя файла account внутри каталога состояния.
//
// Хранится отдельно от status.json/quic.json: это чувствительный файл с
// приватным ключом, и права на него (0600) ставятся явно при записи, независимо
// от прочего состояния.
const warpStateFile = "warp.json"

// warpUsage собирается в рантайме, потому что путь по умолчанию зависит от
// defaultStateDir (определён в status.go).
var warpUsage = `evasion warp — встроенный клиент Cloudflare WARP (Phase 2 транспорта)

  evasion warp register   зарегистрировать новое устройство в WARP
                          (одноразово; сохраняется в <state-dir>/` + warpStateFile + `)
  evasion warp status     показать сохранённое устройство (без приватного ключа)
  evasion warp forget     удалить сохранённое устройство

Регистрация идёт через API api.cloudflareclient.com без браузера, без логина.
Если провайдер режет этот хост, прогон упадёт с ясной ошибкой.
` + "\n"

// warpCommand — точка входа подкоманды.
func warpCommand(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("укажите подкоманду: register | status | forget\n\n%s", warpUsage)
	}
	switch args[0] {
	case "register":
		return warpRegisterCommand(ctx, args[1:])
	case "status":
		return warpStatusCommand(ctx, args[1:])
	case "forget":
		return warpForgetCommand(ctx, args[1:])
	case "-h", "--help":
		fmt.Fprint(os.Stdout, warpUsage)
		return nil
	default:
		return fmt.Errorf("неизвестная подкоманда %q\n\n%s", args[0], warpUsage)
	}
}

// warpRegisterCommand регистрирует новое устройство в WARP и сохраняет его на
// диск. Повторный запуск отвергается — чтобы случайно не перезаписать
// работающий account; для перегенерации нужен явный forget.
func warpRegisterCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("warp register", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir, "каталог состояния для сохранения account")
	force := fs.Bool("force", false, "перезаписать существующий account, если есть")
	jsonOut := fs.Bool("json", false, "машинно-читаемый вывод")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := filepath.Join(*stateDir, warpStateFile)
	if !*force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("account уже существует: %s (используй --force для перезаписи)", path)
		}
	}

	// Таймаут на весь запрос, помимо ctx: регистрация должна занимать секунды,
	// а не повиснуть на минуту, если Cloudflare отвечает очень медленно.
	httpc := &http.Client{Timeout: 30 * time.Second}
	acc, err := warp.Register(ctx, httpc)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*stateDir, 0755); err != nil {
		return fmt.Errorf("создание каталога состояния: %w", err)
	}
	data, err := acc.Marshal()
	if err != nil {
		return err
	}
	// Права 0600 — приватный ключ: пользователю доступно, другим нет. На
	// Windows ACL игнорирует POSIX-биты, но на Linux (разработка) это защита.
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("сохранение account: %w", err)
	}

	if *jsonOut {
		return writeJSON(os.Stdout, struct {
			Path      string `json:"path"`
			DeviceID  string `json:"device_id"`
			Peer      string `json:"peer_endpoint"`
			IPv4      string `json:"ipv4"`
			IPv6      string `json:"ipv6"`
			PublicKey string `json:"public_key"`
		}{path, acc.DeviceID, acc.PeerEndpoint, acc.IPv4.String(), acc.IPv6.String(), acc.Keypair.Public})
	}

	fmt.Fprintf(os.Stdout, "зарегистрирован в WARP\n")
	fmt.Fprintf(os.Stdout, "  device_id:     %s\n", acc.DeviceID)
	fmt.Fprintf(os.Stdout, "  peer_endpoint: %s\n", acc.PeerEndpoint)
	fmt.Fprintf(os.Stdout, "  ipv4:          %s\n", acc.IPv4)
	fmt.Fprintf(os.Stdout, "  ipv6:          %s\n", acc.IPv6)
	fmt.Fprintf(os.Stdout, "  сохранено:     %s (0600)\n", path)
	return nil
}

// warpStatusCommand показывает сохранённое устройство. Приватный ключ НЕ
// печатает — выводить его на экран незачем, а в логах он может утечь.
func warpStatusCommand(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("warp status", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir, "каталог состояния")
	jsonOut := fs.Bool("json", false, "машинно-читаемый вывод")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := filepath.Join(*stateDir, warpStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if *jsonOut {
				return writeJSON(os.Stdout, map[string]bool{"registered": false})
			}
			fmt.Fprintln(os.Stdout, "не зарегистрирован (запусти evasion warp register)")
			return nil
		}
		return fmt.Errorf("чтение account: %w", err)
	}
	acc, err := warp.UnmarshalAccount(data)
	if err != nil {
		return err
	}

	if *jsonOut {
		return writeJSON(os.Stdout, struct {
			Registered bool   `json:"registered"`
			Path       string `json:"path"`
			DeviceID   string `json:"device_id"`
			Peer       string `json:"peer_endpoint"`
			IPv4       string `json:"ipv4"`
			IPv6       string `json:"ipv6"`
			PublicKey  string `json:"public_key"`
		}{true, path, acc.DeviceID, acc.PeerEndpoint, acc.IPv4.String(), acc.IPv6.String(), acc.Keypair.Public})
	}

	fmt.Fprintln(os.Stdout, "зарегистрирован")
	fmt.Fprintf(os.Stdout, "  файл:          %s\n", path)
	fmt.Fprintf(os.Stdout, "  device_id:     %s\n", acc.DeviceID)
	fmt.Fprintf(os.Stdout, "  peer_endpoint: %s\n", acc.PeerEndpoint)
	fmt.Fprintf(os.Stdout, "  ipv4:          %s\n", acc.IPv4)
	fmt.Fprintf(os.Stdout, "  ipv6:          %s\n", acc.IPv6)
	return nil
}

// warpForgetCommand удаляет файл account. Используется перед повторной
// регистрацией или в тестах. Отсутствующий файл — не ошибка, типичный случай
// для чистой машины.
func warpForgetCommand(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("warp forget", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir, "каталог состояния")
	jsonOut := fs.Bool("json", false, "машинно-читаемый вывод")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := filepath.Join(*stateDir, warpStateFile)
	err := os.Remove(path)
	switch {
	case os.IsNotExist(err):
		if *jsonOut {
			return writeJSON(os.Stdout, map[string]bool{"removed": false})
		}
		fmt.Fprintln(os.Stdout, "без изменений: account не был сохранён")
		return nil
	case err != nil:
		return fmt.Errorf("удаление account: %w", err)
	}

	if *jsonOut {
		return writeJSON(os.Stdout, map[string]bool{"removed": true})
	}
	fmt.Fprintln(os.Stdout, "удалён:", path)
	return nil
}
