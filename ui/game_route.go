package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const gameRouteFile = "game-route.dat"

type GameRouteView struct {
	Configured bool `json:"configured"`
	Nodes      int  `json:"nodes"`
}

func gameRouteView(base string) GameRouteView {
	var v GameRouteView
	if st, e := os.Stat(filepath.Join(base, gameRouteFile)); e != nil || st.IsDir() {
		return v
	}
	b, e := os.ReadFile(filepath.Join(base, gameRouteFile+".info.json"))
	if e != nil || len(b) > 256 {
		return v
	}
	if json.Unmarshal(b, &v) == nil && v.Nodes > 0 && v.Nodes <= 16 {
		v.Configured = true
	}
	return v
}

func (a *App) ImportGameRoute(input string) (GameRouteView, error) {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	if a.shuttingDown {
		return GameRouteView{}, errors.New("приложение закрывается")
	}
	input = strings.TrimSpace(input)
	if len(input) == 0 || len(input) > 2<<20 {
		return GameRouteView{}, errors.New("вставьте ссылку подписки, VLESS или JSON")
	}
	l, err := resolveLayout()
	if err != nil {
		return GameRouteView{}, err
	}
	if err = extractPayload(l); err != nil {
		return GameRouteView{}, err
	}
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.Engine, "game-profile", "--output", filepath.Join(l.Base, gameRouteFile))
	hideConsole(cmd)
	cmd.Stdin = strings.NewReader(input)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if cmd.Run() != nil {
		// The importer emits fixed messages only. Never echo input or provider URLs.
		message := strings.TrimSpace(output.String())
		for _, safe := range []string{"не удалось получить подписку", "сервер подписки не выдал профиль", "не найден подходящий профиль", "не удалось защитить или прочитать"} {
			if strings.Contains(message, safe) {
				return GameRouteView{}, errors.New(safe + "; можно вставить JSON из Happ")
			}
		}
		return GameRouteView{}, errors.New("не удалось импортировать игровой профиль")
	}
	return gameRouteView(l.Base), nil
}

func (a *App) RemoveGameRoute() error {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	l, err := resolveLayout()
	if err != nil {
		return err
	}
	for _, name := range []string{gameRouteFile, gameRouteFile + ".info.json"} {
		if err = os.Remove(filepath.Join(l.Base, name)); err != nil && !os.IsNotExist(err) {
			return errors.New("не удалось удалить игровой профиль")
		}
	}
	return nil
}
