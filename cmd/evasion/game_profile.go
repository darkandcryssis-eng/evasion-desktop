package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/fitting-1c/evasion/internal/gamefilter"
	"github.com/fitting-1c/evasion/internal/gameproxy"
)

func gameProfileCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("game-profile", flag.ContinueOnError)
	output := fs.String("output", "", "encrypted profile path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *output == "" {
		return errors.New("не задан путь игрового профиля")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, (2<<20)+1))
	if err != nil {
		return errors.New("не удалось прочитать профиль")
	}
	defer clear(data)
	p, err := gameproxy.ImportInput(ctx, string(data))
	if err != nil {
		return err
	}
	if err = gameproxy.SaveProfile(*output, p); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]int{"nodes": len(p.Outbounds)})
}

func runGameProfile(ctx context.Context, o gamefilter.Options, adaptive bool, path string, logger *slog.Logger, jsonOut bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	gameCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	w, err := gameproxy.StartWorker(gameCtx, path, filepath.Join(filepath.Dir(exe), "xray.exe"))
	if err != nil {
		return err
	}
	defer w.Close()
	go func() {
		select {
		case <-w.Done():
			cancel()
		case <-gameCtx.Done():
		}
	}()
	err = runGamesOnly(gameCtx, o, adaptive, logger, jsonOut, w.Endpoint)
	if ctx.Err() == nil && gameCtx.Err() != nil {
		return errors.New("игровой маршрут остановился; проверьте подписку и включите заново")
	}
	return err
}
