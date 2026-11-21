// Пакет harness — общий инструмент для прогонов из библиотеки tests.
//
// Зачем существует. Прогон — это не юнит-тест: он поднимает настоящий движок,
// пропускает через него настоящий трафик и смотрит, что получилось. Каждому
// такому прогону нужно одно и то же: собрать бинарник, написать конфиг,
// дождаться готовности, сходить через прокси, прочитать состояние, убраться за
// собой. Если бы это писалось в каждом прогоне заново, прогоны разошлись бы в
// мелочах и перестали быть сравнимыми между собой.
//
// Что знает: как запустить и остановить движок, как сходить через SOCKS5, как
// прочитать его состояние и журнал.
//
// Чего знать не должен: что именно проверяет конкретный прогон. Суждение —
// дело прогона, инструмент только добывает факты.
package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/fitting-1c/evasion/internal/control"
)

// readyTimeout — сколько ждать, пока движок опубликует состояние.
//
// Движок выкладывает файл состояния сразу после первого снимка, то есть почти
// мгновенно. Десять секунд — это запас на медленный диск и первый запуск, когда
// Windows проверяет свежесобранный бинарник антивирусом.
const readyTimeout = 10 * time.Second

// Engine — запущенный движок.
type Engine struct {
	// Bin — путь к собранному бинарнику.
	Bin string
	// StateDir — каталог состояния: файл состояния и журнал наблюдений.
	StateDir string
	// ConfigPath — путь к конфигу прогона.
	ConfigPath string
	// Listen — адрес SOCKS5-прокси движка.
	Listen string

	cmd    *exec.Cmd
	logOut *os.File
	logs   string
}

// Config — конфиг движка для прогона.
//
// Отдельная структура, а не config.Config: прогону нужно задать три-четыре
// поля, а не весь конфиг, и собирается он как JSON — ровно так, как его будет
// писать человек.
type Config struct {
	Listen         string              `json:"listen"`
	Groups         map[string][]string `json:"groups"`
	Vantage        map[string]string   `json:"vantage"`
	ProbeTargets   []string            `json:"probe_targets,omitempty"`
	ControlTargets []string            `json:"control_targets,omitempty"`
	Autopilot      map[string]any      `json:"autopilot,omitempty"`
	Strategy       any                 `json:"strategy,omitempty"`
}

// FragmentStrategy возвращает стратегию с разрезом ClientHello по смещению.
//
// Самая простая исполнимая на этапе 0 стратегия: разрез TCP плюс отправка
// обеих частей. Нужна прогонам как заведомо применимое воздействие — прогон
// проверяет движок, а не подбирает стратегию.
func FragmentStrategy(offset int) any {
	return map[string]any{
		"rules": []any{map[string]any{
			"direction": "outbound",
			"trigger":   map[string]any{"match": "client_hello"},
			"action": map[string]any{
				"kind":   "fragment",
				"params": map[string]any{"proto": "tcp", "offset": offset, "order": "forward"},
				"left":   map[string]any{"kind": "send"},
				"right":  map[string]any{"kind": "send"},
			},
		}},
	}
}

// DefaultConfig возвращает конфиг прогона с заданными группами доменов.
func DefaultConfig(listen string, groups map[string][]string) Config {
	return Config{
		Listen: listen,
		Groups: groups,
		// Метка точки наблюдения обязательна: без неё наблюдения некуда
		// отнести (6.1). Для прогона она условная и помечена как прогонная,
		// чтобы её оценки нельзя было спутать с рабочими.
		Vantage:        map[string]string{"operator": "harness", "region": "test", "access": "wired"},
		ControlTargets: []string{"example.com"},
		Strategy:       FragmentStrategy(5),
	}
}

// BuildEngine собирает бинарник движка в указанный каталог.
//
// Собирается настоящий бинарник, а не вызывается внутренняя функция: прогон
// обязан проверять то, что запустит владелец, вместе со сборкой и флагами.
func BuildEngine(dir string) (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	name := "evasion"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(dir, name)

	cmd := exec.Command("go", "build", "-o", bin, "./cmd/evasion")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("сборка движка: %w\n%s", err, out)
	}
	return bin, nil
}

// repoRoot находит корень репозитория, поднимаясь от рабочего каталога до
// go.mod.
//
// Нужно потому, что прогон запускают из любого места: и из корня
// (`go run ./tests/...`), и из каталога самого прогона.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("harness: go.mod не найден: прогон запущен вне репозитория")
		}
		dir = parent
	}
}

// StartEngine собирает движок, пишет конфиг и запускает прокси, дожидаясь
// готовности.
//
// Каталог прогона создаётся временным и удаляется вызывающим (Stop): прогон не
// должен оставлять следов ни в репозитории, ни в рабочем каталоге владельца.
func StartEngine(cfg Config) (*Engine, error) {
	dir, err := os.MkdirTemp("", "evasion-run-*")
	if err != nil {
		return nil, err
	}

	bin, err := BuildEngine(dir)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	if cfg.Listen == "" {
		port, err := freePort()
		if err != nil {
			os.RemoveAll(dir)
			return nil, err
		}
		cfg.Listen = "127.0.0.1:" + strconv.Itoa(port)
	}

	cfgPath := filepath.Join(dir, "config.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	// Конфиг пишется без метки BOM — иначе строгий разбор JSON упадёт. В Go
	// это выходит само, и это одна из причин делать прогоны на Go, а не на
	// PowerShell, где Set-Content метку добавляет сам.
	if err := os.WriteFile(cfgPath, append(data, '\n'), 0o644); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	stateDir := filepath.Join(dir, "state")
	logPath := filepath.Join(dir, "engine.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	cmd := exec.Command(bin, "run",
		"--config", cfgPath,
		"--state-dir", stateDir,
		"--replan", "2s")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("запуск движка: %w", err)
	}

	e := &Engine{
		Bin:        bin,
		StateDir:   stateDir,
		ConfigPath: cfgPath,
		Listen:     cfg.Listen,
		cmd:        cmd,
		logOut:     logFile,
		logs:       logPath,
	}

	if err := e.waitReady(); err != nil {
		_ = e.Stop()
		return nil, err
	}
	return e, nil
}

// waitReady ждёт готовности движка: опубликован первый снимок И прокси
// принимает соединения.
//
// Второе условие добавлено по настоящей ошибке, и оно не перестраховка. Файл
// состояния появляется при первом снимке, а слушающий сокет открывается
// позже — между ними движок измеряет базовый RTT по сети (5.3), что занимает
// от миллисекунд до секунд в зависимости от канала. Прогон, считавший файл
// признаком готовности, успевал отправить все запросы в ещё закрытый порт,
// получал «connection refused» по каждому и объявлял, что **стратегия вредит
// контрольным целям** — ложную тревогу о побочном вреде, то есть именно о том
// признаке, которому обязано доверять автоматическое решение (4.5).
//
// Проверяется именно установка соединения, а не разбор SOCKS: прогону нужно
// знать, что порт открыт, а работоспособность протокола он и так проверит
// первым же запросом. Соединение сразу закрывается — прокси обязан пережить
// клиента, который ушёл, не сказав ни слова.
func (e *Engine) waitReady() error {
	deadline := time.Now().Add(readyTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if e.cmd.ProcessState != nil && e.cmd.ProcessState.Exited() {
			return fmt.Errorf("движок завершился до готовности:\n%s", e.Logs())
		}
		if _, err := control.ReadStatusFile(e.statusPath()); err != nil {
			lastErr = fmt.Errorf("файл состояния: %w", err)
		} else if err := e.dialProxy(); err != nil {
			lastErr = fmt.Errorf("прокси %s не принимает соединения: %w", e.Listen, err)
		} else {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("движок не вышел в готовность за %v (%v):\n%s", readyTimeout, lastErr, e.Logs())
}

// dialProxy проверяет, что прокси принимает соединения.
func (e *Engine) dialProxy() error {
	conn, err := net.DialTimeout("tcp", e.Listen, 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (e *Engine) statusPath() string { return filepath.Join(e.StateDir, "status.json") }

// Status читает состояние движка.
func (e *Engine) Status() (control.Status, error) {
	return control.ReadStatusFile(e.statusPath())
}

// ArchivePath возвращает путь к журналу наблюдений.
func (e *Engine) ArchivePath() string { return filepath.Join(e.StateDir, "evasion.sqlite") }

// Logs возвращает журнал движка целиком — для отчёта прогона.
func (e *Engine) Logs() string {
	data, err := os.ReadFile(e.logs)
	if err != nil {
		return ""
	}
	return string(data)
}

// Stop останавливает движок и убирает каталог прогона.
//
// Остановка мягкая: движку нужно дописать журнал наблюдений, а убийство
// потеряло бы последнюю пачку — то есть ровно те наблюдения, ради которых
// прогон и затевался.
func (e *Engine) Stop() error {
	if e.cmd == nil || e.cmd.Process == nil {
		return nil
	}
	_ = terminate(e.cmd)

	done := make(chan struct{})
	go func() {
		_, _ = e.cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = e.cmd.Process.Kill()
	}

	if e.logOut != nil {
		_ = e.logOut.Close()
	}
	return nil
}

// StopKeepingDir останавливает движок, не удаляя каталог прогона: журнал
// наблюдений нужен прогону уже после остановки.
func (e *Engine) StopKeepingDir() error { return e.Stop() }

// Cleanup удаляет каталог прогона.
func (e *Engine) Cleanup() {
	if dir := filepath.Dir(e.ConfigPath); dir != "" {
		_ = os.RemoveAll(dir)
	}
}

// SocksClient возвращает клиента HTTP, ходящего через SOCKS5-прокси движка.
//
// Свой клиент, а не сторонняя библиотека: внешние зависимости в проекте по
// минимуму (3.1), а CONNECT по SOCKS5 — это тридцать строк.
func (e *Engine) SocksClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return socksDial(ctx, e.Listen, addr)
			},
			// Повторные попытки и постоянные соединения мешают измерению:
			// прогон хочет знать исход одного соединения, а не итог
			// нескольких.
			DisableKeepAlives: true,
		},
	}
}

// Get выполняет запрос через прокси движка и возвращает код ответа.
//
// Нулевой код означает, что ответа не было вовсе — соединение оборвалось или
// истёк срок. Это не ошибка прогона: именно так выглядит заблокированная цель,
// и отличать «ответ 200» от «ответа нет» — главное, что прогон измеряет.
func (e *Engine) Get(url string, timeout time.Duration) (code int, err error) {
	resp, err := e.SocksClient(timeout).Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// freePort подбирает свободный порт, чтобы прогоны не спорили за 1080 с
// работающим движком владельца.
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}
