package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Фазы жизненного цикла подпроцесса движка, как их видит интерфейс.
const (
	phaseStopped  = "stopped"
	phaseStarting = "starting"
	phaseRunning  = "running"
	phaseStopping = "stopping"
	phaseFailed   = "failed"
)

const (
	logRingSize = 400
	// stopTimeout — сколько ждать штатной остановки после закрытия stdin,
	// прежде чем убить процесс. Движку нужно закрыть WinDivert, сбросить
	// rtctrack и журналы; обычно это доли секунды.
	stopTimeout = 15 * time.Second
	// readyTimeout — сколько ждать строки запуска (JSON на stdout) перед
	// перезапуском Discord.
	readyTimeout = 30 * time.Second
)

// StartOptions — параметры запуска, которые выбирает интерфейс (профиль).
type StartOptions struct {
	Voice          string `json:"voice"`
	Quic           string `json:"quic"`
	Observe        bool   `json:"observe"`
	RestartDiscord bool   `json:"restartDiscord"`
	// Boost — «сильный обход сразу»: YouTube стартует с сильного профиля
	// (без прогрева автоподбора от базового), а QUIC к целям блокируется,
	// чтобы браузер сразу шёл по TCP с обходом. Автовосстановление работает
	// поверх, как обычно.
	Boost bool `json:"boost"`
}

var (
	allowedVoice = map[string]bool{"off": true, "ttl": true, "badsum": true, "ttl-quic": true, "badsum-quic": true}
	allowedQuic  = map[string]bool{"off": true, "block": true, "desync": true}
)

func (o StartOptions) validate() error {
	if !allowedVoice[o.Voice] {
		return fmt.Errorf("недопустимый режим голоса %q", o.Voice)
	}
	if !allowedQuic[o.Quic] {
		return fmt.Errorf("недопустимый режим QUIC %q", o.Quic)
	}
	return nil
}

// LogLine — строка журнала движка (slog JSON со stderr) в удобном виде.
type LogLine struct {
	At    string `json:"at"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
	Attrs string `json:"attrs"`
}

// GroupStrategy — какая стратегия действует на группу доменов.
type GroupStrategy struct {
	Group    string `json:"group"`
	Strategy string `json:"strategy"`
}

// HelloStats — периодическая сводка «перехват: разбор ClientHello».
type HelloStats struct {
	At          string `json:"at"`
	Complete    int64  `json:"complete"`
	Assembled   int64  `json:"assembled"`
	Skipped     int64  `json:"skipped"`
	Retransmits int64  `json:"retransmits"`
	Reasons     string `json:"reasons"`
}

// EngineState — снимок для интерфейса; отдаётся целиком на каждый опрос.
type EngineState struct {
	Phase      string          `json:"phase"`
	PID        int             `json:"pid"`
	StartedAt  string          `json:"startedAt"`
	Options    StartOptions    `json:"options"`
	Error      string          `json:"error"`
	Filter     string          `json:"filter"`
	QuicMode   string          `json:"quicMode"`
	Strategies []GroupStrategy `json:"strategies"`
	Hello      *HelloStats     `json:"hello"`
	Discord    string          `json:"discord"`
	Logs       []LogLine       `json:"logs"`
	// Сторож: число автоподъёмов после внезапного выхода и его сообщение.
	Restarts int    `json:"restarts"`
	Guard    string `json:"guard"`
}

// engineManager владеет единственным подпроцессом evasion.exe.
type engineManager struct {
	mu           sync.Mutex
	phase        string
	cmd          *exec.Cmd
	stdin        io.WriteCloser
	done         chan struct{}
	startedAt    time.Time
	opts         StartOptions
	lastErr      string
	filter       string
	quicMode     string
	strategies   map[string]string
	hello        *HelloStats
	discord      string
	discordProxy string
	discordForce bool
	logs         []LogLine
	ready        chan struct{}
	stopAsked    bool
	// Сторож (supervisor.go).
	crashedAt time.Time
	revived   bool
	restarts  int
	guard     string
}

// crashInfo сообщает, что движок внезапно завершился во время работы и ждёт
// автоподъёма.
func (m *engineManager) crashInfo() (time.Time, StartOptions, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.phase != phaseFailed || m.crashedAt.IsZero() {
		return time.Time{}, StartOptions{}, false
	}
	return m.crashedAt, m.opts, true
}

// noteRevived отмечает удачный автоподъём (вызывается сразу после start).
func (m *engineManager) noteRevived() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restarts++
	m.revived = true
	m.guard = fmt.Sprintf("Движок внезапно завершился и был поднят заново (%d).", m.restarts)
}

// giveUp снимает ожидание автоподъёма и объясняет почему.
func (m *engineManager) giveUp(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crashedAt = time.Time{}
	m.guard = msg
}

// resetGuard обнуляет сторожа: пользователь сам запускает или останавливает движок.
func (m *engineManager) resetGuard() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crashedAt, m.restarts, m.guard = time.Time{}, 0, ""
}

func newEngineManager() *engineManager {
	return &engineManager{phase: phaseStopped, strategies: map[string]string{}}
}

// start поднимает движок. l должен быть уже распакован (extractPayload).
func (m *engineManager) start(l layout, opts StartOptions, gameFlags ...string) error {
	if err := opts.validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.phase == phaseStarting || m.phase == phaseRunning || m.phase == phaseStopping {
		return errors.New("движок уже запущен")
	}

	quic := opts.Quic
	if opts.Boost && quic == "off" {
		// Сильный режим без QUIC: браузер не уходит в UDP мимо обхода.
		quic = "block"
	}
	args := []string{
		"run", "--mode", "intercept",
		"--config", l.Config,
		"--quic", quic,
		"--voice", opts.Voice,
		"--json",
		"--stop-on-stdin-eof",
	}
	if opts.Boost {
		args = append(args, "--youtube-profile", "media-sld")
	}
	if gameRouteView(l.Base).Configured {
		args = append(args,
			"--discord-tunnel-profile", filepath.Join(l.Base, gameRouteFile),
			"--youtube-tunnel-profile", filepath.Join(l.Base, gameRouteFile),
			"--telegram-tunnel-profile", filepath.Join(l.Base, gameRouteFile),
		)
	}
	args = append(args, customIPArgs(l.Base)...)
	if len(gameFlags) > 0 {
		args = append([]string{"run", "--game-only", "--json", "--stop-on-stdin-eof"}, gameFlags...)
	}
	if opts.Observe {
		args = append(args, "--observe")
	}
	cmd := exec.Command(l.Engine, args...)
	cmd.Dir = l.Base
	hideConsole(cmd)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("не удалось запустить движок: %w", err)
	}

	m.cmd, m.stdin = cmd, stdin
	m.phase = phaseStarting
	m.startedAt = time.Now()
	m.opts = opts
	m.lastErr, m.filter, m.quicMode, m.discord = "", "", "", ""
	m.discordProxy = ""
	m.discordForce = false
	m.strategies = map[string]string{}
	m.hello = nil
	m.logs = nil
	m.stopAsked = false
	m.crashedAt = time.Time{}
	m.done = make(chan struct{})
	m.ready = make(chan struct{})

	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); m.readStdout(stdout) }()
	go func() { defer readers.Done(); m.readStderr(stderr) }()
	go m.wait(cmd, &readers)
	return nil
}

// wait ждёт выхода процесса и фиксирует итог.
func (m *engineManager) wait(cmd *exec.Cmd, readers *sync.WaitGroup) {
	// Пайпы надо дочитать до Wait: Wait закрывает их.
	readers.Wait()
	err := cmd.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()
	wasRunning := m.phase == phaseRunning
	switch {
	case m.stopAsked && err == nil:
		m.phase = phaseStopped
	case m.stopAsked:
		// Убит по таймауту остановки.
		m.phase = phaseStopped
		if m.lastErr == "" {
			m.lastErr = "движок не остановился штатно и был завершён принудительно"
		}
	case err == nil:
		m.phase = phaseStopped
	default:
		m.phase = phaseFailed
		if m.lastErr == "" {
			m.lastErr = fmt.Sprintf("движок завершился: %v", err)
		}
		// Упал уже после успешного старта — кандидат на автоподъём.
		if wasRunning {
			m.crashedAt = time.Now()
		}
	}
	m.cmd, m.stdin = nil, nil
	select {
	case <-m.ready:
	default:
		close(m.ready)
	}
	close(m.done)
}

// stop просит движок остановиться (закрытие stdin = Ctrl+C для движка) и ждёт.
func (m *engineManager) stop() error {
	m.mu.Lock()
	m.crashedAt = time.Time{}
	if m.cmd == nil {
		m.mu.Unlock()
		return nil
	}
	m.stopAsked = true
	m.phase = phaseStopping
	cmd, stdin, done := m.cmd, m.stdin, m.done
	m.mu.Unlock()

	_ = stdin.Close()
	select {
	case <-done:
		return nil
	case <-time.After(stopTimeout):
		_ = cmd.Process.Kill()
		<-done
		return errors.New("движок не остановился за 15 с и был завершён принудительно")
	}
}

// waitReady ждёт строки запуска; false — не дождались (упал или таймаут).
func (m *engineManager) waitReady() bool {
	m.mu.Lock()
	ready := m.ready
	m.mu.Unlock()
	if ready == nil {
		return false
	}
	select {
	case <-ready:
	case <-time.After(readyTimeout):
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.phase == phaseRunning
}

func (m *engineManager) setDiscord(msg string) {
	m.mu.Lock()
	m.discord = msg
	m.mu.Unlock()
}

// discordProxyAddress возвращает адрес прокси Discord и признак того, что
// он обязателен (маршрут по умолчанию занят сторонним VPN).
func (m *engineManager) discordProxyAddress() (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.discordProxy, m.discordForce
}

// interceptInfo — нужные оболочке поля строки запуска `run --json` (stdout).
type interceptInfo struct {
	Filter       string `json:"filter"`
	QUICMode     string `json:"quic_mode"`
	DiscordProxy string `json:"discord_proxy"`
	DiscordForce bool   `json:"discord_proxy_force"`
	Overrides    []struct {
		Group      string `json:"group"`
		StrategyID string `json:"strategy_id"`
	} `json:"overrides"`
}

func (m *engineManager) readStdout(r io.Reader) {
	dec := json.NewDecoder(r)
	for {
		var info interceptInfo
		if err := dec.Decode(&info); err != nil {
			_, _ = io.Copy(io.Discard, r)
			return
		}
		m.mu.Lock()
		m.filter, m.quicMode = info.Filter, info.QUICMode
		m.discordProxy = info.DiscordProxy
		m.discordForce = info.DiscordForce
		for _, o := range info.Overrides {
			if _, ok := m.strategies[o.Group]; !ok {
				m.strategies[o.Group] = o.StrategyID
			}
		}
		if m.phase == phaseStarting {
			m.phase = phaseRunning
			close(m.ready)
		}
		m.mu.Unlock()
	}
}

func (m *engineManager) readStderr(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		m.consumeLogLine(sc.Text())
	}
}

// consumeLogLine разбирает строку stderr движка. При --json это slog JSON;
// всё остальное (итоговая ошибка `evasion run: ...`, паника) — сырой текст.
func (m *engineManager) consumeLogLine(text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	line := LogLine{At: time.Now().Format(time.RFC3339), Level: "TEXT", Msg: text}
	var rec map[string]any
	if strings.HasPrefix(text, "{") && json.Unmarshal([]byte(text), &rec) == nil {
		line = recordToLine(rec)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, line)
	if len(m.logs) > logRingSize {
		m.logs = m.logs[len(m.logs)-logRingSize:]
	}
	switch {
	case line.Level == "TEXT":
		// main печатает итоговую ошибку команды одной строкой без JSON.
		m.lastErr = strings.TrimPrefix(text, "evasion run: ")
	case line.Level == "ERROR":
		m.lastErr = line.Msg + attrSuffix(line.Attrs)
	}
	if rec == nil {
		return
	}
	switch line.Msg {
	case "стратегия по группе", "стратегия по группе (ротация)":
		g, _ := rec["группа"].(string)
		s, _ := rec["стратегия"].(string)
		if g != "" {
			m.strategies[g] = s
		}
	case "перехват: разбор ClientHello":
		h := &HelloStats{
			At:          line.At,
			Complete:    num(rec["целых_десинк_применим"]),
			Assembled:   num(rec["многосегментных_собрано"]),
			Skipped:     num(rec["многосегментных_пропущено"]),
			Retransmits: num(rec["повторов_clienthello"]),
		}
		h.Reasons, _ = rec["пропущено_причины"].(string)
		m.hello = h
	}
}

// note добавляет в журнал строку самой оболочки; ошибкой она не считается.
func (m *engineManager) note(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, LogLine{At: time.Now().Format(time.RFC3339), Level: "INFO", Msg: msg})
	if len(m.logs) > logRingSize {
		m.logs = m.logs[len(m.logs)-logRingSize:]
	}
}

func attrSuffix(a string) string {
	if a == "" {
		return ""
	}
	return " (" + a + ")"
}

func recordToLine(rec map[string]any) LogLine {
	line := LogLine{}
	line.At, _ = rec["time"].(string)
	line.Level, _ = rec["level"].(string)
	line.Msg, _ = rec["msg"].(string)
	keys := make([]string, 0, len(rec))
	for k := range rec {
		if k == "time" || k == "level" || k == "msg" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, rec[k]))
	}
	line.Attrs = strings.Join(parts, " ")
	return line
}

func num(v any) int64 {
	if f, ok := v.(float64); ok {
		return int64(f)
	}
	return 0
}

func (m *engineManager) snapshot() EngineState {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := EngineState{
		Phase:    m.phase,
		Options:  m.opts,
		Error:    m.lastErr,
		Filter:   m.filter,
		QuicMode: m.quicMode,
		Discord:  m.discord,
		Logs:     append([]LogLine(nil), m.logs...),
		Restarts: m.restarts,
		Guard:    m.guard,
	}
	if m.cmd != nil && m.cmd.Process != nil {
		st.PID = m.cmd.Process.Pid
	}
	if !m.startedAt.IsZero() {
		st.StartedAt = m.startedAt.Format(time.RFC3339)
	}
	if m.hello != nil {
		h := *m.hello
		st.Hello = &h
	}
	for g, s := range m.strategies {
		st.Strategies = append(st.Strategies, GroupStrategy{Group: g, Strategy: s})
	}
	sort.Slice(st.Strategies, func(i, j int) bool { return st.Strategies[i].Group < st.Strategies[j].Group })
	return st
}

func (m *engineManager) awaitStartup() error {
	if m.waitReady() {
		return nil
	}
	state := m.snapshot()
	if state.Phase == phaseStarting {
		_ = m.stop()
		return errors.New("движок не подтвердил готовность за 30 секунд")
	}
	if state.Error != "" {
		return errors.New(state.Error)
	}
	return errors.New("движок завершился до подтверждения готовности")
}
