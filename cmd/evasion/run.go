package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/control"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/gamefilter"
	"github.com/fitting-1c/evasion/internal/policy"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/vantage"
)

// runInfo — машинно-читаемое описание запущенного движка (вывод --json при
// старте run).
//
// Это часть контракта CLI (2.3): структура стабильна и описывает фактические
// действующие параметры после слияния конфига и флагов, а не то, что было в
// файле. По ней интерфейс показывает, в каком режиме и с каким радиусом работает
// движок.
type runInfo struct {
	// Mode — режим исполнения ("proxy" на этапе 0).
	Mode string `json:"mode"`
	// Listen — фактический адрес прослушивания после привязки (с реальным
	// портом, если в конфиге был :0).
	Listen string `json:"listen"`
	// Observe — включён ли режим наблюдения (стратегии не применяются).
	Observe bool `json:"observe"`
	// Groups — имена выбранных групп доменов (радиус поражения). Пусто означает
	// «все группы конфига».
	Groups []string `json:"groups"`
	// Domains — действующий набор доменов радиуса после разворота групп.
	Domains []string `json:"domains"`
	// StrategyID — идентификатор применяемой стратегии; пусто, если стратегии
	// нет.
	StrategyID string `json:"strategy_id"`
	// StrategyApplies — применяется ли стратегия хоть к чему-то. Ложь, если
	// стратегии нет или радиус пуст (стратегия задана, но групп нет). Отдельное
	// поле, потому что это частый повод «обход молча не работает».
	StrategyApplies bool `json:"strategy_applies"`
	// StatusFile — где контур выкладывает состояние для команд status и
	// portfolio.
	StatusFile string `json:"status_file"`
	// ReplanInterval — период пересчёта снимка.
	ReplanInterval string `json:"replan_interval"`
	// Archive — файл журнала наблюдений (6.4).
	Archive string `json:"archive"`
	// ProbeInterval — интервал активных проб (5.7).
	ProbeInterval string `json:"probe_interval"`
	// ProbeTargets — имена, по которым идут пробы (10.1). Пусто означает, что
	// пробы идут к самим целям радиуса, а это хуже: цель может не отвечать по
	// своему имени.
	ProbeTargets []string `json:"probe_targets"`
	// Vantage — определённая точка наблюдения (6.1): без неё наблюдения
	// некуда отнести, поэтому она видна сразу при запуске.
	Vantage string `json:"vantage"`
}

// runCommand разбирает флаги команды run, собирает конфигурацию и запускает
// SOCKS5-прокси до отмены контекста.
//
// Порядок: конфиг из файла (если задан) → переопределения флагами → сборка
// провайдера стратегий → запуск. Флаги имеют приоритет над файлом: это привычное
// поведение и способ быстро поменять параметр без правки файла.
func runCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	gameProfileFlag := fs.String("game-vless-profile", "", "encrypted per-user game profile")
	gameSOCKSFlag := fs.String("game-socks", "", "local game tunnel endpoint")
	gameOnlyFlag := fs.Bool("game-only", false, "independent game filter")
	gameAdaptive := fs.Bool("game-adaptive", true, "enable only after unanswered game traffic")
	gameModeFlag := fs.String("game-mode", "off", "off|auto|gentle|balanced|strong")
	gameProtocolFlag := fs.String("game-protocol", "both", "both|tcp|udp")
	gameAlbionFlag := fs.Bool("game-albion", true, "Albion Online")
	gameUbisoftFlag := fs.Bool("game-ubisoft", true, "Ubisoft Connect and launched games")
	var gameExes gameTargets
	fs.Var(&gameExes, "game-exe", "selected game executable path")
	var (
		mode            = fs.String("mode", "proxy", "режим: proxy (этап 0) или intercept (этап 1)")
		listen          = fs.String("listen", "", "адрес прослушивания прокси (переопределяет конфиг)")
		configPath      = fs.String("config", "", "путь к файлу конфигурации (JSON)")
		observe         = fs.Bool("observe", false, "режим наблюдения: не применять стратегии")
		quicFlag        = fs.String("quic", "", "режим QUIC: block|desync|off (переопределяет конфиг)")
		groupsFlag      = fs.String("groups", "", "ограничить радиус группами через запятую")
		stateDir        = fs.String("state-dir", defaultStateDir, "каталог состояния для команд status и portfolio")
		replanEach      = fs.Duration("replan", time.Minute, "период пересчёта снимка контуром управления")
		autoPilot       = fs.Bool("auto", false, "intercept: сам подбирать и держать рабочую стратегию из портфеля")
		searchGen       = fs.Bool("search", false, "intercept+auto: фоновый генератор ищет новые стратегии и пополняет портфель (5.6)")
		voiceFlag       = fs.String("voice", "ttl", "intercept: десинк голоса Discord по UDP: off|ttl|badsum|ttl-quic|badsum-quic|probe (default: ttl)")
		ytProfile       = fs.String("youtube-profile", "", "intercept: стартовый профиль автоподбора YouTube (split|overlap|fake-sld|media-sld|...); автоподбор продолжает работать поверх")
		discordProfile  = fs.String("discord-tunnel-profile", "", "intercept: зашифрованный VLESS-профиль резервного маршрута Discord")
		youtubeProfile  = fs.String("youtube-tunnel-profile", "", "intercept: зашифрованный VLESS-профиль автоматического резерва YouTube")
		telegramProfile = fs.String("telegram-tunnel-profile", "", "intercept: зашифрованный VLESS-профиль резервного маршрута Telegram")
		ipListFlag      = fs.String("ip-list", "", "intercept: файл со своими IP и подсетями, к которым обход применяется по адресу назначения")
		redirectF       = fs.Bool("rtc-redirect", false, "intercept: переклеивать душимые RTC-порты Discord (2053/2083/2087/2096) на живой 8443")
		jsonOut         = fs.Bool("json", false, "машинно-читаемый вывод")
		stdinStop       = fs.Bool("stop-on-stdin-eof", false, "штатно остановиться, когда закроется stdin (запуск из оболочки Evasion UI)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	games := gamefilter.Options{Mode: *gameModeFlag, Protocol: *gameProtocolFlag, Albion: *gameAlbionFlag, Ubisoft: *gameUbisoftFlag, Executables: gameExes}
	if err := games.Validate(); err != nil {
		return err
	}
	if games.Enabled() && !*gameOnlyFlag {
		return errors.New("игровой фильтр запускается отдельно: --game-only")
	}
	if games.Enabled() && ((*mode != "intercept" && !*gameOnlyFlag) || *autoPilot || *voiceFlag == "probe" || *redirectF) {
		return errors.New("игровой фильтр требует обычный intercept без --auto, --rtc-redirect и --voice probe")
	}

	// Остановка по закрытию stdin — канал управления для оболочки, которая
	// запускает движок подпроцессом. На Windows родитель без консоли не может
	// послать Ctrl+C/Ctrl+Break, а TerminateProcess пропускает все defer
	// (lock, журналы, rtctrack). Закрытие пайпа даёт ту же отмену контекста,
	// что и Ctrl+C, и срабатывает само, если оболочка упала или её убили.
	if *stdinStop {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		go func() {
			_, _ = io.Copy(io.Discard, os.Stdin)
			cancel()
		}()
	}

	if *gameOnlyFlag {
		if !games.Enabled() {
			return errors.New("выберите игровой режим")
		}
		if *gameProfileFlag != "" {
			return runGameProfile(ctx, games, *gameAdaptive, *gameProfileFlag, newLogger(os.Stderr, *jsonOut), *jsonOut)
		}
		return runGamesOnly(ctx, games, *gameAdaptive, newLogger(os.Stderr, *jsonOut), *jsonOut, *gameSOCKSFlag)
	}
	if *mode != "proxy" && *mode != "intercept" {
		return fmt.Errorf("неизвестный режим %q: доступны proxy (этап 0) и intercept (этап 1)", *mode)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	// Переопределения флагами.
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *observe {
		cfg.Observe = true
	}
	// Флаг --quic переопределяет режим QUIC из конфига: удобнее для живых
	// проб (не надо править JSON), и исключает путаницу block_quic/quic_mode.
	if *quicFlag != "" {
		m, err := config.ParseQUICMode(*quicFlag)
		if err != nil {
			return err
		}
		cfg.QUICMode = m
		cfg.BlockQUIC = m == config.QUICBlock
	}

	groupNames := parseGroups(*groupsFlag)
	domainSet, err := cfg.DomainSet(groupNames)
	if err != nil {
		return err
	}

	// Логи — на stderr, чтобы не смешиваться с машинным выводом на stdout.
	// Формат лога следует формату вывода: JSON при --json, иначе текст.
	logger := newLogger(os.Stderr, *jsonOut)

	voice, err := parseVoiceMode(*voiceFlag)
	if err != nil {
		return err
	}

	// Транспорт A (hosts-подмена): применяется до любого режима, чтобы DNS уже
	// отдавал нужные IP к моменту старта клиента. Идемпотентно: если блок уже
	// совпадает с конфигом, hosts не трогается. Нужны права администратора,
	// без них — внятная ошибка (а не тихий пропуск с «молча не работает»).
	if cfg.TransportFallback.Enabled {
		if err := applyTransportFallbackOnStart(cfg.TransportFallback, logger); err != nil {
			return err
		}
	}

	// Этап 1: системный перехват через WinDivert. Путь данных другой, но выбор
	// стратегии и пакеты strategy/scoring/control — те же (4.7 п. 4). Остальная
	// сборка ниже относится к прокси (этап 0).
	if *mode == "intercept" {
		if *ytProfile != "" && !youtubeProfileAllowed(*ytProfile) {
			return fmt.Errorf("неизвестный профиль YouTube %q", *ytProfile)
		}
		return runIntercept(ctx, cfg, domainSet, groupNames, logger, *jsonOut, *autoPilot, *searchGen, voice, *redirectF, *ytProfile, *discordProfile, *youtubeProfile, *telegramProfile, *ipListFlag)
	}

	// Горячая таблица и контур управления (M6). Прокси получает policy.Table
	// как провайдера стратегий: шов тот же, что был у GroupProvider, и сам
	// proxy от замены не меняется.
	hot := policy.NewTable()

	// Журнал наблюдений на диске: оценки контура живут в памяти и исчезают при
	// перезапуске, а каждое наблюдение добыто живым соединением (6.4).
	arch, err := openArchive(ctx, cfg, *stateDir, logger)
	if err != nil {
		return err
	}
	defer func() {
		if err := arch.close(); err != nil {
			logger.Error("журнал наблюдений закрыт с ошибкой", "ошибка", err)
		}
	}()

	engine, err := startEngine(ctx, cfg, domainSet.Domains(), hot, arch, logger, *stateDir, *replanEach)
	if err != nil {
		return err
	}
	defer engine.wait()

	// Расписание проб: без него кандидат не может набрать доказательства, и
	// нижняя ступень лестницы допуска закрыта (5.1, 5.5).
	stopProbes, err := startProbes(ctx, cfg, engine.engine, hot, arch, engine.vantage, logger)
	if err != nil {
		return err
	}
	defer stopProbes()

	srv, err := proxy.NewServer(proxy.Config{
		Provider: hot,
		Observe:  cfg.Observe,
		Logger:   logger,
		// Исходы соединений уходят контуру: без этого шва автопилот не учится
		// на живом трафике и работает как закреплённая вручную стратегия.
		Outcomes: &outcomeObserver{
			sink:    engine.engine,
			archive: arch.writer,
			vantage: engine.vantage,
		},
	})
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("прослушивание %s: %w", cfg.Listen, err)
	}

	info := runInfo{
		Mode:            "proxy",
		Listen:          ln.Addr().String(),
		Observe:         cfg.Observe,
		Groups:          groupNames,
		Domains:         domainSet.Domains(),
		StrategyApplies: cfg.Strategy != nil && !domainSet.Empty(),
		StatusFile:      filepath.Join(*stateDir, statusFileName),
		Archive:         filepath.Join(*stateDir, dbFileName),
		ReplanInterval:  replanEach.String(),
		ProbeInterval:   cfg.Autopilot.ProbeInterval.String(),
		ProbeTargets:    cfg.ProbeTargets,
		Vantage:         engine.vantage.String(),
	}
	if cfg.Strategy != nil {
		info.StrategyID = cfg.Strategy.ID.String()
	}
	emitRunInfo(os.Stdout, info, *jsonOut)

	// Serve блокирует до отмены контекста (SIGINT/SIGTERM) и возвращает причину
	// отмены — это штатное завершение, а не ошибка.
	if err := srv.Serve(ctx, ln); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// loadConfig читает конфиг из файла или возвращает конфиг по умолчанию, если
// путь не задан. Запуск без файла допустим: прокси поднимется на адресе по
// умолчанию и будет работать прозрачно (без стратегии и групп).
func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		return config.Default(), nil
	}
	return config.Load(path)
}

// runningEngine — запущенный контур управления вместе со средствами его
// остановки.
type runningEngine struct {
	engine  *control.Engine
	vantage core.VantageID
	stop    context.CancelFunc
	done    chan struct{}
}

// wait останавливает контур и ждёт завершения его горутины. Без ожидания
// процесс мог бы завершиться посреди записи файла состояния, оставив его
// недописанным.
func (r *runningEngine) wait() {
	r.stop()
	<-r.done
}

// startEngine поднимает контур управления и публикует первый снимок.
//
// Стратегия из конфига (если она задана) попадает в портфель и ЗАКРЕПЛЯЕТСЯ за
// каждой целью радиуса. Это осознанное решение, а не упрощение: стратегия в
// конфиге — выбор человека, а закрепление ровно это и означает (5.1, 4.5).
// Автопилот без закрепления применить её не смог бы — у движка нет о ней ни
// одного наблюдения, а на живой трафик без доказательств он не выпускает
// ничего. Так поведение команды run остаётся прежним, но проходит через
// лестницу допуска, а не минует её.
//
// Чего здесь ещё нет, и это надо знать: наблюдения с пользовательских
// соединений в контур не поступают. Для этого прокси нужен выход для исходов
// соединений, которого у него пока нет, поэтому автопилот учится только на
// пробах (M4) и на том, что ему скажут командами. Признать это честнее, чем
// подсунуть ему выдуманный сигнал (9.3).
func startEngine(
	ctx context.Context,
	cfg *config.Config,
	targets []string,
	hot *policy.Table,
	arch *archive,
	logger *slog.Logger,
	stateDir string,
	replanEach time.Duration,
) (*runningEngine, error) {
	// Точка наблюдения: метка из конфига плюс отпечаток интерфейсов (6.2).
	// Ошибка перечисления интерфейсов не повод не работать — метка остаётся,
	// отпечаток пустой, и это видно в status.
	van, err := vantage.Detect(cfg.Vantage, vantage.SystemInterfaces())
	if err != nil {
		logger.Warn("точка наблюдения определена частично", "ошибка", err)
	}

	// Тёплый старт: восстановить оценки из журнала, чтобы прогон продолжал
	// учёбу, а не начинал с нуля. Окно — срок доверия к оценкам (5.9).
	warmup := arch.warmup(ctx, van.ID, cfg.Autopilot.EstimatesStaleAfter, logger)

	portfolio := control.Portfolio{}
	pins := map[string]core.StrategyID{}
	if cfg.Strategy != nil {
		id, err := strategy.ComputeID(cfg.Strategy)
		if err != nil {
			return nil, err
		}
		portfolio[id] = control.Holding{Strategy: cfg.Strategy, Status: core.StatusActive}
		// Закрепления задаются начальным состоянием, а не командами: иначе
		// первый снимок считался бы без них — с ложной тревогой об обвале
		// портфеля и лишним пересчётом на каждую цель.
		for _, target := range targets {
			pins[target] = id
		}
	}

	engine, err := control.New(control.Options{
		Vantage:    van.ID,
		Targets:    targets,
		Portfolio:  portfolio,
		Pins:       pins,
		Warmup:     warmup,
		Control:    cfg.Autopilot.Control(),
		Scoring:    cfg.Autopilot.Scoring(),
		Table:      hot,
		Interval:   replanEach,
		Logger:     logger,
		StatusPath: filepath.Join(stateDir, statusFileName),
	})
	if err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = engine.Run(runCtx)
	}()

	r := &runningEngine{engine: engine, vantage: van.ID, stop: cancel, done: done}

	// Ждём первый снимок прежде, чем вызывающий откроет слушающий сокет: иначе
	// соединения, пришедшие в первые микросекунды, прошли бы без стратегии не
	// по решению, а по гонке.
	if err := engine.Ready(runCtx); err != nil {
		r.wait()
		return nil, fmt.Errorf("контур управления не успел опубликовать первый снимок: %w", err)
	}
	return r, nil
}

// parseGroups разбирает список групп из флага --groups (через запятую), отбрасывая
// пустые элементы и пробелы. Пустой результат означает «все группы конфига».
func parseGroups(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// newLogger создаёт структурированный журнал нужного формата.
func newLogger(w *os.File, jsonOut bool) *slog.Logger {
	if jsonOut {
		return slog.New(slog.NewJSONHandler(w, nil))
	}
	return slog.New(slog.NewTextHandler(w, nil))
}

// emitRunInfo печатает описание запуска: JSON-объектом или человекочитаемым
// текстом. Форматирование — забота CLI, движок отдаёт только данные (2.2).
func emitRunInfo(w *os.File, info runInfo, jsonOut bool) {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)
		return
	}
	fmt.Fprintf(w, "режим: %s\n", info.Mode)
	fmt.Fprintf(w, "слушаю: %s\n", info.Listen)
	fmt.Fprintf(w, "наблюдение: %t\n", info.Observe)
	if len(info.Groups) > 0 {
		fmt.Fprintf(w, "группы: %s\n", strings.Join(info.Groups, ", "))
	} else {
		fmt.Fprintln(w, "группы: все из конфига")
	}
	if len(info.Domains) > 0 {
		fmt.Fprintf(w, "радиус: %s\n", strings.Join(info.Domains, ", "))
	} else {
		fmt.Fprintln(w, "радиус: пуст")
	}
	switch {
	case info.StrategyID == "":
		fmt.Fprintln(w, "стратегия: нет (прозрачный пропуск)")
	case !info.StrategyApplies:
		fmt.Fprintf(w, "стратегия: %s — НЕ применяется (радиус пуст)\n", info.StrategyID)
	default:
		fmt.Fprintf(w, "стратегия: %s\n", info.StrategyID)
	}
}
