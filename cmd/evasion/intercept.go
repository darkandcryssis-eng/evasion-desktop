package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/control"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/hops"
	"github.com/fitting-1c/evasion/internal/inbound"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/iplist"
	"github.com/fitting-1c/evasion/internal/netbind"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/policy"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/rtcredirect"
	"github.com/fitting-1c/evasion/internal/safego"
	"github.com/fitting-1c/evasion/internal/sandbox"
	"github.com/fitting-1c/evasion/internal/store"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/vantage"
	"github.com/fitting-1c/evasion/internal/windivert"
	"github.com/fitting-1c/evasion/internal/youtubetune"
)

type youtubePacketSink struct{ capture.PacketSink }

func (s youtubePacketSink) Send(p capture.Packet) error {
	d, err := packet.Dissect(p.Data)
	if err == nil && d.Version == packet.Version4 {
		if h, ok := d.IPv4(p.Data); ok {
			h.SetID(0)
			h.RecomputeChecksum()
		}
	}
	return s.PacketSink.Send(p)
}

func openYouTubePacketSender(logger *slog.Logger) (func(string) capture.PacketSink, func()) {
	// Separate capture and injection stages so later filters do not reprocess
	// the deliberately reordered ClientHello segments.
	h, err := windivert.OpenPriority("false", -3000)
	if err != nil {
		logger.Warn("отдельный канал отправки YouTube недоступен; используется обычный", "err", err)
		return nil, func() {}
	}
	sink := youtubePacketSink{h}
	return func(sni string) capture.PacketSink {
		if youtubetune.IsYouTube(sni) {
			return sink
		}
		return nil
	}, func() { _ = h.Close() }
}

// Параметры контура перехвата. В конфиг пока не вынесены: второго потребителя у
// них нет, а значения консервативны. Вынести — когда понадобится настройка.
const (
	// interceptSegments — сегменты, по которым движок что-то решает: с данными
	// или с флагами жизненного цикла потока.
	interceptSegments = "(tcp.PayloadLength > 0 or tcp.Syn or tcp.Fin or tcp.Rst)"
	// rtcRedirectTarget — живой порт, на который уводятся душимые RTC-порты.
	// 8443 выбран, потому что на нём голос discord.media стабилен, а входящего
	// чужого трафика на нём почти нет (в отличие от 443) — фильтр входящих узкий.
	rtcRedirectTarget = 8443
	// flowCapacity — ёмкость таблицы потоков; при переполнении новые потоки идут
	// прозрачно, без вытеснения (4.4).
	flowCapacity = 4096
	// flowTTL — срок жизни записи потока без обновления.
	flowTTL = 2 * time.Minute
	// ksInterval, ksFailThreshold — период и порог killswitch: столько подряд
	// неудачных проверок связности поднимают прозрачный режим (1.6).
	ksInterval      = 10 * time.Second
	ksFailThreshold = 3
)

var (
	interceptPortList = []uint16{443, 2053, 2083, 2087, 2096, 8443}
	interceptPorts    = makePortPredicate("tcp.DstPort", interceptPortList)
	// interceptFilter — фильтр WinDivert: исходящие TCP к HTTPS-портам и не наши
	// собственные инъекции. Узкий фильтр оставляет движку только начало TLS-
	// соединений; "not impostor" исключает повторный перехват своих инъекций.
	interceptFilter = "outbound and tcp and " + interceptPorts + " and " + interceptSegments + " and not impostor"
	// interceptFilterRedirect расширяет фильтр входящими с живого порта 8443:
	// rtcredirect восстанавливает им исходный порт назначения. Чистые ACK не
	// отсекаются, поскольку декоратору нужно переписать каждый исходящий сегмент.
	interceptFilterRedirect = "((outbound and tcp and " + interceptPorts +
		") or (inbound and tcp and tcp.SrcPort == 8443)) and not impostor"
	inboundObserveFilter = "inbound and tcp and ((tcp.Syn and tcp.Ack) or tcp.Rst) and " +
		makePortPredicate("tcp.SrcPort", interceptPortList)
)

func makePortPredicate(field string, ports []uint16) string {
	parts := make([]string, len(ports))
	for i, port := range ports {
		parts[i] = fmt.Sprintf("%s == %d", field, port)
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// rtcRedirectFrom — душимые TSPU RTC-порты Cloudflare, которые при --rtc-redirect
// уводятся на rtcRedirectTarget. Это измеренная карта (443/8443 живые, эти —
// душатся после рукопожатия). Вынесена отдельным списком намеренно: это та
// величина, которой в дальнейшем будет управлять автоподстройка портов —
// по живучести потоков, как автопилот управляет выбором стратегии.
var rtcRedirectFrom = []uint16{2053, 2083, 2087, 2096}

// interceptInfo — машинно-читаемое описание запуска перехвата (вывод --json).
type interceptInfo struct {
	Mode            string   `json:"mode"`
	Filter          string   `json:"filter"`
	Observe         bool     `json:"observe"`
	Domains         []string `json:"domains"`
	StrategyID      string   `json:"strategy_id"`
	StrategyApplies bool     `json:"strategy_applies"`
	// Auto — включён авто-подбор стратегии из портфеля.
	Auto bool `json:"auto"`
	// QUICBlock — активна ли именно БЛОКИРОВКА QUIC к группам (совместимость).
	QUICBlock bool `json:"quic_block"`
	// QUICMode — режим обработки QUIC к группам: block, desync, off (3.3).
	QUICMode string `json:"quic_mode"`
	// DiscordProxy — loopback HTTP CONNECT-прокси резервного маршрута Discord.
	DiscordProxy string `json:"discord_proxy,omitempty"`
	// DiscordProxyForce — Discord обязан идти через DiscordProxy: маршрут по
	// умолчанию занят сторонним VPN, прокси ведёт мимо него.
	DiscordProxyForce bool `json:"discord_proxy_force,omitempty"`
	// YouTubeProxy — отдельный loopback CONNECT/PAC-прокси автоматического резерва YouTube.
	YouTubeProxy string `json:"youtube_proxy,omitempty"`
	// Overrides — подгрупповые переопределения стратегий (cfg.Strategies) в
	// порядке применения. Пусто, если переопределений нет (поведение прежнее).
	Overrides []overrideInfo `json:"overrides,omitempty"`
	// IPList — число применяемых записей пользовательского списка IP (--ip-list).
	IPList int `json:"ip_list,omitempty"`
}

// overrideInfo — одно подгрупповое правило: имя группы и идентификатор её
// стратегии. Нужно владельцу для быстрой диагностики — видеть, какая
// стратегия привязана к какой группе, без разбора полей конфига.
type overrideInfo struct {
	Group      string `json:"group"`
	StrategyID string `json:"strategy_id"`
}

// buildInterceptProvider собирает провайдера стратегий для режима intercept.
//
// Если cfg.Strategies пуст и радиус равен groups, возвращает обычный
// GroupProvider (одна стратегия на выбранный радиус). Для all и при
// переопределениях собирает
// MultiGroupProvider: для каждой группы из cfg.Strategies, попавшей в
// выбранный радиус (--groups), создаёт матчер по её доменам и привязывает её
// стратегию; хосты вне любой подгруппы идут в fallback.
//
// Правила сортируются по имени группы — чтобы разные запуски давали один и
// тот же порядок, и чтобы владелец мог понять, какая выиграет при пересечении
// доменов (это не частый случай, но «первая по имени» — предсказуемо).
func buildInterceptProvider(cfg *config.Config, radius *config.DomainSet, groupNames []string, defStrategy *strategy.Strategy, logger *slog.Logger) (proxy.StrategyProvider, []overrideInfo, error) {
	// Поведение прежнее: без strategies работает одна общая стратегия.
	if len(cfg.Strategies) == 0 && cfg.Radius.Mode != config.RadiusAll {
		p, err := proxy.NewGroupProvider(defStrategy, radius)
		return p, nil, err
	}

	// Если --groups задан, честно уважаем выбор: применяем только те
	// переопределения, чьи группы попали в радиус. Про остальные тихо молчим
	// (владелец их исключил, и напоминать об этом каждым запуском шумно).
	allowed := map[string]bool{}
	if len(groupNames) == 0 {
		for name := range cfg.Groups {
			allowed[name] = true
		}
	} else {
		for _, name := range groupNames {
			allowed[name] = true
		}
	}

	// Детерминированный порядок — ключи cfg.Strategies отсортированы по имени.
	ordered := make([]string, 0, len(cfg.Strategies))
	for name := range cfg.Strategies {
		if !allowed[name] {
			continue
		}
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)

	rules := make([]proxy.GroupRule, 0, len(ordered))
	infos := make([]overrideInfo, 0, len(ordered))
	for _, name := range ordered {
		// Матчер подгруппы — DomainSet по этой одной группе. Безопасно
		// неподтверждённую опечатку мы бы отвергли на validate, поэтому
		// здесь ошибка маловероятна, но пропускать её нельзя (0.3).
		gs, err := cfg.DomainSet([]string{name})
		if err != nil {
			return nil, nil, fmt.Errorf("собираю правило группы %q: %w", name, err)
		}
		// Приоритет: если у группы есть ротация, передаём её, иначе
		// одиночную стратегию.
		rule := proxy.GroupRule{Name: name, Matcher: gs}
		if rotList := cfg.StrategiesRotation[name]; len(rotList) > 0 {
			rule.Strategies = rotList
			ids := make([]string, 0, len(rotList))
			for _, s := range rotList {
				ids = append(ids, s.ID.String())
			}
			infos = append(infos, overrideInfo{Group: name, StrategyID: ids[0]})
			logger.Info("стратегия по группе (ротация)",
				"группа", name, "стратегий", len(rotList), "ids", strings.Join(ids, ","))
		} else {
			s := cfg.Strategies[name]
			rule.Strategy = s
			infos = append(infos, overrideInfo{Group: name, StrategyID: s.ID.String()})
			logger.Info("стратегия по группе", "группа", name, "стратегия", s.ID.String())
		}
		rules = append(rules, rule)
	}

	var fallbackMatcher proxy.HostMatcher = radius
	if cfg.Radius.Mode == config.RadiusAll {
		fallbackMatcher = newAllRadiusMatcher(cfg.Radius.Exclude)
	}
	p, err := proxy.NewMultiGroupProvider(rules, defStrategy, fallbackMatcher)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Radius.Mode == config.RadiusAll {
		p.SetFallbackFailureBypass(true)
	}
	return p, infos, nil
}

type interceptOptions struct {
	ctx                                         context.Context
	cfg                                         *config.Config
	domainSet                                   *config.DomainSet
	groupNames                                  []string
	logger                                      *slog.Logger
	jsonOut, auto, search                       bool
	voice                                       voiceMode
	redirect                                    bool
	ytStartProfile, discordProfile              string
	youtubeProfile, telegramProfile, ipListPath string
	siteReserve                                 bool
}

// runIntercept запускает системный перехват этапа 1 через WinDivert.
//
// Собирает конвейер windivert → flow → policy → packetexec → intercept и сторож
// killswitch. На не-Windows windivert.Open возвращает ошибку (стаб), и команда
// честно откажет, а не притворится работающей.
//
// groupNames — выбранные группы радиуса (из --groups). Пусто значит «все
// группы конфига»; это тот же список, по которому собран domainSet. Нужен
// отдельно, чтобы при --groups отобрать те записи cfg.Strategies, которые
// попадают в выбранный радиус, а остальные тихо пропустить (ошибкой это не
// является: радиус выбирают, strategies — лишь способ разнести его).
func runIntercept(opts interceptOptions) error {
	ctx, cfg, domainSet, groupNames, logger := opts.ctx, opts.cfg, opts.domainSet, opts.groupNames, opts.logger
	jsonOut, auto, search, voice, redirect := opts.jsonOut, opts.auto, opts.search, opts.voice, opts.redirect
	ytStartProfile, discordProfile := opts.ytStartProfile, opts.discordProfile
	youtubeProfile, telegramProfile, ipListPath := opts.youtubeProfile, opts.telegramProfile, opts.ipListPath
	if !auto {
		domainSet, _ = prepareYouTubeAuto(cfg, domainSet, groupNames)
	}
	// Права администратора на этапе 1 обязательны: WinDivert при первом
	// обращении ставит драйвер. Проверяем заранее, чтобы отказать внятно, а не
	// падать внутри WinDivertOpen.
	if elev, checked := elevated(); checked && !elev {
		return errors.New("режим intercept требует прав администратора (драйвер WinDivert)")
	}

	// Защита от двух движков на одном фильтре (инвариант 1.1): acquire
	// mutex-файла state/engine.lock. Второй запуск с тем же фильтром отказывает
	// с ErrConflict и внятным сообщением. Разные фильтры (--auto кейс) — не
	// конфликт. Крах процесса оставит запись, но следующий запуск увидит, что
	// PID не жив, и выбросит её сам.
	lock, err := acquireEngineLock(interceptFilter)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	discordListen := ""
	if discordProfile != "" {
		dt, err := startDiscordTunnel(ctx, discordProfile, "", defaultDiscordTunnelListen, logger)
		if err != nil {
			logger.Error("резервный маршрут Discord недоступен; основной обход продолжает работать", "err", err)
		} else {
			discordListen = dt.Listen
			defer dt.Close()
			logger.Info("резервный маршрут Discord готов", "listen", discordListen)
		}
	}
	discordForce := false
	route := detectBypassRoute(logger)
	if clearStaleSitePAC(windowsPACSettings{}, defaultDiscordTunnelListen) {
		logger.Info("резерв сайтов: снят сценарий прокси, оставшийся от прошлого запуска")
	}
	startDiscordSelfCheck(ctx, route, logger)
	if route.Tunnel && discordListen == "" {
		dp, err := startDiscordDirectProxy(ctx, route, defaultDiscordTunnelListen, logger)
		if err != nil {
			logger.Error("прямой маршрут Discord мимо VPN недоступен", "err", err)
		} else {
			discordListen, discordForce = dp.Listen, true
			defer dp.Close()
			logger.Info("Discord идёт через VPN; прямой путь — резерв на случай отказа VPN", "listen", discordListen, "адаптер", route.Physical.Name)
		}
	}
	if !route.Tunnel && discordListen == "" {
		dp, err := startDiscordWatchProxy(ctx, defaultDiscordTunnelListen, opts.siteReserve, logger)
		if err != nil {
			logger.Warn("локальный прокси Discord не поднят, клиент идёт без него", "err", err)
		} else {
			discordListen, discordForce = dp.Listen, true
			defer dp.Close()
			logger.Info("Discord идёт через локальный прокси под обход: соединения без ответа обрываются для повтора", "listen", discordListen)
		}
	}
	if telegramProfile != "" {
		tt, err := startTelegramTunnel(ctx, telegramProfile, "", defaultTelegramTunnelListen)
		if err != nil {
			logger.Error("резервный маршрут Telegram недоступен; прямые WS-каналы продолжают работать", "err", err)
		} else {
			defer tt.Close()
			logger.Info("резервный маршрут Telegram готов", "listen", tt.Listen)
		}
	}

	// Автопилот v2 — отдельный путь сборки: подбор идёт на выделенных
	// соединениях песочницы (5.2), отбор ведёт контур управления.
	// Режим сканера голоса (voice.probe) тоже идёт через автопилот: Discord
	// должен работать (движок поднят), иначе голос даже не пытается соединиться
	// и сканировать нечего. Вместо десинка голоса там поднимается скан UDP.
	if auto || voice.probe {
		if redirect {
			logger.Warn("--rtc-redirect не поддержан вместе с --auto, проигнорирован")
		}
		return runInterceptAuto(ctx, cfg, domainSet, logger, jsonOut, search, voice, discordListen, discordForce, ipListPath)
	}
	if search {
		logger.Warn("--search действует только вместе с --auto, проигнорирован")
	}

	// Фиксированная стратегия из конфига; в наблюдении — ничего (1.6).
	strat := cfg.Strategy
	if cfg.Observe {
		strat = nil
	}

	// Собираем провайдера: если в конфиге нет strategies — обычный GroupProvider
	// как и раньше (одна стратегия на весь радиус). Если есть — MultiGroupProvider
	// с подгрупповыми правилами: первая группа по порядку, в которую попал
	// хост, определяет стратегию; остальные идут в fallback (общая Strategy
	// по всему радиусу).
	provider, overrideInfos, err := buildInterceptProvider(cfg, domainSet, groupNames, strat, logger)
	if err != nil {
		return err
	}
	var rotationProvider *proxy.MultiGroupProvider
	if multi, ok := provider.(proxy.MultiGroupProvider); ok && !cfg.Observe {
		rotationProvider = &multi
		rotationProvider.SetOnExhausted(func(group string) {
			logger.Warn("все стратегии группы сорвались", "группа", group)
		})
		rotationProvider.SetOnAdvance(func(group, sni string, from, to core.StrategyID) {
			logger.Info("ротация: смена стратегии после срыва", "группа", group, "sni", sni, "было", from, "стало", to)
		})
	}

	if rotationProvider != nil {
		report := newDiscordStallReport(provider, rotationProvider)
		discordStallReport.Store(&report)
		defer discordStallReport.Store(nil)
		adopt := func(from, to string) (core.StrategyID, bool) {
			id := rotationProvider.ActiveStrategies()[from]
			if id == "" || rotationProvider.ActiveStrategies()[to] == id {
				return id, false
			}
			return id, rotationProvider.SetActive(to, id)
		}
		discordAdoptStrategy.Store(&adopt)
		defer discordAdoptStrategy.Store(nil)
	}

	var youtube *youtubeMux
	if !cfg.Observe && domainSet.Matches("www.youtube.com", "www.youtube.com") && youtubetune.ValidateVideoGroup(cfg) == nil {
		youtube, err = newYouTubeMux(provider, domainSet)
		if err != nil {
			return err
		}
		provider = youtube
	}
	// Свой список IP (--ip-list): обход по адресу назначения для того, что не
	// входит в группы доменов. Битый список — отказ запуска с номером строки,
	// а не молчаливая работа без него.
	ipEntries := 0
	if ipListPath != "" {
		ips, err := iplist.Load(ipListPath)
		if err != nil {
			return fmt.Errorf("список IP %s: %w", ipListPath, err)
		}
		if n := ips.Len(); n > 0 && !cfg.Observe {
			ipEntries = n
			if provider, err = newIPListProvider(provider, ips); err != nil {
				return err
			}
			logger.Info("свой список IP подключён", "записей", ipEntries)
		}
	}
	// Диагностика: периодически печатаем топ SNI в пределах радиуса. Нужна,
	// когда что-то в радиусе не работает (например, голос Discord виснет), а
	// по счётчикам engine видно только количество ClientHello — не имена. Чужие
	// SNI (не в радиусе) в лог не попадают: только счётчик, без имён.
	sniTrack := newSNITracker(domainSet, logger)

	// Блокировка QUIC к радиусу (3.3): без неё фиксированная стратегия чинит
	// TCP, а приложение всё равно уходит в QUIC мимо обхода. Поднимаем до
	// движка: её трекер QUIC-only нужно повесить наблюдателем на движок.
	quicStop, quicTracker, quicOn, err := startQUICBlock(ctx, cfg, domainSet, defaultStateDir, logger)
	if err != nil {
		return err
	}
	defer quicStop()

	// Десинк голоса Discord по UDP (эксперимент, 1.6): отдельный дескриптор на
	// высокие UDP-порты, непересекающийся с QUIC и TCP. По умолчанию выключен.
	voiceStop, _, err := startVoiceDesync(ctx, voice, cfg.Observe, logger)
	if err != nil {
		return err
	}
	defer voiceStop()

	// Переклейка душимых RTC-портов (--rtc-redirect): при включении фильтр
	// расширяется входящими с живого порта, а источник оборачивается
	// декоратором, который уводит исходящие с душимых портов на живой ДО движка.
	// Движок при этом не меняется — ему достаётся обычный 8443.
	filter := interceptFilter
	if redirect {
		filter = interceptFilterRedirect
	}

	handle, err := windivert.Open(filter)
	if err != nil {
		return err
	}
	defer handle.Close()
	sendYouTube, closeYouTubeSender := openYouTubePacketSender(logger)
	defer closeYouTubeSender()

	var source capture.PacketSource = handle
	if redirect {
		red := rtcredirect.New(rtcRedirectFrom, rtcRedirectTarget)
		source = rtcredirect.NewSource(handle, red)
		logger.Info("переклейка RTC-портов включена",
			"с_портов", rtcRedirectFrom, "на_порт", rtcRedirectTarget)
	}

	// Journal событий и rtctrack — наблюдаемость и база для будущего автопилота v3.
	// Открываются по возможности; отказ — не фатал, журнал просто не ведётся
	// (инвариант «движок обязан работать без наблюдаемости»).
	eventsWriter, _ := openEventsWriter(logger)
	defer closeEventsWriter(eventsWriter, logger)
	rtcTracker, rtcSaver := openRTCTracker(logger)
	defer rtcSaver.Stop()
	blocklist := &rtcBlocklist{}
	observer := &liveObserver{events: eventsWriter, rtc: rtcTracker}
	// Автоматический обход дёргающихся голосовых серверов: ловит цикл
	// переподключений к одному `*.discord.media` и уводит Discord на другой
	// сервер, не давая крутиться минуту. Только голос — CDN/gateway не трогает.
	churn := newVoiceChurn(logger)

	engine, err := intercept.New(intercept.Options{
		IncludePacketMetadata: true,
		ShortHelloFallback:    true,
		Source:                source,
		Sink:                  handle,
		DesyncSink:            sendYouTube,
		Flows:                 flow.NewTable(flowCapacity, flowTTL, intercept.TLSHelloDetector),
		Provider:              provider,
		Exec:                  packetexec.New(),
		Parse:                 intercept.TLSHelloParser,
		Logger:                logger,
		OnStall:               reportSiteStall,
		// Трекер SNI, хук QUIC-only и детектор дёрганья голоса — все слушают
		// один поток ClientHello.
		OnClientHello: composeHooks(composeHooks(sniTrack.Observe, quicClientHelloHook(quicTracker)), churn.Observe),
		Observer:      observer,
		// Два источника блокировки: статистика rtctrack и живой детектор
		// дёрганья голоса. SNI обходится, если его помечает любой из них.
		Blocklist: anyBlocklist{blocklist, churn},
	})
	if err != nil {
		return err
	}
	if rotationProvider != nil {
		if evolver := newDiscordEvolver(*rotationProvider, (&net.Dialer{}).DialContext, logger); evolver != nil {
			evolver.restore()
			go evolver.run(ctx)
		}
		stopRotationPersistence := startRotationPersistence(*rotationProvider, logger)
		defer stopRotationPersistence()
		active := rotationProvider.ActiveStrategies()
		for i := range overrideInfos {
			if id, ok := active[overrideInfos[i].Group]; ok {
				overrideInfos[i].StrategyID = id.String()
			}
		}
	}
	stopInbound := startInboundObserver(ctx, engine, logger)
	defer stopInbound()

	youtubeListen := ""
	if youtube != nil {
		autoCtx, autoCancel := context.WithCancel(ctx)
		autoDone := make(chan struct{})
		monitor := newYouTubeRecovery(youtube, cfg, defaultStateDir)
		monitor.log = logger
		monitor.paused = engine.Transparent
		if youtubeProfile != "" {
			yt, err := startYouTubeTunnel(ctx, youtubeProfile, "", defaultYouTubeTunnelListen, defaultStateDir, true, false, logger)
			if err != nil {
				logger.Error("автоматический VLESS-резерв YouTube недоступен; прямой обход продолжает работать", "err", err)
			} else {
				youtubeListen = yt.Listen
				monitor.tunnelMeasure = func(ctx context.Context, short bool) []youtubeCheck {
					checks := yt.Measure(ctx, short)
					if !youtubeHealthy(checks) {
						logger.Warn("YouTube: VLESS-резерв не прошёл проверку сайта, превью и видеосети; переключение отменено", "checks", checks)
					}
					return checks
				}
				monitor.route = func(enabled bool) {
					yt.Router.SetTunnel(enabled)
					if enabled {
						logger.Warn("YouTube: прямой обход нестабилен, новые соединения идут через VLESS")
					} else {
						logger.Info("YouTube: прямой обход восстановлен, VLESS-резерв отключён")
					}
				}
				defer yt.Close()
				logger.Info("автоматический VLESS-резерв YouTube готов", "listen", youtubeListen)
			}
		}
		if youtubeProfile == "" && route.Tunnel {
			// Сторонний VPN: проверки и сам YouTube идут мимо туннеля, под
			// обход; VPN остаётся запасным путём.
			youtube.dial = netbind.Dialer(route.Physical.Index)
			youtube.deep = true
			yb, err := startYouTubeBypass(ctx, route, defaultYouTubeTunnelListen, defaultStateDir, logger)
			if err != nil {
				logger.Error("YouTube мимо VPN недоступен, он останется в VPN", "err", err)
			} else {
				youtubeListen = yb.Listen
				monitor.tunnelMeasure = func(ctx context.Context, short bool) []youtubeCheck {
					checks := yb.Measure(ctx, short)
					if !youtubeHealthy(checks) {
						logger.Warn("YouTube: путь через VPN не прошёл проверку сайта, превью и видеосети; переключение отменено", "checks", checks)
					}
					return checks
				}
				monitor.route = func(enabled bool) {
					yb.Router.SetTunnel(enabled)
					if enabled {
						logger.Warn("YouTube: прямой обход мимо VPN нестабилен, новые соединения идут через VPN")
					} else {
						logger.Info("YouTube: прямой обход восстановлен, новые соединения идут мимо VPN")
					}
				}
				defer yb.Close()
				logger.Info("YouTube идёт мимо VPN через физический адаптер, VPN — запасной путь", "listen", youtubeListen, "адаптер", route.Physical.Name)
			}
		}
		if monitor.startProfile(ytStartProfile) {
			logger.Info("YouTube: стартовый профиль задан флагом", "профиль", ytStartProfile)
		}
		go func() { defer close(autoDone); monitor.run(autoCtx) }()
		defer func() { autoCancel(); <-autoDone }()
	} else {
		writeYouTubeJSON(filepath.Join(defaultStateDir, "youtube-health.json"), youtubeHealth{PID: enginePID(), At: time.Now().UTC(), Phase: "disabled", Profile: "current"})
	}
	// killswitch: при потере связности с контрольными целями — прозрачный режим
	// (1.6). Без контрольных целей сторож не запускается: судить о связности не
	// по чему, а глушить перехват вслепую хуже, чем не глушить.
	if len(cfg.ControlTargets) > 0 {
		go engine.Guard(ctx, controlTargetsHealthy(cfg.ControlTargets), ksInterval, ksFailThreshold)
	} else {
		logger.Warn("контрольные цели не заданы: killswitch по связности отключён")
	}

	// Активная блокировка плохих RTC-SNI: раз в N секунд пересобирается
	// blocklist из rtctrack. SNI с явными провалами (SuccessRate < 500‰ при
	// ≥3 попытках) попадают в блок, движок перестаёт туда десинкать — DPI
	// увидит открытый SNI и RST'нёт, Discord моментально следующий сервер
	// (вместо TCP RTO backoff'а). Это и даёт быстрый фидбек по
	// «пилинк→тупит→перезаход».
	go startBlocklistRefresher(ctx, blocklist, rtcTracker, logger)

	// Остановка: по отмене контекста закрываем дескриптор, чтобы разблокировать
	// зависший на приёме Recv — иначе цикл ждал бы пакет вечно.
	go func() {
		<-ctx.Done()
		_ = handle.Close()
	}()

	info := interceptInfo{
		Mode:              "intercept",
		Filter:            filter,
		Observe:           cfg.Observe,
		Domains:           domainSet.Domains(),
		Auto:              false,
		QUICBlock:         quicOn && cfg.QUICMode == config.QUICBlock,
		QUICMode:          quicModeLabel(cfg.QUICMode, quicOn),
		StrategyApplies:   !domainSet.Empty() || (cfg.Radius.Mode == config.RadiusAll && strat != nil),
		DiscordProxy:      discordListen,
		DiscordProxyForce: discordForce,
		YouTubeProxy:      youtubeListen,
		Overrides:         overrideInfos,
		IPList:            ipEntries,
	}
	if s := cfg.Strategy; s != nil && !cfg.Observe {
		info.StrategyID = s.ID.String()
	} else if len(overrideInfos) == 0 {
		// Общей стратегии нет и переопределений нет — применять нечего.
		info.StrategyApplies = false
	}
	emitInterceptInfo(os.Stdout, info, jsonOut)

	// Serve блокирует до отмены контекста. Отмена — штатное завершение, а не
	// ошибка, поэтому её наверх не отдаём.
	if err := engine.Run(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func startInboundObserver(ctx context.Context, engine *intercept.Engine, logger *slog.Logger) func() {
	handle, err := windivert.Observe(inboundObserveFilter)
	if err != nil {
		logger.Warn("наблюдение входящих TCP недоступно; TTL останется резервным", "ошибка", err)
		return func() {}
	}

	observerCtx, cancel := context.WithCancel(ctx)
	var closeOnce sync.Once
	closeHandle := func() {
		closeOnce.Do(func() { _ = handle.Close() })
	}
	done := make(chan struct{})
	go func() {
		defer closeHandle()
		defer close(done)
		loopDone := make(chan struct{})
		watcherDone := make(chan struct{})
		go func() {
			defer close(watcherDone)
			select {
			case <-observerCtx.Done():
				closeHandle()
			case <-loopDone:
			}
		}()
		err := inbound.Run(observerCtx, handle, hops.Default, engine.OnInboundRST)
		close(loopDone)
		<-watcherDone
		if err != nil {
			logger.Warn("наблюдение входящих TCP остановлено", "ошибка", err)
		}
	}()
	return func() {
		cancel()
		closeHandle()
		<-done
	}
}

// interceptReplan — период пересчёта снимка контуром в режиме перехвата.
//
// Короче минуты проводного пути: песочница поставляет наблюдения часто, и
// реакция на них не должна ждать целую минуту. Выдержку смены (MinDwell) это не
// трогает — она своя и живёт в конфиге автопилота.
const interceptReplan = 30 * time.Second

// runInterceptAuto собирает автопилот v2: продуктовый контур перехвата плюс
// песочница на выделенных портах. Отбор ведёт control по исходам песочницы,
// применяет policy к продуктовому трафику. Так подбор идёт фоновым A/B, не
// трогая пользовательские соединения (5.2) — то, чего не умел автопилот v1.
//
// Это единственная часть этапа 1 с реальным живым прогоном: два дескриптора
// WinDivert и их взаимодействие в бою проверяются только на машине владельца.
// На не-Windows windivert.Open возвращает ошибку (стаб), и команда честно
// откажет.
func runInterceptAuto(ctx context.Context, cfg *config.Config, domainSet *config.DomainSet, logger *slog.Logger, jsonOut, search bool, voice voiceMode, discordListen string, discordForce bool, ipListPath string) error {
	if len(cfg.ProbeTargets) == 0 {
		return fmt.Errorf("для --auto нужны probe_targets в конфиге: на них песочница подбирает стратегию")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		return fmt.Errorf("--auto мерит внешним curl, но он не найден в PATH: %w", err)
	}
	cands, err := starterCandidates()
	if err != nil {
		return err
	}

	// --auto держит два дескриптора WinDivert на непересекающихся фильтрах.
	// Используем составной фильтр как ID замка, чтобы два --auto параллельно
	// отказывали, а один --auto + ручной --mode intercept на другом фильтре
	// (вдруг) не блокировали друг друга.
	lock, err := acquireEngineLock("auto:" + interceptFilter)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	// Журнал наблюдений: до этой правки путь --auto его не открывал, и исходы
	// проб песочницы жили только в памяти — поэтому каждый перезапуск --auto
	// обнулял прогресс (владелец на этом терял найденную стратегию). Теперь
	// пробы песочницы пишутся в журнал (ниже), а старт их оттуда восстанавливает
	// тёплым стартом.
	arch, err := openArchive(ctx, cfg, defaultStateDir, logger)
	if err != nil {
		return err
	}
	defer func() {
		if err := arch.close(); err != nil {
			logger.Error("журнал наблюдений закрыт с ошибкой", "ошибка", err)
		}
	}()

	// Точка наблюдения: метка из конфига плюс отпечаток интерфейсов (6.2).
	// Ошибка перечисления интерфейсов не повод не работать — метка остаётся.
	van, err := vantage.Detect(cfg.Vantage, vantage.SystemInterfaces())
	if err != nil {
		logger.Warn("точка наблюдения определена частично", "ошибка", err)
	}

	// Тёплый старт: восстановить оценки из журнала прошлых запусков, чтобы
	// подбор продолжился, а не начался заново. Окно — срок доверия к оценкам
	// (5.9): устаревшее не воскрешаем.
	warmup := arch.warmup(ctx, van.ID, cfg.Autopilot.EstimatesStaleAfter, logger)

	// Горячая таблица продуктового пути: в неё контур публикует снимок, из неё
	// продуктовый движок выбирает стратегию по SNI/радиусу.
	hot := policy.NewTable()
	var productProvider proxy.StrategyProvider = hot
	ipListEntries := 0
	if ipListPath != "" {
		ips, err := iplist.Load(ipListPath)
		if err != nil {
			return fmt.Errorf("список IP %s: %w", ipListPath, err)
		}
		if n := ips.Len(); n > 0 && !cfg.Observe {
			ipListEntries = n
			productProvider, err = newIPListProvider(productProvider, ips)
			if err != nil {
				return err
			}
			logger.Info("свой список IP подключён", "записей", ipListEntries)
		}
	}

	// Портфель — стартовые кандидаты как candidate. Действующей стратегии нет:
	// на старте обвал (прозрачный пропуск, тревога), пока песочница не наберёт
	// доказательств и бандит не поднимет кандидата по лестнице candidate →
	// testing → active (5.1, 5.8). Это и есть разница с v1: кандидат получает
	// первые доказательства на выделенных соединениях, а не на трафике
	// пользователя.
	portfolio := control.Portfolio{}
	for _, c := range cands {
		portfolio[c.Strategy.ID] = control.Holding{Strategy: c.Strategy, Status: core.StatusCandidate}
	}

	// Покрытие по группам: не всякий домен радиуса зондируется (googlevideo.com
	// по своему имени не разрешается). Контур решает по представителю группы,
	// которого есть чем прозондировать, а снимок разворачивает решение на все
	// домены группы. Без этого недообследованные домены (ytimg.com,
	// googlevideo.com) оставались бы голыми, и у ютуба грузился бы только текст.
	reps, coverage := sandboxCoverage(cfg.Groups, domainSet.Domains(), cfg.ProbeTargets)
	if len(reps) == 0 {
		return fmt.Errorf("ни одна группа радиуса не покрыта probe_targets: подбирать не на чем")
	}

	engine, err := control.New(control.Options{
		Vantage:    van.ID,
		Targets:    reps,
		Coverage:   coverage,
		Portfolio:  portfolio,
		Warmup:     warmup,
		Control:    cfg.Autopilot.Control(),
		Scoring:    cfg.Autopilot.Scoring(),
		Table:      hot,
		Interval:   interceptReplan,
		Logger:     logger,
		StatusPath: filepath.Join(defaultStateDir, statusFileName),
	})
	if err != nil {
		return err
	}
	// Контур — в своей горутине. Ждём первый снимок прежде, чем продуктовый
	// движок встанет на перехват: иначе первые соединения прошли бы без
	// стратегии по гонке, а не по решению.
	ctlCtx, ctlCancel := context.WithCancel(ctx)
	ctlDone := make(chan struct{})
	go func() { defer close(ctlDone); _ = engine.Run(ctlCtx) }()
	defer func() { ctlCancel(); <-ctlDone }()
	if err := engine.Ready(ctlCtx); err != nil {
		return fmt.Errorf("контур управления не успел опубликовать первый снимок: %w", err)
	}

	// Песочница в режиме оценки по требованию: что мерить, решает контур через
	// ProbeItems, а не фиксированный список. Так песочница сама подхватывает
	// любого кандидата, которого контур добавил в портфель (в том числе находки
	// генератора), не перечисляя их здесь, и не гоняет лишнего при растущем
	// портфеле (5.8). Исходы кормятся контуру напрямую (ниже), поэтому ни
	// портфель, ни приёмник песочнице не нужны.
	sbCfg := sandbox.DefaultConfig()
	sb, err := sandbox.New(sandbox.Options{
		Config:  sbCfg,
		Targets: cfg.ProbeTargets,
		Prober:  curlProber{timeout: sandboxProbeTimeout},
		Logger:  logger,
	})
	if err != nil {
		return err
	}

	// Перевод «цель радиуса → имя для пробы»: контур называет цель радиуса
	// (youtube.com), а ходить надо разрешимым именем (www.youtube.com).
	targetHosts := make(map[string]string, len(reps))
	for _, host := range cfg.ProbeTargets {
		for _, rep := range reps {
			if matchHost(host, rep) {
				targetHosts[rep] = host
				break
			}
		}
	}

	// Два дескриптора WinDivert по непересекающимся предикатам порта (5.2):
	// продуктовый — порт вне диапазона песочницы, песочный — внутри. Ни один
	// пакет не матчит оба, поэтому десинк не накладывается дважды.
	prodPred, sandPred := sbCfg.PortPredicates()
	prodFilter := interceptFilter + " and " + prodPred
	sandFilter := interceptFilter + " and " + sandPred

	hProd, err := windivert.Open(prodFilter)
	if err != nil {
		return err
	}
	defer hProd.Close()
	hSand, err := windivert.Open(sandFilter)
	if err != nil {
		_ = hProd.Close()
		return err
	}
	defer hSand.Close()
	sendYouTube, closeYouTubeSender := openYouTubePacketSender(logger)
	defer closeYouTubeSender()

	// Раздельные таблицы потоков (5.2): кандидат из песочницы не попадает в
	// продуктовую. Это падает из конструкции — у каждого движка своя таблица.
	// Блокировка QUIC к радиусу (3.3): иначе подобранная для TCP стратегия не
	// помогает — приложение уходит в QUIC мимо обхода, и цель «не лечится».
	// Отдельный дескриптор UDP/443, свой цикл; на связность продуктового пути
	// не влияет (роняет только QUIC радиуса). Поднимаем до продуктового движка:
	// её трекер QUIC-only вешается на движок наблюдателем TCP-откатов.
	quicStop, quicTracker, quicOn, err := startQUICBlock(ctx, cfg, domainSet, defaultStateDir, logger)
	if err != nil {
		return err
	}
	defer quicStop()

	// Либо десинк голоса, либо (в режиме диагностики) сканер UDP. Сканер идёт по
	// портам кроме 443 — там свой дескриптор QUIC, и два на одних пакетах
	// конфликтовали бы; 74-байтные пакеты на 443 считает сама петля QUIC.
	if voice.probe {
		scanStop, err := startUDPScan(ctx, udpScanFilterNo443, logger)
		if err != nil {
			return err
		}
		defer scanStop()
	} else {
		voiceStop, _, err := startVoiceDesync(ctx, voice, cfg.Observe, logger)
		if err != nil {
			return err
		}
		defer voiceStop()
	}

	// Диагностика SNI радиуса — та же, что в пути без автопилота. Подключаем
	// после создания контура, через композицию с хуком QUIC-трекера.
	sniTrack := newSNITracker(domainSet, logger)

	// Journal событий и rtctrack — та же логика, что в простом runIntercept:
	// открываются по возможности, вешаются только на продуктовый движок.
	eventsWriter, _ := openEventsWriter(logger)
	defer closeEventsWriter(eventsWriter, logger)
	rtcTracker, rtcSaver := openRTCTracker(logger)
	defer rtcSaver.Stop()
	blocklist := &rtcBlocklist{}
	liveObs := &liveObserver{events: eventsWriter, rtc: rtcTracker}
	// Та же активная блокировка плохих RTC-SNI.
	go startBlocklistRefresher(ctx, blocklist, rtcTracker, logger)

	prodEngine, err := intercept.New(intercept.Options{
		Source:        hProd,
		Sink:          hProd,
		DesyncSink:    sendYouTube,
		Flows:         flow.NewTable(flowCapacity, flowTTL, intercept.TLSHelloDetector),
		Provider:      productProvider,
		Exec:          packetexec.New(),
		Parse:         intercept.TLSHelloParser,
		Logger:        logger,
		OnStall:       reportSiteStall,
		OnClientHello: composeHooks(sniTrack.Observe, quicClientHelloHook(quicTracker)),
		// Пассивный сигнал срыва (5.10): повтор ClientHello на живом трафике —
		// бесплатный признак, что стратегия на этой цели загибается. Вешается
		// только на продуктовый движок: трафик песочницы синтетический.
		OnPassive: passiveObserver(engine, arch.writer, van.ID, logger),
		Observer:  liveObs,
		Blocklist: blocklist,
	})
	if err != nil {
		return err
	}
	sandEngine, err := intercept.New(intercept.Options{
		Source:     hSand,
		Sink:       hSand,
		DesyncSink: sendYouTube,
		Flows:      flow.NewTable(flowCapacity, flowTTL, intercept.TLSHelloDetector),
		Provider:   sb.Provider(),
		Exec:       packetexec.New(),
		Parse:      intercept.TLSHelloParser,
		Logger:     logger,
	})
	if err != nil {
		return err
	}

	// killswitch — только на продуктовом пути: песочница на связность
	// пользователя не влияет, а её сбой не должен глушить продуктив (5.2).
	if len(cfg.ControlTargets) > 0 {
		go prodEngine.Guard(ctx, controlTargetsHealthy(cfg.ControlTargets), ksInterval, ksFailThreshold)
	} else {
		logger.Warn("контрольные цели не заданы: killswitch по связности отключён")
	}

	// Остановка: по отмене закрываем оба дескриптора — разблокирует Recv в
	// обоих циклах.
	go func() {
		<-ctx.Done()
		_ = hProd.Close()
		_ = hSand.Close()
	}()

	// Фоновые горутины —  через safego.Group: панику гасим, перехват переводим
	// в прозрачный режим, продолжаем жить. На выходе — Wait, чтобы main не
	// возвращал управление до остановки всех фоновых работ (инвариант 1.3).
	bg := safego.NewGroup(logger, func(name string, _ any, _ []byte) {
		// Любая фоновая паника = движок не доверяет своему состоянию: оба
		// пути переводим в прозрачный, чтобы не десинкать на кусках.
		prodEngine.SetTransparent(true)
		sandEngine.SetTransparent(true)
		logger.Error("фоновая горутина упала с паникой — поднят прозрачный режим обоих контуров",
			"горутина", name)
	})
	defer bg.Wait()

	// Песочный цикл перехвата и оркестратор проб — в своих горутинах. Их сбой
	// не трогает продуктовый цикл (5.2).
	bg.Go("sandbox-engine", func() { _ = sandEngine.Run(ctx) })
	bg.Go("sandbox-probes", func() { runSandboxProbes(ctx, engine, sb, targetHosts, arch.writer, van.ID, logger) })

	// Фоновый генератор (5.6): по --search ищет новые стратегии в той же
	// песочнице и пополняет портфель кандидатами. Засев — стартовый портфель.
	// Находки проходят ту же лестницу (контур добудет им доказательства через
	// ProbeItems и повысит только по порогу 5.5), к трафику напрямую они не
	// прикасаются (1.4 п. 6).
	if search {
		known := make([]*strategy.Strategy, 0, len(cands))
		for _, c := range cands {
			known = append(known, c.Strategy)
		}
		// Версия IP IPv4: на нём идёт основной трафик, и это не плодит мёртвых
		// IPv6-правок (как у search по умолчанию). Генератор не заводит своих
		// проб — читает оценки этого же контура и отдаёт потомков в портфель.
		bg.Go("background-search", func() {
			runBackgroundSearch(ctx, engine, packetexec.New().Capabilities(), known, 4, logger)
		})
	}

	info := interceptInfo{
		Mode:              "intercept",
		Filter:            prodFilter,
		Observe:           cfg.Observe,
		Domains:           domainSet.Domains(),
		Auto:              true,
		QUICBlock:         quicOn && cfg.QUICMode == config.QUICBlock,
		QUICMode:          quicModeLabel(cfg.QUICMode, quicOn),
		StrategyApplies:   !domainSet.Empty(),
		IPList:            ipListEntries,
		DiscordProxy:      discordListen,
		DiscordProxyForce: discordForce,
	}
	emitInterceptInfo(os.Stdout, info, jsonOut)

	// Продуктовый цикл блокирует до отмены контекста. Отмена — штатное
	// завершение, а не ошибка.
	if err := prodEngine.Run(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// sandboxCoverage распределяет радиус по группам и выбирает представителя
// каждой группы — домен, которому соответствует какой-либо probe_target.
//
// Возвращает список представителей (цели контура) и карту «представитель →
// домены его группы в радиусе» (покрытие для разворота решений). Группа без
// probe_target пропускается: её домены прозондировать нечем, подбирать на них
// не на чем, и притворяться, что они покрыты, нельзя (их обход просто не
// работает, и это честнее, чем молча отдать им чужую непроверенную стратегию).
func sandboxCoverage(groups map[string][]string, radius, probeTargets []string) (reps []string, coverage map[string][]string) {
	inRadius := make(map[string]bool, len(radius))
	for _, d := range radius {
		inRadius[d] = true
	}
	coverage = map[string][]string{}
	for _, group := range groups {
		domains := make([]string, 0, len(group))
		for _, d := range group {
			if inRadius[d] {
				domains = append(domains, d)
			}
		}
		if len(domains) == 0 {
			continue
		}
		// Представитель — домен группы, в который попадает какой-то probe_target.
		rep := ""
		for _, pt := range probeTargets {
			for _, d := range domains {
				if matchHost(pt, d) {
					rep = d
					break
				}
			}
			if rep != "" {
				break
			}
		}
		if rep == "" {
			continue
		}
		coverage[rep] = domains
		reps = append(reps, rep)
	}
	return reps, coverage
}

// Параметры оркестратора проб песочницы. В конфиг не вынесены: второго
// потребителя нет, значения консервативны.
const (
	// sandboxProbesPerItem — сколько проб на пару «цель × стратегия» за круг.
	// Мало: порог 5.5 набирается за несколько кругов, а каждая проба — живое
	// соединение.
	sandboxProbesPerItem = 2
	// sandboxRoundPause — пауза между кругами проб. Короткая: это выделенные
	// соединения, трафик пользователя они не трогают, и прогрев должен идти
	// быстро. Известный компромисс — чаще интервала 5.7 (12 мин); при сильно
	// разросшемся портфеле стоит удлинить.
	sandboxRoundPause = 5 * time.Second
)

// runSandboxProbes ведёт пробы песочницы по заданию контура (ProbeItems), а не
// по фиксированному списку. Так песочница меряет ровно те пары, которым нужны
// доказательства, и сама подхватывает новых кандидатов портфеля (в том числе
// находки генератора). Исходы кормятся контуру напрямую.
//
// Это пакетный аналог probePlanner проб прокси: контур знает, кого проверять,
// песочница умеет ходить, сшивает их здесь — ни контур, ни sandbox друг о друге
// не знают (4.7 п. 4).
func runSandboxProbes(ctx context.Context, engine *control.Engine, sb *sandbox.Sandbox, targetHosts map[string]string, archive archiveSink, vantage core.VantageID, logger *slog.Logger) {
	for {
		if ctx.Err() != nil {
			return
		}
		items, err := engine.ProbeItems(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Warn("не удалось получить задание проб", "ошибка", err)
			if !sleepCtx(ctx, sandboxRoundPause) {
				return
			}
			continue
		}
		for _, it := range items {
			if ctx.Err() != nil {
				return
			}
			host := targetHosts[it.Target]
			if host == "" {
				// Имени для пробы нет — ходим к самой цели радиуса (хуже: может
				// не отвечать по своему имени, но это честнее, чем молчать).
				host = it.Target
			}
			su, to := sb.Evaluate(ctx, it.Strategy, host, sandboxProbesPerItem)
			if to == 0 {
				continue
			}
			// Каждую пробу отдаём контуру отдельным наблюдением: порог 5.5
			// считается в наблюдениях, и дробить исход на отдельные исходы
			// правильнее, чем усреднять.
			now := time.Now()
			for i := 0; i < to; i++ {
				outcome := core.OutcomeFail
				if i < su {
					outcome = core.OutcomeOK
				}
				engine.Observe(control.Observation{
					StrategyID: it.StrategyID,
					Baseline:   it.Baseline,
					Target:     it.Target,
					Outcome:    outcome,
					Source:     store.SourceProbe,
					At:         now,
				})

				// То же наблюдение — в журнал, чтобы перезапуск --auto не
				// обнулял прогресс (тёплый старт читает его обратно). Пустой
				// StrategyID у базовой линии журнал принимает как базовую линию
				// цели. Причина исхода не детализируется: curl-проба даёт только
				// код, и честнее оставить причину пустой, чем выдумать «reset».
				if archive == nil {
					continue
				}
				archive.Enqueue(store.Observation{
					At:              now,
					StrategyID:      it.StrategyID,
					Target:          it.Target,
					VantageID:       vantage,
					Phase:           core.PhaseFast,
					Outcome:         outcome,
					Source:          store.SourceProbe,
					StrategyApplied: !it.Baseline,
				})
			}
		}
		if !sleepCtx(ctx, sandboxRoundPause) {
			return
		}
	}
}

// passiveObserver сшивает пассивный сигнал перехвата с контуром и журналом
// (5.10). Повтор ClientHello на живом трафике означает, что первая попытка
// осталась без ответа, — стратегия на этой цели загибается. Кормим контур
// наблюдением с источником SourcePassive: его вес ниже активного (0.3), условия
// не контролируются, и серию провалов пассив намеренно не ведёт (это в scoring)
// — вывод делается по накоплению, а не по единичному событию.
//
// Ни контур, ни intercept друг о друге не знают: перевод — работа команды, тот
// же приём, что с исходами проб и соединений (4.7 п. 4).
func passiveObserver(engine *control.Engine, archive archiveSink, vantage core.VantageID, log *slog.Logger) func(intercept.PassiveEvent) {
	return func(ev intercept.PassiveEvent) {
		now := time.Now()
		engine.Observe(control.Observation{
			StrategyID: ev.StrategyID,
			Target:     ev.Target,
			Outcome:    core.OutcomeFail,
			Source:     store.SourcePassive,
			At:         now,
		})
		if archive != nil {
			archive.Enqueue(store.Observation{
				At:         now,
				StrategyID: ev.StrategyID,
				Target:     ev.Target,
				VantageID:  vantage,
				Phase:      core.PhaseFast,
				Outcome:    core.OutcomeFail,
				// Повтор = первая попытка без ответа: ближе всего таймаут.
				Reason:          core.ReasonTimeout,
				Source:          store.SourcePassive,
				StrategyApplied: true,
			})
		}
		log.Debug("пассивный сигнал: повтор ClientHello (срыв)",
			"sni", ev.SNI, "цель", ev.Target, "стратегия", ev.StrategyID.String())
	}
}

// sleepCtx ждёт d или отмену; false — контекст отменён.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// controlTargetsHealthy строит проверку связности для killswitch: достижима ли
// хотя бы одна контрольная цель. Переиспользует замер связности doctor
// (measureReach), чтобы правило «что считать живым» было одним на весь движок.
func controlTargetsHealthy(targets []string) intercept.HealthCheck {
	return func(ctx context.Context) bool {
		var d net.Dialer
		return checkControlTargets(ctx, d.DialContext, targets)
	}
}

func checkControlTargets(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), targets []string) bool {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan bool, len(targets))
	for _, target := range targets {
		go func() {
			results <- measureReach(ctx, dial, []string{target}, controlReachTimeout)[0].Reachable
		}()
	}
	for range targets {
		select {
		case <-ctx.Done():
			return false
		case reachable := <-results:
			if reachable {
				return ctx.Err() == nil
			}
		}
	}
	return false
}

// emitInterceptInfo печатает описание запуска перехвата.
func emitInterceptInfo(w *os.File, info interceptInfo, jsonOut bool) {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)
		return
	}
	fmt.Fprintf(w, "режим: %s\n", info.Mode)
	fmt.Fprintf(w, "фильтр: %s\n", info.Filter)
	fmt.Fprintf(w, "наблюдение: %t\n", info.Observe)
	if len(info.Domains) > 0 {
		fmt.Fprintf(w, "радиус: %s\n", strings.Join(info.Domains, ", "))
	} else {
		fmt.Fprintln(w, "радиус: пуст")
	}
	switch info.QUICMode {
	case "desync":
		fmt.Fprintln(w, "QUIC: десинк к радиусу (обход без блокировки)")
	case "block":
		fmt.Fprintln(w, "QUIC: блокируется к радиусу (откат на TCP)")
	default:
		fmt.Fprintln(w, "QUIC: не трогается")
	}
	switch {
	case info.Auto:
		fmt.Fprintln(w, "стратегия: авто-подбор из портфеля")
	case info.StrategyID == "" && len(info.Overrides) == 0 && info.IPList > 0:
		fmt.Fprintln(w, "стратегия: только свой список IP")
	case info.StrategyID == "" && len(info.Overrides) == 0:
		fmt.Fprintln(w, "стратегия: нет (прозрачный перехват)")
	case !info.StrategyApplies:
		fmt.Fprintf(w, "стратегия: %s — НЕ применяется (радиус пуст)\n", info.StrategyID)
	case info.StrategyID == "":
		fmt.Fprintln(w, "стратегия: только переопределения по группам (общая не задана)")
	default:
		fmt.Fprintf(w, "стратегия (запасная для всего радиуса): %s\n", info.StrategyID)
	}
	for _, o := range info.Overrides {
		fmt.Fprintf(w, "  группа %s → %s\n", o.Group, o.StrategyID)
	}
	if info.IPList > 0 {
		fmt.Fprintf(w, "свой список IP: %d записей — обход по адресу назначения\n", info.IPList)
	}
}
