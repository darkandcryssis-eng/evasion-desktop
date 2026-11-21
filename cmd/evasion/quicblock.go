package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/quic"
	"github.com/fitting-1c/evasion/internal/quicwatch"
	"github.com/fitting-1c/evasion/internal/windivert"
	"github.com/fitting-1c/evasion/internal/youtubetune"
)

// quicFileName — имя файла накопленного признака QUIC-only внутри каталога
// состояния. Отдельный от status.json: его пишет слой перехвата, а не control,
// который обязан не знать про QUIC (этап 1) и не меняться между этапами.
const quicFileName = "quic.json"

// quicWatchInterval — как часто снимок QUIC-only выкладывается в файл. Реже
// файла состояния: признак накапливается медленно, и doctor читает его разово.
const quicWatchInterval = 10 * time.Second

// quicFilter — фильтр WinDivert для блокировки QUIC: исходящий UDP к порту 443.
// Покрывает IPv4 и IPv6. "not impostor" не нужен: блокировка только роняет
// пакеты, своих инъекций не делает, по кругу идти нечему.
const quicFilter = "outbound and udp and udp.DstPort == 443"

// startQUICBlock поднимает блокировку QUIC к отслеживаемым группам (3.3).
//
// QUIC идёт по UDP, и TCP-десинк на него не влияет: без блокировки цель вроде
// YouTube уходит в QUIC мимо обхода и «не лечится». Блокировка роняет QUIC
// ТОЛЬКО к доменам радиуса — приложение откатывается на TCP, где десинк
// работает. Весь прочий UDP/443 (другие сайты) идёт нетронутым.
//
// Включается осознанно и обратимо (1.6): по умолчанию on, но отключается
// block_quic: false; в наблюдении (Observe) и при пустом радиусе не
// запускается вовсе; при остановке дескриптор закрывается, и блокировка
// снимается полностью — остаточных правил не остаётся. На не-Windows
// windivert.Open вернёт ошибку (стаб), и вызывающий честно откажет.
//
// Возвращает функцию остановки (закрывает дескриптор, ждёт завершения циклов),
// трекер QUIC-only (nil, когда блокировка не запущена), признак активности и
// ошибку. Трекер нужен вызывающему, чтобы повесить наблюдатель TCP ClientHello
// на продуктовый движок перехвата (он питает признак отката).
func startQUICBlock(ctx context.Context, cfg *config.Config, domainSet *config.DomainSet, stateDir string, logger *slog.Logger) (stop func(), tracker *quicwatch.Tracker, active bool, err error) {
	if (cfg.QUICMode == config.QUICOff && (cfg.YouTubeQUICMode == nil || *cfg.YouTubeQUICMode == config.QUICOff)) || cfg.Observe || domainSet.Empty() {
		return func() {}, nil, false, nil
	}
	handle, err := windivert.Open(quicFilter)
	if err != nil {
		return nil, nil, false, err
	}

	// Сборщик межпакетного ClientHello (общий на цикл): современный Chrome
	// бьёт постквантовый ClientHello на несколько Initial, и без склейки по
	// DCID его SNI не достать.
	reasm := quic.NewReassembler()

	// Трекер QUIC-only (3.3) имеет смысл только в режиме block: по нему doctor
	// судит, откатилось ли приложение на TCP ПОСЛЕ сброса. В desync мы не
	// роняем, отката ждать не от чего — трекер не заводим и файл не пишем.
	var watchDone chan struct{}
	if cfg.QUICMode == config.QUICBlock {
		tracker = quicwatch.NewTracker()
		watchDone = make(chan struct{})
		go func() {
			defer close(watchDone)
			tracker.Run(ctx, filepath.Join(stateDir, quicFileName), quicWatchInterval, nil)
		}()
	}

	blockDone := make(chan struct{})
	go func() {
		defer close(blockDone)
		if cfg.YouTubeQUICMode != nil {
			runQUICBlock(ctx, handle, domainSet, cfg.QUICMode, reasm, tracker, logger, *cfg.YouTubeQUICMode)
		} else {
			runQUICBlock(ctx, handle, domainSet, cfg.QUICMode, reasm, tracker, logger)
		}
	}()
	stop = func() {
		_ = handle.Close() // разблокирует зависший на приёме Recv
		<-blockDone
		if watchDone != nil {
			<-watchDone // дождёмся финального снимка QUIC-only
		}
	}
	return stop, tracker, true, nil
}

// quicClientHelloHook строит наблюдатель TCP ClientHello для движка перехвата:
// он кормит трекер QUIC-only признаком того, что приложение работает по TCP.
//
// Возвращает nil, если трекера нет (блокировка QUIC выключена): движок тогда
// наблюдателя не зовёт вовсе, лишней работы на каждом ClientHello не возникает.
func quicClientHelloHook(tracker *quicwatch.Tracker) func(sni string) {
	if tracker == nil {
		return nil
	}
	return func(sni string) { tracker.SawTCPHello(sni, time.Now()) }
}

// quicModeLabel — токен режима QUIC для вывода запуска. Неактивный контур
// (наблюдение, пустой радиус, режим off) показываем как off: QUIC не трогаем.
func quicModeLabel(mode config.QUICMode, active bool) string {
	if !active {
		return "off"
	}
	return string(mode)
}

// quicConn — то, что нужно циклу блокировки от дескриптора: приём и
// повторная инъекция. Сужено до пары методов, чтобы цикл не зависел от
// windivert целиком.
type quicConn interface {
	Recv() (capture.Packet, error)
	Send(capture.Packet) error
}

// quicReportEvery — как часто сводка о блокировке QUIC пишется в журнал.
//
// Поштучно писать нельзя: активная вкладка YouTube шлёт десятки QUIC-проб в
// секунду, и журнал бы залило (тот же довод, что у «стратегия применена» —
// Debug). Но и молчать неверно: владелец должен видеть, что блокировка
// действительно срабатывает на живом трафике (7.x). Поэтому первый сброс
// пишется сразу (быстрое подтверждение), дальше — сводкой не чаще этого срока.
const quicReportEvery = 30 * time.Second

// runQUICBlock ведёт цикл блокировки до закрытия дескриптора или отмены.
//
// Пакет к отслеживаемой группе роняется (не реинъектируется), прочий QUIC
// пропускается как есть. Нераспознанный QUIC тоже пропускается: переблокировать
// вслепую опаснее пропуска (1.6).
func runQUICBlock(ctx context.Context, conn quicConn, domainSet *config.DomainSet, mode config.QUICMode, reasm *quic.Reassembler, tracker *quicwatch.Tracker, logger *slog.Logger, youtubeMode ...config.QUICMode) {
	var acted int                         // сброшено (block) либо переписано (desync)
	var dgrams, radiusN int               // диагностика desync: датаграмм UDP/443 и из них к радиусу
	var shaped74Loose, shaped74Strict int // форма Discord IP discovery на udp:443: мягко (len==74) и строго (IsIPDiscoveryRequest)
	var strictEndpoints []string          // первые N dstIP:port строгих — глазами видно, идёт ли к серверу Discord
	var lastReport time.Time
	flows := newQUICFlows(logger)
	for {
		pkt, err := conn.Recv()
		if err != nil {
			// Закрытие дескриптора (остановка) или ошибка приёма — выходим.

			if mode == config.QUICDesync {
				// Нули здесь — ответ: датаграмм_udp443=0 значит QUIC к :443 не
				// шёл вовсе (браузер в QUIC-broken backoff или не пробует QUIC);
				// с_именем>0, переписано=0 — радиусный Initial виден, но
				// переписать не вышло.
				logger.Info("QUIC-десинк остановлен",
					"переписано", acted, "датаграмм_udp443", dgrams, "радиусных", radiusN)
			} else {
				// Финальную сводку печатаем всегда: по ней видно, шёл ли вообще
				// распознаваемый QUIC. Нули здесь — это ответ (например, браузер
				// в QUIC-broken backoff не слал Initial), а не отсутствие данных.
				s := reasm.Snapshot()
				logger.Info("QUIC-блокировка остановлена",
					"сброшено", acted, "датаграмм_udp443", s.Datagrams,
					"initial", s.Initials, "собран_sni", s.Resolved,
					"ещё_собирается", s.Pending, "не_разобрать", s.Failed,
					"74байт_форма", shaped74Loose,
					"74байт_discovery", shaped74Strict,
					"куда_строгие", strings.Join(strictEndpoints, " "))
			}
			return
		}

		// Форма Discord IP discovery на udp:443. Два счётчика намеренно: мягкий
		// по длине (len==74) ловит и шум (QUIC retry, короткие фреймы), строгий
		// по IsIPDiscoveryRequest отвечает на вопрос «это начало голоса».
		// Решение «переключить фильтр на 443» принимается по строгому.
		if d, e := packet.Dissect(pkt.Data); e == nil {
			c := tallyUDPShaped(pkt.Data, d)
			if c.loose {
				shaped74Loose++
			}
			if c.strict {
				shaped74Strict++
				strictEndpoints = appendStrictEndpoint(strictEndpoints, c.endpoint)
			}
		}

		packetMode := mode
		var selectedSNI string
		var selectedScope bool
		if len(youtubeMode) > 0 {
			selectedSNI, selectedScope = flows.shouldBlock(pkt, domainSet, reasm, time.Now())
			if selectedScope && youtubetune.IsYouTube(selectedSNI) {
				packetMode = youtubeMode[0]
			}
		}
		if packetMode == config.QUICOff {
			if err := conn.Send(pkt); err != nil {
				logger.Warn("QUIC: pass failed", "err", err)
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if packetMode == config.QUICDesync {
			dgrams++ // фильтр пропускает только исходящий UDP/443
			out, sni, done := quicDesyncPacket(pkt, domainSet)
			if sni != "" {
				radiusN++ // имя непусто только для радиусного Initial
			}
			if done {
				acted++
				if acted == 1 || time.Since(lastReport) >= quicReportEvery {
					logger.Info("QUIC переписан (десинк) — обход без блокировки",
						"sni", sni, "переписано", acted)
					lastReport = time.Now()
				}
				pkt = out // отправляем переписанный вместо оригинала
			} else if sni != "" && (radiusN == 1 || time.Since(lastReport) >= quicReportEvery) {
				// Радиусный QUIC виден, но переписать не вышло — важно знать.
				logger.Info("QUIC не переписан (пропущен как есть)", "sni", sni)
				lastReport = time.Now()
			}
			if err := conn.Send(pkt); err != nil {
				logger.Warn("QUIC: не удалось отправить пакет", "ошибка", err)
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}

		// Режим block.
		sni, block := selectedSNI, selectedScope
		if len(youtubeMode) == 0 {
			sni, block = flows.shouldBlock(pkt, domainSet, reasm, time.Now())
		}
		if block {
			acted++
			// Накопление признака QUIC-only (3.3): doctor по нему судит, откатилось
			// ли приложение на TCP. nil трекер не бывает в block, но защищает тест.
			if tracker != nil {
				tracker.BlockedQUIC(sni, time.Now())
			}
			// Первый сброс — сразу, дальше сводкой не чаще quicReportEvery.
			if acted == 1 || time.Since(lastReport) >= quicReportEvery {
				logger.Info("QUIC заблокирован — приложение откатится на TCP",
					"sni", sni, "сброшено", acted)
				lastReport = time.Now()
			}
			continue // роняем: пакет не уходит в сеть
		}
		if err := conn.Send(pkt); err != nil {
			logger.Warn("QUIC: не удалось пропустить пакет", "ошибка", err)
		}
		// Периодическая сводка, даже когда ничего не роняем: без неё молчание
		// блокировщика нельзя отличить от «QUIC не шлётся». Печатается не чаще
		// quicReportEvery и только когда датаграммы вообще были.
		if s := reasm.Snapshot(); s.Datagrams > 0 && time.Since(lastReport) >= quicReportEvery {
			logger.Info("QUIC: сводка",
				"датаграмм_udp443", s.Datagrams, "initial", s.Initials,
				"собран_sni", s.Resolved, "ещё_собирается", s.Pending,
				"не_разобрать", s.Failed, "заблокировано", acted,
				"74байт_форма", shaped74Loose,
				"74байт_discovery", shaped74Strict,
				"куда_строгие", strings.Join(strictEndpoints, " "))
			lastReport = time.Now()
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// quicDesyncPacket переписывает исходящий QUIC Initial к радиусу для режима
// desync: переупорядочивает CRYPTO в пределах того же пакета (тот же номер,
// та же длина), чтобы DPI не разобрал SNI, но сервер собрал рукопожатие.
//
// Возвращает пакет к отправке, распознанное имя и признак переписывания. Если
// это не наш/не первый Initial или переписать безопасно нельзя — (pkt,"",false),
// и вызывающий шлёт оригинал без изменений (1.6: десинк не рвёт связность).
//
// Переписанная датаграмма собирается на КОПИИ буфера: при любой неудаче
// оригинал остаётся цел и уходит как есть.
func quicDesyncPacket(pkt capture.Packet, domainSet *config.DomainSet) (capture.Packet, string, bool) {
	if pkt.Dir != core.DirectionOutbound {
		return pkt, "", false
	}
	d, err := packet.Dissect(pkt.Data)
	if err != nil || d.Protocol != packet.ProtoUDP {
		return pkt, "", false
	}
	payload, ok := d.Payload(pkt.Data)
	if !ok {
		return pkt, "", false
	}
	sni, ok := quic.PeekSNI(payload)
	if !ok {
		return pkt, "", false // не клиентский Initial с нулевого смещения
	}
	if !domainSet.Matches("", sni) {
		return pkt, "", false // чужой домен — не трогаем и не шумим в лог
	}
	rewritten, ok := quic.RewriteInitialReorder(payload)
	if !ok || len(rewritten) != len(payload) {
		return pkt, "", false // безопасно переписать не вышло — как есть
	}

	// Копия буфера: оригинал не трогаем, чтобы при сбое пересчёта отправить его.
	buf := append([]byte(nil), pkt.Data...)
	d2, err := packet.Dissect(buf)
	if err != nil {
		return pkt, "", false
	}
	p2, ok := d2.Payload(buf)
	if !ok || len(p2) != len(rewritten) {
		return pkt, "", false
	}
	copy(p2, rewritten)
	if !d2.RecomputeChecksums(buf) {
		return pkt, "", false
	}
	return capture.Packet{Data: buf, Dir: pkt.Dir, Reinject: pkt.Reinject}, sni, true
}

// quicShouldBlock решает, ронять ли QUIC-пакет: он исходящий, это UDP, и его
// ClientHello называет домен из радиуса. Возвращает распознанное имя сервера и
// признак блокировки. Любая неуверенность — ("", false): не блокируем.
//
// Сборщик reasm копит CRYPTO из нескольких Initial одного рукопожатия, поэтому
// у многопакетного ClientHello (постквантовый Chrome) имя становится известно
// на пакете, который дособирает рукопожатие, а предыдущие части проходят как
// неопределённые. Это осознанный компромисс: первый кусок рукопожатия радиусной
// цели уходит в сеть, но без остальных сервер QUIC-соединение не поднимет, а
// переблокировать вслепую (роняя нераспознанные части) задело бы чужой QUIC.
func quicShouldBlock(pkt capture.Packet, domainSet *config.DomainSet, reasm *quic.Reassembler, now time.Time) (sni string, block bool) {
	if pkt.Dir != core.DirectionOutbound {
		return "", false
	}
	d, err := packet.Dissect(pkt.Data)
	if err != nil || d.Protocol != packet.ProtoUDP {
		return "", false
	}
	payload, ok := d.Payload(pkt.Data)
	if !ok {
		return "", false
	}
	sni, ok = reasm.Offer(payload, now)
	if !ok {
		return "", false // не клиентский Initial, ещё не собрано либо имя не достать
	}
	if !domainSet.Matches("", sni) {
		return "", false // не наш домен — чужой QUIC не трогаем
	}
	return sni, true
}

// Параметры таблицы потоков блокировки QUIC.
const (
	// quicFlowTTL — сколько поток остаётся заблокированным без новых пакетов.
	quicFlowTTL = 60 * time.Second
	// quicFlowMax — предел числа потоков; при переполнении новые не запоминаются.
	quicFlowMax = 4096
)

// quicFlows помнит UDP-потоки (адреса и порты), чей ClientHello назвал домен
// радиуса, и роняет все их последующие датаграммы.
//
// Одного вердикта по DCID мало. Первый Initial многопакетного ClientHello
// уходит в сеть до того, как имя собрано; сервер подтверждает его и сообщает
// свой connection ID, после чего клиент повторяет сброшенную часть уже с новым
// DCID. Ключи Initial при этом остаются от исходного DCID, сборщик такой пакет
// расшифровать не может и пропускает его — рукопожатие завершается, и QUIC к
// радиусной цели идёт мимо блокировки.
type quicFlows struct {
	m         map[quicFlowID]quicFlow
	lastSweep time.Time
	logger    *slog.Logger
	// overflowed — о переполнении уже сообщено (пишем один раз, не на пакет).
	overflowed bool
}

// quicFlowID — адреса и порты обеих сторон UDP-потока. Массив фиксированной
// длины, а не строка: ключ строится на каждой датаграмме без выделения памяти.
type quicFlowID struct {
	addrs [32]byte
	ports [4]byte
}

type quicFlow struct {
	sni  string
	seen time.Time
}

func newQUICFlows(logger *slog.Logger) *quicFlows {
	return &quicFlows{m: make(map[quicFlowID]quicFlow), logger: logger}
}

// shouldBlock — quicShouldBlock с памятью по потоку: датаграмма, имя которой
// не достать, получает вердикт своего потока. Собранное имя вне радиуса
// вердикт снимает (порт мог быть переиспользован другим соединением).
func (f *quicFlows) shouldBlock(pkt capture.Packet, domainSet *config.DomainSet, reasm *quic.Reassembler, now time.Time) (string, bool) {
	if pkt.Dir != core.DirectionOutbound {
		return "", false
	}
	d, err := packet.Dissect(pkt.Data)
	if err != nil || d.Protocol != packet.ProtoUDP {
		return "", false
	}
	payload, ok := d.Payload(pkt.Data)
	if !ok {
		return "", false
	}
	key, keyed := quicFlowKey(pkt.Data, d)
	f.sweep(now)
	if sni, ok := reasm.Offer(payload, now); ok {
		if !domainSet.Matches("", sni) {
			delete(f.m, key)
			return "", false
		}
		if keyed {
			if _, known := f.m[key]; known || len(f.m) < quicFlowMax {
				f.m[key] = quicFlow{sni: sni, seen: now}
			} else if !f.overflowed && f.logger != nil {
				// Деградация в прежнее поведение (вердикт только по собранному
				// ClientHello), а не слепая блокировка — но не молча (4.4).
				f.overflowed = true
				f.logger.Warn("QUIC: таблица заблокированных потоков переполнена — новые потоки блокируются только по собранному ClientHello",
					"предел", quicFlowMax)
			}
		}
		return sni, true
	}
	if !keyed {
		return "", false
	}
	fl, known := f.m[key]
	if !known {
		return "", false
	}
	fl.seen = now
	f.m[key] = fl
	return fl.sni, true
}

func (f *quicFlows) sweep(now time.Time) {
	if now.Sub(f.lastSweep) < time.Second {
		return
	}
	f.lastSweep = now
	for k, fl := range f.m {
		if now.Sub(fl.seen) > quicFlowTTL {
			delete(f.m, k)
		}
	}
}

// quicFlowKey — ключ UDP-потока: адреса и порты обеих сторон.
func quicFlowKey(buf []byte, d packet.Dissection) (quicFlowID, bool) {
	var key quicFlowID
	u, ok := d.UDP(buf)
	if !ok {
		return key, false
	}
	var src, dst []byte
	if h, ok := d.IPv4(buf); ok {
		src, dst = h.Src(), h.Dst()
	} else if h, ok := d.IPv6(buf); ok {
		src, dst = h.Src(), h.Dst()
	} else {
		return key, false
	}
	copy(key.addrs[:], src)
	copy(key.addrs[len(key.addrs)/2:], dst)
	copy(key.ports[:], u[:len(key.ports)])
	return key, true
}
