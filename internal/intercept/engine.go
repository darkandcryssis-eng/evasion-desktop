package intercept

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/desync"
	"github.com/fitting-1c/evasion/internal/executor"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// HelloParser извлекает из распознанного ClientHello то, что нужно для выбора и
// применения стратегии: имя сервера и структурные точки разреза.
//
// Инъектируется, чтобы ядро цикла не зависело от tlsparse и проверялось без
// него (тот же приём разделения, что в flow и packetexec). Настоящий адаптер —
// TLSHelloParser. ok == false означает, что разобрать не удалось: соединение
// пропускается без изменений.
type HelloParser func(hello []byte) (sni string, cuts []core.CutPoint, ok bool)

// Options задаёт зависимости контура.
type Options struct {
	IncludePacketMetadata bool
	// ShortHelloFallback режет внутри имени ClientHello, слишком короткий для
	// tcp_overlap. Только для фиксированных стратегий: в песочнице подмена
	// приписала бы успех кандидату, который не исполнялся.
	ShortHelloFallback bool
	// Source, Sink — захват пакетов.
	Source capture.PacketSource
	Sink   capture.PacketSink
	// DesyncSink optionally selects a separate sender for modified ClientHello.
	// Returning nil preserves Sink; ordinary traffic always uses Sink.
	DesyncSink func(sni string) capture.PacketSink
	// Flows — таблица потоков с настроенным детектором ClientHello.
	Flows *flow.Table
	// Provider — выбор стратегии по метаданным соединения.
	Provider proxy.StrategyProvider
	// Exec — пакетный исполнитель (packetexec.New()).
	Exec executor.Executor
	// Parse — разбор ClientHello (SNI, точки разреза).
	Parse HelloParser
	// Logger — журнал; nil допустим (пишет в никуда).
	Logger *slog.Logger
	// Now — источник времени для таблицы потоков; nil означает time.Now.
	Now func() time.Time
	// OnClientHello — необязательный наблюдатель: вызывается с именем сервера
	// (SNI) на каждом распознанном исходящем TCP ClientHello, до выбора и
	// применения стратегии. Нужен трекеру QUIC-only (3.3): по нему видно, что
	// приложение откатилось на TCP после блокировки QUIC. nil допустим и ничего
	// не меняет. Вешается только на продуктовый путь: трафик песочницы
	// синтетический и к признаку QUIC-only отношения не имеет.
	OnClientHello func(sni string)
	// OnPassive — необязательный приёмник пассивных наблюдений срыва (5.10):
	// вызывается при повторной отправке ClientHello на уже решённом потоке.
	// Повтор означает, что первая попытка осталась без ответа, — бесплатный
	// признак, что стратегия на этой цели загибается, без единой пробы. nil
	// допустим. Вешается только на продуктовый путь: повтор на синтетическом
	// трафике песочницы к живому сигналу отношения не имеет (её исход и так
	// меряется пробой).
	OnPassive func(PassiveEvent)
	// Observer — расширенный наблюдатель жизненного цикла соединения.
	// Получает коррелированные события каждого соединения:
	// увиденный ClientHello, применённая/непримененная стратегия, пассивный
	// retransmit. Используется для записи в events.jsonl и для rtctrack.
	// nil допустим; старые хуки OnClientHello/OnPassive продолжают работать
	// независимо.
	Observer Observer
	// Blocklist — набор SNI, с которыми движок НЕ пытается десинкаться
	// (пропускает сырьём). Нужен для «быстрого фидбека»: если конкретный
	// RTC-сервер TSPU всегда роняет, попытки десинка туда — потеря времени.
	// Сырой пропуск → DPI увидит SNI → RST → Discord моментально следующий
	// сервер (вместо TCP RTO backoff'а). Blocklist обновляется автопилотом
	// на основе статистики rtctrack. nil допустим — тогда ничего не
	// блокируется.
	Blocklist Blocklist
}

// Blocklist — набор SNI, которые движок не должен пытаться десинкать.
// Контракт: Contains должна быть ОЧЕНЬ быстрой (hot path), без аллокаций.
// Типичная реализация — чтение атомарного указателя на map[string]struct{}.
type Blocklist interface {
	// Contains сообщает, в блок-листе ли SNI.
	Contains(sni string) bool
}

// Observer — расширенный приёмник событий жизненного цикла соединения.
//
// Все методы вызываются синхронно из горутины движка и НЕ ДОЛЖНЫ блокироваться.
// Типичная реализация — тонкая обёртка над events.Writer с асинхронным
// приёмом; тяжёлая работа (сетевой I/O, диск) не допускается.
//
// FlowID — непрозрачный коррелирующий идентификатор одного TCP-соединения в
// пределах запуска движка; одни и те же FlowID = одно соединение. Генерируется
// движком хешированием flow.Key, вызывающему разбирать его не нужно.
type Observer interface {
	// OnClientHelloSeen — распознан ClientHello. assembled = true, если имя
	// собрано из нескольких сегментов (многосегментный путь).
	OnClientHelloSeen(flowID uint64, sni string, assembled bool)
	// OnStrategyApplied — стратегия применена, пакеты отправлены.
	OnStrategyApplied(flowID uint64, sni string, strategyID core.StrategyID)
	// OnStrategyFailed — стратегия не применена (не исполнима, вне радиуса,
	// отказ сборки). reason — короткая строка-причина.
	OnStrategyFailed(flowID uint64, sni string, strategyID core.StrategyID, reason string)
	// OnPassiveRetransmit — повтор ClientHello, пассивный признак срыва.
	OnPassiveRetransmit(flowID uint64, sni string, target string, strategyID core.StrategyID)
}

// PassiveEvent — пассивное наблюдение срыва соединения (5.10).
//
// Атрибутируется стратегии, выбранной для этого имени текущим снимком, — тем же
// выбором, что у настоящего соединения. Вес такого наблюдения ниже активного
// (0.3, store.SourcePassive): условия не контролируются, и ретрансмиссия бывает
// от обычной потери пакета, поэтому вывод делается по накоплению.
type PassiveEvent struct {
	// SNI — имя сервера из повторного ClientHello.
	SNI string
	// StrategyID — стратегия, выбранная для этого имени сейчас.
	StrategyID core.StrategyID
	// Target — цель радиуса, которой принадлежит имя.
	Target string
}

// Engine — контур перехвата.
type Engine struct {
	includePacketMetadata bool
	src                   capture.PacketSource
	sink                  capture.PacketSink
	desyncSink            func(string) capture.PacketSink
	flows                 *flow.Table
	prov                  proxy.StrategyProvider
	exec                  executor.Executor
	parse                 HelloParser
	shortHelloFallback    bool
	log                   *slog.Logger
	now                   func() time.Time
	onCH                  func(sni string)
	onPsv                 func(PassiveEvent)
	obs                   Observer
	block                 Blocklist
	failureMu             sync.Mutex
	recentDesync          map[desyncKey]desyncRecord

	// Счётчики разбора ClientHello (принадлежат горутине Run, без синхронизации).
	// Нужны наблюдаемости: отличить «десинк применён, но не помог» от «десинк
	// не применялся, потому что ClientHello не собрался».
	//
	//   - helloComplete — имя видно в первом сегменте, десинк применён сразу;
	//   - helloAssembled — имя нашлось во втором-третьем сегменте после сборки,
	//     десинк применён к тому сегменту;
	//   - helloMultiseg — собрать ClientHello не удалось (имя не показалось в
	//     пределах склейки или склейку оборвал разрыв нумерации), десинк мимо.
	helloComplete  int
	helloAssembled int
	helloMultiseg  int
	// multisegReason — разбивка пропусков многосегментной сборки по причине
	// (индекс — значение flow.GiveUpReason). Нужна, чтобы отличить разрыв
	// нумерации вперёд от исчерпания лимита или холостых повторов и чинить
	// прицельно. Размер с запасом; индекс проверяется перед записью.
	multisegReason [8]int
	// retransmits — повторы ClientHello (пассивный признак срыва, 5.10). В
	// сводке, чтобы срыв был виден человеку, а не только копился в оценках.
	retransmits   int
	lastHelloLog  time.Time
	lastFlowSweep time.Time

	// transparent — прозрачный режим killswitch. Атомарный, потому что
	// поднимается сторожем из другой горутины, а читается в цикле на каждый
	// пакет.
	transparent atomic.Bool
	async       *asyncRun
}

type FailureReporter interface {
	ReportFailure(sni string, failed core.StrategyID)
}

type desyncKey struct {
	remote    netip.AddrPort
	localPort uint16
}

type desyncRecord struct {
	sni        string
	strategyID core.StrategyID
	at         time.Time
}

const (
	recentDesyncWindow   = 5 * time.Second
	recentDesyncCapacity = 4096
	maxAsyncWorkers      = 256
)

type receiveEvent struct {
	pkt capture.Packet
	err error
}

type asyncCompletion struct {
	flowID uint64
	finish func()
}

type pendingFlow struct {
	queue []capture.Packet
}

type asyncRun struct {
	ctx         context.Context
	cancel      context.CancelFunc
	completions chan asyncCompletion
	mu          sync.Mutex
	active      map[uint64]*pendingFlow
	workerCount int
	workers     sync.WaitGroup
}

func (r *asyncRun) start(flowID uint64, work func(context.Context) func()) bool {
	if r == nil || r.workerCount >= maxAsyncWorkers {
		return false
	}
	r.mu.Lock()
	if r.active[flowID] != nil {
		r.mu.Unlock()
		return false
	}
	r.active[flowID] = &pendingFlow{}
	r.mu.Unlock()
	r.workerCount++
	r.workers.Add(1)
	go func() {
		defer r.workers.Done()
		r.completions <- asyncCompletion{flowID: flowID, finish: work(r.ctx)}
	}()
	return true
}

// New создаёт контур, проверив обязательные зависимости.
func New(opts Options) (*Engine, error) {
	switch {
	case opts.Source == nil:
		return nil, errors.New("intercept: не задан источник пакетов")
	case opts.Sink == nil:
		return nil, errors.New("intercept: не задан приёмник пакетов")
	case opts.Flows == nil:
		return nil, errors.New("intercept: не задана таблица потоков")
	case opts.Provider == nil:
		return nil, errors.New("intercept: не задан провайдер стратегий")
	case opts.Exec == nil:
		return nil, errors.New("intercept: не задан исполнитель")
	case opts.Parse == nil:
		return nil, errors.New("intercept: не задан разбор ClientHello")
	}
	e := &Engine{
		src:                   opts.Source,
		sink:                  opts.Sink,
		desyncSink:            opts.DesyncSink,
		flows:                 opts.Flows,
		prov:                  opts.Provider,
		exec:                  opts.Exec,
		parse:                 opts.Parse,
		shortHelloFallback:    opts.ShortHelloFallback,
		includePacketMetadata: opts.IncludePacketMetadata,
		log:                   opts.Logger,
		now:                   opts.Now,
		onCH:                  opts.OnClientHello,
		onPsv:                 opts.OnPassive,
		obs:                   opts.Observer,
		block:                 opts.Blocklist,
	}
	if e.log == nil {
		e.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if e.now == nil {
		e.now = time.Now
	}
	return e, nil
}

// SetTransparent переводит контур в прозрачный режим или обратно. Вызывается
// killswitch-сторожем.
func (e *Engine) SetTransparent(on bool) { e.transparent.Store(on) }

// Transparent сообщает, в прозрачном ли режиме контур.
func (e *Engine) Transparent() bool { return e.transparent.Load() }

// Run ведёт цикл перехвата до ошибки источника или отмены контекста.
//
// Приёмная горутина копирует буфер источника; таблица потоков и callbacks
// остаются во владении этой горутины. Задержанные планы завершаются через
// очередь результатов, сохраняя FIFO-порядок пакетов одного потока.
func (e *Engine) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	state := &asyncRun{
		ctx:         runCtx,
		cancel:      cancel,
		completions: make(chan asyncCompletion, maxAsyncWorkers),
		active:      make(map[uint64]*pendingFlow),
	}
	e.async = state
	defer func() {
		cancel()
		e.async = nil
	}()

	received := make(chan receiveEvent, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer close(received)
		for {
			pkt, err := e.src.Recv()
			if err == nil {
				pkt = clonePacket(pkt)
			}
			received <- receiveEvent{pkt: pkt, err: err}
			if err != nil {
				return
			}
		}
	}()

	sourceDone := false
	for {
		if sourceDone && state.workerCount == 0 {
			state.workers.Wait()
			<-readerDone
			return nil
		}
		select {
		case <-ctx.Done():
			e.stopAsyncRun(state, received, readerDone, true)
			return ctx.Err()
		case event, ok := <-received:
			if !ok {
				received = nil
				sourceDone = true
				continue
			}
			if event.err != nil {
				received = nil
				if errors.Is(event.err, io.EOF) {
					sourceDone = true
					continue
				}
				if ctx.Err() != nil {
					e.stopAsyncRun(state, received, readerDone, true)
					return ctx.Err()
				}
				err := fmt.Errorf("intercept: приём пакета: %w", event.err)
				e.stopAsyncRun(state, received, readerDone, true)
				return err
			}
			if ctx.Err() != nil {
				e.forwardOrQueue(state, event.pkt)
				e.stopAsyncRun(state, received, readerDone, true)
				return ctx.Err()
			}
			if flowID, ok := packetFlowID(event.pkt); ok {
				state.mu.Lock()
				if pending := state.active[flowID]; pending != nil {
					pending.queue = append(pending.queue, clonePacket(event.pkt))
					state.mu.Unlock()
					continue
				}
				state.mu.Unlock()
			}
			e.handle(runCtx, event.pkt)
		case result := <-state.completions:
			state.workerCount--
			result.finish()
			e.drainPending(state, result.flowID)
		}
	}
}

func (e *Engine) drainPending(state *asyncRun, flowID uint64) {
	state.mu.Lock()
	pending := state.active[flowID]
	if pending == nil {
		state.mu.Unlock()
		return
	}
	delete(state.active, flowID)
	state.mu.Unlock()
	for i, pkt := range pending.queue {
		state.mu.Lock()
		if next := state.active[flowID]; next != nil {
			next.queue = append(next.queue, pending.queue[i:]...)
			state.mu.Unlock()
			return
		}
		state.mu.Unlock()
		e.handle(state.ctx, pkt)
	}
}

func (e *Engine) stopAsyncRun(state *asyncRun, received <-chan receiveEvent, readerDone <-chan struct{}, stopSource bool) {
	state.cancel()
	waitReader := false
	if stopSource {
		if source, ok := e.src.(interface{ ShutdownReceive() error }); ok {
			waitReader = source.ShutdownReceive() == nil
		}
	}

	for state.workerCount > 0 {
		select {
		case result := <-state.completions:
			state.workerCount--
			result.finish()
			e.forwardPending(state, result.flowID)
		case event, ok := <-received:
			if !ok {
				received = nil
				continue
			}
			if event.err == nil {
				e.forwardOrQueue(state, event.pkt)
			}
		case <-readerDone:
			readerDone = nil
		}
	}
	state.workers.Wait()

	if waitReader && readerDone != nil {
		for readerDone != nil {
			select {
			case event, ok := <-received:
				if !ok {
					received = nil
					continue
				}
				if event.err == nil {
					e.forwardOrQueue(state, event.pkt)
				}
			case <-readerDone:
				readerDone = nil
			}
		}
	}
	e.forwardAllPending(state)
	for received != nil {
		select {
		case event, ok := <-received:
			if !ok {
				received = nil
				continue
			}
			if event.err == nil {
				e.forwardOrQueue(state, event.pkt)
			}
		default:
			received = nil
		}
	}
	e.forwardAllPending(state)
}

func (e *Engine) forwardAllPending(state *asyncRun) {
	state.mu.Lock()
	flowIDs := make([]uint64, 0, len(state.active))
	for flowID := range state.active {
		flowIDs = append(flowIDs, flowID)
	}
	state.mu.Unlock()
	for _, flowID := range flowIDs {
		e.forwardPending(state, flowID)
	}
}

func (e *Engine) forwardOrQueue(state *asyncRun, pkt capture.Packet) {
	if flowID, ok := packetFlowID(pkt); ok {
		state.mu.Lock()
		if pending := state.active[flowID]; pending != nil {
			pending.queue = append(pending.queue, clonePacket(pkt))
			state.mu.Unlock()
			return
		}
		state.mu.Unlock()
	}
	e.forward(pkt)
}

func (e *Engine) forwardPending(state *asyncRun, flowID uint64) {
	state.mu.Lock()
	pending := state.active[flowID]
	if pending == nil {
		state.mu.Unlock()
		return
	}
	delete(state.active, flowID)
	state.mu.Unlock()
	for _, pkt := range pending.queue {
		e.forward(pkt)
	}
}

func clonePacket(pkt capture.Packet) capture.Packet {
	pkt.Data = append([]byte(nil), pkt.Data...)
	return pkt
}

func packetFlowID(pkt capture.Packet) (uint64, bool) {
	d, err := packet.Dissect(pkt.Data)
	if err != nil || d.Protocol != packet.ProtoTCP {
		return 0, false
	}
	key, ok := keyOf(d, pkt.Data)
	if !ok {
		return 0, false
	}
	return hashFlowKey(key), true
}

// handle обрабатывает один пакет.
func (e *Engine) handle(ctx context.Context, pkt capture.Packet) {
	// Killswitch: прозрачный режим не трогает ничего.
	if e.transparent.Load() {
		e.forward(pkt)
		return
	}

	d, err := packet.Dissect(pkt.Data)
	if err != nil {
		// Неразобранный пакет пропускаем: решать по нему нечего, а ронять
		// чужой трафик из-за своей неспособности разобрать нельзя.
		e.forward(pkt)
		return
	}

	// Интересны только исходящие TCP с полезной нагрузкой. Всё прочее — мимо
	// (4.2 правило 3): входящие, не-TCP, пустые сегменты рукопожатия.
	if pkt.Dir != core.DirectionOutbound || d.Protocol != packet.ProtoTCP {
		e.forward(pkt)
		return
	}
	payload, _ := d.Payload(pkt.Data)

	th, hasTCP := d.TCP(pkt.Data)
	if !hasTCP {
		e.forward(pkt)
		return
	}
	key, ok := keyOf(d, pkt.Data)
	if !ok {
		e.forward(pkt)
		return
	}

	now := e.now()
	// Keep maintenance on the owning goroutine; a full table bypasses desync.
	if e.lastFlowSweep.IsZero() || now.Sub(e.lastFlowSweep) >= time.Second {
		e.flows.Sweep(now)
		e.lastFlowSweep = now
	}
	flags := th.Flags()
	if flags&packet.FlagSYN != 0 && flags&packet.FlagACK == 0 {
		// A reused TCP tuple belongs to a new connection.
		e.flows.Forget(key)
	}
	if flags&(packet.FlagFIN|packet.FlagRST) != 0 {
		defer e.flows.Forget(key)
		if len(payload) == 0 || flags&packet.FlagRST != 0 {
			e.forward(pkt)
			return
		}
	}
	act := e.flows.Outbound(key, th.Seq(), payload, now)

	switch {
	case act.Buffering:
		// Сегмент удержан под сборку многосегментного ClientHello: в сеть он
		// пока не идёт, байты уже в таблице. Ничего не шлём и ничего не считаем —
		// решение будет на более позднем сегменте.
		return

	case act.Disposition == flow.Apply:
		flowID := hashFlowKey(key)
		// Пакет исходящий (проверено выше), поэтому исходный порт TCP — это
		// локальный порт соединения. Он нужен провайдеру песочницы, который
		// выбирает стратегию по порту, а не по SNI (5.2).
		if len(act.SegLens) >= 2 {
			// Имя нашлось не в первом сегменте: ClientHello собран из нескольких.
			e.helloAssembled++
			e.applyAssembled(ctx, pkt, act, th.SrcPort(), flowID)
		} else {
			e.helloComplete++
			e.applySingle(ctx, pkt, act.Hello, act.BaseSeq, th.SrcPort(), flowID)
		}

	case act.Incomplete:
		// Многосегментный ClientHello собрать не удалось — десинк мимо.
		// Удержанные до этого сегменты ещё не отправлены: досылаем их сырьём по
		// исходным границам, затем пропускаем текущий пакет.
		e.helloMultiseg++
		if int(act.Reason) < len(e.multisegReason) {
			e.multisegReason[act.Reason]++
		}
		e.emitHeldRange(ctx, pkt, act.Hello, act.BaseSeq, act.SegLens, 0, len(act.SegLens))
		e.forward(pkt)

	case act.Retransmit:
		flowID := hashFlowKey(key)
		// Повтор ClientHello — первая попытка осталась без ответа (5.10).
		// Это пассивный признак срыва: кормим наблюдателя, но стратегию
		// ПЕРЕприменять НЕ пытаемся — просто пропускаем сырьём.
		//
		// Прежний «второй шанс» (applySingle заново) создавал шторм
		// ретрансмитов на многосегментных ClientHello: ~1:1 с собранными
		// (повторов=60 на 61 многосегментных в живом прогоне). При одном и
		// том же приёме втором пропуск не меняет результата — DPI отвечает
		// одинаково. Хуже: двойной десинк создаёт seq-конфликты на уже
		// частично отправленном потоке, и клиентская TCP ждёт TCP RTO
		// (~15-30 с × экспоненциальный backoff), прежде чем сдаться и
		// перейти на следующий RTC-сервер Discord. Это и есть пресловутый
		// затуп AUTHENTICATING на 1-2 минуты.
		//
		// Пропуск сырьём делает отказ быстрее: DPI увидит SNI открытым
		// текстом, RST'нёт поток, Discord моментально переходит к
		// следующему серверу. Один сервер = одна проба; живой — живой,
		// мёртвый — быстро отбрасывается. Пассивный сигнал всё равно
		// записывается в оценку стратегии — только через OnPassive, без
		// повторной отправки пакетов.
		e.retransmits++
		e.observePassive(act.Hello, flowID, pkt)
		e.forward(pkt)

	default:
		// Pass: не-TLS, уже settled или прозрачный режим таблицы (переполнение).
		e.forward(pkt)
	}

	e.maybeLogHello()
}

// helloLogEvery — не чаще этого срока печатается сводка по ClientHello.
const helloLogEvery = 30 * time.Second

// maybeLogHello печатает сводку разбора ClientHello: сколько десинкнуто по
// первому сегменту (имя видно сразу), сколько собрано из нескольких сегментов
// (имя во втором-третьем) и сколько пропущено (собрать не удалось). Нужна, чтобы
// отличить «приём не сработал» от «приём к цели не применялся». Первый вызов
// печатает сразу, дальше — не чаще helloLogEvery.
func (e *Engine) maybeLogHello() {
	if e.helloComplete == 0 && e.helloAssembled == 0 && e.helloMultiseg == 0 && e.retransmits == 0 {
		return
	}
	now := e.now()
	if !e.lastHelloLog.IsZero() && now.Sub(e.lastHelloLog) < helloLogEvery {
		return
	}
	e.lastHelloLog = now
	args := []any{
		"целых_десинк_применим", e.helloComplete,
		"многосегментных_собрано", e.helloAssembled,
		"многосегментных_пропущено", e.helloMultiseg,
		"повторов_clienthello", e.retransmits,
	}
	// Разбивку причин печатаем, только когда есть что пропускать: иначе строка
	// пуста и лишь зашумляет журнал.
	if e.helloMultiseg > 0 {
		args = append(args, "пропущено_причины", e.multisegReasonSummary())
	}
	e.log.Info("перехват: разбор ClientHello", args...)
}

// multisegReasonSummary собирает человекочитаемую разбивку пропусков по
// причинам, напр. "разрыв_seq:2 не_tls:1". Порядок — по значению причины,
// нулевые опускаются. Пусто означает «пропусков не было».
func (e *Engine) multisegReasonSummary() string {
	var parts []string
	for r, n := range e.multisegReason {
		if n == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d", flow.GiveUpReason(r).String(), n))
	}
	return strings.Join(parts, " ")
}

// observePassive связывает повтор ClientHello с последней применённой
// стратегией потока и сообщает о возможном срыве. Разбор нагрузки здесь не
// горячий путь — повтор ClientHello редок.
func (e *Engine) observePassive(hello []byte, flowID uint64, pkt capture.Packet) {
	reporter, reportsFailures := e.prov.(FailureReporter)
	if e.onPsv == nil && e.obs == nil && !reportsFailures {
		return
	}
	sni, _, ok := e.parse(hello)
	if !ok {
		return
	}
	record, hasApplied := e.takeRecentDesyncForPacket(pkt)
	if reportsFailures && hasApplied && record.strategyID != "" {
		reporter.ReportFailure(sni, record.strategyID)
	}
	if e.onPsv == nil && e.obs == nil {
		return
	}
	sel := e.prov.Select(proxy.ConnMeta{SNI: sni, IsClientHello: true})
	if hasApplied && record.strategyID != "" {
		sel.ID = record.strategyID
	}
	if sel.Strategy == nil || sel.Target == "" {
		return
	}
	if e.onPsv != nil {
		e.onPsv(PassiveEvent{SNI: sni, StrategyID: sel.ID, Target: sel.Target})
	}
	if e.obs != nil {
		e.obs.OnPassiveRetransmit(flowID, sni, sel.Target, sel.ID)
	}
}

// applySingle применяет стратегию к одиночному (уместившемуся или с именем в
// первом сегменте) ClientHello. hello — его байты, baseSeq — их seq в потоке.
// На отказе, если ещё ничего не отправлено, оригинал пропускается без изменений.
func (e *Engine) applySingle(ctx context.Context, pkt capture.Packet, hello []byte, baseSeq uint32, localPort uint16, flowID uint64) {
	sni, cuts, ok := e.parse(hello)
	if !ok {
		e.forward(pkt)
		return
	}
	fallback := func() { e.forward(pkt) }
	if e.execDesync(ctx, pkt, hello, cuts, baseSeq, sni, localPort, flowID, false, 0, fallback) {
		// Десинк не отправлен (вне радиуса, несобираемо, неисполнимо) — оригинал
		// пропускаем как есть.
		fallback()
	}
}

// applyAssembled применяет десинк к ClientHello, собранному из нескольких
// удержанных сегментов (act несёт склейку, её seq и границы сегментов).
//
// Сегменты до того, в котором имя НАЧИНАЕТСЯ, досылаются сырьём (DPI по ним
// имени не прочтёт), а сегмент с началом имени и всё за ним десинкуется как один
// кусок. Текущий пакет (последний сегмент) отдельно не пропускается — он входит
// в этот кусок. Благодаря удержанию до начала имени можно дотянуться даже когда
// имя расщеплено на границе сегментов.
func (e *Engine) applyAssembled(ctx context.Context, pkt capture.Packet, act flow.Action, localPort uint16, flowID uint64) {
	sni, cuts, ok := e.parse(act.Hello)
	if !ok {
		// Разбор склейки не удался (не должен при complete от детектора): не
		// теряем байты — досылаем всю склейку сырьём.
		e.emitHeldRange(ctx, pkt, act.Hello, act.BaseSeq, act.SegLens, 0, len(act.SegLens))
		return
	}

	// Приёмы, перекрывающие ВЕСЬ ClientHello cover-пакетом (tcp_overlap), нельзя
	// применять к одному хвосту от начала имени: cover длиной M перекрывает лишь
	// хвост, и если хвост короче M (а на многосегментном hello он почти всегда
	// короче 681-байтного cover'а), перекрытие невозможно — приём падает
	// (exec_failed), и настоящий ClientHello с открытым SNI уходит сырьём, после
	// чего TSPU рубит соединение. Это и ломало загрузку ресурсов GUI с
	// cdn.discordapp.com: крупные ClientHello Chrome приходят несколькими
	// сегментами.
	//
	// Для таких стратегий десинкуем ВЕСЬ собранный hello одним куском (как
	// одиночный ClientHello): длина L = полный hello (у Chrome это >681), cover
	// перекрывает его хвост, SNI скрыт. Признак «цельного» приёма — потребность в
	// CapTCPOverlap; прочие (fragment/split) работают по хвосту как прежде.
	sel := e.prov.Select(e.packetConnMeta(pkt, sni, localPort, len(act.Hello)))
	wholeSLD := strategyCutsSLD(sel.Strategy)
	if sel.Strategy != nil && (wholeSLD || strategy.RequiredCapabilities(sel.Strategy).Has(core.CapTCPOverlap)) {
		// Склейка длиннее любого исходного сегмента, а значит и MSS пути: одним
		// пакетом она в MTU не пролезет (у Chrome hello ~1800 байт), и настоящий
		// ClientHello терялся бы. Режем замену не крупнее самого большого
		// исходного сегмента — он заведомо проходил.
		limit := 0
		for _, n := range act.SegLens {
			limit = max(limit, n)
		}
		if !wholeSLD && limit < overlapMinSegment {
			// Мелкие исходные сегменты: последний кусок обязан вмещать cover
			// целиком, иначе сервер примет cover как данные.
			limit = max(limit, min(len(act.Hello), safeSegment))
		}
		fallback := func() {
			// Не отправлено (вне радиуса/неисполнимо) — досылаем всю склейку
			// сырьём по исходным границам сегментов, байты не теряем.
			e.emitHeldRange(ctx, pkt, act.Hello, act.BaseSeq, act.SegLens, 0, len(act.SegLens))
		}
		if e.execDesync(ctx, pkt, act.Hello, cuts, act.BaseSeq, sni, localPort, flowID, true, limit, fallback) {
			fallback()
		}
		return
	}

	sniOff, ok := cutOffsetOf(cuts, core.CutBeforeSNI)
	if !ok {
		// Нет точки начала имени — десинкать нечего по месту; досылаем сырьём.
		e.emitHeldRange(ctx, pkt, act.Hello, act.BaseSeq, act.SegLens, 0, len(act.SegLens))
		return
	}

	// Сегмент, в котором имя начинается, и его смещение в склейке.
	segK, segKoff := segmentAt(act.SegLens, sniOff)

	// Сегменты строго до него уходят сырьём по исходным границам.
	e.emitHeldRange(ctx, pkt, act.Hello, act.BaseSeq, act.SegLens, 0, segK)

	// Десинкуем кусок от начала этого сегмента. Смещения разрезов абсолютны в
	// склейке — переводим в координаты куска.
	span := act.Hello[segKoff:]
	shiftCuts(cuts, segKoff)
	fallback := func() {
		// Десинк не отправлен — досылаем кусок сырьём по исходным границам
		// сегментов (не одним пакетом сверх MTU).
		e.emitHeldRange(ctx, pkt, act.Hello, act.BaseSeq, act.SegLens, segK, len(act.SegLens))
	}
	if e.execDesync(ctx, pkt, span, cuts, act.BaseSeq+uint32(segKoff), sni, localPort, flowID, true, 0, fallback) {
		fallback()
	}
}

// execDesync выбирает стратегию по имени и применяет её к payload, собирая пакеты
// из шаблона tmpl с базовым номером последовательности baseSeq. Возвращает
// forwardRaw=true, если десинк отправлен НЕ был и вызывающий должен пропустить
// нагрузку сырьём; false — если замена отправлена (или начата) и слать оригинал
// нельзя.
func strategyCutsSLD(s *strategy.Strategy) bool {
	if s == nil {
		return false
	}
	var uses func(*strategy.Action) bool
	uses = func(a *strategy.Action) bool {
		if a == nil {
			return false
		}
		if p, ok := a.Params.(*strategy.FragmentParams); ok && p.At == core.CutInsideSLD {
			return true
		}
		return uses(a.Left) || uses(a.Right)
	}
	for _, r := range s.Rules {
		if uses(r.Action) {
			return true
		}
	}
	return false
}

func (e *Engine) execDesync(ctx context.Context, tmpl capture.Packet, payload []byte, cuts []core.CutPoint, baseSeq uint32, sni string, localPort uint16, flowID uint64, assembled bool, segmentLimit int, fallback func()) (forwardRaw bool) {
	// Наблюдатель QUIC-only: факт TCP ClientHello по имени — признак того, что
	// приложение на TCP работает (откат после блокировки QUIC состоялся).
	// Зовётся ВСЕГДА, до выбора стратегии: трекер сам игнорирует имена, к
	// которым QUIC не блокировался. onCH — дешёвый hook без аллокаций.
	if e.onCH != nil {
		e.onCH(sni)
	}

	// Blocklist: SNI, которые автопилот признал бесполезными для десинка
	// (повторные провалы). Пропускаем сырьём, DPI увидит SNI → RST → Discord
	// моментально следующий сервер (вместо TCP RTO backoff'а).
	if e.block != nil && e.block.Contains(sni) {
		if e.obs != nil {
			var zero core.StrategyID
			e.obs.OnStrategyFailed(flowID, sni, zero, "blocklisted")
		}
		return true
	}

	sel := e.prov.Select(e.packetConnMeta(tmpl, sni, localPort, len(payload)))
	if sel.Strategy == nil {
		// Вне радиуса поражения — пропускаем прозрачно и МОЛЧА. В events не
		// пишем: такое соединение не несёт сигнала о работе движка (мы его не
		// трогаем), а на нагруженной машине (сотни посторонних ClientHello в
		// секунду при открытии ленты VK/YouTube) каждое событие — это map-
		// аллокация в hot path. GC-давление от шумных событий способно
		// задержать перехват и выглядеть как «движок ломает VK/YouTube»,
		// хотя пакеты не меняются. Для диагностики достаточно периодических
		// сводок snitracker («SNI радиуса топ=...»).
		return true
	}

	// Наблюдатель жизненного цикла: распознан ClientHello (invariant 1.4).
	// Пишем ТОЛЬКО для in-radius SNI — то, по чему движок реально принимает
	// решения. Это и даёт корреляцию в events: один соединение = пара
	// client_hello.seen → strategy.applied|failed, без шума из out_of_radius.
	if e.obs != nil {
		e.obs.OnClientHelloSeen(flowID, sni, assembled)
	}

	input := desync.Input{
		Direction:     core.DirectionOutbound,
		Payload:       payload,
		Ordinal:       1,
		IsClientHello: true,
		Cuts:          cuts,
	}
	delayPlan := e.async != nil && strategy.RequiredCapabilities(sel.Strategy).Has(core.CapDelay)
	if delayPlan {
		input.Payload = append([]byte(nil), input.Payload...)
		input.Cuts = append([]core.CutPoint(nil), input.Cuts...)
		tmpl = clonePacket(tmpl)
	}
	sink := e.sink
	if e.desyncSink != nil {
		if selected := e.desyncSink(sni); selected != nil {
			sink = selected
		}
	}
	conn, err := packetexec.NewConnAt(sink, input, tmpl, baseSeq)
	if err != nil {
		// Штатный прозрачный откат, не ошибка: соединение проходит как есть.
		// Debug, а не Warn: при поиске (генератор) такие кандидаты часты, и на
		// Warn журнал залился бы — тот же довод, что у «стратегия применена».
		e.log.Debug("не удалось построить соединение исполнителя, пропуск без изменений",
			"sni", sni, "err", err)
		if e.obs != nil {
			e.obs.OnStrategyFailed(flowID, sni, sel.ID, "conn_build_failed")
		}
		return true
	}
	conn.SetSegmentLimit(segmentLimit)
	if strategyCutsSLD(sel.Strategy) {
		// Captured offloaded packets can exceed the actual path MSS.
		if segmentLimit <= 0 || segmentLimit > safeSegment {
			conn.SetSegmentLimit(safeSegment)
		}
	} else if strategy.RequiredCapabilities(sel.Strategy).Has(core.CapTCPOverlap) {
		// Cover перекрывает хвост и уходит первым. Сервер выбросит его, только
		// если настоящие байты поверх него придут одним сегментом по порядку;
		// при нарезке с головы граница попала бы внутрь cover, и он был бы
		// принят как данные. Поэтому полным делаем последний кусок.
		conn.SetSegmentTailAligned(true)
	}

	execute := func(execCtx context.Context) (error, bool) {
		execErr := e.exec.Execute(execCtx, sel.Strategy, conn)
		finalConn := conn
		if execErr != nil && e.shortHelloFallback && !conn.Sent() && errors.Is(execErr, desync.ErrCutUnavailable) &&
			strategy.RequiredCapabilities(sel.Strategy).Has(core.CapTCPOverlap) {
			// ClientHello не длиннее cover'а (клиент без постквантового обмена:
			// старый браузер, сторонний клиент) — перекрытие невозможно. Сырьём
			// такой hello ушёл бы с открытым SNI, поэтому режем его внутри имени.
			var buildErr error
			finalConn, buildErr = packetexec.NewConnAt(sink, input, tmpl, baseSeq)
			if buildErr != nil {
				return buildErr, false
			}
			finalConn.SetSegmentLimit(segmentLimit)
			execErr = e.exec.Execute(execCtx, shortHelloFallback, finalConn)
		}
		return execErr, finalConn.Sent()
	}

	finish := func(execErr error, sent bool) bool {
		if execErr != nil {
			if sent {
				// Часть пакетов уже ушла: поток необратимо начат, пропускать
				// оригинал нельзя — он лёг бы поверх уже отправленного. Это
				// по-настоящему тревожный случай (полуотправленный поток), поэтому
				// остаётся Warn.
				e.log.Warn("исполнение прервано после отправки, оригинал не пропускаем",
					"strategy", sel.ID, "err", execErr)
				if e.obs != nil {
					e.obs.OnStrategyFailed(flowID, sni, sel.ID, "exec_partial")
				}
				return false
			}
			// Ничего не ушло: безопасно пропускаем оригинал как есть.
			if e.obs != nil {
				e.obs.OnStrategyFailed(flowID, sni, sel.ID, "exec_failed")
			}
			e.log.Debug("стратегия не применена, пропуск без изменений",
				"strategy", sel.ID, "err", execErr)
			return true
		}

		if e.obs != nil {
			e.obs.OnStrategyApplied(flowID, sni, sel.ID)
		}
		e.rememberDesync(tmpl, sni, sel.ID, localPort)
		e.log.Debug("стратегия применена", "sni", sni, "strategy", sel.ID)
		return false
	}

	if delayPlan && e.async.start(flowID, func(execCtx context.Context) func() {
		execErr, sent := execute(execCtx)
		return func() {
			if finish(execErr, sent) {
				fallback()
			}
		}
	}) {
		return false
	}

	err, sent := execute(ctx)
	return finish(err, sent)
}

func (e *Engine) rememberDesync(tmpl capture.Packet, sni string, strategyID core.StrategyID, localPort uint16) {
	key, ok := desyncKeyForPacket(tmpl)
	if !ok {
		return
	}
	key.localPort = localPort
	e.rememberDesyncAt(key, sni, strategyID, e.now())
}

func desyncKeyForPacket(tmpl capture.Packet) (desyncKey, bool) {
	d, err := packet.Dissect(tmpl.Data)
	if err != nil || d.Protocol != packet.ProtoTCP {
		return desyncKey{}, false
	}
	tcp, ok := d.TCP(tmpl.Data)
	if !ok {
		return desyncKey{}, false
	}
	var remote netip.Addr
	switch d.Version {
	case packet.Version4:
		ip, ok := d.IPv4(tmpl.Data)
		if !ok {
			return desyncKey{}, false
		}
		remote, ok = netip.AddrFromSlice(ip.Dst())
		if !ok {
			return desyncKey{}, false
		}
		remote = remote.Unmap()
	case packet.Version6:
		ip, ok := d.IPv6(tmpl.Data)
		if !ok {
			return desyncKey{}, false
		}
		remote, ok = netip.AddrFromSlice(ip.Dst())
		if !ok {
			return desyncKey{}, false
		}
	default:
		return desyncKey{}, false
	}
	return desyncKey{
		remote:    netip.AddrPortFrom(remote, tcp.DstPort()),
		localPort: tcp.SrcPort(),
	}, true
}

func (e *Engine) rememberDesyncAt(key desyncKey, sni string, strategyID core.StrategyID, now time.Time) {
	if !key.remote.IsValid() || sni == "" || strategyID == "" {
		return
	}
	e.failureMu.Lock()
	defer e.failureMu.Unlock()
	if e.recentDesync == nil {
		e.recentDesync = make(map[desyncKey]desyncRecord)
	}
	e.pruneRecentDesync(now)
	if _, exists := e.recentDesync[key]; !exists && len(e.recentDesync) >= recentDesyncCapacity {
		var oldestKey desyncKey
		var oldest time.Time
		first := true
		for candidate, record := range e.recentDesync {
			if first || record.at.Before(oldest) {
				oldestKey, oldest, first = candidate, record.at, false
			}
		}
		delete(e.recentDesync, oldestKey)
	}
	e.recentDesync[key] = desyncRecord{sni: sni, strategyID: strategyID, at: now}
}

func (e *Engine) takeRecentDesyncForPacket(pkt capture.Packet) (desyncRecord, bool) {
	key, ok := desyncKeyForPacket(pkt)
	if !ok {
		return desyncRecord{}, false
	}
	now := e.now()
	e.failureMu.Lock()
	defer e.failureMu.Unlock()
	e.pruneRecentDesync(now)
	record, ok := e.recentDesync[key]
	if ok {
		delete(e.recentDesync, key)
	}
	return record, ok
}

func (e *Engine) pruneRecentDesync(now time.Time) {
	for key, record := range e.recentDesync {
		if now.Sub(record.at) > recentDesyncWindow {
			delete(e.recentDesync, key)
		}
	}
}

func (e *Engine) OnInboundRST(remote netip.AddrPort, localPort uint16) {
	if e == nil || !remote.IsValid() {
		return
	}
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	key := desyncKey{remote: remote, localPort: localPort}
	now := time.Now()
	if e.now != nil {
		now = e.now()
	}
	e.failureMu.Lock()
	e.pruneRecentDesync(now)
	record, ok := e.recentDesync[key]
	if ok {
		delete(e.recentDesync, key)
	}
	e.failureMu.Unlock()
	if !ok {
		return
	}
	if reporter, ok := e.prov.(FailureReporter); ok {
		reporter.ReportFailure(record.sni, record.strategyID)
	}
	if e.log != nil {
		e.log.Debug("RST после десинка, ротация стратегии", "sni", record.sni, "strategy", record.strategyID)
	}
}

// rawPassthrough — стратегия без правил: BuildPlan разворачивает её в сквозной
// пропуск нагрузки. Нужна для досылки удержанных сегментов сырьём через того же
// исполнителя (единый путь сборки пакета, верные суммы).
var rawPassthrough = &strategy.Strategy{}

// shortHelloFallback — замена tcp_overlap для ClientHello, который не длиннее
// cover'а: разрез внутри имени, части в обратном порядке.
var shortHelloFallback = func() *strategy.Strategy {
	s, err := strategy.Unmarshal([]byte(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"reverse"},"left":{"kind":"send"},"right":{"kind":"send"}}}]}`), strategy.DefaultLimits())
	if err != nil {
		panic(err)
	}
	return s
}()

const (
	// safeSegment — нагрузка, которая проходит и там, где MSS пути меньше 1460.
	safeSegment = 1400
	// overlapMinSegment — нижняя граница куска для tcp_overlap: он должен быть
	// заведомо длиннее cover (самый длинный пресет — 681 байт).
	overlapMinSegment = 1200
)

// emitHeldRange досылает сырьём сегменты склейки с индексами [from, to) по их
// исходным границам (segLens), каждый отдельным пакетом с верным seq. Пакеты
// собираются из шаблона tmpl. Эмитит по границам, а не одним куском, чтобы не
// превысить MTU при длинном префиксе.
func (e *Engine) emitHeldRange(ctx context.Context, tmpl capture.Packet, buf []byte, baseSeq uint32, segLens []int, from, to int) {
	off := 0
	for i := 0; i < to && i < len(segLens); i++ {
		if i >= from {
			seg := buf[off : off+segLens[i]]
			e.emitRaw(ctx, tmpl, seg, baseSeq+uint32(off))
		}
		off += segLens[i]
	}
}

// emitRaw досылает один сегмент сырьём: нагрузка seg с номером последовательности
// seq, собранная из шаблона tmpl тем же исполнителем через сквозную стратегию.
func (e *Engine) emitRaw(ctx context.Context, tmpl capture.Packet, seg []byte, seq uint32) {
	input := desync.Input{Direction: core.DirectionOutbound, Payload: seg, Ordinal: 1, IsClientHello: true}
	conn, err := packetexec.NewConnAt(e.sink, input, tmpl, seq)
	if err != nil {
		e.log.Warn("не удалось собрать удержанный сегмент для досылки", "err", err)
		return
	}
	if err := e.exec.Execute(ctx, rawPassthrough, conn); err != nil {
		e.log.Warn("не удалось дослать удержанный сегмент", "err", err)
	}
}

// shiftCuts переводит абсолютные смещения точек разреза из координат склейки в
// координаты десинкуемого куска, вычитая его начальное смещение. Правит срез на
// месте: parse отдаёт его свежевыделенным на каждый вызов, так что чужих данных
// это не портит, а лишней аллокации на горячем пути нет.
func shiftCuts(cuts []core.CutPoint, by int) {
	for i := range cuts {
		cuts[i].Offset -= by
	}
}

// cutOffsetOf возвращает смещение точки разреза заданного вида, если она есть.
func cutOffsetOf(cuts []core.CutPoint, kind core.CutKind) (int, bool) {
	for _, c := range cuts {
		if c.Kind == kind {
			return c.Offset, true
		}
	}
	return 0, false
}

// segmentAt находит индекс сегмента, в котором лежит абсолютное смещение off, и
// смещение начала этого сегмента в склейке. Если off за пределами — последний
// сегмент (защитная сетка; при корректных данных не достигается).
func segmentAt(segLens []int, off int) (idx, segOff int) {
	acc := 0
	for i, n := range segLens {
		if off < acc+n {
			return i, acc
		}
		acc += n
	}
	last := len(segLens) - 1
	if last < 0 {
		return 0, 0
	}
	return last, acc - segLens[last]
}

// forward пропускает пакет без изменений (повторная инъекция).
func (e *Engine) forward(pkt capture.Packet) {
	if err := e.sink.Send(pkt); err != nil {
		e.log.Warn("не удалось пропустить пакет", "err", err)
	}
}

// hashFlowKey сворачивает flow.Key в 64-битный идентификатор для корреляции
// событий одного соединения в events.jsonl.
//
// Это НЕ криптографический хеш — только короткая метка. Коллизии возможны,
// но на масштабах сессии (единицы тысяч потоков) FNV-64 даёт достаточную
// уникальность для чтения глазами и для группировки `jq -s 'group_by(.flow)'`.
func hashFlowKey(k flow.Key) uint64 {
	var buf [36]byte
	copy(buf[0:16], k.A.IP[:])
	buf[16] = byte(k.A.Port >> 8)
	buf[17] = byte(k.A.Port)
	copy(buf[18:34], k.B.IP[:])
	buf[34] = byte(k.B.Port >> 8)
	buf[35] = byte(k.B.Port)

	// FNV-1a 64-bit — одна строка, без зависимостей.
	const (
		offset64 uint64 = 14695981039346656037
		prime64  uint64 = 1099511628211
	)
	h := offset64
	for _, b := range buf {
		h ^= uint64(b)
		h *= prime64
	}
	return h
}

// keyOf строит ключ потока из адресов и портов разобранного пакета.
func keyOf(d packet.Dissection, buf []byte) (flow.Key, bool) {
	th, ok := d.TCP(buf)
	if !ok {
		return flow.Key{}, false
	}
	var src, dst net.IP
	switch d.Version {
	case packet.Version4:
		h, ok := d.IPv4(buf)
		if !ok {
			return flow.Key{}, false
		}
		src, dst = net.IP(h.Src()), net.IP(h.Dst())
	case packet.Version6:
		h, ok := d.IPv6(buf)
		if !ok {
			return flow.Key{}, false
		}
		src, dst = net.IP(h.Src()), net.IP(h.Dst())
	default:
		return flow.Key{}, false
	}
	return flow.NewKey(src, th.SrcPort(), dst, th.DstPort()), true
}

func (e *Engine) packetConnMeta(pkt capture.Packet, sni string, localPort uint16, length int) proxy.ConnMeta {
	meta := proxy.ConnMeta{SNI: sni, IsClientHello: true, LocalPort: localPort}
	if !e.includePacketMetadata {
		return meta
	}
	meta.PayloadLength = length
	d, err := packet.Dissect(pkt.Data)
	if err != nil {
		return meta
	}
	if h, ok := d.TCP(pkt.Data); ok {
		meta.Port = h.DstPort()
	}
	var dst []byte
	if h, ok := d.IPv4(pkt.Data); ok {
		dst = h.Dst()
	} else if h, ok := d.IPv6(pkt.Data); ok {
		dst = h.Dst()
	}
	if ip, ok := netip.AddrFromSlice(dst); ok {
		meta.Host = ip.Unmap().String()
	}
	return meta
}
