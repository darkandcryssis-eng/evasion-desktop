package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/executor"
	"github.com/fitting-1c/evasion/internal/socketexec"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// Значения по умолчанию. Применяются только там, где конфиг оставил поле
// нулевым: все эти числа принадлежат конфигурации (10.1), а здесь задана
// разумная подстановка, чтобы пакет был пригоден без неё.
const (
	// defaultMinTimeout — нижняя граница срока ожидания. Провал должен
	// разрешаться примерно за секунду (5.3 п. 1), и снижать границу дальше
	// нельзя: на медленном канале это давало бы ложные провалы.
	defaultMinTimeout = 1500 * time.Millisecond
	// defaultMaxTimeout — верхняя граница. Нужна потому, что срок выводится из
	// измеренного RTT, а единственный выброс в измерении иначе растянул бы
	// каждую последующую пробу.
	defaultMaxTimeout = 8 * time.Second
	// defaultRTTFactor — во сколько раз срок ожидания превышает базовый RTT.
	// Рукопожатие TLS — это один или два оборота плюс работа сервера, поэтому
	// кратность берётся с запасом.
	defaultRTTFactor = 12
	// defaultSlowWindow — окно наблюдения полосы на медленном уровне.
	defaultSlowWindow = 8 * time.Second
	// defaultReadBuffer — размер буфера чтения при замере полосы.
	defaultReadBuffer = 32 << 10
	// minThroughputWindow — наименьшее окно, при котором скорость вообще
	// имеет смысл вычислять. Ниже него разрешения таймера не хватает, и
	// частное «байты на время» перестаёт что-либо означать.
	minThroughputWindow = 50 * time.Millisecond
)

// DialFunc устанавливает соединение TCP.
//
// Вынесен в конфиг, чтобы пробы проверялись на соединении в памяти или на
// локальном слушателе, без выхода в сеть.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Config задаёт параметры пробника.
type Config struct {
	// Executor — исполнитель стратегии. Обязателен.
	Executor executor.Executor
	// Dial — установка соединения; nil означает обычный сетевой диалер.
	Dial DialFunc
	// MinTimeout, MaxTimeout — границы срока ожидания.
	MinTimeout, MaxTimeout time.Duration
	// RTTFactor — кратность срока ожидания к базовому RTT.
	RTTFactor int
	// SlowWindow — окно наблюдения полосы.
	SlowWindow time.Duration
	// MinThroughput — порог полосы в байтах в секунду, ниже которого исход
	// считается замедлением. Ноль отключает различение замедления.
	MinThroughput int64
}

// Prober проводит пробы.
//
// Базовый RTT хранится в пробнике, а не передаётся в каждый вызов, потому что
// это свойство точки наблюдения, а не отдельной пробы. Пробник не
// потокобезопасен: предполагается по экземпляру на горутину воркера (5.4).
type Prober struct {
	cfg     Config
	baseRTT time.Duration
}

// New создаёт пробник. Исполнитель обязателен: без него нечем применять
// стратегию, а проба без стратегии измеряла бы только доступность цели.
func New(cfg Config) (*Prober, error) {
	if cfg.Executor == nil {
		return nil, errors.New("probe: не задан исполнитель стратегии")
	}
	if cfg.MinTimeout <= 0 {
		cfg.MinTimeout = defaultMinTimeout
	}
	if cfg.MaxTimeout <= 0 {
		cfg.MaxTimeout = defaultMaxTimeout
	}
	if cfg.RTTFactor <= 0 {
		cfg.RTTFactor = defaultRTTFactor
	}
	if cfg.SlowWindow <= 0 {
		cfg.SlowWindow = defaultSlowWindow
	}
	if cfg.Dial == nil {
		var d net.Dialer
		cfg.Dial = d.DialContext
	}
	return &Prober{cfg: cfg}, nil
}

// BaseRTT возвращает текущий базовый RTT. Ноль означает «не измерен».
func (p *Prober) BaseRTT() time.Duration { return p.baseRTT }

// SetBaseRTT задаёт базовый RTT.
//
// Нужен отдельным методом, потому что измеряется он по контрольным целям, а
// применяется ко всем пробам: смешивать измерение с применением в одном вызове
// значило бы пересчитывать базу на каждой пробе и получать срок ожидания,
// зависящий от последней цели.
func (p *Prober) SetBaseRTT(d time.Duration) {
	if d > 0 {
		p.baseRTT = d
	}
}

// timeout вычисляет срок ожидания для пробы.
//
// Выводится из измеренного RTT, а не задаётся константой (5.3 п. 1): на
// быстром канале константа означала бы, что каждый провал стоит секунды,
// а на медленном — что рабочая стратегия объявляется провалом.
func (p *Prober) timeout() time.Duration {
	if p.baseRTT <= 0 {
		return p.cfg.MinTimeout
	}
	t := time.Duration(p.cfg.RTTFactor) * p.baseRTT
	if t < p.cfg.MinTimeout {
		return p.cfg.MinTimeout
	}
	if t > p.cfg.MaxTimeout {
		return p.cfg.MaxTimeout
	}
	return t
}

// MeasureBaseRTT измеряет базовый RTT по времени установки соединения TCP.
//
// Берётся наименьшее из удачных измерений, а не среднее: нас интересует
// свойство канала, а единственная задержка из-за занятости сервера или потери
// пакета завысила бы среднее и растянула бы сроки ожидания всех последующих
// проб. Наименьшее значение ближе к настоящему времени оборота.
//
// Цели должны быть контрольными, то есть заведомо доступными: измерять RTT по
// заблокированной цели бессмысленно — соединение до неё может устанавливаться
// как угодно.
func (p *Prober) MeasureBaseRTT(ctx context.Context, targets []string) (time.Duration, error) {
	if len(targets) == 0 {
		return 0, errors.New("probe: не заданы цели для измерения RTT")
	}

	var (
		samples []time.Duration
		lastErr error
	)
	for _, t := range targets {
		dctx, cancel := context.WithTimeout(ctx, p.cfg.MaxTimeout)
		start := time.Now()
		conn, err := p.cfg.Dial(dctx, "tcp", t)
		elapsed := time.Since(start)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		_ = conn.Close()
		samples = append(samples, elapsed)
	}

	best, measured := pickMinRTT(samples)
	if !measured {
		if lastErr != nil {
			return 0, fmt.Errorf("probe: ни одна контрольная цель не ответила: %w", lastErr)
		}
		return 0, errors.New("probe: ни одна контрольная цель не ответила")
	}
	// Ноль означает «быстрее разрешения таймера». Сохранять его как базовый
	// RTT нельзя (SetBaseRTT такое значение отвергает), и срок ожидания тогда
	// берётся по нижней границе — это верное поведение: вычислять срок от
	// неизмеримо малого значения всё равно нечем.
	p.SetBaseRTT(best)
	return best, nil
}

// pickMinRTT выбирает наименьшее измерение и сообщает, было ли оно вообще.
//
// Выделено отдельной функцией ради проверяемости. Признак «измерение было»
// обязан держаться отдельно от значения: на Windows разрешение таймера грубое,
// и для соединения по петле или в локальной сети time.Since возвращает ровно
// ноль. Если считать нулём отсутствие данных, быстрый канал выглядел бы как
// недоступная цель — именно так и проявился этот дефект на рабочей машине.
//
// Проверить такое через настоящие соединения можно только на Windows: на
// системах с наносекундным таймером нулевое измерение не воспроизвести.
// Поэтому выбор минимума сделан чистой функцией — её поведение при нуле
// проверяется где угодно и без сети.
func pickMinRTT(samples []time.Duration) (best time.Duration, measured bool) {
	for _, s := range samples {
		// Отрицательное измерение невозможно при исправных часах, но принять
		// его как наименьшее значило бы испортить все последующие сроки.
		if s < 0 {
			continue
		}
		if !measured || s < best {
			best = s
			measured = true
		}
	}
	return best, measured
}

// Request описывает пробу.
type Request struct {
	// Target — цель в виде host:port.
	Target string
	// SNI — имя сервера для ClientHello. Пусто означает «взять из Target».
	SNI string
	// Strategy — применяемая стратегия; nil означает пробу без десинка.
	Strategy *strategy.Strategy
	// StrategyID — идентификатор стратегии для записи в наблюдение.
	StrategyID core.StrategyID
}

// serverName возвращает имя сервера для рукопожатия.
func (r Request) serverName() string {
	if r.SNI != "" {
		return r.SNI
	}
	host, _, err := net.SplitHostPort(r.Target)
	if err != nil {
		return r.Target
	}
	return host
}

// Fast проводит пробу быстрого уровня: рукопожатие TCP и TLS.
//
// Вердикт выносится по завершению рукопожатия, и ничего сверх него не
// делается: генетическому алгоритму достаточно двоичного «обманулся ли DPI»
// (5.3). Ранний вердикт получается сам собой — рукопожатие либо завершилось,
// либо сорвалось, досиживать окно не требуется.
func (p *Prober) Fast(ctx context.Context, req Request) Result {
	res := Result{
		Target:     req.Target,
		SNI:        req.serverName(),
		StrategyID: req.StrategyID,
		Phase:      core.PhaseFast,
		Started:    time.Now(),
	}

	conn, err := p.handshake(ctx, req, &res)
	res.Elapsed = time.Since(res.Started)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		res.Outcome = core.OutcomeOK
		res.Reason = core.ReasonHandshakeDone
	}
	return res
}

// Slow проводит пробу медленного уровня: рукопожатие и форма полосы за окно.
//
// Применяется только к стратегиям, дошедшим до решения о повышении (5.3):
// окно наблюдения стоит секунды, и тратить его на каждого кандидата значило бы
// сжечь бюджет живых прогонов в таймаутах.
func (p *Prober) Slow(ctx context.Context, req Request) Result {
	res := Result{
		Target:     req.Target,
		SNI:        req.serverName(),
		StrategyID: req.StrategyID,
		Phase:      core.PhaseSlow,
		Started:    time.Now(),
	}

	conn, err := p.handshake(ctx, req, &res)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		res.Elapsed = time.Since(res.Started)
		return res
	}

	// Рукопожатие прошло — замеряем полосу. Исход рукопожатия при этом уже
	// известен и не теряется: если замер не удастся, останется вердикт по
	// рукопожатию.
	res.Outcome = core.OutcomeOK
	res.Reason = core.ReasonHandshakeDone

	bytesDown, window, rerr := p.measureThroughput(ctx, conn, req.serverName())
	res.BytesDown = bytesDown
	res.Elapsed = time.Since(res.Started)

	// Скорость вычисляется только при достаточно длинном окне наблюдения.
	//
	// Это главная тонкость медленного уровня. Ответ может прийти быстрее
	// разрешения таймера, и тогда окно равно нулю: делить на него нельзя, а
	// записать нулевую скорость было бы прямым вредом — мгновенный ответ
	// оказался бы признан замедлением, и рабочая стратегия получила бы штраф.
	// Поэтому при коротком окне скорость считается НЕИЗМЕРЕННОЙ, и вердикт о
	// замедлении не выносится вовсе: нет данных — нет вердикта.
	if window >= minThroughputWindow && bytesDown > 0 {
		res.Throughput = int64(float64(bytesDown) / window.Seconds())
		res.ThroughputMeasured = true
	}

	switch {
	case rerr != nil && bytesDown == 0:
		// Рукопожатие прошло, а данных не пришло вовсе: соединение сорвано
		// после рукопожатия. Это полноценный провал, а не неопределённость.
		res.Outcome = core.OutcomeFail
		res.Reason = classifyNetError(rerr)
		res.Err = rerr.Error()
	case res.ThroughputMeasured && p.cfg.MinThroughput > 0 && res.Throughput < p.cfg.MinThroughput:
		res.Outcome = core.OutcomeThrottled
		res.Reason = core.ReasonThroughputLow
	}
	return res
}

// handshake устанавливает соединение и проводит рукопожатие TLS, заполняя
// обстоятельства исхода в res.
//
// При неудаче res уже содержит исход и причину, поэтому вызывающему остаётся
// только вернуть его. Соединение возвращается даже при ошибке рукопожатия,
// чтобы вызывающий закрыл его.
func (p *Prober) handshake(ctx context.Context, req Request, res *Result) (net.Conn, error) {
	timeout := p.timeout()
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	connectStart := time.Now()
	raw, err := p.cfg.Dial(dctx, "tcp", req.Target)
	if err != nil {
		// Соединение не установилось — ClientHello не отправлялся, значит
		// стратегия не проверялась. Исход «не определено» независимо от
		// причины: приписать стратегии чужую неудачу нельзя.
		res.Outcome = core.OutcomeInconclusive
		res.Reason = classifyDialError(err)
		res.Err = err.Error()
		return nil, err
	}
	res.ConnectRTT = time.Since(connectStart)
	res.Connected = true

	// Выключаем задержку Нейгла: без этого подряд идущие записи стратегии
	// склеятся в один сегмент, и разрез не доедет до сети.
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = socketexec.EnableSegmentation(tcp)
	}

	hc := newHelloConn(dctx, raw, p.cfg.Executor, req.Strategy)
	tconn := tls.Client(hc, &tls.Config{
		ServerName: req.serverName(),
		// Подлинность сертификата не проверяется намеренно: измеряется
		// достижимость, а не подлинность. Обоснование и цена — в doc.go.
		// На пути пользовательского трафика это недопустимо.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})

	hsStart := time.Now()
	hsErr := tconn.HandshakeContext(dctx)
	res.HandshakeTime = time.Since(hsStart)

	applied, applyErr := hc.state()
	res.StrategyApplied = applied && req.Strategy != nil

	if hsErr == nil {
		return tconn, nil
	}

	switch {
	case req.Strategy != nil && !applied:
		// Стратегию применить не удалось: про цензора это не говорит ничего.
		res.Outcome = core.OutcomeInconclusive
		res.Reason = core.ReasonStrategyNotApplied
		res.Err = joinErrors(applyErr, hsErr)
	default:
		res.Outcome, res.Reason = classifyHandshakeError(ctx, hsErr)
		res.Err = hsErr.Error()
	}
	return tconn, hsErr
}

// measureThroughput отправляет минимальный запрос и считает принятые байты за
// окно наблюдения.
//
// Запрос намеренно простейший: нас интересует форма полосы, а не содержимое
// ответа. Чтение идёт до истечения окна или до конца ответа; окно
// ограничивается и контекстом, чтобы проба не продолжалась после отмены.
func (p *Prober) measureThroughput(ctx context.Context, conn net.Conn, host string) (int64, time.Duration, error) {
	wctx, cancel := context.WithTimeout(ctx, p.cfg.SlowWindow)
	defer cancel()

	deadline, _ := wctx.Deadline()
	_ = conn.SetDeadline(deadline)

	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: evasion-probe\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return 0, 0, err
	}

	start := time.Now()
	buf := make([]byte, defaultReadBuffer)
	var total int64
	for {
		n, err := conn.Read(buf)
		total += int64(n)
		if err != nil {
			elapsed := time.Since(start)
			// Конец ответа и истечение окна — не ошибки замера: данные
			// получены, полосу посчитать можно.
			if errors.Is(err, io.EOF) || isTimeout(err) {
				return total, elapsed, nil
			}
			return total, elapsed, err
		}
	}
}

// classifyDialError определяет причину неудачи установки соединения.
func classifyDialError(err error) core.Reason {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return core.ReasonResolveFailed
	}
	if errors.Is(err, context.Canceled) {
		return core.ReasonCanceled
	}
	// Истечение срока на установке соединения тоже не говорит о стратегии:
	// ClientHello не отправлялся. Причина различается, исход — нет.
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return core.ReasonTimeout
	}
	return core.ReasonConnectFailed
}

// classifyHandshakeError определяет исход и причину неудачи рукопожатия.
//
// Здесь и находится главное различение быстрого уровня: сброс и зависание —
// это провал стратегии, а ответ сервера на уровне TLS означает, что до
// сервера мы дошли, и вердикта о цензоре из этого не следует.
func classifyHandshakeError(ctx context.Context, err error) (core.Outcome, core.Reason) {
	// Отмена извне — не свойство стратегии.
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return core.OutcomeInconclusive, core.ReasonCanceled
	}
	if errors.Is(err, context.Canceled) {
		return core.OutcomeInconclusive, core.ReasonCanceled
	}

	// Сервер ответил предупреждением TLS: значит рукопожатие дошло до него.
	var alert tls.RecordHeaderError
	if errors.As(err, &alert) {
		return core.OutcomeInconclusive, core.ReasonTLSRejected
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		// Проверка подлинности отключена, но если ошибка всё же пришла —
		// сервер достигнут, и это не вердикт о цензоре.
		return core.OutcomeInconclusive, core.ReasonTLSRejected
	}

	if isReset(err) {
		return core.OutcomeFail, core.ReasonReset
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) || errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return core.OutcomeFail, core.ReasonTimeout
	}
	// Неразобранная ошибка: безопаснее признать её неопределённой, чем
	// записать стратегии провал, которого могло не быть.
	return core.OutcomeInconclusive, core.ReasonLocalError
}

// classifyNetError определяет причину сетевой ошибки после рукопожатия.
func classifyNetError(err error) core.Reason {
	if isReset(err) {
		return core.ReasonReset
	}
	if isTimeout(err) || errors.Is(err, context.DeadlineExceeded) {
		return core.ReasonTimeout
	}
	return core.ReasonLocalError
}

// isTimeout сообщает, является ли ошибка сетевым истечением срока.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// joinErrors соединяет описания двух ошибок, пропуская пустые.
func joinErrors(a, b error) string {
	switch {
	case a != nil && b != nil:
		return a.Error() + "; " + b.Error()
	case a != nil:
		return a.Error()
	case b != nil:
		return b.Error()
	default:
		return ""
	}
}
