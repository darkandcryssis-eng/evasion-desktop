package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/desync"
	"github.com/fitting-1c/evasion/internal/executor"
	"github.com/fitting-1c/evasion/internal/socketexec"
)

// errNoProvider — конфиг без провайдера стратегий.
var errNoProvider = errors.New("proxy: не задан провайдер стратегий")

// errNoMatcher — GroupProvider без матчера радиуса.
var errNoMatcher = errors.New("proxy: не задан матчер радиуса поражения")

// handle обслуживает одно клиентское соединение целиком: рукопожатие SOCKS5,
// установку соединения с сервером, применение стратегии к ClientHello и
// перекладывание остального потока.
//
// Это горячее начало соединения в терминах правила 3 (4.2): движок трогает лишь
// первые пакеты, а дальше просто перекладывает поток. Логируются события
// жизненного цикла соединения — слой «всегда включено» (блок 7).
func (s *Server) handle(ctx context.Context, client net.Conn) {
	start := time.Now()
	defer client.Close()

	remote := client.RemoteAddr().String()
	s.log.Info("соединение принято", "remote", remote)

	if err := socksNegotiate(client); err != nil {
		s.log.Warn("рукопожатие SOCKS не удалось", "remote", remote, "err", err)
		return
	}

	target, err := socksReadConnect(client)
	if err != nil {
		// Команда не CONNECT или битый запрос: сообщаем клиенту отказ.
		_ = socksReply(client, socksReplyCommandNotSupported)
		s.log.Warn("запрос SOCKS отклонён", "remote", remote, "err", err)
		return
	}

	dialStart := time.Now()
	upstream, err := s.dial(ctx, "tcp", target.addr())
	connectAfter := time.Since(dialStart)
	if err != nil {
		_ = socksReply(client, socksReplyGeneralFailure)
		s.log.Warn("соединение с сервером не установлено", "target", target.addr(), "err", err)
		return
	}
	defer upstream.Close()

	if err := socksReply(client, socksReplySuccess); err != nil {
		s.log.Warn("ответ SOCKS не отправлен", "remote", remote, "err", err)
		return
	}

	// Включаем сегментацию на соединении с сервером: без выключенного Нейгла
	// подряд идущие записи стратегии склеятся в один сегмент (см. socketexec).
	if tcp, ok := upstream.(*net.TCPConn); ok {
		if err := socketexec.EnableSegmentation(tcp); err != nil {
			s.log.Warn("не удалось включить сегментацию", "err", err)
		}
	}

	// Вычленяем ClientHello. Дедлайн — на эту фазу; дальше перекладывание идёт
	// без него.
	if s.cfg.HelloTimeout > 0 {
		_ = client.SetReadDeadline(time.Now().Add(s.cfg.HelloTimeout))
	}
	res, readErr := readClientHello(client, s.cfg.HelloLimit)
	_ = client.SetReadDeadline(time.Time{})

	meta := ConnMeta{
		Host:          target.host,
		Port:          target.port,
		SNI:           res.sni,
		IsClientHello: res.isHello,
	}
	sel := s.cfg.Provider.Select(meta)

	label, applied := s.emitHead(ctx, upstream, res, sel)
	s.log.Info("начало соединения обработано",
		"target", target.addr(),
		"sni", res.sni,
		"is_tls", res.isHello,
		"strategy", label,
	)

	// Если при чтении ClientHello уже наступил конец потока от клиента, слать
	// нечего и перекладывать нечего в эту сторону — но ответ сервера мог ещё
	// прийти, поэтому релеим в любом случае.
	if readErr != nil && !errors.Is(readErr, io.EOF) && !isTimeout(readErr) {
		s.log.Warn("чтение начала потока прервано", "err", readErr)
	}

	rr := relay(client, upstream)
	s.log.Info("соединение закрыто",
		"target", target.addr(),
		"bytes_up", rr.up,
		"bytes_down", rr.down,
		"server_answered", rr.gotDown,
		"reset", isReset(rr.downErr),
		"duration_ms", time.Since(start).Milliseconds(),
	)
	s.reportOutcome(meta, sel, applied, rr, connectAfter)
}

// reportOutcome отдаёт исход соединения приёмнику, если он задан.
//
// Вызов идёт после перекладывания потока, то есть вне горячего начала
// соединения: исход становится известен только по его завершению.
func (s *Server) reportOutcome(meta ConnMeta, sel Selection, applied bool, rr relayResult, connect time.Duration) {
	if s.cfg.Outcomes == nil {
		return
	}
	outcome, reason := classifyConn(applied, rr)
	s.cfg.Outcomes.ConnOutcome(ConnOutcome{
		Target:            sel.Target,
		Host:              meta.Host,
		SNI:               meta.SNI,
		StrategyID:        sel.ID,
		Trial:             sel.Trial,
		StrategyApplied:   applied,
		Outcome:           outcome,
		Reason:            reason,
		At:                time.Now(),
		BytesUp:           rr.up,
		BytesDown:         rr.down,
		Connect:           connect,
		ConnectMeasured:   true,
		FirstByte:         rr.firstDownAfter,
		FirstByteMeasured: rr.firstDownMeasured,
	})
}

// emitHead отправляет серверу начало потока: через стратегию или как есть.
// Возвращает краткую метку применённого (для журнала): идентификатор стратегии,
// "observe", "passthrough" или "none".
func (s *Server) emitHead(ctx context.Context, upstream net.Conn, res helloResult, sel Selection) (label string, applied bool) {
	// Пересылка без изменений, если: режим наблюдения, стратегии нет, или
	// начало потока — не ClientHello (стратегия привязана к нему).
	if s.cfg.Observe || sel.Strategy == nil || !res.isHello {
		if len(res.buf) > 0 {
			_, _ = upstream.Write(res.buf)
		}
		switch {
		case s.cfg.Observe:
			return "observe", false
		case sel.Strategy == nil:
			return "none", false
		default:
			return "passthrough", false
		}
	}

	input := desync.Input{
		Direction:     core.DirectionOutbound,
		Payload:       res.hello(),
		Ordinal:       1,
		IsClientHello: true,
		Cuts:          res.cuts,
	}
	econn := socketexec.NewConn(upstream, input)

	err := s.exec.Execute(ctx, sel.Strategy, econn)
	if err != nil {
		var ce *executor.CapabilityError
		switch {
		case errors.As(err, &ce):
			// Стратегию выбрали неисполнимую: это ошибка контура выбора, а не
			// сети. Безопасно деградируем в прозрачный режим — рвать соединение
			// из-за своей ошибки недопустимо (1.6).
			s.log.Error("выбранная стратегия неисполнима, пропуск без изменений",
				"strategy", sel.ID, "missing", ce.Missing)
			if len(res.buf) > 0 {
				_, _ = upstream.Write(res.buf)
			}
			return "passthrough_fallback", false

		case !econn.Wrote():
			// Исполнение сорвалось до первой записи: например, стратегия
			// требует структурной точки разреза, которой у этого ClientHello
			// нет (desync.ErrCutUnavailable). Поток ещё не начат, поэтому
			// начало можно послать как есть и соединение уцелеет.
			//
			// Это отдельная ветвь, а не общий случай, потому что судить о
			// безопасности отката по виду ошибки нельзя: важен не вид, а факт
			// того, что в сокет ничего не уходило.
			s.log.Warn("стратегия не применена, пропуск без изменений",
				"strategy", sel.ID, "err", err)
			if len(res.buf) > 0 {
				_, _ = upstream.Write(res.buf)
			}
			return "passthrough_fallback", false

		default:
			// Запись уже начата: часть ClientHello ушла, восстановить поток
			// нельзя. Соединение будет закрыто релеем.
			// Часть ClientHello уже ушла в сеть, значит стратегия
			// применилась — пусть и не полностью. Исход принадлежит ей:
			// назвать такое соединение непроверенным значило бы скрыть
			// последствия собственной стратегии.
			s.log.Warn("исполнение стратегии прервано", "strategy", sel.ID, "err", err)
			return sel.ID.String(), true
		}
	}

	// Байты, прочитанные за записью ClientHello, досылаем как есть.
	if rest := res.rest(); len(rest) > 0 {
		_, _ = upstream.Write(rest)
	}
	return sel.ID.String(), true
}

// relay перекладывает данные между клиентом и сервером в обе стороны до
// закрытия любой из сторон. Возвращает число переданных байт в каждую сторону.
//
// При завершении одной стороны закрываются оба соединения: полузакрытие
// усложнило бы код без пользы для режима прокси, где обе стороны живут вместе.
func relay(client, upstream net.Conn) relayResult {
	var (
		wg      sync.WaitGroup
		rr      relayResult
		watcher = &downstreamWatcher{r: upstream, start: time.Now()}
		// ended запоминает, какая сторона кончилась первой. Это и есть
		// различие между «нас оборвали» и «пользователь ушёл», без которого
		// закрытие вкладки выглядело бы провалом стратегии.
		ended sync.Once
	)
	wg.Add(2)

	go func() {
		defer wg.Done()
		rr.up, _ = io.Copy(upstream, client)
		ended.Do(func() { rr.serverEndedFirst = false })
		// Разблокируем встречное копирование, закрыв соединения.
		_ = upstream.Close()
		_ = client.Close()
	}()
	go func() {
		defer wg.Done()
		var err error
		rr.down, err = io.Copy(client, watcher)
		ended.Do(func() {
			rr.serverEndedFirst = true
			rr.downErr = err
		})
		_ = client.Close()
		_ = upstream.Close()
	}()

	wg.Wait()

	rr.gotDown = watcher.got
	rr.firstDownByte = watcher.firstByte
	rr.firstDownAfter = watcher.after
	rr.firstDownMeasured = watcher.measured
	return rr
}

// isTimeout сообщает, является ли ошибка сетевым таймаутом. Таймаут при чтении
// ClientHello не аномален: клиент мог не прислать его сразу, и это не повод
// шуметь в журнале.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
