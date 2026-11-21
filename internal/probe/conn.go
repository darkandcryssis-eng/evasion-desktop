package probe

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/desync"
	"github.com/fitting-1c/evasion/internal/executor"
	"github.com/fitting-1c/evasion/internal/socketexec"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/tlsparse"
)

// ErrStrategyNotApplied — стратегию применить не удалось.
//
// Отдельная ошибка нужна классификации исходов: такая неудача не говорит о
// цензоре ничего, и наблюдение обязано стать «не определено», а не провалом.
var ErrStrategyNotApplied = errors.New("probe: стратегия не применена")

// helloConn — соединение, у которого ПЕРВАЯ запись проходит через стратегию.
//
// Зачем так. Пробе нужно и применить десинк к ClientHello, и получить
// полноценный сеанс TLS для медленного уровня. Собрать ClientHello самим
// значило бы завести собственный сборщик сообщений и лишиться возможности
// завершить рукопожатие, то есть замерить полосу. Поэтому сообщение формирует
// crypto/tls, а мы перехватываем ровно его первую запись: в ней и лежит
// ClientHello.
//
// Неочевидное следствие, из-за которого здесь нужны комментарии: Write обязан
// сообщить вызывающему, что записал ВСЕ байты, хотя фактически отправил их
// частями через исполнителя. Для crypto/tls частичная запись — нарушение
// контракта io.Writer, и он прервал бы рукопожатие.
//
// Пакет proxy решает ту же задачу иначе, и это не дублирование: там
// ClientHello приходит от клиента, то есть байты известны до отправки, и
// перехватывать нечего. Общая часть — десяток строк «разобрать, вычислить
// точки разреза, исполнить», и ради них заводить общий пакет означало бы
// связать proxy с crypto/tls без надобности.
type helloConn struct {
	net.Conn

	exec  executor.Executor
	strat *strategy.Strategy
	ctx   context.Context

	// mu защищает поля ниже. Запись в соединение идёт из одной горутины
	// (рукопожатие последовательно), но Applied и ApplyErr читает проба после
	// завершения, и без защиты это была бы гонка.
	mu sync.Mutex
	// done — первая запись уже обработана.
	done bool
	// applied — стратегия была фактически применена.
	applied bool
	// applyErr — ошибка применения стратегии, если была.
	applyErr error
	// sent — в сеть ушло хоть что-то. По этому признаку решается, можно ли
	// безопасно откатиться к отправке без изменений.
	sent bool
}

// newHelloConn оборачивает соединение. Стратегия nil означает отправку без
// изменений — обёртка тогда прозрачна.
func newHelloConn(ctx context.Context, c net.Conn, exec executor.Executor, s *strategy.Strategy) *helloConn {
	return &helloConn{Conn: c, exec: exec, strat: s, ctx: ctx}
}

// Write отправляет данные, применяя стратегию к первой записи.
func (c *helloConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	first := !c.done
	if first {
		c.done = true
	}
	c.mu.Unlock()

	if !first || c.strat == nil {
		return c.Conn.Write(b)
	}
	return c.writeHello(b)
}

// writeHello проводит первую запись через стратегию.
//
// Возвращает len(b) при успехе: для вызывающего запись обязана выглядеть
// целой, независимо от того, на сколько частей её разбил исполнитель.
func (c *helloConn) writeHello(b []byte) (int, error) {
	ch, err := tlsparse.ParseClientHello(b)
	if err != nil {
		// Первая запись оказалась не ClientHello: отправляем как есть и
		// отмечаем, что стратегия не применялась. Молчаливо считать её
		// применённой нельзя — это испортило бы статистику.
		c.note(false, nil)
		return c.passthrough(b)
	}

	// Имя сервера здесь не извлекаем: пробе оно известно заранее из запроса,
	// а разбирать его повторно значило бы тратить время на горячем пути.
	in := desync.Input{
		Direction:     core.DirectionOutbound,
		Payload:       b[:ch.Record.End()],
		Ordinal:       1,
		IsClientHello: true,
		Cuts:          ch.CutPoints(make([]core.CutPoint, 0, 8)),
	}

	econn := socketexec.NewConn(c.Conn, in)
	if err := c.exec.Execute(c.ctx, c.strat, econn); err != nil {
		if econn.Wrote() {
			// Часть байт уже ушла: поток необратимо начат, восстановить его
			// нельзя. Сообщаем ошибку — соединение будет закрыто.
			c.note(true, err)
			c.markSent()
			return 0, err
		}
		// В сеть ничего не ушло: отправляем начало без изменений, чтобы
		// соединение уцелело, и помечаем, что стратегия не применена.
		c.note(false, err)
		return c.passthrough(b)
	}
	c.note(true, nil)
	c.markSent()

	// Байты за записью ClientHello (если вызывающий прислал их тем же куском)
	// досылаем как есть: стратегия привязана к записи, а не к буферу.
	if rest := b[ch.Record.End():]; len(rest) > 0 {
		if _, err := c.Conn.Write(rest); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// passthrough отправляет буфер без изменений.
func (c *helloConn) passthrough(b []byte) (int, error) {
	c.markSent()
	return c.Conn.Write(b)
}

// note запоминает, была ли стратегия применена и с какой ошибкой.
func (c *helloConn) note(applied bool, err error) {
	c.mu.Lock()
	c.applied = applied
	c.applyErr = err
	c.mu.Unlock()
}

// markSent отмечает, что в сеть что-то ушло.
func (c *helloConn) markSent() {
	c.mu.Lock()
	c.sent = true
	c.mu.Unlock()
}

// state возвращает сведения о применении стратегии.
func (c *helloConn) state() (applied bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applied, c.applyErr
}
