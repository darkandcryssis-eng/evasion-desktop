package control

import (
	"context"
	"errors"
	"log/slog"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/scoring"
)

// errUnexpectedReply — ответ не того типа, какой ожидался. Означает дефект в
// самом контуре, а не ошибку вызывающего, поэтому отдельная сигнальная ошибка:
// в журнале её видно сразу.
var errUnexpectedReply = errors.New("control: неожиданный тип ответа на команду")

// Команды контура. Числа не сериализуются и наружу не видны: снаружи есть
// только методы Engine, а канал команд — внутренний шов.
type commandKind int

const (
	cmdStatus commandKind = iota
	cmdReplan
	cmdPin
	cmdUnpin
	cmdCollateral
	cmdAllowCollateral
	cmdAdd
	cmdReload
	cmdVantage
	cmdProbeItems
)

// command — единица работы, приходящая контуру извне.
//
// Команды передаются каналом, а не правкой состояния (4.2, правило 2). Ответ
// возвращается своим каналом внутри команды: так вызывающий узнаёт и об
// ошибке, и о том, что команда действительно исполнена, а не просто поставлена
// в очередь. Для команд вроде закрепления это существенно — за ними следует
// пересчёт снимка, и CLI обязан дождаться его, прежде чем докладывать об
// успехе.
type command struct {
	kind     commandKind
	target   string
	strategy core.StrategyID
	flag     bool
	holding  Holding
	control  Config
	scoring  scoring.Config
	targets  []string
	vantage  core.VantageID
	done     chan result
}

// result — ответ на команду.
type result struct {
	value any
	err   error
}

// reply отправляет ответ. Канал буферизован на одну запись, поэтому владелец
// никогда не ждёт вызывающего: иначе отменённый вызов заблокировал бы контур.
func (c command) reply(value any, err error) {
	if c.done == nil {
		return
	}
	select {
	case c.done <- result{value: value, err: err}:
	default:
	}
}

// send отправляет команду и ждёт ответа.
//
// Возвращает ошибку контекста, если ждать больше нельзя: контур мог быть
// остановлен, и вечное ожидание ответа превратило бы остановку движка в
// зависание CLI.
func (e *Engine) send(ctx context.Context, c command) (any, error) {
	c.done = make(chan result, 1)
	select {
	case e.cmds <- c:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case r := <-c.done:
		return r.value, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Replan просит пересчитать снимок немедленно.
func (e *Engine) Replan(ctx context.Context) error {
	_, err := e.send(ctx, command{kind: cmdReplan})
	return err
}

// Pin закрепляет стратегию за целью. Закрепление обходит пороги автопилота:
// это осознанная команда человека (см. doc.go).
func (e *Engine) Pin(ctx context.Context, target string, id core.StrategyID) error {
	_, err := e.send(ctx, command{kind: cmdPin, target: target, strategy: id})
	return err
}

// Unpin снимает закрепление с цели.
func (e *Engine) Unpin(ctx context.Context, target string) error {
	_, err := e.send(ctx, command{kind: cmdUnpin, target: target})
	return err
}

// SetCollateral отмечает или снимает признак побочного вреда (4.5).
//
// Признак приходит извне потому, что измеряется он не здесь: побочный вред
// определяется по контрольным целям, которые обязаны работать всегда, и это
// дело проб, а не контура.
func (e *Engine) SetCollateral(ctx context.Context, id core.StrategyID, detected bool) error {
	_, err := e.send(ctx, command{kind: cmdCollateral, strategy: id, flag: detected})
	return err
}

// AllowCollateral разрешает применять стратегию, несмотря на побочный вред
// (4.5: «без явного разрешения владельца» — вот оно, это разрешение).
//
// Разрешение снимает запрет, но не отменяет лестницу допуска: уже снятая
// стратегия вернётся через долю проверки, а не прыжком на весь трафик. Так
// сделано потому, что разрешение касается вреда, а не доказательств, — а
// доказательства после снятия надо набрать заново. Кому нужно «применяй
// немедленно», тот пользуется Pin: это другая команда и другая
// ответственность.
func (e *Engine) AllowCollateral(ctx context.Context, id core.StrategyID, allowed bool) error {
	_, err := e.send(ctx, command{kind: cmdAllowCollateral, strategy: id, flag: allowed})
	return err
}

// Add добавляет стратегию в портфель.
func (e *Engine) Add(ctx context.Context, id core.StrategyID, h Holding) error {
	_, err := e.send(ctx, command{kind: cmdAdd, strategy: id, holding: h})
	return err
}

// Reload применяет новые параметры и радиус без перезапуска (10.5).
//
// targets == nil означает «радиус не менять». Пустой непустой срез означает
// «радиус пуст» — и это разные вещи, поэтому различать их обязательно.
func (e *Engine) Reload(ctx context.Context, c Config, s scoring.Config, targets []string) error {
	_, err := e.send(ctx, command{kind: cmdReload, control: c, scoring: s, targets: targets})
	return err
}

// SetVantage переводит контур в другую точку наблюдения (6.2): при смене сети
// оценки прежней точки неприменимы.
func (e *Engine) SetVantage(ctx context.Context, v core.VantageID) error {
	_, err := e.send(ctx, command{kind: cmdVantage, vantage: v})
	return err
}

// Status отдаёт состояние контура.
func (e *Engine) Status(ctx context.Context) (Status, error) {
	v, err := e.send(ctx, command{kind: cmdStatus})
	if err != nil {
		return Status{}, err
	}
	st, ok := v.(Status)
	if !ok {
		return Status{}, errUnexpectedReply
	}
	return st, nil
}

// discardHandler — обработчик журнала, который ничего не пишет. Нужен, чтобы
// контур без журнала не проверял nil на каждой записи.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h discardHandler) WithGroup(string) slog.Handler           { return h }
