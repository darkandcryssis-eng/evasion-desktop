package events

import (
	"encoding/json"
	"fmt"
	"time"
)

// Kind — вид события жизненного цикла. Строковый тип, чтобы расширение
// (новый вид) было дополнением константы, без правок enum'а.
type Kind string

// Виды событий, которые пишет движок. Структура параметров (Attrs) у каждого
// вида задокументирована в комментариях — внешний потребитель волен опираться
// на них.
const (
	// KindFlowStarted — замечено новое TCP-соединение в радиусе.
	// Attrs: {"key": "src:port→dst:port"}.
	KindFlowStarted Kind = "flow.started"
	// KindClientHelloSeen — распознан ClientHello.
	// Attrs: {"sni": "...", "assembled": bool} (assembled=true, если имя
	// собрано из нескольких сегментов).
	KindClientHelloSeen Kind = "client_hello.seen"
	// KindStrategyApplied — стратегия выбрана и исполнена.
	// Attrs: {"sni": "...", "strategy": "...", "target": "..."}.
	KindStrategyApplied Kind = "strategy.applied"
	// KindStrategyFailed — стратегия не применилась (отказ, несовместимость).
	// Attrs: {"sni": "...", "strategy": "...", "reason": "..."}.
	KindStrategyFailed Kind = "strategy.failed"
	// KindFlowReset — соединение разорвано (RST), пассивный сигнал провала.
	// Attrs: {"sni": "...", "dir": "inbound|outbound"}.
	KindFlowReset Kind = "flow.reset"
	// KindFlowSettled — соединение прошло ClientHello и уже обменивается
	// шифрованным трафиком — пассивный сигнал успеха.
	// Attrs: {"sni": "...", "strategy": "..."}.
	KindFlowSettled Kind = "flow.settled"
	// KindPassiveRetransmit — повтор ClientHello, слабый пассивный сигнал
	// провала. Attrs: {"sni": "...", "target": "...", "strategy": "..."}.
	KindPassiveRetransmit Kind = "passive.retransmit"
	// KindGoroutinePanic — в фоновой горутине восстановлена паника. Процесс
	// жив, перехват переведён в прозрачный режим.
	// Attrs: {"name": "...", "panic": "..."}.
	KindGoroutinePanic Kind = "runtime.goroutine_panic"
	// KindKillswitchEngaged — killswitch поднят по падению связности с
	// контрольными целями. Attrs: {"targets_failed": [...], "attempts": N}.
	KindKillswitchEngaged Kind = "killswitch.engaged"
	// KindKillswitchReleased — killswitch снят, связность восстановлена.
	KindKillswitchReleased Kind = "killswitch.released"
	// KindSystemChangeApplied — зарегистрировано системное изменение (hosts,
	// firewall). Attrs: {"kind": "...", "id": "..."}.
	KindSystemChangeApplied Kind = "system.change_applied"
	// KindSystemChangeReverted — системное изменение откатано.
	KindSystemChangeReverted Kind = "system.change_reverted"
)

// FlowID — идентификатор соединения в пределах одного запуска.
// Простая обёртка над uint64, чтобы корреляция по значению была очевидной и
// неосторожное смешение с другими числами не компилировалось.
type FlowID uint64

// String для FlowID — hex-представление: короче decimal, легко grep'ать.
func (f FlowID) String() string { return fmt.Sprintf("%016x", uint64(f)) }

// Event — одно зарегистрированное событие.
//
// Поля именованы коротко: это читается глазами в `tail -f events.jsonl`, и
// длинные ключи делали бы вывод нечитаемым. Длинные имена оставлены Attrs,
// где каждый вид сам решает, что писать.
type Event struct {
	At     time.Time      `json:"at"`
	Kind   Kind           `json:"kind"`
	FlowID FlowID         `json:"flow,omitempty"`
	Attrs  map[string]any `json:"attrs,omitempty"`
}

// eventWire — транспортная форма Event: FlowID как строка hex. Используется и
// MarshalJSON, и UnmarshalJSON, чтобы симметрия была очевидной.
type eventWire struct {
	At     time.Time      `json:"at"`
	Kind   Kind           `json:"kind"`
	FlowID string         `json:"flow,omitempty"`
	Attrs  map[string]any `json:"attrs,omitempty"`
}

// MarshalJSON сериализует Event в компактный JSON без пробелов, годный к
// JSON Lines (одна строка — одно событие). FlowID пишется в hex (16
// символов), нулевой опускается.
func (e Event) MarshalJSON() ([]byte, error) {
	a := eventWire{
		At:    e.At,
		Kind:  e.Kind,
		Attrs: e.Attrs,
	}
	if e.FlowID != 0 {
		a.FlowID = e.FlowID.String()
	}
	return json.Marshal(a)
}

// UnmarshalJSON — симметричная десериализация. Пустой или отсутствующий
// FlowID даёт нулевой; невалидный hex — ошибку.
func (e *Event) UnmarshalJSON(data []byte) error {
	var a eventWire
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	e.At = a.At
	e.Kind = a.Kind
	e.Attrs = a.Attrs
	e.FlowID = 0
	if a.FlowID != "" {
		var v uint64
		if _, err := fmt.Sscanf(a.FlowID, "%x", &v); err != nil {
			return fmt.Errorf("events: разбор FlowID %q: %w", a.FlowID, err)
		}
		e.FlowID = FlowID(v)
	}
	return nil
}
