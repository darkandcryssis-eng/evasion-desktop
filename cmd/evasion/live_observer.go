package main

import (
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/events"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/rtctrack"
)

// liveObserver — реализация intercept.Observer, которая кормит два независимых
// приёмника: events.Writer (журнал для оператора) и rtctrack.Tracker
// (статистика живучести Discord-соединений).
//
// Оба nil допустимы: observer становится дешёвой заглушкой.
//
// Отличается от outcomeObserver (observer.go, прокси) — тот про исходы
// соединений SOCKS. liveObserver — про жизненный цикл перехвата WinDivert.
type liveObserver struct {
	events *events.Writer
	rtc    *rtctrack.Tracker
}

// rtcVirtualPort — порт-заглушка для rtctrack.Pair, когда реальный порт
// недоступен в контексте вызова Observer.
const rtcVirtualPort uint16 = 0

// trackedExact — хосты, по которым имеет смысл копить статистику rtctrack.
// Это ключевые домены Discord-инфраструктуры: по их живости видно здоровье
// обхода в целом.
var trackedExact = map[string]struct{}{
	"cdn.discordapp.com":   {},
	"media.discordapp.net": {},
	"discord.com":          {},
	"gateway.discord.gg":   {},
	"updates.discord.com":  {},
}

// trackedRTCSuffix — суффикс голосовых RTC-серверов Discord (хосты вида
// c-arnXX-....discord.media). Полное имя у каждого соединения новое, поэтому
// совпадение по суффиксу, а не по точному имени.
const trackedRTCSuffix = ".discord.media"

// OnClientHelloSeen записывает событие и регистрирует попытку в rtctrack.
// Для rtctrack это Observe — факт того, что ClientHello увиден; успех/провал
// — отдельные сигналы ниже.
func (o *liveObserver) OnClientHelloSeen(flowID uint64, sni string, assembled bool) {
	if o.events != nil {
		o.events.Enqueue(events.Event{
			Kind:   events.KindClientHelloSeen,
			FlowID: events.FlowID(flowID),
			Attrs:  map[string]any{"sni": sni, "assembled": assembled},
		})
	}
	if o.rtc != nil && isTracked(sni) {
		o.rtc.Observe(rtctrack.Pair{SNI: sni, Port: rtcVirtualPort})
	}
}

// OnStrategyApplied — пакеты десинка отправлены. Это не значит, что сервер их
// принял и соединение живо: ответ сервера нам в этот момент неизвестен.
// rtctrack.Settled автоматически не ставится — иначе SuccessRate был бы 100%
// для всех соединений независимо от реального исхода. Истина выводится по
// отсутствию OnPassiveRetransmit:
//
//	SuccessRate = (Observed - Reset) / Observed,
//
// где Reset ставится на retransmit (явный провал первой попытки).
func (o *liveObserver) OnStrategyApplied(flowID uint64, sni string, strategyID core.StrategyID) {
	if o.events != nil {
		o.events.Enqueue(events.Event{
			Kind:   events.KindStrategyApplied,
			FlowID: events.FlowID(flowID),
			Attrs:  map[string]any{"sni": sni, "strategy": string(strategyID)},
		})
	}
}

// OnStrategyFailed — отказ применения. В rtctrack не трактуем как Reset:
// соединение могло пройти и без десинка (вне радиуса). Пишем только в журнал.
func (o *liveObserver) OnStrategyFailed(flowID uint64, sni string, strategyID core.StrategyID, reason string) {
	if o.events != nil {
		o.events.Enqueue(events.Event{
			Kind:   events.KindStrategyFailed,
			FlowID: events.FlowID(flowID),
			Attrs:  map[string]any{"sni": sni, "strategy": string(strategyID), "reason": reason},
		})
	}
}

// OnPassiveRetransmit — повтор ClientHello: первая попытка осталась без
// ответа, значит стратегия на этой паре не сработала. Регистрируем Reset в
// rtctrack: SuccessRate честно падает при повторах и растёт при их отсутствии.
func (o *liveObserver) OnPassiveRetransmit(flowID uint64, sni string, target string, strategyID core.StrategyID) {
	if o.events != nil {
		o.events.Enqueue(events.Event{
			Kind:   events.KindPassiveRetransmit,
			FlowID: events.FlowID(flowID),
			Attrs: map[string]any{
				"sni":      sni,
				"target":   target,
				"strategy": string(strategyID),
			},
		})
	}
	if o.rtc != nil && isTracked(sni) {
		o.rtc.Reset(rtctrack.Pair{SNI: sni, Port: rtcVirtualPort})
	}
}

// isTracked сообщает, стоит ли копить статистику по этому имени: точное
// совпадение с trackedExact либо суффикс trackedRTCSuffix. Критерии узкие
// намеренно — остальной радиус (youtube, googlevideo) к обходу Discord
// отношения не имеет и в снимке только засорял бы вывод.
func isTracked(sni string) bool {
	if _, ok := trackedExact[sni]; ok {
		return true
	}
	if len(sni) >= len(trackedRTCSuffix) &&
		sni[len(sni)-len(trackedRTCSuffix):] == trackedRTCSuffix {
		return true
	}
	return false
}

// статическая проверка соответствия интерфейсу.
var _ intercept.Observer = (*liveObserver)(nil)
