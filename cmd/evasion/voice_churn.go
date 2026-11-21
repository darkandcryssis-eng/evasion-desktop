package main

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/intercept"
)

// voiceChurn — автоматический обход «дёргающегося» голосового сервера Discord.
//
// Проблема. Входящий медиа-поток (сервер→клиент) к части стокгольмских RTC-
// серверов (`c-arnNN-*.discord.media`) режется TSPU. Discord этого не знает:
// control-сокет (WSS) поднимается, канал входит, но голоса нет (heartbeat
// `last received sequence number: -1`), через ~15 сек соединение рвётся
// (`1006` / `4801 Cannot resume`) и Discord переподключается к ТОМУ ЖЕ серверу
// по кругу — пользователь слышит бесконечный «вход/выход». Сервер сам по себе
// не выбирается заново, пока Discord не упрётся достаточно раз.
//
// Чего движок сделать не может: переключить Override Region (это настройка
// канала на стороне аккаунта Discord, за TLS, требует прав). Что может:
// заметить цикл и ускорить уход. Если один и тот же `*.discord.media` SNI
// получает подряд несколько ClientHello за короткое окно — это и есть цикл
// переподключений. Такой SNI помечается, и движок перестаёт его десинкать
// (intercept спускает его сырьём): DPI видит открытый SNI и рвёт control-сокет
// немедленно, Discord быстрее упирается и запрашивает у гейтвея ДРУГОЙ сервер,
// вместо того чтобы минуту крутиться на мёртвом. Пометка временная (TTL): если
// позже Discord вернётся на этот сервер «на холодную», он снова получит
// честную попытку десинка.
//
// Безопасность радиуса. Детектор действует ТОЛЬКО на `*.discord.media` (голос).
// CDN/gateway/прочий HTTPS он не трогает никогда: для них «пропустить сырьём»
// означало бы утечку SNI и обрыв картинок (net_error -101), ровно та регрессия,
// которую чинили в сборке. Поэтому и Observe, и Contains жёстко ограничены
// голосовым суффиксом.
type voiceChurn struct {
	log *slog.Logger
	now func() time.Time

	threshold int           // сколько ClientHello за окно считается циклом
	window    time.Duration // окно подсчёта переподключений
	ttl       time.Duration // как долго держать сервер «обходимым» после срабатывания

	mu           sync.Mutex
	seen         map[string][]time.Time // SNI → недавние времена ClientHello
	blockedUntil map[string]time.Time   // SNI → до какого времени обходим
}

// Пороги. Консервативны: здоровое голосовое подключение — ОДИН ClientHello,
// держащий соединение весь звонок. Три переподключения к одному и тому же
// серверу за минуту — это уже цикл (в поле: `4801 Cannot resume` к тому же
// `c-arnNN-*` раз в ~15-20 сек). Channel-switch сюда не попадает: там каждый
// заход идёт на СВОЙ сервер (разные SNI), счётчик по одному SNI не растёт.
const (
	voiceChurnThreshold = 3
	voiceChurnWindow    = 60 * time.Second
	// TTL длиннее окна: пока держим сервер обходимым, Discord успевает уйти на
	// другой; по истечении — честная попытка заново, не вечный бан.
	voiceChurnTTL = 90 * time.Second
)

// voiceSNISuffix — суффикс голосовых RTC-серверов Discord. Только по нему
// детектор и действует.
const voiceSNISuffix = ".discord.media"

// newVoiceChurn создаёт детектор с консервативными порогами и системными
// часами. nil-логгер недопустим у вызывающего (intercept всегда с логом).
func newVoiceChurn(log *slog.Logger) *voiceChurn {
	return &voiceChurn{
		log:          log,
		now:          time.Now,
		threshold:    voiceChurnThreshold,
		window:       voiceChurnWindow,
		ttl:          voiceChurnTTL,
		seen:         make(map[string][]time.Time),
		blockedUntil: make(map[string]time.Time),
	}
}

// isVoiceSNI сообщает, что имя — голосовой RTC-сервер Discord. Остальное
// детектор не трогает ни при каких условиях (безопасность радиуса).
func isVoiceSNI(sni string) bool {
	return strings.HasSuffix(sni, voiceSNISuffix)
}

// Observe принимает одно наблюдение ClientHello (хук OnClientHello движка).
// Для не-голосовых имён — ничего. Для голосовых копит времена в скользящем
// окне и, при превышении порога, помечает SNI обходимым на TTL.
func (c *voiceChurn) Observe(sni string) {
	if c == nil || !isVoiceSNI(sni) {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()

	// Добавляем текущее наблюдение и отбрасываем вышедшие за окно.
	times := append(c.seen[sni], now)
	cutoff := now.Add(-c.window)
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(c.seen, sni)
	} else {
		c.seen[sni] = kept
	}

	if len(kept) < c.threshold {
		return
	}
	// Цикл переподключений. Помечаем сервер обходимым. Лог печатаем только на
	// ПЕРЕХОДЕ в обходимое состояние (не на каждом ClientHello), чтобы не шуметь.
	if until, ok := c.blockedUntil[sni]; !ok || !until.After(now) {
		c.log.Info("голос: сервер дёргается, обхожу автоматически",
			"sni", sni,
			"переподключений", len(kept),
			"за_сек", int(c.window.Seconds()),
			"обход_сек", int(c.ttl.Seconds()))
	}
	c.blockedUntil[sni] = now.Add(c.ttl)
}

// Contains — hot path intercept.Blocklist. true → движок пропускает SNI сырьём
// (быстрый отказ). Только для голосовых имён и только пока не истёк TTL.
func (c *voiceChurn) Contains(sni string) bool {
	if c == nil || !isVoiceSNI(sni) {
		return false
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.blockedUntil[sni]
	if !ok {
		return false
	}
	if !until.After(now) {
		delete(c.blockedUntil, sni)
		return false
	}
	return true
}

// статическая проверка соответствия интерфейсу движка.
var _ intercept.Blocklist = (*voiceChurn)(nil)

// anyBlocklist объединяет несколько blocklist в один: SNI заблокирован, если
// его блокирует ЛЮБОЙ из них. Нужен, потому что движок принимает единственный
// Blocklist, а источников два — rtctrack-based rtcBlocklist и voiceChurn.
type anyBlocklist []intercept.Blocklist

// Contains — true, если хоть один источник считает SNI заблокированным.
func (a anyBlocklist) Contains(sni string) bool {
	for _, b := range a {
		if b != nil && b.Contains(sni) {
			return true
		}
	}
	return false
}

var _ intercept.Blocklist = anyBlocklist(nil)
