package main

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/rtctrack"
)

// rtcBlocklist — активный blocklist SNI, построенный на основе rtctrack.
//
// Контракт intercept.Blocklist: Contains() должна быть быстрой и без
// аллокаций. Храним atomic.Pointer на map, Rebuild пересобирает полностью и
// атомарно подменяет указатель. Горячий путь (handle()) видит либо старый
// снимок, либо новый — промежуточных состояний не бывает.
type rtcBlocklist struct {
	current atomic.Pointer[map[string]struct{}]
}

// Contains — hot path. Защищено от nil pointer, выделения памяти нет.
func (b *rtcBlocklist) Contains(sni string) bool {
	m := b.current.Load()
	if m == nil {
		return false
	}
	_, in := (*m)[sni]
	return in
}

// Rebuild пересобирает список из текущего снимка tracker.
//
// Критерий: SNI попадает в блок, если:
//   - Observed >= minObserved (достаточно пробы, одна-две — шум);
//   - SuccessRate < maxSuccessPermille (явно плохой сервер).
//
// Хорошие и малопроверенные пары блок не трогает. Это и даёт «быстрый
// фидбек на плохих, никакого вреда для рабочих» — ровно то, чего не хватало
// затупу AUTHENTICATING.
func (b *rtcBlocklist) Rebuild(tracker *rtctrack.Tracker, minObserved, maxSuccessPermille int) int {
	snap := tracker.Snapshot()
	nm := make(map[string]struct{}, 32)
	for pair, stat := range snap {
		if stat.Observed < minObserved {
			continue
		}
		if stat.SuccessRate() >= maxSuccessPermille {
			continue
		}
		// Статистика переживает перезапуск: без срока давности сервер, однажды
		// давший сбои, остался бы без десинка навсегда.
		if time.Since(stat.LastAt) > blocklistMaxAge {
			continue
		}
		nm[pair.SNI] = struct{}{}
	}
	b.current.Store(&nm)
	return len(nm)
}

// статическая проверка соответствия интерфейсу.
var _ intercept.Blocklist = (*rtcBlocklist)(nil)

// blocklistRebuildInterval — как часто пересобирается blocklist.
// 30 секунд: статистика копится быстрее горячего пути (ClientHello каждые
// секунды), а слишком частая пересборка — лишняя CPU.
const blocklistRebuildInterval = 30 * time.Second

// Параметры решения о блокировке. В конфиг не вынесены: второго потребителя
// нет, значения консервативны. При желании можно сделать настраиваемыми.
const (
	// blocklistMinObserved — сколько раз SNI должен быть «виден» прежде чем
	// попадёт в кандидаты блока. 3 попытки — минимум, чтоб отличить
	// одноразовый сбой от стабильно плохого.
	blocklistMinObserved = 3
	// blocklistMaxSuccess — порог SuccessRate в permille, ниже которого
	// SNI считается плохим. 500‰ (50%): больше половины попыток
	// провалились → лучше пропускать сырьём, не ждать очередной провал.
	blocklistMaxSuccess = 500
	// blocklistMaxAge — сколько держится блок после последнего события по SNI;
	// затем сервер получает честную попытку десинка заново.
	blocklistMaxAge = 10 * time.Minute
)

// startBlocklistRefresher запускает фоновую горутину периодической пересборки
// blocklist. Горутина останавливается на отмене ctx. Нужна `safego.Group` для
// recovery в случае паники (используется в вызывающем коде).
func startBlocklistRefresher(ctx context.Context, bl *rtcBlocklist, tracker *rtctrack.Tracker, logger *slog.Logger) {
	tick := time.NewTicker(blocklistRebuildInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			n := bl.Rebuild(tracker, blocklistMinObserved, blocklistMaxSuccess)
			if n > 0 {
				logger.Info("blocklist: обновлён",
					"заблокировано_sni", n,
					"порог_попыток", blocklistMinObserved,
					"порог_успеха_permille", blocklistMaxSuccess)
			}
		}
	}
}
