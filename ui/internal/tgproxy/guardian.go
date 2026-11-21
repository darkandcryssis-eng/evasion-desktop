package tgproxy

import (
	"context"
	"fmt"
	"time"
)

// Страж маршрутов: пока прокси работает, раз в guardianInterval проверяет
// каналы к тем дата-центрам, где реально был трафик, и держит тёплый пул
// полным. После обрыва канала просыпается по сигналу почти сразу — так
// следующее подключение Telegram получает готовый проверенный маршрут,
// не дожидаясь полного перебора.
const guardianInterval = 40 * time.Second
const guardianSignalCooldown = 5 * time.Second

func (s *Server) guardian() {
	defer s.wg.Done()
	ticker := time.NewTicker(guardianInterval)
	defer ticker.Stop()
	var lastSignal time.Time
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.guardianPass()
		case <-s.guardianSignal:
			if time.Since(lastSignal) < guardianSignalCooldown {
				continue
			}
			lastSignal = time.Now()
			// Короткая пауза, чтобы каскад одновременных обрывов
			// не превратился в шквал проверок.
			timer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-s.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			s.guardianPass()
		}
	}
}

func (s *Server) guardianPass() {
	for _, key := range s.usedKeysSnapshot() {
		if s.ctx.Err() != nil {
			return
		}
		ctx, cancel := context.WithTimeout(s.ctx, 8*time.Second)
		s.router.probeRoutes(ctx, key.dc, key.media, 3)
		cancel()
		if s.ctx.Err() != nil {
			return
		}
		s.router.warmBest(key.dc, key.media)
	}
}

func (s *Server) usedKeysSnapshot() []poolKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]poolKey, 0, len(s.usedKeys))
	for key := range s.usedKeys {
		keys = append(keys, key)
	}
	return keys
}

// pingGuardian будит стража без блокировки вызывающего.
func (s *Server) pingGuardian() {
	select {
	case s.guardianSignal <- struct{}{}:
	default:
	}
}

// replyTimeoutFor подбирает ожидание первого ответа по известной
// латентности маршрута: живой маршрут отвечает быстро, а зависший
// канал-«чёрная дыра» не должен держать клиента все base секунд.
func replyTimeoutFor(base, hint time.Duration) time.Duration {
	if hint <= 0 {
		return base
	}
	timeout := 4 * hint
	if timeout < 2500*time.Millisecond {
		timeout = 2500 * time.Millisecond
	}
	if timeout > base {
		timeout = base
	}
	return timeout
}

// refreshDomains повторяет upstream-обновление CF-доменов раз в час.
// Скачиваются только доменные имена; ошибка сети не затрагивает встроенный пул.
func (s *Server) refreshDomains() {
	defer s.wg.Done()
	client := communityHTTPClient()
	defer client.CloseIdleConnections()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	refresh := func() {
		ctx, cancel := context.WithTimeout(s.ctx, 12*time.Second)
		domains, err := fetchCommunityDomains(ctx, client, communityDomainsURL)
		cancel()
		if err == nil && s.router.domains.replace(domains) && s.ctx.Err() == nil {
			s.log("INFO", "Резервные маршруты Telegram обновлены", fmt.Sprintf("%d доменов", len(domains)))
			s.pingGuardian()
		}
	}
	refresh()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}
