package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/netbind"
	"github.com/fitting-1c/evasion/internal/youtubeproxy"
)

// youtubeBypass — локальный прокси YouTube на случай стороннего VPN. Браузер
// получает его через PAC только для узлов YouTube. Основной путь — мимо VPN,
// через физический адаптер и под обход: так видео идёт на полной скорости
// провайдера, а не через VPN-сервер. Запасной путь — сам VPN: на него монитор
// YouTube переводит новые соединения, когда прямой обход нестабилен.
type youtubeBypass struct {
	Listen  string
	Router  *youtubeproxy.Router
	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
	restore func()
}

func startYouTubeBypass(parent context.Context, route netbind.Route, listen, stateDir string, logger *slog.Logger) (*youtubeBypass, error) {
	ln, err := net.Listen("tcp4", listen)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть локальный прокси YouTube: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	b := &youtubeBypass{Listen: ln.Addr().String(), cancel: cancel, done: make(chan struct{})}
	b.Router = &youtubeproxy.Router{
		Direct: youtubeproxy.DialContextFunc(netbind.Dialer(route.Physical.Index)),
		Tunnel: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}
	b.restore, err = installYouTubePAC(windowsPACSettings{}, filepath.Join(stateDir, "youtube-pac-backup.json"), "http://"+b.Listen+"/proxy.pac")
	if err != nil {
		_ = ln.Close()
		cancel()
		return nil, err
	}
	server := &youtubeproxy.Server{Router: b.Router, Logger: logger, PAC: youtubeproxy.PAC(b.Listen)}
	go func() {
		_ = server.Serve(ctx, ln)
		close(b.done)
	}()
	return b, nil
}

// Measure проверяет запасной путь (через VPN): сайт, превью и видеосеть.
func (b *youtubeBypass) Measure(ctx context.Context, short bool) []youtubeCheck {
	p := &youtubeMux{dial: b.Router.Tunnel, media: "redirector.googlevideo.com", leases: map[youtubeLease]string{}, deep: true}
	return p.measure(ctx, "active", short)
}

func (b *youtubeBypass) Close() {
	b.once.Do(func() {
		b.cancel()
		<-b.done
		b.restore()
	})
}
