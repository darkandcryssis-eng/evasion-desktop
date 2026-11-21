package sandbox

import (
	"sync"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/proxy"
)

func TestPortProviderSelectByPort(t *testing.T) {
	p := newPortProvider()

	// Непривязанный порт — прозрачный пропуск.
	if sel := p.Select(proxy.ConnMeta{LocalPort: 40000}); sel.Strategy != nil {
		t.Fatal("непривязанный порт должен давать пустой выбор")
	}

	sel := proxy.Selection{ID: core.StrategyID("abc"), Target: "youtube.com"}
	p.bind(40000, sel)

	got := p.Select(proxy.ConnMeta{LocalPort: 40000})
	if got.ID != sel.ID || got.Target != sel.Target {
		t.Fatalf("привязка не вернулась: %+v", got)
	}
	// Другой порт по-прежнему пуст: выбор строго по порту.
	if other := p.Select(proxy.ConnMeta{LocalPort: 40001}); other.ID != "" {
		t.Fatalf("чужой порт получил привязку: %+v", other)
	}

	p.release(40000)
	if sel := p.Select(proxy.ConnMeta{LocalPort: 40000}); sel.ID != "" {
		t.Fatal("после release порт должен снова быть пуст")
	}
}

// TestPortProviderConcurrentReadWrite гоняет чтение горячего пути одновременно с
// привязкой и снятием — под -race это ловит гонку, если копирование-при-записи
// нарушено.
func TestPortProviderConcurrentReadWrite(t *testing.T) {
	p := newPortProvider()
	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = p.Select(proxy.ConnMeta{LocalPort: 40000})
			}
		}
	}()

	for i := 0; i < 2000; i++ {
		p.bind(40000, proxy.Selection{ID: core.StrategyID("x")})
		p.release(40000)
	}
	close(stop)
	wg.Wait()
}
