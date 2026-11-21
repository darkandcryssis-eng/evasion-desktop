package sandbox

import (
	"sync"
	"sync/atomic"

	"github.com/fitting-1c/evasion/internal/proxy"
)

// portProvider — провайдер стратегии по локальному порту соединения.
//
// Отличается от продуктовых провайдеров ключом выбора: там стратегия
// выбирается по SNI и радиусу, здесь — по исходному порту. Причина в природе
// песочницы: все пробы идут к одной цели, и различить, какую стратегию
// проверяет данное соединение, можно только по порту, с которого оно
// инициировано (5.2).
//
// Реализует proxy.StrategyProvider: контур перехвата песочницы спрашивает его
// на каждом ClientHello пробы так же, как продуктовый контур спрашивает
// policy.Table. Поэтому к intercept.Engine его можно подключить без изменений
// движка.
//
// Горячий путь (Select) читает неизменяемый снимок карты через atomic.Pointer
// без блокировок (4.2, правило 1). Запись (bind/release) идёт под мьютексом
// копированием-при-записи: она редкая (перед каждой пробой и после неё), а
// читателей много и они на горячем пути.
type portProvider struct {
	mu  sync.Mutex
	cur atomic.Pointer[map[uint16]proxy.Selection]
}

// newPortProvider создаёт провайдер с пустой картой: пока порт не привязан,
// Select отдаёт прозрачный пропуск.
func newPortProvider() *portProvider {
	p := &portProvider{}
	empty := map[uint16]proxy.Selection{}
	p.cur.Store(&empty)
	return p
}

// Select возвращает стратегию, привязанную к порту соединения, либо пустой
// выбор (прозрачный пропуск) для портов без привязки — в том числе для базовой
// линии, которая идёт без десинка.
func (p *portProvider) Select(meta proxy.ConnMeta) proxy.Selection {
	m := *p.cur.Load()
	return m[meta.LocalPort]
}

// bind привязывает стратегию к порту. Копирование-при-записи: читатели на
// горячем пути продолжают видеть прежний снимок, пока не опубликован новый.
func (p *portProvider) bind(port uint16, sel proxy.Selection) {
	p.mu.Lock()
	defer p.mu.Unlock()
	old := *p.cur.Load()
	next := make(map[uint16]proxy.Selection, len(old)+1)
	for k, v := range old {
		next[k] = v
	}
	next[port] = sel
	p.cur.Store(&next)
}

// release снимает привязку порта. Если привязки не было — ничего не меняет и
// лишний снимок не публикует.
func (p *portProvider) release(port uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	old := *p.cur.Load()
	if _, ok := old[port]; !ok {
		return
	}
	next := make(map[uint16]proxy.Selection, len(old))
	for k, v := range old {
		if k != port {
			next[k] = v
		}
	}
	p.cur.Store(&next)
}

// статическая проверка: провайдер песочницы — это proxy.StrategyProvider.
var _ proxy.StrategyProvider = (*portProvider)(nil)
