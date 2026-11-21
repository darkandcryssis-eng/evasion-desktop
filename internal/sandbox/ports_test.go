package sandbox

import (
	"context"
	"testing"
	"time"
)

func TestPortPoolRange(t *testing.T) {
	pp, err := newPortPool(40000, 40003)
	if err != nil {
		t.Fatal(err)
	}
	if pp.size() != 4 {
		t.Fatalf("ожидалось 4 порта, получено %d", pp.size())
	}
	// Все порты диапазона выдаются ровно один раз.
	seen := map[uint16]bool{}
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		p, err := pp.acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if p < 40000 || p > 40003 {
			t.Fatalf("порт %d вне диапазона", p)
		}
		if seen[p] {
			t.Fatalf("порт %d выдан дважды", p)
		}
		seen[p] = true
	}
	if pp.available() != 0 {
		t.Fatalf("после исчерпания свободных быть не должно, есть %d", pp.available())
	}
}

func TestPortPoolBoundarySinglePort(t *testing.T) {
	// hi == lo — один порт, не ноль: границы включительны.
	pp, err := newPortPool(50000, 50000)
	if err != nil {
		t.Fatal(err)
	}
	if pp.size() != 1 {
		t.Fatalf("ожидался 1 порт, получено %d", pp.size())
	}
}

func TestPortPoolEmptyRange(t *testing.T) {
	if _, err := newPortPool(40010, 40000); err == nil {
		t.Fatal("ожидалась ошибка для пустого диапазона")
	}
}

func TestPortPoolAcquireBlocksThenReleases(t *testing.T) {
	pp, err := newPortPool(40000, 40000)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pp.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Пул пуст: acquire с уже отменённым контекстом обязан вернуть ошибку, а не
	// зависнуть.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pp.acquire(cctx); err == nil {
		t.Fatal("ожидалась ошибка контекста при пустом пуле")
	}
	// После возврата порт снова берётся.
	pp.release(p)
	if _, err := pp.acquire(context.Background()); err != nil {
		t.Fatalf("порт после release не выдался: %v", err)
	}
}

func TestPortPoolDoubleReleaseSafe(t *testing.T) {
	pp, err := newPortPool(40000, 40000)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pp.acquire(context.Background())
	pp.release(p)
	// Повторный release не должен ни паниковать, ни блокировать, ни раздувать
	// пул сверх ёмкости.
	pp.release(p)
	if pp.available() != 1 {
		t.Fatalf("двойной release раздул пул: свободно %d при ёмкости 1", pp.available())
	}
}

func TestPortPoolAcquireRespectsContextDeadline(t *testing.T) {
	pp, _ := newPortPool(40000, 40000)
	_, _ = pp.acquire(context.Background()) // исчерпали
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := pp.acquire(ctx); err == nil {
		t.Fatal("ожидалась ошибка по дедлайну")
	}
	if time.Since(start) < 10*time.Millisecond {
		t.Fatal("acquire вернулся слишком рано: не ждал дедлайна")
	}
}
