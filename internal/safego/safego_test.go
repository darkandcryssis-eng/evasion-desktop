package safego

import (
	"bytes"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Нормальная горутина — Wait возвращает после её завершения, паник нет.
func TestGroupNormalGoroutine(t *testing.T) {
	g := NewGroup(nil, nil)
	var ran atomic.Bool
	g.Go("test-normal", func() { ran.Store(true) })
	g.Wait()
	if !ran.Load() {
		t.Fatal("горутина не выполнилась")
	}
	if g.Panicked() {
		t.Fatal("Panicked должен быть false после нормальной работы")
	}
	if g.Count() != 1 {
		t.Fatalf("Count = %d, ожидали 1", g.Count())
	}
}

// Паника в горутине не роняет процесс и не задерживает Wait. onPanic получает
// имя, значение, непустую трассу.
func TestGroupRecoversPanic(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	var (
		gotName  atomic.Value
		gotValue atomic.Value
		gotStack atomic.Value
	)
	onPanic := func(name string, v any, stack []byte) {
		gotName.Store(name)
		gotValue.Store(v)
		gotStack.Store(stack)
	}
	g := NewGroup(logger, onPanic)
	g.Go("test-panic", func() { panic("ломаю специально") })
	g.Wait()

	if !g.Panicked() {
		t.Fatal("Panicked должен быть true после паники")
	}
	if n := gotName.Load(); n != "test-panic" {
		t.Fatalf("onPanic получил имя %q, ожидали %q", n, "test-panic")
	}
	if v := gotValue.Load(); v != "ломаю специально" {
		t.Fatalf("onPanic получил значение %v, ожидали строку", v)
	}
	stack, _ := gotStack.Load().([]byte)
	if len(stack) == 0 {
		t.Fatal("onPanic получил пустую трассу")
	}
	logOut := buf.String()
	if !strings.Contains(logOut, "паника горутины") {
		t.Fatalf("журнал не содержит заголовок паники: %q", logOut)
	}
	if !strings.Contains(logOut, "test-panic") {
		t.Fatalf("журнал не содержит имя горутины: %q", logOut)
	}
}

// Несколько горутин: одна паникует, остальные доходят до конца, Wait возвращает
// после всех.
func TestGroupMixedPanicAndNormal(t *testing.T) {
	g := NewGroup(nil, nil)
	var okCount atomic.Int32
	for i := 0; i < 3; i++ {
		g.Go("ok", func() { okCount.Add(1) })
	}
	g.Go("boom", func() { panic("boom") })
	for i := 0; i < 3; i++ {
		g.Go("ok", func() { okCount.Add(1) })
	}
	g.Wait()

	if n := okCount.Load(); n != 6 {
		t.Fatalf("ok-горутин выполнилось %d, ожидали 6", n)
	}
	if !g.Panicked() {
		t.Fatal("Panicked должен быть true")
	}
	if g.Count() != 7 {
		t.Fatalf("Count = %d, ожидали 7", g.Count())
	}
}

// Нулевое значение Group допустимо: паника восстанавливается молча, Wait
// возвращает после горутины.
func TestZeroGroupIsUsable(t *testing.T) {
	var g Group
	done := make(chan struct{})
	g.Go("zero", func() {
		defer close(done)
		panic("падаю на нулевой группе")
	})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("горутина не завершилась")
	}
	g.Wait()
	if !g.Panicked() {
		t.Fatal("Panicked должен быть true даже без логгера")
	}
}

// onPanic сам паникует — Group это гасит и Wait всё равно возвращает. Иначе
// Done остался бы без парного Add, и Wait висел бы вечно.
func TestOnPanicItselfPanics(t *testing.T) {
	badOnPanic := func(string, any, []byte) {
		panic("плохой коллбек тоже паникует")
	}
	g := NewGroup(nil, badOnPanic)
	g.Go("double-trouble", func() { panic("исходная") })

	done := make(chan struct{})
	go func() {
		g.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wait завис из-за паники в onPanic — обёртка не защитила")
	}
	if !g.Panicked() {
		t.Fatal("Panicked должен быть true: исходная паника произошла")
	}
}

// Логгер nil — паника восстанавливается, но ничего не пишется (защита от
// случайной зависимости в тестах).
func TestNilLogger(t *testing.T) {
	g := NewGroup(nil, nil)
	g.Go("silent", func() { panic("без лога") })
	g.Wait()
	if !g.Panicked() {
		t.Fatal("Panicked должен быть true")
	}
}

// Отсутствие паники не должно взводить флаг.
func TestNoPanicLeavesFlagFalse(t *testing.T) {
	g := NewGroup(nil, func(string, any, []byte) { t.Fatal("onPanic не должен был вызваться") })
	g.Go("clean", func() { time.Sleep(time.Millisecond) })
	g.Wait()
	if g.Panicked() {
		t.Fatal("Panicked ложно true")
	}
}
