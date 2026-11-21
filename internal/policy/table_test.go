package policy

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/fitting-1c/evasion/internal/proxy"
)

func TestTableWithoutSnapshotPassesThrough(t *testing.T) {
	tab := NewTable()
	if tab.Current() != nil {
		t.Fatal("у новой таблицы не должно быть снимка")
	}
	// Ноль означает «снимка нет» и ничем другим быть не может: нумерация
	// снимков начинается с единицы.
	if tab.Rev() != 0 {
		t.Fatalf("номер снимка пустой таблицы = %d, ожидался 0", tab.Rev())
	}
	if sel := tab.Select(proxy.ConnMeta{Host: "youtube.com", SNI: "www.youtube.com"}); sel.Strategy != nil {
		t.Fatal("до первого снимка таблица обязана пропускать трафик")
	}
}

func TestTableInstallReplacesSnapshot(t *testing.T) {
	tab := NewTable()
	first := splitStrategy(5)
	second := splitStrategy(77)

	s1, err := NewSnapshot(testVantage, 1, []Entry{{Domain: "youtube.com", Strategy: first}})
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	tab.Install(s1)

	sel := tab.Select(proxy.ConnMeta{Host: "www.youtube.com"})
	if sel.Strategy != first {
		t.Fatal("после установки снимка должна применяться его стратегия")
	}
	if tab.Rev() != 1 {
		t.Fatalf("номер снимка = %d, ожидался 1", tab.Rev())
	}

	s2, err := NewSnapshot(testVantage, 2, []Entry{{Domain: "youtube.com", Strategy: second}})
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	tab.Install(s2)

	if sel := tab.Select(proxy.ConnMeta{Host: "www.youtube.com"}); sel.Strategy != second {
		t.Fatal("после подмены должна применяться стратегия нового снимка")
	}
	if tab.Rev() != 2 {
		t.Fatalf("номер снимка = %d, ожидался 2", tab.Rev())
	}
	// Прежний снимок не изменился: он неизменяем, и соединения, читающие его,
	// продолжают видеть прежнее решение.
	if sel, _ := s1.Lookup("www.youtube.com", ""); sel.Strategy != first {
		t.Fatal("установка нового снимка не должна менять прежний")
	}
}

// TestTableInstallNilDisables: Install(nil) — законная команда «выключить
// автопилот», а не ошибка.
func TestTableInstallNilDisables(t *testing.T) {
	tab := NewTable()
	s, err := NewSnapshot(testVantage, 1, []Entry{{Domain: "youtube.com", Strategy: splitStrategy(5)}})
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	tab.Install(s)
	tab.Install(nil)

	if sel := tab.Select(proxy.ConnMeta{Host: "www.youtube.com"}); sel.Strategy != nil {
		t.Fatal("после Install(nil) таблица должна пропускать трафик")
	}
	if tab.Rev() != 0 {
		t.Fatalf("номер снимка после Install(nil) = %d, ожидался 0", tab.Rev())
	}
}

// TestTableConcurrentSelectDuringInstall — проверка под -race того свойства,
// ради которого здесь атомарный указатель: читатели работают одновременно с
// подменой снимка владельцем.
//
// Тест заодно требует связности результата: раз снимки неизменяемы, читатель
// обязан увидеть какой-то один снимок целиком, то есть стратегию, у которой
// идентификатор соответствует ей самой. Полуобновлённого состояния быть не
// может.
func TestTableConcurrentSelectDuringInstall(t *testing.T) {
	tab := NewTable()

	const revs = 200
	snaps := make([]*Snapshot, revs)
	ids := make(map[string]struct{}, revs)
	for i := range snaps {
		s := splitStrategy(i)
		snap, err := NewSnapshot(testVantage, uint64(i+1), []Entry{{Domain: "youtube.com", Strategy: s}})
		if err != nil {
			t.Fatalf("NewSnapshot: %v", err)
		}
		snaps[i] = snap
		sel, _ := snap.Lookup("youtube.com", "")
		ids[string(sel.ID)] = struct{}{}
	}
	tab.Install(snaps[0])

	const readers = 8
	var (
		wg    sync.WaitGroup
		ready sync.WaitGroup
		reads atomic.Int64
		done  = make(chan struct{})
	)

	for range readers {
		wg.Add(1)
		ready.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				sel := tab.Select(proxy.ConnMeta{Host: "www.youtube.com", SNI: "www.youtube.com"})
				if sel.Strategy == nil {
					t.Error("во время подмены снимка радиус не должен пропадать")
					return
				}
				if _, ok := ids[string(sel.ID)]; !ok {
					t.Errorf("идентификатор %q не принадлежит ни одному снимку", sel.ID)
					return
				}
				reads.Add(1)
			}
		}()
	}

	// Барьер и длинный цикл подмен — не украшение. Без них владелец успевает
	// пройти все снимки раньше, чем планировщик пустит читателей, чтения и
	// подмены не пересекаются, и тест проходит, ничего не проверив: гонку,
	// внесённую нарочно, -race в такой постановке не находил.
	ready.Wait()
	const cycles = 100
	for range cycles {
		for _, snap := range snaps {
			tab.Install(snap)
		}
	}
	close(done)
	wg.Wait()

	// Защита от беззвучного успеха: если читатели не сделали ни одного
	// решения, выше ничего не проверялось.
	if n := reads.Load(); n == 0 {
		t.Fatal("читатели не выполнили ни одного решения: тест ничего не проверил")
	}

	if tab.Rev() != revs {
		t.Fatalf("номер последнего снимка = %d, ожидался %d", tab.Rev(), revs)
	}
}
