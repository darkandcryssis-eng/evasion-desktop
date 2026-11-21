package sysmanifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Пустой путь — ошибка, а не паника: журналу нужно знать, куда писать.
func TestOpenEmptyPathFails(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("Open(\"\") должен вернуть ошибку")
	}
}

// Открытие несуществующего файла даёт пустой журнал — чистый старт.
func TestOpenMissingFileIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if n := m.Len(); n != 0 {
		t.Fatalf("Len = %d, ожидали 0", n)
	}
	if m.Pending() == nil {
		t.Fatal("Pending возвращает nil, ожидали пустой срез")
	}
}

// Запись и перечитывание из нового экземпляра даёт те же данные.
func TestRecordPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	type undoHosts struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	}
	if err := m.Record(KindFirewallRule, "movok-discord-bad-rtc", nil); err != nil {
		t.Fatalf("Record firewall: %v", err)
	}
	if err := m.Record(KindHostsEntry, "162.159.138.232\tgateway.discord.gg",
		undoHosts{IP: "162.159.138.232", Name: "gateway.discord.gg"}); err != nil {
		t.Fatalf("Record hosts: %v", err)
	}

	// Открываем журнал заново из того же файла.
	m2, err := Open(path)
	if err != nil {
		t.Fatalf("Open #2: %v", err)
	}
	if n := m2.Len(); n != 2 {
		t.Fatalf("после реоткрытия Len = %d, ожидали 2", n)
	}
	got := m2.Pending()
	var seenFW, seenHosts bool
	for _, r := range got {
		switch r.Kind {
		case KindFirewallRule:
			seenFW = true
			if r.ID != "movok-discord-bad-rtc" {
				t.Fatalf("firewall rule ID %q", r.ID)
			}
			if len(r.UndoData) != 0 {
				t.Fatalf("firewall rule UndoData должен быть пуст, получили %s", r.UndoData)
			}
		case KindHostsEntry:
			seenHosts = true
			var u undoHosts
			if err := json.Unmarshal(r.UndoData, &u); err != nil {
				t.Fatalf("разбор hosts undo: %v", err)
			}
			if u.IP != "162.159.138.232" || u.Name != "gateway.discord.gg" {
				t.Fatalf("hosts undo потерян: %+v", u)
			}
		}
	}
	if !seenFW || !seenHosts {
		t.Fatalf("не все записи после реоткрытия: fw=%t hosts=%t", seenFW, seenHosts)
	}
}

// Повторная Record с тем же (kind, id) замещает запись, а не плодит дубль.
func TestRecordReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m, _ := Open(path)
	_ = m.Record(KindFirewallRule, "rule-A", map[string]any{"attempt": 1})
	time.Sleep(2 * time.Millisecond) // гарантируем разные applied_at
	_ = m.Record(KindFirewallRule, "rule-A", map[string]any{"attempt": 2})

	if n := m.Len(); n != 1 {
		t.Fatalf("после повтора Len = %d, ожидали 1 (замещение)", n)
	}
	var u map[string]any
	if err := json.Unmarshal(m.Pending()[0].UndoData, &u); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if int(u["attempt"].(float64)) != 2 {
		t.Fatalf("UndoData старая: %+v", u)
	}
}

// Remove вычёркивает конкретную запись; остальные остаются.
func TestRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m, _ := Open(path)
	_ = m.Record(KindFirewallRule, "A", nil)
	_ = m.Record(KindFirewallRule, "B", nil)
	_ = m.Record(KindHostsEntry, "C", nil)
	if err := m.Remove(KindFirewallRule, "A"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if n := m.Len(); n != 2 {
		t.Fatalf("после Remove Len = %d, ожидали 2", n)
	}
	// Записи сохранены на диске.
	m2, _ := Open(path)
	for _, r := range m2.Pending() {
		if r.Kind == KindFirewallRule && r.ID == "A" {
			t.Fatal("удалённая запись осталась на диске")
		}
	}
}

// Remove на несуществующей записи — не ошибка. Идемпотентность.
func TestRemoveIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m, _ := Open(path)
	if err := m.Remove(KindFirewallRule, "никогда-не-было"); err != nil {
		t.Fatalf("Remove несуществующего: %v", err)
	}
	if err := m.Remove(KindHostsEntry, "и-этого-тоже"); err != nil {
		t.Fatalf("Remove #2: %v", err)
	}
}

// Pending возвращает копию: правка возврата не должна править журнал.
func TestPendingReturnsCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m, _ := Open(path)
	_ = m.Record(KindFirewallRule, "A", nil)
	p := m.Pending()
	p[0].ID = "ИСПОРЧЕНО"
	// Запрашиваем ещё раз: источник не должен быть испорчен.
	p2 := m.Pending()
	if p2[0].ID == "ИСПОРЧЕНО" {
		t.Fatal("Pending отдал ссылку на внутренние данные, их испортили")
	}
}

// Clear вычищает журнал и удаляет файл.
func TestClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m, _ := Open(path)
	_ = m.Record(KindFirewallRule, "A", nil)
	if err := m.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if n := m.Len(); n != 0 {
		t.Fatalf("после Clear Len = %d, ожидали 0", n)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("после Clear файл всё ещё существует: %v", err)
	}
}

// Clear на отсутствующем файле — не ошибка.
func TestClearIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m, _ := Open(path)
	if err := m.Clear(); err != nil {
		t.Fatalf("Clear на пустом: %v", err)
	}
}

// Пустые Kind/ID — ошибка, а не молчаливая запись невосстановимого мусора.
func TestEmptyKindOrIDFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m, _ := Open(path)
	if err := m.Record("", "A", nil); err == nil {
		t.Fatal("пустой Kind должен быть ошибкой")
	}
	if err := m.Record(KindFirewallRule, "", nil); err == nil {
		t.Fatal("пустой ID должен быть ошибкой")
	}
}

// Сломанный JSON в файле — Open возвращает ошибку, а не делает вид что всё ок.
func TestOpenCorruptedFileFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte("{не-JSON"), 0o644); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open на сломанном JSON должен вернуть ошибку")
	}
}

// Параллельные Record/Remove не падают под -race.
func TestConcurrentRecordRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m, _ := Open(path)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		id := "rule-" + string(rune('A'+i%26))
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = m.Record(KindFirewallRule, id, nil)
		}()
		go func() {
			defer wg.Done()
			_ = m.Remove(KindFirewallRule, id)
		}()
	}
	wg.Wait()
	// Главное — не упало под -race и файл читается обратно.
	m2, err := Open(path)
	if err != nil {
		t.Fatalf("Open после parallel: %v", err)
	}
	_ = m2.Pending()
}

// Пустая UndoData сериализуется компактно (ключ опущен, не "null").
func TestEmptyUndoDataIsOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	m, _ := Open(path)
	_ = m.Record(KindFirewallRule, "A", nil)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Поля undo_data в сериализованной форме быть не должно: `omitempty`.
	if containsAll(string(data), []string{`"undo_data"`}) {
		t.Fatalf("undo_data для nil-undo попало в файл: %s", data)
	}
}

func containsAll(s string, parts []string) bool {
	for _, p := range parts {
		if !contains(s, p) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
