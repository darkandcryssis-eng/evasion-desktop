package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/fitting-1c/evasion/internal/sysmanifest"
)

// Основная цель — проверить, что команда:
//   - корректно работает на пустом/отсутствующем журнале (чистый старт);
//   - читает журнал и в dry-run показывает намерения, не трогая систему;
//   - JSON-вывод соответствует структуре cleanupInfo.
//
// Полный путь отмены (netsh/hosts) требует реальной Windows с правами и
// отдельного окружения; покрываем его интеграционно, не unit'ом.

// withStateDir перенаправляет defaultStateDir на tmp, чтобы cleanup читал
// журнал оттуда. Возвращает путь к файлу журнала.
func withStateDir(t *testing.T) string {
	t.Helper()
	// defaultStateDir — пакетная константа, поэтому для тестов читаем её
	// текущее значение и подкладываем файл.
	dir := t.TempDir()
	// Переопределяем через chdir: cleanup использует filepath.Join(defaultStateDir, "system.json")
	// без учёта абсолютности, то есть опирается на cwd. Явная подмена
	// defaultStateDir потребовала бы его экспорт — ненужное изменение API.
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	return filepath.Join(dir, defaultStateDir, "system.json")
}

// Пустой журнал — успешный no-op c нулевыми счётчиками.
func TestCleanupEmptyManifest(t *testing.T) {
	withStateDir(t)
	// Перехватываем stdout.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = old }()

	err := cleanupCommand(context.Background(), []string{"--json"})
	_ = w.Close()
	if err != nil {
		t.Fatalf("cleanup --json на пустом: %v", err)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	var info cleanupInfo
	if err := json.Unmarshal(buf.Bytes(), &info); err != nil {
		t.Fatalf("разбор JSON: %v\n%s", err, buf.String())
	}
	if info.Attempted != 0 || info.Succeeded != 0 || info.Failed != 0 {
		t.Fatalf("на пустом журнале ненулевые счётчики: %+v", info)
	}
	if len(info.Records) != 0 {
		t.Fatalf("на пустом журнале Records не пуст: %+v", info.Records)
	}
}

// Dry-run не меняет диск и показывает намерения.
func TestCleanupDryRunShowsIntent(t *testing.T) {
	path := withStateDir(t)
	// Положим в журнал одну фиктивную запись.
	m, err := sysmanifest.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	undo := struct {
		BlockID string `json:"block_id"`
	}{BlockID: "cloudflare-fallback"}
	if err := m.Record(sysmanifest.KindHostsEntry, "hosts-block:cloudflare-fallback", undo); err != nil {
		t.Fatalf("Record: %v", err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	if err := cleanupCommand(context.Background(), []string{"--json", "--dry-run"}); err != nil {
		os.Stdout = old
		t.Fatalf("cleanup --dry-run: %v", err)
	}
	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	var info cleanupInfo
	if err := json.Unmarshal(buf.Bytes(), &info); err != nil {
		t.Fatalf("разбор JSON: %v\n%s", err, buf.String())
	}
	if info.Attempted != 1 {
		t.Fatalf("Attempted = %d, ожидали 1", info.Attempted)
	}
	// Dry-run не считает Succeeded/Failed.
	if info.Succeeded != 0 || info.Failed != 0 {
		t.Fatalf("dry-run должен давать succeeded=0 failed=0, получили %+v", info)
	}
	if len(info.Records) != 1 || info.Records[0].Action != "skipped_dry_run" {
		t.Fatalf("Records не отражает dry-run: %+v", info.Records)
	}

	// Запись должна остаться в журнале — dry-run не трогает диск.
	m2, _ := sysmanifest.Open(path)
	if m2.Len() != 1 {
		t.Fatalf("после dry-run журнал изменён: %d записей", m2.Len())
	}
}

// Неизвестный аргумент — ошибка. Защита от опечаток в CLI.
func TestCleanupUnknownArg(t *testing.T) {
	withStateDir(t)
	err := cleanupCommand(context.Background(), []string{"something-random"})
	if err == nil {
		t.Fatal("ожидали ошибку на лишнем аргументе")
	}
}

// JSON-вывод — валидный JSON, не частично-печатный мусор.
func TestCleanupJSONIsValid(t *testing.T) {
	withStateDir(t)
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	if err := cleanupCommand(context.Background(), []string{"--json"}); err != nil {
		os.Stdout = old
		t.Fatalf("cleanup: %v", err)
	}
	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	var tmp any
	if err := json.Unmarshal(buf.Bytes(), &tmp); err != nil {
		t.Fatalf("не JSON: %v\n%s", err, buf.String())
	}
}
