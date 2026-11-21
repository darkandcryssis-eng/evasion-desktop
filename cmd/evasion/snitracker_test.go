package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/fitting-1c/evasion/internal/config"
)

// loadDomainSet строит радиус из нескольких доменов для теста.
func loadDomainSet(t *testing.T, domains ...string) *config.DomainSet {
	t.Helper()
	cfg := &config.Config{Groups: map[string][]string{"g": domains}}
	ds, err := cfg.DomainSet(nil)
	if err != nil {
		t.Fatalf("радиус: %v", err)
	}
	return ds
}

// TestSNITrackerFiltersByRadius: имена в радиусе копятся по имени, вне радиуса
// — только числом. Это и есть граница приватности: чужие SNI в лог не попадают.
func TestSNITrackerFiltersByRadius(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	tr := newSNITracker(loadDomainSet(t, "discord.com", "discord.media"), logger)

	tr.Observe("discord.com")
	tr.Observe("rtc.discord.media")
	tr.Observe("example.com") // вне радиуса — должен попасть только в outside
	tr.Observe("")            // пусто — игнорируется полностью

	tr.mu.Lock()
	if tr.counts["discord.com"] != 1 || tr.counts["rtc.discord.media"] != 1 {
		t.Fatalf("ожидалось два имени радиуса по 1, получено %+v", tr.counts)
	}
	if tr.outside != 1 {
		t.Fatalf("ожидалось outside=1, получено %d", tr.outside)
	}
	if _, ok := tr.counts["example.com"]; ok {
		t.Fatal("имя вне радиуса не должно попадать в counts: это и есть граница приватности")
	}
	tr.mu.Unlock()
}

// TestSNITrackerLogShapes: сводка печатается с нужными ключами (топ, уникальных,
// вне_радиуса). Без этого потребитель лога (глазами или grep'ом) не найдёт то,
// ради чего трекер и заведён. Flush нужен, потому что Observe логирует первый
// раз сразу (чтобы человек видел «что-то идёт»), а дальше ждёт таймера; тесту
// надо принудительно спросить итог.
func TestSNITrackerLogShapes(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	tr := newSNITracker(loadDomainSet(t, "discord.com", "discord.media"), logger)

	tr.Observe("discord.com")
	tr.Observe("discord.com")
	tr.Observe("rtc.discord.media")
	tr.Flush()

	out := buf.String()
	if !strings.Contains(out, "SNI радиуса") {
		t.Fatalf("ожидалось сообщение 'SNI радиуса', получено: %s", out)
	}
	// Самое частое имя должно идти первым в топе: discord.com:2, затем
	// rtc.discord.media:1. Сверять строку целиком бессмысленно (slog расставляет
	// ключи по-своему); проверяем подстроку.
	if !strings.Contains(out, "discord.com:2") {
		t.Fatalf("ожидалось 'discord.com:2' в топе, получено: %s", out)
	}
	if !strings.Contains(out, "rtc.discord.media:1") {
		t.Fatalf("ожидалось 'rtc.discord.media:1' в топе, получено: %s", out)
	}
}

// TestSNITrackerFlushEmpty: Flush при пустом трекере тоже печатает сводку с
// нулями — иначе потребитель не отличит «трекер работает, SNI радиуса не было»
// от «трекер забыл». То же правило о нулевых значениях, в седьмой раз в проекте.
func TestSNITrackerFlushEmpty(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	tr := newSNITracker(loadDomainSet(t, "discord.com"), logger)
	tr.Flush()
	out := buf.String()
	if !strings.Contains(out, "SNI радиуса") {
		t.Fatalf("Flush пустого трекера должен печатать сводку с нулями, получено: %s", out)
	}
	if !strings.Contains(out, "уникальных=0") {
		t.Fatalf("ожидалось 'уникальных=0' при пустом трекере, получено: %s", out)
	}
}

// TestComposeHooks: два хука срабатывают оба; nil-любая сторона допустима.
func TestComposeHooks(t *testing.T) {
	var a, b []string
	hookA := func(s string) { a = append(a, s) }
	hookB := func(s string) { b = append(b, s) }

	// Оба заданы — оба вызываются.
	composeHooks(hookA, hookB)("x")
	if len(a) != 1 || a[0] != "x" || len(b) != 1 || b[0] != "x" {
		t.Fatalf("оба хука должны получить вызов, a=%v b=%v", a, b)
	}

	// Левый nil — работает один правый.
	a, b = nil, nil
	composeHooks(nil, hookB)("y")
	if len(a) != 0 || len(b) != 1 {
		t.Fatalf("при nil слева должен сработать только правый, a=%v b=%v", a, b)
	}

	// Правый nil — работает один левый.
	a, b = nil, nil
	composeHooks(hookA, nil)("z")
	if len(a) != 1 || len(b) != 0 {
		t.Fatalf("при nil справа должен сработать только левый, a=%v b=%v", a, b)
	}

	// Оба nil — nil (вызывающий сам проверит).
	if composeHooks(nil, nil) != nil {
		t.Fatal("при двух nil должен быть nil, иначе вызывающий зря делал бы крюк")
	}
}

// TestSNITrackerNilRadiusSafe: nil-радиус разрешён (вариант, где трекер не
// нужен) — Observe не должен паниковать, счётчики не растут.
func TestSNITrackerNilRadiusSafe(t *testing.T) {
	tr := newSNITracker(nil, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	tr.Observe("anything")
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.counts) != 0 {
		t.Fatalf("при nil-радиусе counts должен быть пустым, получено %+v", tr.counts)
	}
	if tr.outside != 1 {
		t.Fatalf("outside должен расти даже при nil-радиусе: получено %d", tr.outside)
	}
}
