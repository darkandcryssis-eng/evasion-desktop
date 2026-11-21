package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fitting-1c/evasion/internal/enginelock"
	"github.com/fitting-1c/evasion/internal/hosts"
	"github.com/fitting-1c/evasion/internal/sysmanifest"
)

// cleanupUsage описывает команду cleanup. Собирается в рантайме, потому что
// пути (`defaultStateDir`, `systemHostsPath`) берутся из констант/окружения.
var cleanupUsage = `evasion cleanup — откат всех системных изменений, которые делал движок

Читает журнал ` + filepath.Join(defaultStateDir, "system.json") + ` и
последовательно откатывает каждое изменение: удаляет правила файрвола, убирает
управляемые блоки из hosts, снимает прочие правки.

Безопасно вызывать повторно: уже отменённые записи игнорируются; записи, которые
не удалось отменить (нет прав, антивирус держит файл, правило уже удалено
руками), остаются в журнале, с диагностикой в выводе.

  evasion cleanup                обычный откат, показать результат
  evasion cleanup --json         машинно-читаемый вывод
  evasion cleanup --dry-run      показать что бы откатили, но не трогать
  evasion cleanup --force        игнорировать ошибки отмены и очистить журнал
                                  (использовать только когда известно, что
                                  изменения уже удалены руками)

Правка hosts и файрвольных правил требует прав администратора.
`

// cleanupInfo — машинно-читаемая сводка.
type cleanupInfo struct {
	ManifestPath string          `json:"manifest_path"`
	StartedAt    string          `json:"started_at"`
	LiveEngines  []enginelock.Entry `json:"live_engines,omitempty"`
	Attempted    int             `json:"attempted"`
	Succeeded    int             `json:"succeeded"`
	Failed       int             `json:"failed"`
	Records      []cleanupItem   `json:"records"`
}

// cleanupItem — результат по одной записи.
type cleanupItem struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Action  string `json:"action"` // "removed", "already_absent", "failed", "skipped_dry_run"
	Error   string `json:"error,omitempty"`
}

// cleanupCommand — точка входа подкоманды `evasion cleanup`.
func cleanupCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "машинно-читаемый вывод")
	dryRun := fs.Bool("dry-run", false, "показать что бы откатили, не трогая систему")
	force := fs.Bool("force", false, "игнорировать ошибки отмены, очистить журнал")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) > 0 {
		fmt.Fprint(os.Stderr, cleanupUsage)
		return fmt.Errorf("неожиданный аргумент %q", fs.Arg(0))
	}

	manifestPath := filepath.Join(defaultStateDir, "system.json")
	m, err := sysmanifest.Open(manifestPath)
	if err != nil {
		return fmt.Errorf("открытие журнала %s: %w", manifestPath, err)
	}

	// Если ещё работает экземпляр движка, предупреждаем: откат при живом
	// движке может расщепить состояние (движок как раз держит правило или
	// только что его применил). Это не блок, а предупреждение: админ знает
	// что делает.
	live, _ := enginelock.ListLive(filepath.Join(defaultStateDir, "engine.lock"), nil)

	info := cleanupInfo{
		ManifestPath: manifestPath,
		LiveEngines:  live,
		StartedAt:    nowRFC3339(),
	}

	pending := m.Pending()
	for _, rec := range pending {
		item := cleanupItem{Kind: string(rec.Kind), ID: rec.ID}
		info.Attempted++
		if *dryRun {
			item.Action = "skipped_dry_run"
			info.Records = append(info.Records, item)
			continue
		}
		err := undoRecord(rec)
		switch {
		case err == nil:
			item.Action = "removed"
			info.Succeeded++
			if removeErr := m.Remove(rec.Kind, rec.ID); removeErr != nil {
				item.Error = removeErr.Error()
			}
		case *force:
			// Форсированный режим: учитываем провал, но запись из журнала
			// всё равно убираем. Используется для «я уже удалил вручную».
			item.Action = "removed"
			item.Error = "forced: " + err.Error()
			info.Succeeded++
			_ = m.Remove(rec.Kind, rec.ID)
		default:
			item.Action = "failed"
			item.Error = err.Error()
			info.Failed++
		}
		info.Records = append(info.Records, item)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}
	printCleanupInfo(os.Stdout, info, *dryRun, *force)
	return nil
}

// undoRecord выполняет отмену конкретной записи. Диспатч по виду; каждый вид
// обслуживается в своей функции, чтобы расширение (новый вид) было одной
// добавкой и не трогало существующие ветки.
func undoRecord(rec sysmanifest.Record) error {
	switch rec.Kind {
	case sysmanifest.KindFirewallRule:
		return undoFirewallRule(rec)
	case sysmanifest.KindHostsEntry:
		return undoHostsEntry(rec)
	default:
		return fmt.Errorf("неизвестный вид изменения %q", rec.Kind)
	}
}

// undoFirewallRule снимает правило `netsh advfirewall firewall` по имени.
//
// На не-Windows это стаб (команда недоступна), и мы не теряем лицо: такой
// записи в журнале на не-Windows быть не должно; если она появилась, вернём
// ошибку, которую `--force` погасит.
func undoFirewallRule(rec sysmanifest.Record) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("правила файрвола отменяются только на Windows (вид %q, id %q)", rec.Kind, rec.ID)
	}
	// netsh возвращает 0 при успехе; «нет такого правила» он тоже считает успехом
	// в большинстве версий, но на всякий случай игнорируем конкретные коды.
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+rec.ID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// «No rules match the specified criteria» — не ошибка, запись
		// уже убрана руками: это и есть идемпотентность отмены.
		if strings.Contains(strings.ToLower(string(out)), "no rules") {
			return nil
		}
		return fmt.Errorf("netsh: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// undoHostsEntry убирает управляемый блок из hosts.
//
// UndoData у hosts содержит block_id (имя блока, как hostsBlockID). Если
// UndoData пустая — используем hostsBlockID по умолчанию (на старых записях
// до внедрения манифеста).
func undoHostsEntry(rec sysmanifest.Record) error {
	blockID := hostsBlockID
	if len(rec.UndoData) > 0 {
		var undo struct {
			BlockID string `json:"block_id"`
		}
		if err := json.Unmarshal(rec.UndoData, &undo); err == nil && undo.BlockID != "" {
			blockID = undo.BlockID
		}
	}
	data, err := os.ReadFile(systemHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // нечего отменять
		}
		return fmt.Errorf("чтение hosts: %w", err)
	}
	h := hosts.Parse(data)
	if !h.Remove(blockID) {
		return nil // блока уже нет — идемпотентно ок
	}
	if err := writeHostsInPlace(systemHostsPath, h.Render()); err != nil {
		return err
	}
	return nil
}

// printCleanupInfo печатает человекочитаемую сводку.
func printCleanupInfo(w *os.File, info cleanupInfo, dryRun, force bool) {
	fmt.Fprintf(w, "журнал: %s\n", info.ManifestPath)
	if len(info.LiveEngines) > 0 {
		fmt.Fprintf(w, "ВНИМАНИЕ: обнаружены работающие экземпляры движка (%d) — откат во время работы может расщепить состояние\n",
			len(info.LiveEngines))
		for _, e := range info.LiveEngines {
			fmt.Fprintf(w, "  pid %d, фильтр %q, запущен %s\n", e.PID, e.Filter, e.StartedAt.Format("15:04:05"))
		}
	}
	fmt.Fprintf(w, "записей в журнале: %d\n", info.Attempted)
	if dryRun {
		fmt.Fprintln(w, "(dry-run: ничего не меняем)")
	}
	for _, r := range info.Records {
		fmt.Fprintf(w, "  %s/%s", r.Kind, r.ID)
		switch r.Action {
		case "removed":
			if r.Error != "" {
				fmt.Fprintf(w, " — удалено (с принуждением: %s)\n", r.Error)
			} else {
				fmt.Fprintln(w, " — удалено")
			}
		case "skipped_dry_run":
			fmt.Fprintln(w, " — было бы удалено (dry-run)")
		case "failed":
			fmt.Fprintf(w, " — НЕ УДАЛОСЬ: %s\n", r.Error)
		default:
			fmt.Fprintln(w, " — "+r.Action)
		}
	}
	fmt.Fprintf(w, "итог: удалено %d, провалено %d\n", info.Succeeded, info.Failed)
	if info.Failed > 0 && !force {
		fmt.Fprintln(w, "записи с ошибками остались в журнале; можно повторить cleanup, снять правки руками или использовать --force")
	}
	if info.Attempted == 0 {
		fmt.Fprintln(w, "ничего не отменяли: журнал пуст или движок никогда не менял систему")
	}
}

// nowRFC3339 — отдельная функция ради удобства замены в тестах.
var nowRFC3339 = func() string {
	return formatNow()
}
