package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/hosts"
	"github.com/fitting-1c/evasion/internal/sysmanifest"
)

// systemHostsPath — путь к системному hosts-файлу.
//
// На Windows этот путь — константа ОС (по размещению драйверов), и смысла
// делать его настраиваемым нет: правка не в этом файле не имеет никакого
// эффекта на системное разрешение имён. На не-Windows пакет пока не
// используется в живом движке, но путь определён для разработки/тестов (там
// это обычно `/etc/hosts`). Задание 3.1 называет Windows единственной целевой
// платформой, поэтому поведение на других ОС — развития ради, не продукта.
var systemHostsPath = func() string {
	if runtime.GOOS == "windows" {
		if sys := os.Getenv("SystemRoot"); sys != "" {
			return sys + `\System32\drivers\etc\hosts`
		}
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}()

// hostsCommand — точка входа в подкоманду `evasion hosts`.
//
// Три подкоманды: status (посмотреть), apply (применить из конфига), clean
// (убрать всё управляемое движком). Специально нет «просто подать IP и имя
// руками» — поверхность управления контрактная и должна описываться конфигом,
// иначе hosts превратится в свалку.
func hostsCommand(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("укажите подкоманду: status | apply | clean\nСм. evasion hosts status -h")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "status":
		return hostsStatusCommand(ctx, rest)
	case "apply":
		return hostsApplyCommand(ctx, rest)
	case "clean":
		return hostsCleanCommand(ctx, rest)
	case "-h", "--help":
		fmt.Fprint(os.Stdout, hostsUsage)
		return nil
	default:
		return fmt.Errorf("неизвестная подкоманда %q\n\n%s", sub, hostsUsage)
	}
}

// hostsUsage собирается в рантайме, потому что `systemHostsPath` зависит от
// переменной окружения SystemRoot — константой её не сделать.
var hostsUsage = `evasion hosts — управление системным hosts-файлом (транспорт A)

  evasion hosts status            показать управляемые движком блоки
  evasion hosts apply --config F  применить transport_fallback из конфига
  evasion hosts clean             убрать все evasion-блоки из hosts

Правка hosts требует прав администратора; status — не требует.
Файл: ` + systemHostsPath + "\n"

// hostsBlockID — ID управляемого блока для transport_fallback (используется в
// Apply и Clean). Хранится константой: при переименовании его маркер в hosts
// у существующих пользователей не узнается, и Clean пропустит старый блок.
// Если когда-то понадобится переименование, Clean обязан принимать оба имени
// — старое и новое — до окончания переходного периода.
const hostsBlockID = "cloudflare-fallback"

// hostsStatusInfo — машинно-читаемый вывод status.
type hostsStatusInfo struct {
	Path         string          `json:"path"`
	Exists       bool            `json:"exists"`
	Readable     bool            `json:"readable"`
	BlockPresent bool            `json:"block_present"`
	Block        *hostsBlockInfo `json:"block,omitempty"`
}

// hostsBlockInfo — что лежит в блоке, кратко.
type hostsBlockInfo struct {
	ID      string   `json:"id"`
	Entries []string `json:"entries"`
}

// hostsStatusCommand показывает состояние hosts: есть ли управляемый блок, что
// в нём. Не требует прав — только чтение.
func hostsStatusCommand(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("hosts status", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "машинно-читаемый вывод")
	if err := fs.Parse(args); err != nil {
		return err
	}

	info := hostsStatusInfo{Path: systemHostsPath}
	data, err := os.ReadFile(systemHostsPath)
	switch {
	case os.IsNotExist(err):
		info.Exists = false
	case err != nil:
		info.Exists = true
		info.Readable = false
	default:
		info.Exists = true
		info.Readable = true
		h := hosts.Parse(data)
		if h.HasBlock(hostsBlockID) {
			info.BlockPresent = true
			info.Block = &hostsBlockInfo{
				ID:      hostsBlockID,
				Entries: extractBlockEntries(data, hostsBlockID),
			}
		}
	}

	if *jsonOut {
		return writeJSON(os.Stdout, info)
	}
	printHostsStatus(os.Stdout, info)
	return nil
}

// extractBlockEntries вытаскивает строки «IP host» из управляемого блока.
// Отдельно от internal/hosts, потому что hosts.Hosts хранит строки блока без
// семантики; тут только для вывода, не для правки.
func extractBlockEntries(data []byte, id string) []string {
	begin := "# >>> evasion:" + id + " begin >>>"
	end := "# <<< evasion:" + id + " end <<<"
	in := false
	var entries []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == begin {
			in = true
			continue
		}
		if line == end {
			in = false
			continue
		}
		if in && line != "" && !strings.HasPrefix(line, "#") {
			entries = append(entries, line)
		}
	}
	return entries
}

func printHostsStatus(w *os.File, info hostsStatusInfo) {
	fmt.Fprintf(w, "hosts: %s\n", info.Path)
	switch {
	case !info.Exists:
		fmt.Fprintln(w, "состояние: файл не найден")
	case !info.Readable:
		fmt.Fprintln(w, "состояние: не читается (нужны права?)")
	case !info.BlockPresent:
		fmt.Fprintln(w, "управляемый блок: отсутствует (hosts нетронут)")
	default:
		fmt.Fprintf(w, "управляемый блок: evasion:%s, записей: %d\n", info.Block.ID, len(info.Block.Entries))
		for _, e := range info.Block.Entries {
			fmt.Fprintf(w, "  %s\n", e)
		}
	}
}

// hostsApplyCommand читает конфиг, собирает блок из TransportFallback и
// применяет в hosts.
func hostsApplyCommand(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("hosts apply", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "путь к файлу конфигурации (обязательно)")
	jsonOut := fs.Bool("json", false, "машинно-читаемый вывод")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("укажите --config: без него нечего применять")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if !cfg.TransportFallback.Enabled {
		return fmt.Errorf("в конфиге transport_fallback.enabled=false: нечего применять")
	}

	if elev, checked := elevated(); checked && !elev {
		return fmt.Errorf("правка hosts требует прав администратора")
	}

	changed, err := applyFallback(cfg.TransportFallback)
	if err != nil {
		return err
	}
	// Запись в журнал системных изменений — чтобы evasion cleanup знал,
	// что откатывать. Пишем всегда (включая changed=false): прежний блок
	// в hosts мог появиться от предыдущего запуска, и его тоже надо
	// учитывать для cleanup. Ошибку записи не роняем в фатал: применение
	// уже успешно, журнал — побочная наблюдаемость.
	allDomains := transportFallbackDomains(cfg.TransportFallback)
	if err := recordHostsBlockApplied(hostsBlockID, allDomains); err != nil {
		fmt.Fprintf(os.Stderr, "ВНИМАНИЕ: не удалось записать в журнал системных изменений: %v\n", err)
	}

	// Выходим с чистым статусом, но помечаем в JSON, что меняли или нет.
	if *jsonOut {
		return writeJSON(os.Stdout, struct {
			Changed bool                            `json:"changed"`
			Entries []config.TransportFallbackEntry `json:"entries"`
		}{changed, cfg.TransportFallback.Entries})
	}
	if changed {
		fmt.Printf("применено: %d доменов, %d групп IP\n",
			len(allDomains), len(cfg.TransportFallback.Entries))
		for _, e := range cfg.TransportFallback.Entries {
			fmt.Printf("  %s → %s\n", strings.Join(e.Domains, ", "), e.SafeIP)
		}
	} else {
		fmt.Println("без изменений: блок уже совпадает")
	}
	fmt.Println("не забудь: ipconfig /flushdns")
	return nil
}

// applyFallback — чистая часть apply: читает текущий hosts, собирает блок,
// пишет при изменении. Выделено отдельно, чтобы на синтетике проверять без
// обращения к системному hosts. internal/hosts уже чистый; эта функция — её
// обёртка для доменной логики (сборка записей из конфига) + I/O.
//
// Собирает ВСЕ Entries в один управляемый блок (единый ID = hostsBlockID).
// Разные entries кладут в блок разные записи (IP, Host) — hosts.ManagedBlock
// не навязывает единый IP на блок, он просто рендерит список Entry строками.
// Поэтому мультисетевой transport_fallback (gateway/media на одном IP, cdn
// на другом) выражается без ветвления по ID блока.
func applyFallback(f config.TransportFallback) (changed bool, err error) {
	data, err := os.ReadFile(systemHostsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("чтение hosts: %w", err)
		}
		data = nil // пустой hosts — создадим с нуля
	}
	h := hosts.Parse(data)

	// Собираем все (IP, Host) пары из всех Entries по порядку.
	// Entries уже заполнены парсером: либо из нового формата entries, либо
	// свёрнуты из старого safe_ip+domains в одну Entry.
	var entries []hosts.Entry
	for _, e := range f.Entries {
		for _, d := range e.Domains {
			entries = append(entries, hosts.Entry{IP: e.SafeIP, Host: d})
		}
	}

	block := hosts.ManagedBlock{
		ID: hostsBlockID,
		Comment: []string{
			"Transport-A: подмена доменов на незаблокированные Cloudflare IP.",
			"Нужна, пока ISP режет SYN до реального диапазона Discord (162.159.*)",
			"на TCP:443. Разные Cloudflare Spectrum endpoints не серверят чужой",
			"SNI, поэтому разные домены разводятся на разные IP (суффикс .232",
			"для gateway/media, .233 для cdn.discordapp.com).",
			"Управляется evasion hosts apply/clean.",
		},
		Entries: entries,
	}

	changed, err = h.Apply(block)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}

	out := h.Render()
	if err := writeHostsInPlace(systemHostsPath, out); err != nil {
		return false, err
	}
	return true, nil
}

// transportFallbackDomains возвращает плоский список всех доменов из всех
// Entries — для логирования и записи в sysmanifest, где важен список доменов
// независимо от того, как они разбиты по IP.
func transportFallbackDomains(f config.TransportFallback) []string {
	var out []string
	for _, e := range f.Entries {
		out = append(out, e.Domains...)
	}
	return out
}

// writeHostsInPlace записывает hosts, перезаписывая содержимое по месту.
//
// Задумано было через tmp+rename ради атомарности, но на Windows замена файла
// в системной папке `C:\Windows\System32\drivers\etc\` даёт Access denied даже
// у администратора — ACL каталога запрещает move-replace. Прямая перезапись
// (OpenFile с O_TRUNC) ту же защиту не задевает: это именно то, что делает
// StreamWriter в PowerShell и чем работает apply-cloudflare-fallback.ps1.
//
// Атомарности от этого терять не страшно: системный DNS-ресолвер Windows не
// читает hosts на каждом запросе — он кэширует и перечитывает по сбросу
// (`ipconfig /flushdns`) или перезапуску службы. Промежуточное состояние
// файла доступ к имени не ломает.
//
// Для безопасности от катастрофы (система упала посреди записи, hosts остался
// обрезанным) пишем на изолированной транзакции: сначала помечаем файл
// бэкапом (`.bak-prev`), если он ещё не создан вызывающим, затем перезаписываем.
// Этого достаточно, чтобы вручную откатить руками, если что-то пошло не так.
func writeHostsInPlace(path string, data []byte) error {
	// Открываем существующий файл для перезаписи. O_CREATE нужен для случая,
	// когда hosts отсутствует вовсе (новая установка Windows с удалённым
	// файлом — редкость, но валидный случай).
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("открытие hosts для записи: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("запись hosts: %w", err)
	}
	if err := f.Sync(); err != nil {
		// Sync обязателен: без него система может откладывать запись, и при
		// падении питания hosts останется в прежнем виде. Для системного
		// файла это нежелательно.
		return fmt.Errorf("sync hosts: %w", err)
	}
	return nil
}

// hostsCleanCommand удаляет управляемый блок из hosts.
//
// Не требует конфига: ID блока известен константой. Это осознано — Clean
// должен работать даже когда конфиг потерян, иначе невозможно откатить
// изменение, если юзер удалил cfg.json.
func hostsCleanCommand(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("hosts clean", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "машинно-читаемый вывод")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if elev, checked := elevated(); checked && !elev {
		return fmt.Errorf("правка hosts требует прав администратора")
	}

	data, err := os.ReadFile(systemHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			if *jsonOut {
				return writeJSON(os.Stdout, map[string]bool{"removed": false, "exists": false})
			}
			fmt.Println("hosts не найден — нечего убирать")
			return nil
		}
		return fmt.Errorf("чтение hosts: %w", err)
	}

	h := hosts.Parse(data)
	removed := h.Remove(hostsBlockID)
	if !removed {
		// Из журнала — тоже убираем на случай, если запись осталась от
		// предыдущего запуска, а блок в hosts уже удалён руками.
		_ = removeHostsBlockRecord(hostsBlockID)
		if *jsonOut {
			return writeJSON(os.Stdout, map[string]bool{"removed": false})
		}
		fmt.Println("без изменений: управляемого блока не было")
		return nil
	}

	if err := writeHostsInPlace(systemHostsPath, h.Render()); err != nil {
		return err
	}
	// Отменили — вычёркиваем из журнала (cleanup потом не будет пытаться
	// отменить то, чего уже нет).
	_ = removeHostsBlockRecord(hostsBlockID)
	if *jsonOut {
		return writeJSON(os.Stdout, map[string]bool{"removed": true})
	}
	fmt.Println("удалено: evasion:" + hostsBlockID)
	fmt.Println("не забудь: ipconfig /flushdns")
	return nil
}

// recordHostsBlockApplied сохраняет в sysmanifest, что блок id с данными
// домены был применён. Используется и ручной hosts apply, и автоприменением
// при старте.
func recordHostsBlockApplied(id string, domains []string) error {
	path := filepath.Join(defaultStateDir, "system.json")
	m, err := sysmanifest.Open(path)
	if err != nil {
		return err
	}
	undo := struct {
		BlockID string   `json:"block_id"`
		Domains []string `json:"domains"`
	}{BlockID: id, Domains: domains}
	return m.Record(sysmanifest.KindHostsEntry, "hosts-block:"+id, undo)
}

// removeHostsBlockRecord вычёркивает запись блока из sysmanifest. Безопасно
// вызывать на несуществующей записи.
func removeHostsBlockRecord(id string) error {
	path := filepath.Join(defaultStateDir, "system.json")
	m, err := sysmanifest.Open(path)
	if err != nil {
		return err
	}
	return m.Remove(sysmanifest.KindHostsEntry, "hosts-block:"+id)
}



// applyTransportFallbackOnStart — автоприменение hosts-блока при старте
// `evasion run`. Вызывается из runCommand только когда
// cfg.TransportFallback.Enabled=true.
//
// Политика: применить при старте, НЕ снимать при остановке. Это осознано —
// клиент (Discord) без hosts-подмены пойдёт на реальные IP, которые ISP режет,
// и перестанет работать даже когда movok отработал и ушёл. Пользователь явно
// снимает подмену через `evasion hosts clean`, когда она ему больше не нужна.
//
// Любая неудача на старте — фатальная: конфиг включил эту настройку, значит
// пользователь ожидает её работы. Молча пропускать и запускать движок дальше
// — это тот же класс «молчаливой потери наблюдаемости», от которого в проекте
// уже страдали (ложная тревога обвала, вечный «подключается»).
func applyTransportFallbackOnStart(f config.TransportFallback, logger interface{ Info(string, ...any) }) error {
	if elev, checked := elevated(); checked && !elev {
		return fmt.Errorf("transport_fallback включён, но нет прав администратора — hosts править нельзя")
	}
	changed, err := applyFallback(f)
	if err != nil {
		return fmt.Errorf("transport_fallback: %w", err)
	}
	// Пишем в журнал системных изменений — одинаково для changed=true/false.
	// Если блок там уже есть (прошлый запуск), Record его замещает с новым
	// временем применения.
	allDomains := transportFallbackDomains(f)
	if err := recordHostsBlockApplied(hostsBlockID, allDomains); err != nil {
		logger.Info("transport_fallback: не удалось записать в журнал системных изменений",
			"ошибка", err)
	}
	if changed {
		logger.Info("transport_fallback: применён блок",
			"id", hostsBlockID, "групп_IP", len(f.Entries), "доменов", len(allDomains))
	} else {
		logger.Info("transport_fallback: блок уже в hosts, пропуск",
			"id", hostsBlockID, "групп_IP", len(f.Entries), "доменов", len(allDomains))
	}
	return nil
}
