package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fitting-1c/evasion/internal/events"
)

const eventsUsage = `evasion events — поток событий жизненного цикла движка

  evasion events --tail             живая лента (следит за файлом events.jsonl)
  evasion events --since 10m        последние события за N минут
  evasion events --filter sni=XXX   фильтр по SNI
  evasion events --filter kind=X    фильтр по виду события
  evasion events --format json      машинно-читаемый вывод (как в файле)
  evasion events --format table     краткий человекочитаемый вывод

Виды событий (--filter kind=):
  client_hello.seen        распознан ClientHello
  strategy.applied         стратегия применена
  strategy.failed          стратегия не применилась
  passive.retransmit       повтор ClientHello (пассивный признак срыва)
  flow.reset               соединение разорвано
  flow.settled             соединение дошло до шифрованного обмена
  killswitch.engaged       killswitch поднят
  killswitch.released      killswitch снят
  runtime.goroutine_panic  горутина упала с паникой
  system.change_applied    системное изменение применено
  system.change_reverted   системное изменение отменено
`

// eventsCommand — точка входа команды.
func eventsCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("events", flag.ContinueOnError)
	tail := fs.Bool("tail", false, "следить за файлом в реальном времени")
	since := fs.Duration("since", 0, "показать события за последние N (например 10m, 1h)")
	filterStr := fs.String("filter", "", "фильтр: ключ=значение (sni=X, kind=X)")
	format := fs.String("format", "table", "format: json|table")
	path := fs.String("file", filepath.Join(defaultStateDir, "events.jsonl"),
		"путь к файлу журнала событий")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) > 0 {
		fmt.Fprint(os.Stderr, eventsUsage)
		return fmt.Errorf("неожиданный аргумент %q", fs.Arg(0))
	}

	filter, err := parseEventFilter(*filterStr)
	if err != nil {
		return err
	}
	cutoff := time.Time{}
	if *since > 0 {
		cutoff = time.Now().Add(-*since)
	}

	f, err := os.Open(*path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("файл %s не найден — движок ещё не писал событий, либо путь другой", *path)
		}
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	// Начальное чтение всего файла с фильтром.
	scanner := bufio.NewScanner(f)
	// Увеличиваем буфер — события могут быть длиннее стандартных 64К при
	// широких Attrs (например, большой список SNI).
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if err := emitEventLine(w, scanner.Bytes(), filter, cutoff, *format); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("чтение %s: %w", *path, err)
	}

	// Режим --tail: следим за дописыванием. Простая реализация через polling,
	// без fsnotify: события не настолько частые, чтобы это стало узким местом.
	if *tail {
		w.Flush()
		return tailEvents(ctx, f, w, filter, cutoff, *format)
	}
	return nil
}

// eventFilter — простой парсер фильтра `ключ=значение`.
type eventFilter struct {
	sni  string
	kind string
}

func parseEventFilter(s string) (eventFilter, error) {
	if s == "" {
		return eventFilter{}, nil
	}
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 {
		return eventFilter{}, fmt.Errorf("фильтр должен быть key=value, получено %q", s)
	}
	key, val := parts[0], parts[1]
	var out eventFilter
	switch key {
	case "sni":
		out.sni = val
	case "kind":
		out.kind = val
	default:
		return eventFilter{}, fmt.Errorf("неизвестный ключ фильтра %q (поддержаны: sni, kind)", key)
	}
	return out, nil
}

func (f eventFilter) match(e events.Event) bool {
	if f.kind != "" && string(e.Kind) != f.kind {
		return false
	}
	if f.sni != "" {
		sni, _ := e.Attrs["sni"].(string)
		if sni != f.sni {
			return false
		}
	}
	return true
}

// emitEventLine разбирает одну строку и, если проходит фильтр, печатает.
func emitEventLine(w *bufio.Writer, line []byte, f eventFilter, cutoff time.Time, format string) error {
	if len(line) == 0 {
		return nil
	}
	var e events.Event
	if err := json.Unmarshal(line, &e); err != nil {
		// Повреждённая строка (не JSON) — пропускаем молча: журнал может
		// содержать половины последней записи при аварийной остановке.
		return nil
	}
	if !cutoff.IsZero() && e.At.Before(cutoff) {
		return nil
	}
	if !f.match(e) {
		return nil
	}
	switch format {
	case "json":
		if _, err := w.Write(line); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	default:
		if _, err := fmt.Fprintf(w, "%s  %-24s  flow=%s  %s\n",
			e.At.Format("15:04:05.000"),
			e.Kind,
			e.FlowID,
			formatAttrs(e.Attrs)); err != nil {
			return err
		}
	}
	return nil
}

// formatAttrs превращает map атрибутов в короткую строку key=value.
func formatAttrs(attrs map[string]any) string {
	if len(attrs) == 0 {
		return ""
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	// Сортировка не критична, но делаем ради предсказуемости вывода.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%s=%v", k, attrs[k])
	}
	return sb.String()
}

// tailEvents продолжает читать файл, следя за новыми строками. Простой
// polling: каждые 100 мс пытаемся прочитать ещё; при EOF ждём и повторяем.
func tailEvents(ctx context.Context, f *os.File, w *bufio.Writer, filter eventFilter, cutoff time.Time, format string) error {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	reader := bufio.NewReader(f)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			for {
				line, err := reader.ReadBytes('\n')
				if len(line) > 0 {
					if err2 := emitEventLine(w, trimNewline(line), filter, cutoff, format); err2 != nil {
						return err2
					}
				}
				if err != nil {
					break // EOF — ждём следующего тика
				}
			}
			w.Flush()
		}
	}
}

// trimNewline убирает trailing \n из буфера (ReadBytes его включает).
func trimNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		return b[:len(b)-1]
	}
	return b
}
