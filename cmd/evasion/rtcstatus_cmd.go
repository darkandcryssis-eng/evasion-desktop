package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/fitting-1c/evasion/internal/rtctrack"
)

const rtcStatusUsage = `evasion status --rtc — карта живучести RTC-серверов Discord

Читает snapshot ` + "`state/rtctrack.json`" + ` и выводит таблицу: SNI сервера,
сколько попыток было, сколько прошли TLS-рукопожатие, какова доля успеха,
средний dwell живого соединения, итоговый score живучести (0..1000, выше =
лучше). Snapshot движок пишет сам раз в минуту во время работы + при
штатном shutdown.

  evasion status --rtc              таблица (txt)
  evasion status --rtc --json       машинно-читаемый
  evasion status --rtc --top 10     только top-N по score (default: все)
  evasion status --rtc --min 3      скрыть пары с observed < min (default: 1)
`

// rtcStatusInfo — машинно-читаемый формат.
type rtcStatusInfo struct {
	Path    string            `json:"path"`
	SavedAt time.Time         `json:"saved_at,omitempty"`
	Count   int               `json:"count"`
	Entries []rtcStatusEntry  `json:"entries"`
}

type rtcStatusEntry struct {
	SNI         string        `json:"sni"`
	Port        uint16        `json:"port"`
	Observed    int           `json:"observed"`
	Settled     int           `json:"settled"`
	Reset       int           `json:"reset"`
	SuccessPct  int           `json:"success_permille"`
	AvgDwellMs  int64         `json:"avg_dwell_ms"`
	Score       int           `json:"score"`
	LastAt      time.Time     `json:"last_at"`
}

// rtcStatusCommand — обработка `evasion status --rtc`.
func rtcStatusCommand(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("status --rtc", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "машинно-читаемый вывод")
	topN := fs.Int("top", 0, "только top-N по score (0 = все)")
	minObserved := fs.Int("min", 1, "скрыть пары с observed меньше этого (default 1)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := filepath.Join(defaultStateDir, rtcSnapshotName)
	tracker, err := rtctrack.Load(path, nil)
	if err != nil {
		return fmt.Errorf("rtctrack snapshot %s: %w", path, err)
	}
	entries := tracker.Rank(*topN, *minObserved)

	info := rtcStatusInfo{
		Path:    path,
		Count:   len(entries),
		Entries: make([]rtcStatusEntry, 0, len(entries)),
	}
	for _, e := range entries {
		info.Entries = append(info.Entries, rtcStatusEntry{
			SNI:        e.Pair.SNI,
			Port:       e.Pair.Port,
			Observed:   e.Stat.Observed,
			Settled:    e.Stat.Settled,
			Reset:      e.Stat.Reset,
			SuccessPct: e.Stat.SuccessRate(),
			AvgDwellMs: e.Stat.AvgDwell().Milliseconds(),
			Score:      e.Score,
			LastAt:     e.Stat.LastAt,
		})
	}

	if *jsonOut {
		return writeJSON(os.Stdout, info)
	}
	printRTCStatus(os.Stdout, info)
	return nil
}

// printRTCStatus — табличный вывод для глаз.
func printRTCStatus(w *os.File, info rtcStatusInfo) {
	fmt.Fprintf(w, "rtctrack snapshot: %s\n", info.Path)
	if info.Count == 0 {
		fmt.Fprintln(w, "ещё нет данных — движок не запускался или не видел RTC-соединений")
		return
	}
	fmt.Fprintf(w, "записей: %d\n\n", info.Count)
	tw := tabwriter.NewWriter(w, 2, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "SNI\tпорт\tпробы\tуспех\tsuccess‰\tdwell\tscore\tпоследнее")
	fmt.Fprintln(tw, "---\t----\t-----\t-----\t--------\t-----\t-----\t---------")
	for _, e := range info.Entries {
		dwell := "-"
		if e.AvgDwellMs > 0 {
			dwell = time.Duration(e.AvgDwellMs * int64(time.Millisecond)).Truncate(time.Second).String()
		}
		last := "-"
		if !e.LastAt.IsZero() {
			last = e.LastAt.Format("15:04:05")
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d‰\t%s\t%d\t%s\n",
			truncate(e.SNI, 44), e.Port, e.Observed, e.Settled, e.SuccessPct, dwell, e.Score, last)
	}
	tw.Flush()
}

// truncate обрезает длинные строки для таблицы.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// writeJSON помощник (объявлен в status.go, тут только используется).
var _ = json.NewEncoder
