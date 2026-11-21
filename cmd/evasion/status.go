package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/fitting-1c/evasion/internal/control"
)

// defaultStateDir — каталог состояния по умолчанию.
//
// Относительный путь намеренно: движок запускается консольно из своего
// каталога (4.6), системной службы нет, и прописывать абсолютные пути вроде
// ProgramData значило бы требовать прав, которых на этапе 0 не нужно.
const defaultStateDir = "state"

// statusFileName — имя файла состояния внутри каталога состояния.
const statusFileName = "status.json"

// statusCommand показывает состояние работающего движка (2.3).
//
// Читает снимок, который движок выкладывает при каждом пересчёте. Это снимок,
// а не запрос к движку, поэтому в выводе есть planned_at: по нему видно,
// насколько данные свежи. Если движок не запущен, файла нет, и команда
// говорит об этом прямо, а не показывает пустое состояние как рабочее.
//
// Флаг --rtc переключает в режим карты живучести RTC-серверов Discord
// (см. rtcstatus_cmd.go).
func statusCommand(ctx context.Context, args []string) error {
	// Пропуск предварительной проверки: если среди аргументов есть --rtc, идём
	// в отдельный обработчик с собственным набором флагов.
	for _, a := range args {
		if a == "--rtc" || a == "-rtc" {
			// Убираем --rtc из args и передаём остальное дочерней команде.
			var passthrough []string
			for _, aa := range args {
				if aa == "--rtc" || aa == "-rtc" {
					continue
				}
				passthrough = append(passthrough, aa)
			}
			return rtcStatusCommand(ctx, passthrough)
		}
	}

	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	var (
		stateDir = fs.String("state-dir", defaultStateDir, "каталог состояния движка")
		jsonOut  = fs.Bool("json", false, "машинно-читаемый вывод")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := readStatus(*stateDir)
	if err != nil {
		return err
	}
	if *jsonOut {
		return writeJSON(os.Stdout, st)
	}
	printStatus(os.Stdout, st)
	return nil
}

// portfolioCommand показывает стратегии с их ступенями (2.3).
//
// Отдельная команда, а не раздел status, потому что задание называет её
// отдельно и потому что у неё другой вопрос: status отвечает «что сейчас
// происходит», portfolio — «что у движка есть».
func portfolioCommand(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("portfolio", flag.ContinueOnError)
	var (
		stateDir = fs.String("state-dir", defaultStateDir, "каталог состояния движка")
		jsonOut  = fs.Bool("json", false, "машинно-читаемый вывод")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := readStatus(*stateDir)
	if err != nil {
		return err
	}

	if *jsonOut {
		// Выводится не только список: точка наблюдения и время пересчёта
		// нужны, чтобы оценки было к чему отнести (6.1). Список без них
		// отвечал бы на вопрос «работает ли стратегия» без указания, у кого
		// именно, а такой ответ не имеет смысла.
		return writeJSON(os.Stdout, struct {
			Vantage   string                  `json:"vantage"`
			PlannedAt time.Time               `json:"planned_at"`
			Portfolio []control.HoldingStatus `json:"portfolio"`
		}{
			Vantage:   st.Vantage.String(),
			PlannedAt: st.PlannedAt,
			Portfolio: st.Portfolio,
		})
	}
	printPortfolio(os.Stdout, st)
	return nil
}

// readStatus читает файл состояния из каталога.
func readStatus(dir string) (control.Status, error) {
	path := filepath.Join(dir, statusFileName)
	st, err := control.ReadStatusFile(path)
	if err != nil {
		if os.IsNotExist(errUnwrap(err)) {
			return control.Status{}, fmt.Errorf("состояние не найдено (%s): движок не запущен или запущен с другим --state-dir", path)
		}
		return control.Status{}, err
	}
	return st, nil
}

// errUnwrap достаёт исходную ошибку, чтобы отличить «файла нет» от прочих
// неудач чтения: сообщения у них разные по смыслу.
func errUnwrap(err error) error {
	for {
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return err
		}
		next := u.Unwrap()
		if next == nil {
			return err
		}
		err = next
	}
}

// writeJSON выводит структуру с отступами: вывод читают и люди, и программы, а
// отступы не меняют разбор.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// printStatus выводит состояние человекочитаемо.
//
// Это отдельная ветка форматирования, и на структуры --json она не влияет
// (2.3): подписи, выравнивание и порядок столбцов живут только здесь.
func printStatus(w io.Writer, st control.Status) {
	fmt.Fprintf(w, "точка наблюдения: %s\n", st.Vantage)
	fmt.Fprintf(w, "снимок:           №%d от %s\n", st.SnapshotRev, st.PlannedAt.Format(time.RFC3339))
	// Два времени показываются раздельно намеренно: решения пересчитываются
	// по своему периоду, а данные обновляются непрерывно. Видя только время
	// снимка, человек принимал бы его за время данных и считал устаревшими
	// числа приёма, которые на деле свежие.
	fmt.Fprintf(w, "состояние:        записано %s\n", st.UpdatedAt.Format(time.RFC3339))
	if st.Blackout {
		fmt.Fprintf(w, "ТРЕВОГА:          полный обвал портфеля, ни одной действующей стратегии\n")
	}
	fmt.Fprintf(w, "доля проверки:    %d‰\n", st.TrialPermille)
	fmt.Fprintf(w, "наблюдения:       принято %d, отброшено %d, непригодных %d (очередь %d, оценок %d)\n",
		st.Intake.Accepted, st.Intake.Dropped, st.Intake.Invalid, st.Intake.Queue, st.Intake.Estimates)

	if len(st.Targets) > 0 {
		fmt.Fprintf(w, "\nцели:\n")
		tw := tabwriter.NewWriter(w, 2, 8, 2, ' ', 0)
		fmt.Fprintf(tw, "  цель\tдействует\tпричина\tпроверка\tдоля\tсмен\tбез стратегии\n")
		for _, t := range st.Targets {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%d‰\t%d\t%s\n",
				t.Target, short(t.Active.String()), t.Reason,
				short(t.Trial.String()), t.TrialPermille, t.Switches,
				baselineCell(t.Baseline))
		}
		tw.Flush()
	}
}

// printPortfolio выводит портфель человекочитаемо.
func printPortfolio(w io.Writer, st control.Status) {
	if len(st.Portfolio) == 0 {
		fmt.Fprintf(w, "портфель пуст (точка наблюдения %s)\n", st.Vantage)
		return
	}
	fmt.Fprintf(w, "портфель, точка наблюдения %s, снимок от %s:\n",
		st.Vantage, st.PlannedAt.Format(time.RFC3339))
	tw := tabwriter.NewWriter(w, 2, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "  стратегия\tступень\tвред\tразрешён\tдерево\n")
	for _, h := range st.Portfolio {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
			short(h.StrategyID.String()), h.Status,
			yesNo(h.Collateral), yesNo(h.CollateralAllowed), yesNo(h.HasTree))
	}
	tw.Flush()
}

// baselineCell описывает базовую линию цели для таблицы.
//
// Столбец отвечает на вопрос «а блокируется ли цель вообще» — без него отказ
// автопилота повысить стратегию выглядит необъяснимым: человек видит успешные
// пробы и неприменённую стратегию. Неизмеренная базовая линия показывается
// прочерком, а не нулями: ноль здесь означал бы «цель мертва», то есть прямо
// противоположное незнанию.
func baselineCell(b control.BaselineStatus) string {
	if !b.Known {
		return "—"
	}
	return fmt.Sprintf("%d/%d ok (≤%d‰)", b.Successes, b.Observations, b.UpperPermille)
}

// short сокращает идентификатор до читаемой длины. Только для
// человекочитаемого вывода: в --json идентификаторы остаются полными, потому
// что по ним ищут.
func short(id string) string {
	const keep = 12
	switch {
	case id == "":
		return "—"
	case len(id) <= keep:
		return id
	default:
		return id[:keep]
	}
}

// yesNo переводит признак в пометку для таблицы.
func yesNo(v bool) string {
	if v {
		return "да"
	}
	return "нет"
}
