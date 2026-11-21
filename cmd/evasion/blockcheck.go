package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/windivert"
)

// blockcheck перебирает портфель стратегий по одной цели и измеряет, какая
// обходит DPI (2.3). Это ручной предшественник генератора: тот же перебор, но
// внутри движка и с измерением исхода, а не глазами через curl.
//
// Измерение на этапе 1: для каждого кандидата поднимается контур перехвата с
// этой стратегией, затем своя проба — обычное рукопожатие TLS к цели (десинк
// накладывает WinDivert), и смотрится исход. Параллельной песочницы (5.2) здесь
// нет: перебор последовательный и запускается рукой, изоляция по портам нужна
// фоновому генератору, а не этому.

// Параметры по умолчанию. Вынести в конфиг — когда понадобится настройка.
const (
	blockProbesDefault = 5
	blockProbeTimeout  = 8 * time.Second
	// blockProbeGap — пауза между пробами: лёгкий джиттер, чтобы подряд идущие
	// соединения к одной цели не выглядели необычным рисунком (5.4).
	blockProbeGap = 300 * time.Millisecond
	// engineSettle — пауза после старта контура, чтобы он успел встать на
	// перехват до первой пробы.
	engineSettle = 400 * time.Millisecond
)

// blockCandidate — именованная стратегия-кандидат.
type blockCandidate struct {
	Name     string
	Strategy *strategy.Strategy
}

// candidateDefs — встроенный портфель проверенных приёмов. Хранится как JSON
// стратегии: тот же формат, что у конфигов и у будущих находок генератора, и
// каждый разбирается строгой валидацией при старте (негодный кандидат —
// программная ошибка, её ловит тест). Это стартовый набор, от которого потом
// отталкивается генератор (M7).
var candidateDefs = []struct {
	name  string
	strat string
}{
	{"disorder-sni", `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"reverse"},"left":{"kind":"send"},"right":{"kind":"send"}}}]}`},
	{"split-sni", `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"forward"},"left":{"kind":"send"},"right":{"kind":"send"}}}]}`},
	{"fake-badsum", `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"duplicate","left":{"kind":"tamper","params":{"field":"tcp_checksum","mode":"corrupt"},"left":{"kind":"tamper","params":{"field":"payload","mode":"replace","length":200},"left":{"kind":"send"}}},"right":{"kind":"send"}}}]}`},
	{"fake-split-sni", `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"duplicate","left":{"kind":"tamper","params":{"field":"tcp_checksum","mode":"corrupt"},"left":{"kind":"tamper","params":{"field":"payload","mode":"replace","length":200},"left":{"kind":"send"}}},"right":{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"forward"},"left":{"kind":"send"},"right":{"kind":"send"}}}}]}`},
	// fake-tls-google-badseq — fake,split, где фейк несёт БЕЗОБИДНЫЙ ClientHello
	// (SNI google), а обман — badseq: номер последовательности фейка уведён в
	// прошлое (seq-10000), поэтому сервер отбрасывает фейк на уровне TCP
	// (вне окна) НЕЗАВИСИМО от контрольной суммы. Это важно на Windows: offload
	// сетевой карты пересчитывает битую сумму в верную, и фейк с badsum доходил
	// до сервера, ломая рукопожатие (ответ по чужому ClientHello -> net_error
	// -113). badseq этого лишён — номер последовательности в прошлом сервер
	// отбрасывает по правилам TCP ещё до декодера, независимо от суммы.
	// Эта форма стоит в стратегии голоса discord_voice.
	{"fake-tls-google-badseq", `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"duplicate","left":{"kind":"tamper","params":{"field":"tcp_seq","mode":"add","value":4294957296},"left":{"kind":"tamper","params":{"field":"payload","mode":"replace","preset":"tls_clienthello_google"},"left":{"kind":"send"}}},"right":{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"forward"},"left":{"kind":"send"},"right":{"kind":"send"}}}}]}`},
	{"fake-disorder-sni", `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"duplicate","left":{"kind":"tamper","params":{"field":"tcp_checksum","mode":"corrupt"},"left":{"kind":"tamper","params":{"field":"payload","mode":"replace","length":200},"left":{"kind":"send"}}},"right":{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"reverse"},"left":{"kind":"send"},"right":{"kind":"send"}}}}]}`},
	{"fake-ttl-2", `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"duplicate","left":{"kind":"tamper","params":{"field":"ipv4_ttl","mode":"replace","value":2},"left":{"kind":"tamper","params":{"field":"payload","mode":"replace","length":200},"left":{"kind":"send"}}},"right":{"kind":"send"}}}]}`},
	{"fake-ttl-6", `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"duplicate","left":{"kind":"tamper","params":{"field":"ipv4_ttl","mode":"replace","value":6},"left":{"kind":"tamper","params":{"field":"payload","mode":"replace","length":200},"left":{"kind":"send"}}},"right":{"kind":"send"}}}]}`},
}

// starterCandidates разбирает встроенный портфель. Ошибка разбора — дефект
// кода, а не ввода, поэтому возвращается наружу и ловится тестом.
func starterCandidates() ([]blockCandidate, error) {
	out := make([]blockCandidate, 0, len(candidateDefs))
	for _, d := range candidateDefs {
		s, err := strategy.Unmarshal([]byte(d.strat), strategy.DefaultLimits())
		if err != nil {
			return nil, fmt.Errorf("blockcheck: кандидат %s: %w", d.name, err)
		}
		out = append(out, blockCandidate{Name: d.name, Strategy: s})
	}
	return out, nil
}

// blockResult — исход проверки одного кандидата.
type blockResult struct {
	Name       string `json:"name"`
	StrategyID string `json:"strategy_id,omitempty"`
	Success    int    `json:"success"`
	Total      int    `json:"total"`
	// Err — если измерение не состоялось (например, не поднялся перехват).
	// Отдельно от нулевого успеха: «не измерили» и «измерили, ноль» — разное.
	Err string `json:"err,omitempty"`
}

// rate возвращает долю успеха; -1, если не измерено (ошибка или ноль проб),
// чтобы такие строки не притворялись нулевой долей при ранжировании.
func (r blockResult) rate() float64 {
	if r.Err != "" || r.Total == 0 {
		return -1
	}
	return float64(r.Success) / float64(r.Total)
}

// measurer измеряет исход стратегии на цели. Вынесен за интерфейс, чтобы
// оркестровку blockcheck проверять без сети и WinDivert. nil-стратегия означает
// базовую линию: мерить цель без всякого десинка.
type measurer interface {
	Measure(ctx context.Context, cand *strategy.Strategy, host string, probes int) (success, total int, err error)
}

// runBlockcheck прогоняет базовую линию и всех кандидатов и собирает исходы.
// Оркестровка чистая: сетевое — в measurer. Прогресс пишется в log, потому что
// перебор идёт минуты, а таблица печатается лишь в конце: без прогресса это
// выглядело бы зависанием.
func runBlockcheck(ctx context.Context, m measurer, cands []blockCandidate, host string, probes int, log *slog.Logger) []blockResult {
	results := make([]blockResult, 0, len(cands)+1)
	total := len(cands) + 1

	// Базовая линия: цель без десинка. С ней сравнивается всё остальное —
	// кандидат «работает», только если берёт заметно лучше голой цели.
	log.Info("измеряю", "шаг", "1/"+itoa(total), "что", "base")
	bs, bt, berr := m.Measure(ctx, nil, host, probes)
	base := blockResult{Name: "base", Success: bs, Total: bt}
	if berr != nil {
		base.Err = berr.Error()
	}
	results = append(results, base)
	log.Info("готово", "что", "base", "успех", successCell(base))

	for i, c := range cands {
		if ctx.Err() != nil {
			break
		}
		log.Info("измеряю", "шаг", itoa(i+2)+"/"+itoa(total), "что", c.Name)
		s, t, err := m.Measure(ctx, c.Strategy, host, probes)
		r := blockResult{Name: c.Name, Success: s, Total: t}
		if c.Strategy != nil {
			r.StrategyID = c.Strategy.ID.String()
		}
		if err != nil {
			r.Err = err.Error()
		}
		results = append(results, r)
		log.Info("готово", "что", c.Name, "успех", successCell(r))
	}
	return results
}

// itoa — маленькая замена strconv для номеров шага в прогрессе.
func itoa(n int) string { return fmt.Sprintf("%d", n) }

// rankCandidates возвращает исходы кандидатов (без базовой линии),
// отсортированные по доле успеха убыванию; при равенстве — по имени, чтобы
// порядок был устойчив.
func rankCandidates(results []blockResult) []blockResult {
	out := make([]blockResult, 0, len(results))
	for _, r := range results {
		if r.Name != "base" {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].rate() != out[j].rate() {
			return out[i].rate() > out[j].rate()
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// blockcheckCommand разбирает флаги и запускает перебор.
func blockcheckCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("blockcheck", flag.ContinueOnError)
	var (
		probes  = fs.Int("probes", blockProbesDefault, "сколько проб на кандидата")
		jsonOut = fs.Bool("json", false, "машинно-читаемый вывод")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	host := fs.Arg(0)
	if host == "" {
		return fmt.Errorf("укажите цель: evasion blockcheck <host> [--probes N] [--json]")
	}
	if *probes < 1 {
		return fmt.Errorf("число проб должно быть положительным, получено %d", *probes)
	}

	// Перехват требует прав администратора (драйвер). Базовую линию измерить
	// можно и без них, но кандидаты — нет, поэтому отказываем заранее.
	if elev, checked := elevated(); checked && !elev {
		return fmt.Errorf("blockcheck измеряет через перехват и требует прав администратора (драйвер WinDivert)")
	}

	// Проба идёт внешним curl (внутрипроцессная не десинкается, см. probeOnce).
	if _, err := exec.LookPath("curl"); err != nil {
		return fmt.Errorf("blockcheck измеряет внешним curl, но он не найден в PATH: %w", err)
	}

	cands, err := starterCandidates()
	if err != nil {
		return err
	}

	logger := newLogger(os.Stderr, *jsonOut)
	m := &liveMeasurer{probeTimeout: blockProbeTimeout, logger: logger}

	results := runBlockcheck(ctx, m, cands, host, *probes, logger)

	if *jsonOut {
		return writeJSON(os.Stdout, struct {
			Host    string        `json:"host"`
			Probes  int           `json:"probes"`
			Results []blockResult `json:"results"`
		}{Host: host, Probes: *probes, Results: results})
	}
	printBlockcheck(os.Stdout, host, results)
	return nil
}

// Код возврата blockcheck всегда 0: это отчёт, вердикт несут данные (как в
// doctor). «Ничего не обошло» — тоже результат, а не ошибка команды.

// printBlockcheck выводит таблицу: базовая линия, затем кандидаты по убыванию
// доли успеха.
func printBlockcheck(w *os.File, host string, results []blockResult) {
	fmt.Fprintf(w, "цель: %s\n\n", host)
	tw := tabwriter.NewWriter(w, 2, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "  стратегия\tуспех\tдоля\tстратегия-id\n")

	var base blockResult
	for _, r := range results {
		if r.Name == "base" {
			base = r
		}
	}
	fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", "base", successCell(base), rateCell(base), "—")
	for _, r := range rankCandidates(results) {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", r.Name, successCell(r), rateCell(r), short(r.StrategyID))
	}
	tw.Flush()

	fmt.Fprintf(w, "\nдоля больше базовой линии = приём обходит DPI; base — голая цель.\n")
}

func successCell(r blockResult) string {
	if r.Err != "" {
		return "ошибка"
	}
	return fmt.Sprintf("%d/%d", r.Success, r.Total)
}

func rateCell(r blockResult) string {
	if r.rate() < 0 {
		return "—"
	}
	return fmt.Sprintf("%d%%", int(r.rate()*100+0.5))
}

// hostMatcher — радиус из одной цели для blockcheck. Совпадает по самому имени
// и его поддоменам: проба идёт к цели, и десинк нужен только ей.
type hostMatcher struct{ host string }

func (h hostMatcher) Matches(host, sni string) bool {
	return matchHost(sni, h.host) || matchHost(host, h.host)
}

// matchHost сообщает, совпадает ли name с целью или её поддоменом.
func matchHost(name, target string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return name == target || strings.HasSuffix(name, "."+target)
}

// liveMeasurer измеряет через настоящий перехват WinDivert.
type liveMeasurer struct {
	probeTimeout time.Duration
	logger       *slog.Logger
}

// Measure поднимает контур перехвата с кандидатом (nil = базовая линия без
// десинка), затем шлёт probes рукопожатий TLS к цели и считает удачные.
func (m *liveMeasurer) Measure(ctx context.Context, cand *strategy.Strategy, host string, probes int) (int, int, error) {
	// Базовая линия: без десинка — просто пробуем цель, перехват не поднимаем.
	if cand == nil {
		return m.probeN(ctx, host, probes), probes, nil
	}

	provider, err := proxy.NewGroupProvider(cand, hostMatcher{host: strings.ToLower(host)})
	if err != nil {
		return 0, 0, err
	}
	handle, err := windivert.Open(interceptFilter)
	if err != nil {
		return 0, 0, err
	}

	engine, err := intercept.New(intercept.Options{
		Source:   handle,
		Sink:     handle,
		Flows:    flow.NewTable(flowCapacity, flowTTL, intercept.TLSHelloDetector),
		Provider: provider,
		Exec:     packetexec.New(),
		Parse:    intercept.TLSHelloParser,
		Logger:   m.logger,
	})
	if err != nil {
		_ = handle.Close()
		return 0, 0, err
	}

	ectx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = engine.Run(ectx)
	}()

	// Даём контуру встать на перехват до первой пробы.
	time.Sleep(engineSettle)
	success := m.probeN(ctx, host, probes)

	// Останавливаем: отмена плюс закрытие дескриптора разблокирует Recv.
	cancel()
	_ = handle.Close()
	<-done

	return success, probes, nil
}

// probeN шлёт probes рукопожатий и возвращает число удачных.
func (m *liveMeasurer) probeN(ctx context.Context, host string, probes int) int {
	success := 0
	for i := 0; i < probes; i++ {
		if ctx.Err() != nil {
			break
		}
		if probeOnce(ctx, host, m.probeTimeout) {
			success++
		}
		if i < probes-1 {
			select {
			case <-ctx.Done():
			case <-time.After(blockProbeGap):
			}
		}
	}
	return success
}

// probeOnce делает одну пробу внешним curl и сообщает, прошло ли рукопожатие.
//
// Пробуем ВНЕШНИМ процессом (curl), а не рукопожатием внутри процесса движка.
// Причина измерена: внутрипроцессная проба не получает десинк так, как внешнее
// соединение, — тонкость WinDivert с трафиком процесса-владельца дескриптора.
// Внешний curl ведёт себя как настоящий клиент, и именно на нём обход
// подтверждён вживую. Десинк накладывает контур перехвата на уровне пакетов, а
// не проба.
//
// Успех = curl получил любой код ответа HTTP (рукопожатие TLS прошло). Код
// "000" или ошибка запуска = соединение не состоялось (сброс/таймаут).
func probeOnce(ctx context.Context, host string, timeout time.Duration) bool {
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	// Небольшой запас сверх curl --max-time, чтобы контекст не убивал curl
	// раньше его собственного таймаута.
	cctx, cancel := context.WithTimeout(ctx, timeout+2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cctx, "curl",
		"-s", "-o", os.DevNull, "-w", "%{http_code}",
		"--max-time", strconv.Itoa(secs),
		"https://"+host)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	code := strings.TrimSpace(string(out))
	return code != "" && code != "000"
}
