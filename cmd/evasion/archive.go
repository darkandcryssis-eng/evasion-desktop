package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/control"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/store"
	"github.com/fitting-1c/evasion/internal/store/sqlite"
)

// dbFileName — имя файла журнала наблюдений внутри каталога состояния.
const dbFileName = "evasion.sqlite"

// purgeInterval — как часто проверять сроки хранения (6.4).
//
// Раз в час: удаление устаревшего — не срочная работа, а сроки измеряются
// сутками. Чаще значило бы будить диск без пользы, реже — держать лишнее
// после смены настроек дольше, чем нужно.
const purgeInterval = time.Hour

// archive — журнал наблюдений на диске вместе со всем, что нужно для его
// закрытия.
//
// Зачем он нужен, если оценки и так есть в контуре. Оценки живут в памяти и
// исчезают при перезапуске, а наблюдения добываются дорого: каждое — это живое
// соединение. Задание требует писать строку на каждое соединение с применённой
// стратегией (6.4) именно поэтому: без архива движок после каждого запуска
// начинал бы учиться заново.
type archive struct {
	store  *sqlite.Store
	writer *store.Writer
	stop   context.CancelFunc
	done   chan struct{}
}

// openArchive открывает журнал наблюдений и запускает уборку по срокам.
//
// Ошибка открытия — причина не запускаться. Движок мог бы работать и без
// архива, но тогда он молча терял бы всё добытое, а узнал бы об этом владелец
// только при следующем запуске, по пустому портфелю. Явный отказ на старте
// честнее (9.3).
func openArchive(ctx context.Context, cfg *config.Config, stateDir string, log *slog.Logger) (*archive, error) {
	// Каталог состояния создаётся здесь, а не доверяется хранилищу: SQLite
	// открывает файл в существующем каталоге и на отсутствующем падает
	// невнятно («unable to open database file»). Обнаружено живым прогоном —
	// тесты пользуются готовым каталогом (t.TempDir) и этого не видели.
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("каталог состояния %s: %w", stateDir, err)
	}

	path := filepath.Join(stateDir, dbFileName)
	st, err := sqlite.Open(path)
	if err != nil {
		return nil, fmt.Errorf("журнал наблюдений %s: %w", path, err)
	}

	// Писатель отбрасывает при переполнении и сообщает об этом обратным
	// вызовом: ожидание означало бы, что замедление диска замедляет
	// пользовательский трафик.
	writer, err := store.NewWriter(st, store.WriterConfig{
		OnDropped: func() {
			log.Warn("наблюдение не записано: очередь журнала переполнена")
		},
		OnError: func(err error) {
			// Ошибку записи нельзя вернуть вызывающему — он давно ушёл, —
			// но и терять её нельзя: иначе движок считал бы, что наблюдения
			// сохранены, и оценки опирались бы на данные, которых нет.
			log.Error("пачка наблюдений не записана", "ошибка", err)
		},
	})
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("журнал наблюдений: приёмник записи: %w", err)
	}

	purgeCtx, cancel := context.WithCancel(ctx)
	a := &archive{store: st, writer: writer, stop: cancel, done: make(chan struct{})}

	go a.purgeLoop(purgeCtx, cfg.Retention, log)
	return a, nil
}

// purgeLoop удаляет устаревшее по срокам хранения (6.4).
//
// Уборка автоматическая и без ручного вмешательства — так требует задание, и
// это единственный способ удержать объём: на активной машине соединений
// десятки тысяч в сутки.
func (a *archive) purgeLoop(ctx context.Context, r config.Retention, log *slog.Logger) {
	defer close(a.done)

	policy := store.RetentionPolicy{
		Observations: r.Rows,
		Tallies:      r.Aggregates,
		Events:       r.Events,
	}

	ticker := time.NewTicker(purgeInterval)
	defer ticker.Stop()

	for {
		// Первая уборка — сразу при запуске: после долгого перерыва устаревшего
		// накапливается больше всего, и ждать час незачем.
		stats, err := a.store.Purge(ctx, time.Now(), policy)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			log.Warn("уборка журнала не удалась", "ошибка", err)
		case stats.Observations > 0 || stats.Tallies > 0 || stats.Events > 0:
			log.Info("журнал убран",
				"наблюдений", stats.Observations,
				"срезов", stats.Tallies,
				"событий", stats.Events)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// warmup читает недавние наблюдения из журнала для прогрева оценок (тёплый
// старт).
//
// Зачем здесь, а не в контуре: журнал и точка наблюдения известны команде,
// которая собирает движок, а контур про файлы знать не должен (4.7 п. 4).
// Команда читает сырьё и отдаёт контуру через control.Options.Warmup.
//
// Окно ограничено сроком доверия к оценкам (5.9): за его пределами движок и сам
// считает оценки устаревшими, и воскрешать их незачем. Пустое окно или пустая
// точка наблюдения означают «не прогревать» — законно, движок работоспособен и
// с нуля.
//
// Ошибка чтения не мешает запуску: прогрев — ускорение, а не работа движка.
// Упасть из-за нечитаемого журнала значило бы променять обход на историю о нём.
func (a *archive) warmup(ctx context.Context, vantage core.VantageID, window time.Duration, log *slog.Logger) []control.Observation {
	if a == nil || window <= 0 || vantage == "" {
		return nil
	}
	now := time.Now()
	obs, err := a.store.Observations(ctx, store.Query{
		VantageID: vantage,
		Since:     now.Add(-window),
		Until:     now,
		// Все уровни: контур при живой работе учитывает исход независимо от
		// уровня оценки, поэтому прогрев обязан восстановить то же множество.
		IncludeAllPhases: true,
	})
	if err != nil {
		log.Warn("тёплый старт: журнал не прочитан, старт с пустых оценок", "ошибка", err)
		return nil
	}
	out := toControlObservations(obs)
	if len(out) > 0 {
		log.Info("тёплый старт: наблюдения загружены из журнала",
			"наблюдений", len(out), "окно", window.String(),
			"точка_наблюдения", vantage.String())
	}
	return out
}

// toControlObservations переводит записи журнала в наблюдения контура.
//
// Контуру от полной записи нужно немногое (control.Observation): идентификатор,
// цель, исход, источник, время. Базовая линия распознаётся по пустой стратегии
// — ровно так её и пишет журнал (пустой StrategyID), и ровно так контур ждёт её
// обратно (Baseline при пустом идентификаторе).
func toControlObservations(src []store.Observation) []control.Observation {
	out := make([]control.Observation, 0, len(src))
	for _, o := range src {
		out = append(out, control.Observation{
			StrategyID: o.StrategyID,
			Baseline:   o.StrategyID == "",
			Target:     o.Target,
			Outcome:    o.Outcome,
			Source:     o.Source,
			At:         o.At,
		})
	}
	return out
}

// close дописывает принятое и закрывает журнал.
//
// Порядок важен: сначала писатель (он дописывает очередь), потом хранилище.
// Обратный порядок потерял бы последнюю пачку — то есть ровно те наблюдения,
// ради которых движок только что работал.
func (a *archive) close() error {
	a.stop()
	<-a.done
	if err := a.writer.Close(); err != nil {
		_ = a.store.Close()
		return err
	}
	return a.store.Close()
}
