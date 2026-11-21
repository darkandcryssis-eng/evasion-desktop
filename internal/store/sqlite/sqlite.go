package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/store"

	// Драйвер SQLite без CGO. Подключается только здесь: весь остальной код
	// работает через интерфейс store.Store и об этой зависимости не знает.
	_ "modernc.org/sqlite"
)

// driverName — имя драйвера, под которым он себя регистрирует.
const driverName = "sqlite"

// Store — хранилище наблюдений на SQLite.
//
// Два соединения с одним файлом, и это главное решение реализации.
//
// Писатель ограничен одним соединением: SQLite допускает одного писателя
// одновременно, и пул из нескольких лишь переводил бы это ограничение в ошибки
// занятости. Читатели живут в отдельном пуле, потому что иначе длинная
// аналитическая выборка задерживала бы приём наблюдений, а приём при
// задержке отбрасывает записи (store.Writer). То есть на одном пуле тяжёлый
// запрос приводил бы к потере измерений — ровно к тому, от чего разделение
// слоёв и защищает (6.3).
//
// Разделение безопасно благодаря журналу опережающей записи: читатели не
// блокируют писателя и наоборот.
type Store struct {
	w *sql.DB
	r *sql.DB
}

// Open открывает или создаёт базу по пути и готовит схему.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("sqlite: пустой путь к базе")
	}

	w, err := openDB(path, 1)
	if err != nil {
		return nil, err
	}
	if err := applySchema(w); err != nil {
		_ = w.Close()
		return nil, err
	}

	// Пул читателей: по одному соединению на аналитический запрос. Четыре —
	// с запасом, так как аналитика идёт в стороне от горячего пути и
	// одновременных запросов единицы.
	r, err := openDB(path, 4)
	if err != nil {
		_ = w.Close()
		return nil, err
	}

	return &Store{w: w, r: r}, nil
}

// openDB открывает соединение с заданным пределом одновременных подключений и
// применяет настройки.
func openDB(path string, maxOpen int) (*sql.DB, error) {
	db, err := sql.Open(driverName, path)
	if err != nil {
		return nil, fmt.Errorf("sqlite: открытие %s: %w", path, err)
	}
	db.SetMaxOpenConns(maxOpen)
	// Соединения не закрываются по простою: повторное открытие заново
	// применяло бы настройки, а забытая настройка журнала означала бы потерю
	// его свойств незаметно для нас.
	db.SetConnMaxIdleTime(0)
	db.SetMaxIdleConns(maxOpen)

	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite: настройка %q: %w", p, err)
		}
	}
	return db, nil
}

// applySchema создаёт таблицы и записывает версию схемы.
func applySchema(db *sql.DB) error {
	for _, stmt := range schemaStatements {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("sqlite: создание схемы: %w", err)
		}
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&count); err != nil {
		return fmt.Errorf("sqlite: чтение версии схемы: %w", err)
	}
	if count == 0 {
		if _, err := db.Exec(`INSERT INTO schema_version (version) VALUES (?)`, schemaVersion); err != nil {
			return fmt.Errorf("sqlite: запись версии схемы: %w", err)
		}
		return nil
	}

	var have int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&have); err != nil {
		return fmt.Errorf("sqlite: чтение версии схемы: %w", err)
	}
	if have > schemaVersion {
		// База новее кода. Работать с ней нельзя: мы не знаем, что означают
		// её столбцы, и запись испортила бы данные, которые кто-то другой
		// считает своими.
		return fmt.Errorf("sqlite: база версии %d новее поддерживаемой %d", have, schemaVersion)
	}
	return nil
}

// dayOf возвращает номер дня от эпохи для временного раздела.
//
// Делится время в UTC, а не по местному поясу: иначе при смене пояса или
// перехода на летнее время границы разделов сдвинулись бы, и удаление по сроку
// задело бы не те данные.
func dayOf(t time.Time) int64 {
	return t.UTC().Unix() / 86400
}

// boolToInt переводит логическое значение в число для хранения.
func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// AppendObservations записывает наблюдения одной сделкой.
//
// Сделка нужна не ради согласованности между записями — они независимы, — а
// ради скорости: без неё SQLite выполнял бы отдельную фиксацию на каждую
// строку, и пакетная запись потеряла бы смысл.
func (s *Store) AppendObservations(ctx context.Context, obs []store.Observation) error {
	if len(obs) == 0 {
		return nil
	}
	for i := range obs {
		if err := store.ValidateObservation(obs[i]); err != nil {
			return err
		}
	}

	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: начало сделки: %w", err)
	}
	// Откат при любом выходе до фиксации. После удачной фиксации откат —
	// безвредная пустая операция.
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO observations (
		at_ms, day, strategy_id, target, vantage_id, phase, outcome, reason,
		source, strategy_applied, rtt_ns, rtt_measured, throughput, throughput_measured
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("sqlite: подготовка вставки: %w", err)
	}
	defer stmt.Close()

	for _, o := range obs {
		_, err := stmt.ExecContext(ctx,
			o.At.UnixMilli(), dayOf(o.At),
			string(o.StrategyID), o.Target, string(o.VantageID),
			o.Phase.String(), o.Outcome.String(), string(o.Reason), o.Source.String(),
			boolToInt(o.StrategyApplied),
			int64(o.RTT), boolToInt(o.RTTMeasured),
			o.Throughput, boolToInt(o.ThroughputMeasured),
		)
		if err != nil {
			return fmt.Errorf("sqlite: вставка наблюдения: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: фиксация наблюдений: %w", err)
	}
	return nil
}

// AppendStrategyEvents записывает события жизненного цикла стратегий.
func (s *Store) AppendStrategyEvents(ctx context.Context, events []store.StrategyEvent) error {
	if len(events) == 0 {
		return nil
	}
	for i := range events {
		if err := store.ValidateStrategyEvent(events[i]); err != nil {
			return err
		}
	}

	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: начало сделки: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO strategy_events (
		at_ms, day, strategy_id, kind, vantage_id, target, from_state, to_state, note
	) VALUES (?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("sqlite: подготовка вставки события: %w", err)
	}
	defer stmt.Close()

	for _, e := range events {
		_, err := stmt.ExecContext(ctx,
			e.At.UnixMilli(), dayOf(e.At),
			string(e.StrategyID), e.Kind.String(), string(e.VantageID),
			e.Target, e.From, e.To, e.Note,
		)
		if err != nil {
			return fmt.Errorf("sqlite: вставка события: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: фиксация событий: %w", err)
	}
	return nil
}

// Tallies собирает срезы наблюдений по запросу.
//
// Группировка выполняется в базе, а взвешивание — в Go, и это принципиально.
// Веса источников принадлежат конфигурации и могут поменяться (5.7); будь они
// вписаны в запрос, смена весов потребовала бы либо пересчёта истории, либо
// жизни с несопоставимыми числами. База отдаёт количества, вес применяется
// при чтении — единым для всех хранилищ способом (store.WeightPermille).
func (s *Store) Tallies(ctx context.Context, q store.Query) ([]store.Tally, error) {
	if err := store.ValidateQuery(q); err != nil {
		return nil, err
	}
	until := q.Until
	if until.IsZero() {
		until = time.Now()
	}

	// Границы окна включительны: иначе наблюдение ровно на границе терялось бы
	// при склейке соседних окон.
	query := `SELECT strategy_id, target, outcome, source, COUNT(*), MIN(at_ms), MAX(at_ms)
		FROM observations
		WHERE vantage_id = ? AND at_ms >= ? AND at_ms <= ?`
	args := []any{string(q.VantageID), q.Since.UnixMilli(), until.UnixMilli()}

	if q.Target != "" {
		query += ` AND target = ?`
		args = append(args, q.Target)
	}
	if q.StrategyID != "" {
		query += ` AND strategy_id = ?`
		args = append(args, string(q.StrategyID))
	}
	if !q.IncludeAllPhases {
		query += ` AND phase = ?`
		args = append(args, q.Phase.String())
	}
	// Устойчивый порядок задаётся запросом: иначе вывод CLI и тесты менялись
	// бы от запуска к запуску.
	query += ` GROUP BY strategy_id, target, outcome, source
		ORDER BY target, strategy_id`

	rows, err := s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: запрос срезов: %w", err)
	}
	defer rows.Close()

	type key struct {
		strategy core.StrategyID
		target   string
	}
	// Порядок ключей сохраняется отдельно: обход карты в Go случаен, а
	// упорядоченность, заданную запросом, терять нельзя.
	acc := make(map[key]*store.Tally)
	var order []key

	for rows.Next() {
		var (
			strategyID, target, outcomeText, sourceText string
			count, minMS, maxMS                         int64
		)
		if err := rows.Scan(&strategyID, &target, &outcomeText, &sourceText, &count, &minMS, &maxMS); err != nil {
			return nil, fmt.Errorf("sqlite: чтение среза: %w", err)
		}

		var outcome core.Outcome
		if err := outcome.UnmarshalText([]byte(outcomeText)); err != nil {
			// Неизвестное обозначение в архиве означает, что база писалась
			// другой версией кода. Молча отнести такую запись к какому-нибудь
			// исходу нельзя: оценка оказалась бы основана на догадке.
			return nil, fmt.Errorf("sqlite: исход %q в базе не распознан: %w", outcomeText, err)
		}
		var source store.Source
		if err := source.UnmarshalText([]byte(sourceText)); err != nil {
			return nil, fmt.Errorf("sqlite: источник %q в базе не распознан: %w", sourceText, err)
		}

		k := key{core.StrategyID(strategyID), target}
		t := acc[k]
		if t == nil {
			t = &store.Tally{
				StrategyID:     k.strategy,
				Target:         target,
				Counts:         make(map[core.Outcome]int64, 4),
				WeightedCounts: make(map[core.Outcome]int64, 4),
				First:          time.UnixMilli(minMS),
				Last:           time.UnixMilli(maxMS),
			}
			acc[k] = t
			order = append(order, k)
		}
		t.Counts[outcome] += count
		t.WeightedCounts[outcome] += count * store.WeightPermille(source)
		t.Total += count
		if ts := time.UnixMilli(minMS); ts.Before(t.First) {
			t.First = ts
		}
		if ts := time.UnixMilli(maxMS); ts.After(t.Last) {
			t.Last = ts
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: обход срезов: %w", err)
	}

	out := make([]store.Tally, 0, len(order))
	for _, k := range order {
		out = append(out, *acc[k])
	}
	return out, nil
}

// Observations возвращает сырые наблюдения по запросу, от старых к новым.
//
// В отличие от Tallies здесь нет группировки: прогреву оценок нужны сами
// исходы в порядке наступления, иначе серию провалов и чередование не
// воспроизвести. Поэтому и запрос без GROUP BY, и порядок задан явно.
func (s *Store) Observations(ctx context.Context, q store.Query) ([]store.Observation, error) {
	if err := store.ValidateQuery(q); err != nil {
		return nil, err
	}
	until := q.Until
	if until.IsZero() {
		until = time.Now()
	}

	// Границы окна включительны — как у Tallies, по той же причине.
	query := `SELECT at_ms, strategy_id, target, vantage_id, phase, outcome, reason,
		source, strategy_applied, rtt_ns, rtt_measured, throughput, throughput_measured
		FROM observations
		WHERE vantage_id = ? AND at_ms >= ? AND at_ms <= ?`
	args := []any{string(q.VantageID), q.Since.UnixMilli(), until.UnixMilli()}

	if q.Target != "" {
		query += ` AND target = ?`
		args = append(args, q.Target)
	}
	if q.StrategyID != "" {
		query += ` AND strategy_id = ?`
		args = append(args, string(q.StrategyID))
	}
	if !q.IncludeAllPhases {
		query += ` AND phase = ?`
		args = append(args, q.Phase.String())
	}
	// Порядок по времени обязателен: прогрев детерминирован только на
	// упорядоченной последовательности. rowid вторичным ключом даёт устойчивый
	// порядок внутри одной миллисекунды — порядок вставки, то есть наступления.
	query += ` ORDER BY at_ms, rowid`

	rows, err := s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: запрос наблюдений: %w", err)
	}
	defer rows.Close()

	var out []store.Observation
	for rows.Next() {
		var (
			atMS, rttNS, throughput                          int64
			strategyApplied, rttMeasured, throughputMeasured int64
			strategyID, target, vantageID                    string
			phaseText, outcomeText, reasonText, sourceText   string
		)
		if err := rows.Scan(&atMS, &strategyID, &target, &vantageID, &phaseText,
			&outcomeText, &reasonText, &sourceText, &strategyApplied,
			&rttNS, &rttMeasured, &throughput, &throughputMeasured); err != nil {
			return nil, fmt.Errorf("sqlite: чтение наблюдения: %w", err)
		}

		var phase core.Phase
		if err := phase.UnmarshalText([]byte(phaseText)); err != nil {
			return nil, fmt.Errorf("sqlite: уровень %q в базе не распознан: %w", phaseText, err)
		}
		var outcome core.Outcome
		if err := outcome.UnmarshalText([]byte(outcomeText)); err != nil {
			return nil, fmt.Errorf("sqlite: исход %q в базе не распознан: %w", outcomeText, err)
		}
		var source store.Source
		if err := source.UnmarshalText([]byte(sourceText)); err != nil {
			return nil, fmt.Errorf("sqlite: источник %q в базе не распознан: %w", sourceText, err)
		}

		out = append(out, store.Observation{
			At:                 time.UnixMilli(atMS),
			StrategyID:         core.StrategyID(strategyID),
			Target:             target,
			VantageID:          core.VantageID(vantageID),
			Phase:              phase,
			Outcome:            outcome,
			Reason:             core.Reason(reasonText),
			Source:             source,
			StrategyApplied:    strategyApplied != 0,
			RTT:                time.Duration(rttNS),
			RTTMeasured:        rttMeasured != 0,
			Throughput:         throughput,
			ThroughputMeasured: throughputMeasured != 0,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: обход наблюдений: %w", err)
	}
	return out, nil
}

// StrategyEvents возвращает события стратегии от новых к старым.
func (s *Store) StrategyEvents(ctx context.Context, id core.StrategyID, limit int) ([]store.StrategyEvent, error) {
	query := `SELECT at_ms, strategy_id, kind, vantage_id, target, from_state, to_state, note
		FROM strategy_events WHERE strategy_id = ? ORDER BY at_ms DESC`
	args := []any{string(id)}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: запрос событий: %w", err)
	}
	defer rows.Close()

	var out []store.StrategyEvent
	for rows.Next() {
		var (
			atMS                                                    int64
			strategyID, kindText, vantageID, target, from, to, note string
		)
		if err := rows.Scan(&atMS, &strategyID, &kindText, &vantageID, &target, &from, &to, &note); err != nil {
			return nil, fmt.Errorf("sqlite: чтение события: %w", err)
		}
		kind, err := parseEventKind(kindText)
		if err != nil {
			return nil, err
		}
		out = append(out, store.StrategyEvent{
			At:         time.UnixMilli(atMS),
			StrategyID: core.StrategyID(strategyID),
			Kind:       kind,
			VantageID:  core.VantageID(vantageID),
			Target:     target,
			From:       from,
			To:         to,
			Note:       note,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: обход событий: %w", err)
	}
	return out, nil
}

// parseEventKind разбирает обозначение вида события.
//
// Отдельной функцией, потому что у вида события нет разбора текста в store:
// он нужен только при чтении из архива, и заводить его в доменном типе ради
// одного места значило бы расширять поверхность без надобности.
func parseEventKind(text string) (store.StrategyEventKind, error) {
	for _, k := range []store.StrategyEventKind{
		store.EventCreated, store.EventStatusChanged, store.EventSelected,
		store.EventRetired, store.EventCollateralDetected,
	} {
		if k.String() == text {
			return k, nil
		}
	}
	return store.EventUnknown, fmt.Errorf("sqlite: вид события %q в базе не распознан", text)
}

// Purge удаляет устаревшее согласно сроку хранения.
//
// Удаление идёт по столбцу дня, а не по точному времени: по дню есть указатель,
// и уборка не перебирает таблицу целиком. Срок при этом соблюдается с точностью
// до суток в сторону БОЛЬШЕГО хранения — удаляются только полностью истёкшие
// дни. Удалять частично истёкший день значило бы терять наблюдения раньше
// заявленного срока.
func (s *Store) Purge(ctx context.Context, now time.Time, policy store.RetentionPolicy) (store.PurgeStats, error) {
	var stats store.PurgeStats

	if policy.Observations > 0 {
		cutoff := dayOf(now.Add(-policy.Observations))
		res, err := s.w.ExecContext(ctx, `DELETE FROM observations WHERE day < ?`, cutoff)
		if err != nil {
			return stats, fmt.Errorf("sqlite: удаление наблюдений: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return stats, fmt.Errorf("sqlite: число удалённых наблюдений: %w", err)
		}
		stats.Observations = n
	}

	// Нулевой срок означает «бессрочно» и ничего не удаляет: так задано для
	// событий стратегий (6.4), объём которых мал, а история решений нужна.
	if policy.Events > 0 {
		cutoff := dayOf(now.Add(-policy.Events))
		res, err := s.w.ExecContext(ctx, `DELETE FROM strategy_events WHERE day < ?`, cutoff)
		if err != nil {
			return stats, fmt.Errorf("sqlite: удаление событий: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return stats, fmt.Errorf("sqlite: число удалённых событий: %w", err)
		}
		stats.Events = n
	}

	return stats, nil
}

// Close закрывает оба соединения.
//
// Ошибки обоих закрытий соединяются, а не теряются: закрытие писателя может
// не удаться при незавершённой контрольной точке журнала, и знать об этом
// нужно — иначе часть принятого осталась бы только в журнале.
func (s *Store) Close() error {
	errW := s.w.Close()
	errR := s.r.Close()
	return errors.Join(errW, errR)
}

// статическая проверка соответствия интерфейсу.
var _ store.Store = (*Store)(nil)
