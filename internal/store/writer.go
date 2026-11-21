package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Значения по умолчанию для приёма записи. Принадлежат конфигурации (10.1);
// здесь задана подстановка, чтобы пакет был пригоден без неё.
const (
	// defaultQueueSize — ёмкость очереди наблюдений.
	//
	// Очередь существует, чтобы вызывающий не ждал диска. Её размер — это
	// запас на всплеск: при длительном превышении потока над записью никакая
	// ёмкость не спасёт, и правильным поведением будет отбрасывать, а не
	// расти без предела.
	defaultQueueSize = 4096
	// defaultBatchSize — сколько наблюдений писать одной пачкой.
	defaultBatchSize = 256
	// defaultFlushInterval — через сколько дописывать неполную пачку.
	//
	// Нужен потому, что иначе редкие наблюдения лежали бы в очереди
	// неопределённо долго и пропали бы при сбое.
	defaultFlushInterval = 2 * time.Second
)

// ErrWriterClosed — попытка записи в закрытый приёмник.
var ErrWriterClosed = errors.New("store: приёмник закрыт")

// WriterConfig задаёт параметры приёма записи.
type WriterConfig struct {
	// QueueSize — ёмкость очереди.
	QueueSize int
	// BatchSize — размер пачки.
	BatchSize int
	// FlushInterval — срок дописывания неполной пачки.
	FlushInterval time.Duration
	// OnDropped вызывается при отбрасывании наблюдения из-за переполнения.
	//
	// Обратный вызов, а не счётчик внутри: счётчики живут в telemetry, и
	// тянуть его сюда значило бы связать хранилище с наблюдаемостью без
	// надобности. Вызывается из горячего пути, поэтому обязан быть дешёвым —
	// на практике это инкремент счётчика.
	OnDropped func()
	// OnError вызывается при ошибке записи пачки.
	//
	// Ошибку нельзя вернуть вызывающему: запись идёт асинхронно, и к моменту
	// сбоя тот давно продолжил работу. Молча терять её тоже нельзя — иначе
	// движок считал бы, что наблюдения сохранены, и оценки опирались бы на
	// данные, которых нет.
	OnError func(error)
}

// Writer принимает наблюдения с горячего пути и пишет их в хранилище пачками.
//
// Зачем нужен отдельный слой. Решение по ClientHello обязано укладываться в
// 10 мкс (8.1), а запись на диск туда не вмещается ни при каком устройстве
// хранилища. Поэтому приём разделён: вызывающий кладёт наблюдение в очередь и
// сразу продолжает, а запись идёт в отдельной горутине.
//
// Поведение при переполнении — отбрасывать, а не ждать. Это осознанный выбор:
// ожидание на горячем пути означало бы, что замедление диска замедляет сам
// обход, то есть наблюдение портит наблюдаемое. Отброшенные наблюдения
// считаются и сообщаются наружу — измерению с потерями верить можно только
// зная о потерях.
type Writer struct {
	store Store
	cfg   WriterConfig

	obs    chan Observation
	events chan StrategyEvent

	// dropped — сколько наблюдений отброшено. Атомарное, потому что
	// увеличивается с горячего пути и читается наблюдаемостью.
	dropped atomic.Int64

	// closeOnce защищает от повторного закрытия: Close может быть вызван и
	// по завершении работы, и из обработчика сигнала.
	closeOnce sync.Once
	// closed закрывается при остановке и служит признаком для Enqueue.
	closed chan struct{}
	// done закрывается, когда горутина записи дописала всё и вышла.
	done chan struct{}
}

// NewWriter создаёт приёмник и запускает его горутину записи.
//
// Горутина запускается сразу, а не при первой записи: иначе наблюдения,
// поступившие до неё, были бы потеряны, а момент первой записи зависел бы от
// трафика.
//
// Возвращает ошибку, если s == nil. Прежняя версия на такой случай паниковала,
// но инвариант 1.3 блюпринта запрещает панику в прод-коде: обработка nil-Store
// как ошибки на границе создания лучше, чем срабатывание defensive panic в
// проде.
func NewWriter(s Store, cfg WriterConfig) (*Writer, error) {
	if s == nil {
		return nil, errors.New("store: NewWriter без хранилища")
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}

	w := &Writer{
		store:  s,
		cfg:    cfg,
		obs:    make(chan Observation, cfg.QueueSize),
		events: make(chan StrategyEvent, cfg.QueueSize),
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}
	go w.run()
	return w, nil
}

// Enqueue кладёт наблюдение в очередь, не ожидая записи.
//
// Возвращает ложь, если наблюдение отброшено: очередь полна либо приёмник
// закрыт. Вызывающий не обязан реагировать — для этого есть OnDropped, — но
// возвращаемое значение позволяет отличить принятое от потерянного там, где
// это важно (например, в тестах).
//
// Вызывается с горячего пути: не блокируется и не выделяет памяти.
func (w *Writer) Enqueue(o Observation) bool {
	// Проверка закрытия до отправки обязательна: запись в закрытый канал
	// вызвала бы панику, а паника на горячем пути уронила бы движок.
	select {
	case <-w.closed:
		w.drop()
		return false
	default:
	}

	select {
	case w.obs <- o:
		return true
	default:
		// Очередь полна. Отбрасываем, а не ждём: ожидание здесь означало бы,
		// что замедление диска замедляет обход.
		w.drop()
		return false
	}
}

// EnqueueEvent кладёт событие жизненного цикла стратегии.
//
// События редки и важны, поэтому при полной очереди они не отбрасываются
// молча, а сообщаются через возвращаемое значение: потеря истории решений
// лишила бы возможности разобрать прошлое поведение автопилота.
func (w *Writer) EnqueueEvent(e StrategyEvent) bool {
	select {
	case <-w.closed:
		return false
	default:
	}
	select {
	case w.events <- e:
		return true
	default:
		return false
	}
}

// drop учитывает отброшенное наблюдение.
func (w *Writer) drop() {
	w.dropped.Add(1)
	if w.cfg.OnDropped != nil {
		w.cfg.OnDropped()
	}
}

// Dropped возвращает число отброшенных наблюдений.
func (w *Writer) Dropped() int64 { return w.dropped.Load() }

// run — горутина записи: собирает пачки и отдаёт их хранилищу.
//
// Владеет буферами пачек единолично, поэтому блокировки не нужны: это та самая
// схема «изменяемое состояние принадлежит одной горутине» (4.2, правило 2).
func (w *Writer) run() {
	defer close(w.done)

	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	obsBatch := make([]Observation, 0, w.cfg.BatchSize)
	evBatch := make([]StrategyEvent, 0, w.cfg.BatchSize)

	for {
		select {
		case o := <-w.obs:
			obsBatch = append(obsBatch, o)
			if len(obsBatch) >= w.cfg.BatchSize {
				obsBatch = w.flushObs(obsBatch)
			}

		case e := <-w.events:
			evBatch = append(evBatch, e)
			if len(evBatch) >= w.cfg.BatchSize {
				evBatch = w.flushEvents(evBatch)
			}

		case <-ticker.C:
			obsBatch = w.flushObs(obsBatch)
			evBatch = w.flushEvents(evBatch)

		case <-w.closed:
			// Дочитываем очереди до конца и дописываем остатки. Терять уже
			// принятое при остановке нельзя: вызывающий считает эти
			// наблюдения сохранёнными.
			for {
				select {
				case o := <-w.obs:
					obsBatch = append(obsBatch, o)
					if len(obsBatch) >= w.cfg.BatchSize {
						obsBatch = w.flushObs(obsBatch)
					}
					continue
				case e := <-w.events:
					evBatch = append(evBatch, e)
					if len(evBatch) >= w.cfg.BatchSize {
						evBatch = w.flushEvents(evBatch)
					}
					continue
				default:
				}
				break
			}
			w.flushObs(obsBatch)
			w.flushEvents(evBatch)
			return
		}
	}
}

// flushObs записывает пачку наблюдений и возвращает опорожнённый буфер.
//
// Буфер переиспользуется, а не выделяется заново: горутина записи работает всё
// время жизни движка, и выделение пачки на каждый сброс давало бы постоянный
// мусор без всякой пользы.
func (w *Writer) flushObs(batch []Observation) []Observation {
	if len(batch) == 0 {
		return batch
	}
	// Своё ограничение по времени: запись не должна висеть неопределённо
	// долго, иначе остановка движка не дождётся её никогда.
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	err := w.store.AppendObservations(ctx, batch)
	cancel()
	if err != nil && w.cfg.OnError != nil {
		w.cfg.OnError(err)
	}
	return batch[:0]
}

// flushEvents записывает пачку событий и возвращает опорожнённый буфер.
func (w *Writer) flushEvents(batch []StrategyEvent) []StrategyEvent {
	if len(batch) == 0 {
		return batch
	}
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	err := w.store.AppendStrategyEvents(ctx, batch)
	cancel()
	if err != nil && w.cfg.OnError != nil {
		w.cfg.OnError(err)
	}
	return batch[:0]
}

// flushTimeout — предел ожидания одной записи пачки.
//
// Нужен, чтобы остановка движка не зависела от состояния диска: без предела
// зависшая запись задержала бы завершение навсегда.
const flushTimeout = 30 * time.Second

// Close останавливает приём, дописывает принятое и закрывает хранилище.
//
// Дожидается горутины записи: иначе принятые наблюдения пропали бы, а
// вызывающий считал бы их сохранёнными.
func (w *Writer) Close() error {
	w.closeOnce.Do(func() {
		close(w.closed)
	})
	<-w.done
	return w.store.Close()
}
