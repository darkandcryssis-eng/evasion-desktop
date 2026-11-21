package telemetry

import (
	"context"
	"log/slog"
)

// Handler — обработчик журнала, который попутно складывает события в кольцевой
// буфер.
//
// Устроен как надстройка над другим обработчиком, а не как замена: вывод в
// поток ошибок, его формат и уровень остаются заботой вызывающего, а здесь
// добавляется только запоминание. Так CLI сохраняет выбор между текстовым и
// машинным выводом, не зная о буфере ничего.
type Handler struct {
	next slog.Handler
	ring *Ring
	// ringLevel — с какого уровня событие попадает в буфер.
	ringLevel slog.Level
	// fields — накопленные поля, УЖЕ приведённые к составным именам.
	//
	// Хранятся преобразованными, а не сырыми, и это принципиально. Поле,
	// добавленное до открытия группы, принадлежит верхнему уровню; если
	// держать поля сырыми и приписывать им группы в момент записи, такое поле
	// получило бы имя из группы, открытой позже. Эту ошибку поймал
	// собственный тест: conn, добавленный до WithGroup("strategy"),
	// превращался в strategy.conn.
	//
	// Цена: значение приводится к основе в момент добавления, а не записи.
	// Для slog.LogValuer это значит, что берётся значение на момент
	// добавления — так же поступают и стандартные обработчики, заранее
	// готовящие часть строки.
	fields []Field
	// groups — открытые группы. Хранятся, чтобы имена полей в буфере
	// совпадали с тем, что уходит в журнал: иначе разбор сбоя шёл бы по
	// именам, которых нет в файле.
	groups []string
}

// NewHandler создаёт обработчик. next обязателен; ring при nil создаётся с
// ёмкостью по умолчанию.
func NewHandler(next slog.Handler, ring *Ring, ringLevel slog.Level) *Handler {
	if ring == nil {
		ring = NewRing(0)
	}
	return &Handler{next: next, ring: ring, ringLevel: ringLevel}
}

// Ring возвращает буфер, в который пишет обработчик.
func (h *Handler) Ring() *Ring { return h.ring }

// Enabled сообщает, нужно ли обрабатывать запись этого уровня.
//
// Истина возвращается, если запись нужна либо нижележащему обработчику, либо
// буферу. Это не придирка: если спрашивать только нижележащий, то при журнале
// на уровне предупреждений события жизненного цикла соединения (они идут на
// уровне сведений) до Handle не доходили бы, и буфер остался бы пустым — ровно
// тогда, когда он нужен для разбора сбоя.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level) || level >= h.ringLevel
}

// Handle записывает событие в буфер и передаёт его дальше.
//
// В нижележащий обработчик запись уходит только если он её принимает: иначе
// надстройка повысила бы разговорчивость журнала, а решать это должен
// вызывающий.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= h.ringLevel {
		h.ring.Append(h.event(r))
	}
	if h.next.Enabled(ctx, r.Level) {
		return h.next.Handle(ctx, r)
	}
	return nil
}

// event превращает запись журнала в событие буфера.
func (h *Handler) event(r slog.Record) Event {
	e := Event{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
		// Ёмкость с запасом на накопленные поля и поля записи, чтобы append
		// не перевыделял.
		Fields: make([]Field, 0, len(h.fields)+r.NumAttrs()),
	}
	e.Fields = append(e.Fields, h.fields...)
	r.Attrs(func(a slog.Attr) bool {
		e.Fields = appendAttr(e.Fields, h.groups, a)
		return true
	})
	return e
}

// appendAttr разворачивает поле журнала в поля события.
//
// Группы разворачиваются в составные имена через точку, а вложенные наборы
// полей — рекурсивно. Иначе поле внутри группы попало бы в буфер под коротким
// именем и перекрыло бы одноимённое поле из другой группы: при разборе сбоя это
// означало бы потерю данных ровно там, где их нельзя терять.
func appendAttr(dst []Field, groups []string, a slog.Attr) []Field {
	// Приведение значения к основе раскрывает slog.LogValuer: иначе в буфер
	// попал бы объект, а не его представление, и значение могло измениться
	// после записи.
	v := a.Value.Resolve()

	if v.Kind() == slog.KindGroup {
		sub := v.Group()
		if a.Key == "" {
			// Безымянная группа вливается в текущий уровень — так же, как это
			// делает стандартный обработчик.
			for _, s := range sub {
				dst = appendAttr(dst, groups, s)
			}
			return dst
		}
		inner := append(append([]string{}, groups...), a.Key)
		for _, s := range sub {
			dst = appendAttr(dst, inner, s)
		}
		return dst
	}

	// Пустое поле без значения стандартный обработчик опускает; поступаем так
	// же, чтобы буфер и файл журнала совпадали.
	if a.Equal(slog.Attr{}) {
		return dst
	}
	return append(dst, Field{Key: joinKey(groups, a.Key), Value: v.Any()})
}

// joinKey собирает составное имя поля из групп и собственного имени.
func joinKey(groups []string, key string) string {
	if len(groups) == 0 {
		return key
	}
	n := len(key)
	for _, g := range groups {
		n += len(g) + 1
	}
	b := make([]byte, 0, n)
	for _, g := range groups {
		b = append(b, g...)
		b = append(b, '.')
	}
	b = append(b, key...)
	return string(b)
}

// WithAttrs возвращает обработчик с добавленными полями.
//
// Поля приводятся к составным именам НЕМЕДЛЕННО, по группам, открытым на этот
// момент: именно так они и принадлежат уровню, где их добавили.
//
// Накопленное копируется, а не дописывается в общий срез: обработчик с полями
// может быть создан однажды и использован из нескольких горутин, и общий срез
// тогда стал бы гонкой.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	cp := *h
	cp.next = h.next.WithAttrs(attrs)
	cp.fields = make([]Field, 0, len(h.fields)+len(attrs))
	cp.fields = append(cp.fields, h.fields...)
	for _, a := range attrs {
		cp.fields = appendAttr(cp.fields, h.groups, a)
	}
	return &cp
}

// WithGroup возвращает обработчик с открытой группой.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	cp := *h
	cp.next = h.next.WithGroup(name)
	cp.groups = append(append([]string{}, h.groups...), name)
	return &cp
}

// статическая проверка соответствия интерфейсу.
var _ slog.Handler = (*Handler)(nil)
