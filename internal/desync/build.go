package desync

import (
	"errors"
	"fmt"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// ErrMalformedStrategy — стратегия структурно непригодна для построения плана
// (пустой узел, параметры не того типа). В норме не возникает: executor строит
// план только из прошедшей strategy.Validate стратегии. Проверка оставлена как
// защита от прямого вызова BuildPlan с несогласованным деревом.
var ErrMalformedStrategy = errors.New("desync: непригодная для исполнения стратегия")

// ErrCutUnavailable — стратегия требует структурной точки разреза, которой у
// этого события нет или которая лежит вне разрезаемой части.
//
// Отдельная ошибка, а не зажим смещения по границам, потому что зажим превратил
// бы разрез в пустую операцию: стратегия выглядела бы применённой, ничего не
// изменив, и была бы оценена как нерабочая, хотя не применялась. Это тот же
// класс порчи измерений, что молчаливое игнорирование непосильного примитива
// (4.7 п. 2), и он так же запрещён.
var ErrCutUnavailable = errors.New("desync: структурная точка разреза недоступна")

// BuildPlan разворачивает стратегию в план для одного события.
//
// Детерминирован и без ввода-вывода: одна и та же пара (стратегия, событие)
// всегда даёт один и тот же план. Это и позволяет проверять desync золотыми
// тестами офлайн (8.3).
//
// Если ни одно правило не сработало, план — сквозной пропуск: событие уходит
// неизменным (одна операция OpSendReal с полной нагрузкой). Это безопасное
// умолчание: стратегия, не трогающая данное событие, не должна его терять.
// Пустой план (ни одной операции) возможен только как явный результат
// сработавшего правила — например, Drop; тогда событие намеренно уничтожается.
func BuildPlan(s *strategy.Strategy, in Input) (Plan, error) {
	if s == nil {
		return Plan{}, ErrMalformedStrategy
	}

	var ops []Op
	matched := false

	for i := range s.Rules {
		r := &s.Rules[i]
		if r.Direction != in.Direction {
			continue
		}
		if !in.triggerMatches(r.Trigger) {
			continue
		}
		matched = true
		b := builder{in: in}
		produced, err := b.walk(r.Action, rootUnit(in.Payload))
		if err != nil {
			return Plan{}, err
		}
		ops = append(ops, produced...)
	}

	if !matched {
		// Сквозной пропуск: ни одно правило не относится к событию.
		return passthrough(in.Payload), nil
	}
	return Plan{Ops: ops}, nil
}

// passthrough возвращает план «отправить нагрузку как есть».
func passthrough(payload []byte) Plan {
	if len(payload) == 0 {
		return Plan{}
	}
	return Plan{Ops: []Op{{Kind: OpSendReal, Payload: payload, Frame: FrameSegment}}}
}

// unit — промежуточное состояние при обходе дерева: что отправить и с какими
// правками.
//
// edits накапливает ТОЛЬКО правки полей заголовка. Правка тела (подмена фейком)
// применяется немедленно к payload при обходе, поэтому в edits не попадает: к
// моменту отправки тело уже окончательно. frame хранит обрамление,
// унаследованное от разреза.
type unit struct {
	payload []byte
	edits   []strategy.TamperParams
	frame   Framing
	// start — смещение payload от начала нагрузки события.
	//
	// Нужно для структурных точек разреза: их смещения абсолютны, а разрезать
	// приходится текущую часть. При вложенных разрезах части начинаются не с
	// нуля, и без этого поля вложенный разрез «внутри имени сервера» отрезал бы
	// не там, где надо, причём незаметно.
	start int
	// synth — тело подменено фейковыми байтами (Tamper по полю payload).
	//
	// Для подменённого тела структурные точки исходного сообщения смысла не
	// имеют: структуры там больше нет. Признак позволяет отвергнуть такой
	// разрез явной ошибкой вместо молчаливой нарезки мусора.
	synth bool
	// insertMD5 — к этому куску при отправке добавляется фейковая опция TCP
	// MD5 Signature (ActionMD5Sig). Делает кусок фейком так же, как edits:
	// emit выдаст OpSendFake с InsertMD5Sig. Копируется при clone по значению.
	insertMD5 bool
	// insertIPv6Ext — к этому куску при отправке добавляется заголовок
	// расширения IPv6 Hop-by-Hop (ActionIPv6Ext). Делает кусок фейком.
	insertIPv6Ext bool
}

// rootUnit создаёт исходную единицу обхода из нагрузки события.
func rootUnit(payload []byte) unit {
	return unit{payload: payload, frame: FrameSegment}
}

// builder несёт контекст события на время обхода дерева.
//
// Нужен потому, что разрешение структурных точек требует доступа к Input, а
// протаскивать его отдельным параметром через каждую функцию обхода значило бы
// засорить все подписи. Состояния builder не имеет: обход остаётся
// детерминированным и без побочных действий, что и позволяет проверять его
// золотыми тестами (8.3).
type builder struct {
	in Input
}

// clone возвращает копию единицы с независимым срезом правок.
//
// Независимость правок обязательна: при Duplicate обе ветви получают копию, и
// добавление правки в одной ветви не должно просачиваться в другую. Срез
// payload при этом общий — он только читается, а подмена тела всегда создаёт
// новый срез (synthFakePayload), не трогая исходный.
func (u unit) clone() unit {
	cp := u
	if len(u.edits) > 0 {
		cp.edits = make([]strategy.TamperParams, len(u.edits))
		copy(cp.edits, u.edits)
	}
	return cp
}

// walk обходит узел дерева и возвращает операции для него.
//
// Это и есть семантика примитивов — ядро пакета. Каждый вид узла описан у своей
// ветви switch.
func (b *builder) walk(a *strategy.Action, u unit) ([]Op, error) {
	if a == nil {
		return nil, ErrMalformedStrategy
	}

	switch a.Kind {
	case core.ActionSend:
		return emit(u), nil

	case core.ActionDrop:
		// Лист-уничтожитель: ничего не отправляем, ветвь обрывается.
		return nil, nil

	case core.ActionTamper:
		p, ok := a.Params.(*strategy.TamperParams)
		if !ok {
			return nil, ErrMalformedStrategy
		}
		return b.walkTamper(a, u, p)

	case core.ActionDuplicate:
		// Обе ветви получают независимую копию единицы. Порядок отправки —
		// сначала левая ветвь, затем правая.
		left, err := b.walk(a.Left, u.clone())
		if err != nil {
			return nil, err
		}
		right, err := b.walk(a.Right, u.clone())
		if err != nil {
			return nil, err
		}
		return append(left, right...), nil

	case core.ActionFragment:
		p, ok := a.Params.(*strategy.FragmentParams)
		if !ok {
			return nil, ErrMalformedStrategy
		}
		return b.walkFragment(a, u, p)

	case core.ActionTCPOverlap:
		p, ok := a.Params.(*strategy.TCPOverlapParams)
		if !ok {
			return nil, ErrMalformedStrategy
		}
		return b.walkTCPOverlap(u, p)

	case core.ActionMD5Sig:
		// Пометка «вставить фейковую MD5-опцию» и спуск в единственную ветвь.
		// Параметров нет — содержимое опции задаёт исполнитель. Пометка делает
		// кусок фейком (emit увидит insertMD5), поэтому отдельного вброса здесь
		// не требуется: вставку выполнит пакетный исполнитель при сборке.
		u = u.clone()
		u.insertMD5 = true
		return b.walk(a.Left, u)

	case core.ActionIPv6Ext:
		// Пометка «вставить Hop-by-Hop на фейке» и спуск в единственную ветвь.
		// Вставку (и проверку, что пакет IPv6) выполнит пакетный исполнитель.
		u = u.clone()
		u.insertIPv6Ext = true
		return b.walk(a.Left, u)

	default:
		return nil, ErrMalformedStrategy
	}
}

// walkTCPOverlap разворачивает ActionTCPOverlap в два варианта. Без Offset
// cover перекрывает конец нагрузки, после чего полная настоящая нагрузка
// перезаписывает его на сервере. С Offset реализуется split-seqovl: первый
// сегмент содержит cover и начало нагрузки, но начинается на len(cover) байт
// раньше окна; сервер отбрасывает cover как out-of-window, а DPI его разбирает.
func (b *builder) walkTCPOverlap(u unit, p *strategy.TCPOverlapParams) ([]Op, error) {
	pattern, ok := strategy.FakePreset(p.Preset)
	if !ok {
		return nil, ErrMalformedStrategy
	}
	L := len(u.payload)
	M := len(pattern)
	if p.Offset > 0 {
		cut, err := b.cutOffset(u, &strategy.FragmentParams{Offset: p.Offset})
		if err != nil || cut == 0 || cut == L || M+cut > 1200 {
			return nil, fmt.Errorf("%w: split-seqovl offset %d недопустим для нагрузки %d байт", ErrCutUnavailable, p.Offset, L)
		}
		firstPayload := make([]byte, 0, M+cut)
		firstPayload = append(firstPayload, pattern...)
		firstPayload = append(firstPayload, u.payload[:cut]...)
		return []Op{
			{Kind: OpSendReal, Payload: firstPayload, Frame: FrameSegment, StreamOffset: u.start - M},
			{Kind: OpSendReal, Payload: u.payload[cut:], Frame: FrameSegment, StreamOffset: u.start + cut},
		}, nil
	}
	if M >= L {
		// Короткий ClientHello (без постквантового key_share): собираем cover
		// той же личности на байт короче нагрузки вместо отказа.
		if sized, ok := strategy.CoverPresetSized(p.Preset, L-1); ok {
			pattern, M = sized, len(sized)
		}
	}
	if M >= L {
		return nil, fmt.Errorf("%w: tcp_overlap cover %d байт >= нагрузки %d байт, перекрытие невозможно",
			ErrCutUnavailable, M, L)
	}
	coverOp := Op{
		Kind:         OpSendReal,
		Payload:      pattern,
		Frame:        FrameSegment,
		StreamOffset: u.start + L - M,
	}
	realOp := Op{
		Kind:         OpSendReal,
		Payload:      u.payload,
		Frame:        FrameSegment,
		StreamOffset: u.start,
	}
	return []Op{coverOp, realOp}, nil
}

// walkTamper применяет правку и спускается в единственную ветвь.
func (b *builder) walkTamper(a *strategy.Action, u unit, p *strategy.TamperParams) ([]Op, error) {
	if p.Field == strategy.FieldPayload {
		// Правка тела: подменяем нагрузку фейковыми байтами немедленно.
		// Содержимое детерминировано: именованный пресет (готовая нагрузка,
		// например безобидный ClientHello) либо синтетический узор заданной
		// длины. Пресет уже проверен валидацией; отказ здесь — защита от прямого
		// вызова BuildPlan с несогласованным деревом.
		u = u.clone()
		if p.Preset != "" {
			b, ok := strategy.FakePreset(p.Preset)
			if !ok {
				return nil, ErrMalformedStrategy
			}
			u.payload = b
		} else {
			u.payload = synthFakePayload(u.payload, p.Length)
		}
		u.synth = true
	} else {
		// Правка поля заголовка откладывается до формирования пакета фейка:
		// в режиме прокси заголовком реального сегмента управлять нельзя,
		// поэтому наличие такой правки и делает кусок фейком.
		u = u.clone()
		u.edits = append(u.edits, *p)
	}
	return b.walk(a.Left, u)
}

// walkFragment разрезает нагрузку и обходит обе части в заданном порядке.
func (b *builder) walkFragment(a *strategy.Action, u unit, p *strategy.FragmentParams) ([]Op, error) {
	// Разрез на уровне TLS-записи — отдельная ветка: каждая половина
	// переоборачивается в собственную TLS-запись, вместо того чтобы разрезать
	// байты «как они есть».
	if p.Proto == strategy.FragTLSRecord {
		return b.walkFragmentTLS(a, u, p)
	}
	cut, err := b.cutOffset(u, p)
	if err != nil {
		return nil, err
	}

	frame := u.frame
	if p.Proto == strategy.FragIP {
		// Разрез на уровне IP: части уйдут IP-фрагментами. Наследуется обеими
		// ветвями, так что вложенный разрез сохранит обрамление.
		frame = FrameIPFragment
	}

	leftUnit := u.clone()
	leftUnit.payload = u.payload[:cut]
	leftUnit.frame = frame

	rightUnit := u.clone()
	rightUnit.payload = u.payload[cut:]
	rightUnit.frame = frame
	// Вторая часть начинается на cut байт дальше: без этого вложенный разрез по
	// структурной точке считал бы смещения от начала события, а резал бы от
	// начала части.
	rightUnit.start = u.start + cut

	leftOps, err := b.walk(a.Left, leftUnit)
	if err != nil {
		return nil, err
	}
	rightOps, err := b.walk(a.Right, rightUnit)
	if err != nil {
		return nil, err
	}

	// Порядок отправки частей. Обратный порядок выражается именно здесь —
	// перестановкой операций в плане, без отдельного флага: исполнитель просто
	// отправляет операции подряд.
	//
	// Пауза назначается ПОСЛЕ перестановки, той группе, которая уходит второй.
	// Назначать её ветви дерева было бы ошибкой: при обратном порядке вторая
	// ветвь уходит первой, и пауза оказалась бы перед самым началом отправки,
	// где она бессмысленна.
	first, second := leftOps, rightOps
	if p.Order == strategy.FragReverse {
		first, second = rightOps, leftOps
	}
	delayBefore(second, time.Duration(p.DelayMs)*time.Millisecond)
	return append(first, second...), nil
}

// walkFragmentTLS разрезает единицу на две валидных TLS-записи.
//
// Исходная единица должна содержать РОВНО одну полную TLS-запись (5 байт
// заголовка + payload). Результат — две записи того же типа с теми же версией
// и TLS-headerами, но с разделённым payload'ом.
//
// Структурные точки разреза (CutInsideSNI и подобные) задаются в АБСОЛЮТНЫХ
// байтах нагрузки события. Исходный ClientHello начинается с 5-байтного
// заголовка TLS, поэтому структурная точка внутри handshake лежит ПОСЛЕ этого
// заголовка. Это уже учтено в tlsparse: его CutPoints используют смещения в
// байтах полной TLS-записи.
//
// Что делаем:
//
//  1. Разбираем первые 5 байт как заголовок TLS: тип (0x16 для handshake),
//     версия (2 байта), длина payload (2 байта). Валидация строгая — иначе
//     попытка разделить непонятно что даст непонятно что.
//  2. Вычисляем точку разреза внутри payload (не внутри заголовка): если
//     структурная точка указала offset < 5, это разрез в середине TLS-headerа,
//     семантически бессмысленный — отвергаем.
//  3. Собираем две новых записи:
//        rec1 = header + payload[:cutInContent]
//        rec2 = header + payload[cutInContent:]
//     У каждой — свой заголовок с пересчитанной длиной.
//  4. Обе ветви получают по unit с полной записью как нагрузкой и своим
//     start-offset'ом. Структурные точки у подменённого payload'а не
//     используются (вложенный разрез по SNI поверх первой записи обычно
//     не имеет смысла — SNI либо в первой, либо во второй), но если ветвь
//     попросит structural cut, cutOffset увидит и явно откажет.
func (b *builder) walkFragmentTLS(a *strategy.Action, u unit, p *strategy.FragmentParams) ([]Op, error) {
	const (
		tlsHeaderLen     = 5
		tlsContentTypeHS = 0x16 // handshake
	)
	if u.synth {
		return nil, fmt.Errorf("%w: TLS-разрез неприменим к подменённому телу", ErrCutUnavailable)
	}
	if len(u.payload) < tlsHeaderLen+1 {
		return nil, fmt.Errorf("%w: TLS-разрез: нагрузка слишком коротка (%d байт)",
			ErrCutUnavailable, len(u.payload))
	}
	if u.payload[0] != tlsContentTypeHS {
		return nil, fmt.Errorf("%w: TLS-разрез: первая запись не handshake (тип 0x%02x)",
			ErrCutUnavailable, u.payload[0])
	}
	// Длина payload из TLS-headerа — проверяем, что буфер её содержит.
	declared := int(u.payload[3])<<8 | int(u.payload[4])
	if declared != len(u.payload)-tlsHeaderLen {
		return nil, fmt.Errorf("%w: TLS-разрез: длина в заголовке %d, фактически %d",
			ErrCutUnavailable, declared, len(u.payload)-tlsHeaderLen)
	}

	// Точка разреза: применяется к КОНТЕНТУ (payload после заголовка).
	// cutOffset возвращает позицию внутри u.payload (включая 5 байт заголовка),
	// поэтому вычитаем заголовок для получения позиции внутри content.
	cutInBuf, err := b.cutOffset(u, p)
	if err != nil {
		return nil, err
	}
	if cutInBuf <= tlsHeaderLen {
		return nil, fmt.Errorf("%w: TLS-разрез: точка попала в заголовок записи (смещение %d <= %d)",
			ErrCutUnavailable, cutInBuf, tlsHeaderLen)
	}
	cutInContent := cutInBuf - tlsHeaderLen

	content := u.payload[tlsHeaderLen:]
	rec1 := assembleTLSRecord(u.payload[:tlsHeaderLen], content[:cutInContent])
	rec2 := assembleTLSRecord(u.payload[:tlsHeaderLen], content[cutInContent:])

	// Внутри обеих ветвей нагрузка — полная запись. Структурные точки
	// подменённой записи не действительны: TLS структуры там нет, зеркально
	// отражено в synth у Tamper.payload. Отличие: TLS-split сохраняет
	// handshake-семантику (сервер склеит), поэтому synth не ставим — только
	// запрещаем ВЛОЖЕННЫЙ structural cut, помечая payload синтетическим
	// только с точки зрения CutKind.
	leftUnit := u.clone()
	leftUnit.payload = rec1
	leftUnit.synth = true // блокируем вложенные structural cuts поверх

	rightUnit := u.clone()
	rightUnit.payload = rec2
	rightUnit.synth = true
	rightUnit.start = u.start // новая запись начинается с собственного заголовка

	leftOps, err := b.walk(a.Left, leftUnit)
	if err != nil {
		return nil, err
	}
	rightOps, err := b.walk(a.Right, rightUnit)
	if err != nil {
		return nil, err
	}

	// Порядок отправки и пауза — та же механика, что в walkFragment.
	first, second := leftOps, rightOps
	if p.Order == strategy.FragReverse {
		first, second = rightOps, leftOps
	}
	delayBefore(second, time.Duration(p.DelayMs)*time.Millisecond)
	return append(first, second...), nil
}

// assembleTLSRecord собирает TLS-запись с заданным заголовком-шаблоном (5 байт)
// и телом. Длина в заголовке переписывается по факту; остальные поля
// (тип, версия) копируются из шаблона.
func assembleTLSRecord(header, content []byte) []byte {
	out := make([]byte, len(header)+len(content))
	copy(out[:len(header)], header)
	// Байты 3-4 — длина (big-endian uint16).
	out[3] = byte(len(content) >> 8)
	out[4] = byte(len(content))
	copy(out[len(header):], content)
	return out
}

// delayBefore добавляет паузу перед первой операцией группы.
//
// Паузы складываются, а не замещают друг друга: при вложенных разрезах внешняя
// пауза должна прибавляться к внутренней, иначе внешний разрез молча отменял бы
// задержку, заданную внутренним.
//
// Пустая группа паузы не получает: задерживать нечего (например, ветвь
// заканчивается Drop).
func delayBefore(ops []Op, d time.Duration) {
	if d <= 0 || len(ops) == 0 {
		return
	}
	ops[0].DelayBefore += d
}

// cutOffset вычисляет место разреза внутри текущей части.
//
// Числовое смещение задаётся от начала разрезаемой части и лишь зажимается по
// её длине: валидация ограничивает его общим пределом, но не длиной конкретного
// события, которая заранее неизвестна.
//
// Структурная точка, напротив, задана абсолютным смещением в нагрузке события,
// поэтому переводится в смещение внутри части. Если точки у события нет или она
// лежит вне части, возвращается ошибка: зажим превратил бы разрез в пустую
// операцию, и стратегия выглядела бы применённой, ничего не изменив.
func (b *builder) cutOffset(u unit, p *strategy.FragmentParams) (int, error) {
	if p.At == core.CutNone {
		cut := p.Offset
		if cut > len(u.payload) {
			cut = len(u.payload)
		}
		return cut, nil
	}

	if u.synth {
		return 0, fmt.Errorf("%w: точка %s неприменима к подменённому телу", ErrCutUnavailable, p.At)
	}
	abs, ok := b.in.resolveCut(p.At)
	if !ok {
		return 0, fmt.Errorf("%w: у события нет точки %s", ErrCutUnavailable, p.At)
	}

	rel := abs - u.start
	// Границы включительно по обоим концам дали бы пустую часть, то есть
	// отсутствие разреза. Такой разрез бессмысленен, и признать его успешным
	// значило бы испортить измерение.
	if rel <= 0 || rel >= len(u.payload) {
		return 0, fmt.Errorf("%w: точка %s (смещение %d) вне разрезаемой части [%d, %d)",
			ErrCutUnavailable, p.At, abs, u.start, u.start+len(u.payload))
	}
	return rel, nil
}

// emit превращает единицу в операцию отправки.
//
// Фейк от реальных данных отличается наличием правок заголовка: правка поля
// означает, что кусок должен уйти пакетом под нашим контролем, а не через сокет
// как настоящие данные. Пустую реальную отправку пропускаем (запись нуля байт —
// это ничто), но пустой фейк оставляем: фейк без тела — это осмысленный
// служебный пакет (например, с одними флагами).
func emit(u unit) []Op {
	if len(u.edits) > 0 || u.insertMD5 || u.insertIPv6Ext {
		return []Op{{Kind: OpSendFake, Payload: u.payload, Edits: u.edits, Frame: u.frame, StreamOffset: u.start, InsertMD5Sig: u.insertMD5, InsertIPv6HopByHop: u.insertIPv6Ext}}
	}
	if len(u.payload) == 0 {
		return nil
	}
	return []Op{{Kind: OpSendReal, Payload: u.payload, Frame: u.frame, StreamOffset: u.start}}
}
