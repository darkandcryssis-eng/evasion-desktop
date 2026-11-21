package strategy

import (
	"fmt"

	"github.com/fitting-1c/evasion/internal/core"
)

// Params — параметры одного узла-преобразователя дерева.
//
// Это интерфейс, а не отдельный тип на каждое действие, потому что генетический
// поиск мутирует и скрещивает единое дерево; алгебраические типы с визитором
// были бы типобезопаснее, но мутации на них пишутся заметно сложнее (разбор
// компромисса — в задании, 4.3). Цена интерфейса — меньше статической проверки,
// поэтому вся валидация параметров собрана здесь и в validate.go и покрыта
// тестами.
//
// Методы неэкспортируемые: новые виды параметров добавляются только внутри
// пакета strategy (вместе с записью в реестре и исполнением в desync), что и
// требуется моделью расширения (10.3). Внешний код конструирует параметры через
// разбор сериализованной формы, а не реализуя интерфейс.
type Params interface {
	// validate проверяет параметры против границ протокола и лимитов.
	validate(limits Limits) error
	// requiredCapabilities возвращает возможности, нужные именно для этих
	// параметров (помимо базовой возможности вида примитива).
	requiredCapabilities() core.PrimitiveSet
}

// TamperMode — как примитив Tamper изменяет поле.
type TamperMode uint8

const (
	// TamperReplace — заменить поле на константу Value (для тела — на фейк
	// длиной Length).
	TamperReplace TamperMode = iota
	// TamperAdd — прибавить к полю знаковую дельту Value (вычитание — через
	// отрицательную дельту в дополнительном коде).
	TamperAdd
	// TamperCorrupt — испортить поле псевдослучайным значением. Детерминизм при
	// воспроизведении обеспечивает desync фиксированным сидом, не само
	// представление.
	TamperCorrupt
)

const (
	tamperReplaceText = "replace"
	tamperAddText     = "add"
	tamperCorruptText = "corrupt"
)

// String возвращает токен режима правки.
func (m TamperMode) String() string {
	switch m {
	case TamperReplace:
		return tamperReplaceText
	case TamperAdd:
		return tamperAddText
	case TamperCorrupt:
		return tamperCorruptText
	default:
		return fmt.Sprintf("TamperMode(%d)", uint8(m))
	}
}

// MarshalText сериализует режим правки как токен.
func (m TamperMode) MarshalText() ([]byte, error) {
	switch m {
	case TamperReplace, TamperAdd, TamperCorrupt:
		return []byte(m.String()), nil
	default:
		return nil, fmt.Errorf("strategy: недопустимый режим правки %d", uint8(m))
	}
}

// UnmarshalText разбирает токен режима правки.
func (m *TamperMode) UnmarshalText(text []byte) error {
	switch string(text) {
	case tamperReplaceText:
		*m = TamperReplace
	case tamperAddText:
		*m = TamperAdd
	case tamperCorruptText:
		*m = TamperCorrupt
	default:
		return fmt.Errorf("strategy: неизвестный режим правки %q", string(text))
	}
	return nil
}

// TamperParams — параметры примитива Tamper: какое поле, как и на что менять.
type TamperParams struct {
	// Field — поле заголовка или тело.
	Field FieldID `json:"field"`
	// Mode — способ изменения.
	Mode TamperMode `json:"mode"`
	// Value — константа замены или знаковая дельта. Для режима Corrupt и для
	// подмены тела не используется.
	Value uint64 `json:"value,omitempty"`
	// Length — длина фейковых байт при подмене тела (Field == FieldPayload).
	// Содержимое при этом синтетическое (детерминированный узор). Взаимоисключимо
	// с Preset.
	Length int `json:"length,omitempty"`
	// Preset — имя готовой нагрузки фейка при подмене тела (Field ==
	// FieldPayload): вместо синтетической длины фейк несёт конкретные байты из
	// реестра (например, безобидный ClientHello с SNI google — PresetTLSGoogle).
	// Нужно, чтобы DPI, разобрав фейк, отнёс соединение к безобидному домену, а
	// настоящий SNI собрать не смог. Взаимоисключимо с Length.
	Preset string `json:"preset,omitempty"`
}

// validate проверяет параметры Tamper.
func (p *TamperParams) validate(limits Limits) error {
	fi, ok := p.Field.info()
	if !ok {
		return fmt.Errorf("неизвестное поле %d", uint8(p.Field))
	}
	switch p.Mode {
	case TamperReplace, TamperAdd, TamperCorrupt:
	default:
		return fmt.Errorf("недопустимый режим правки %d", uint8(p.Mode))
	}

	if fi.isPayload {
		// Тело правится только подменой на фейк; дельта и «порча» к потоку байт
		// как к целому неприменимы.
		if p.Mode != TamperReplace {
			return fmt.Errorf("тело можно только заменять (replace), режим %s недопустим", p.Mode)
		}
		// Содержимое фейка задаётся ровно одним способом: синтетической длиной
		// (Length) ЛИБО готовой нагрузкой по имени (Preset). И то, и другое —
		// бессмысленный ввод; ничего — тоже (нечего подставить).
		hasPreset := p.Preset != ""
		if hasPreset && p.Length != 0 {
			return fmt.Errorf("подмена тела: заданы и preset %q, и length %d — нужно ровно одно", p.Preset, p.Length)
		}
		if hasPreset {
			b, ok := FakePreset(p.Preset)
			if !ok {
				return fmt.Errorf("неизвестный пресет фейка %q", p.Preset)
			}
			if len(b) > limits.MaxFakePayload {
				return fmt.Errorf("пресет фейка %q длиной %d превышает предел %d", p.Preset, len(b), limits.MaxFakePayload)
			}
			return nil
		}
		if p.Length <= 0 {
			return fmt.Errorf("длина фейка тела должна быть > 0 (или задайте preset), получено %d", p.Length)
		}
		if p.Length > limits.MaxFakePayload {
			return fmt.Errorf("длина фейка тела %d превышает предел %d", p.Length, limits.MaxFakePayload)
		}
		return nil
	}

	// Числовое поле: ни длина фейка, ни пресет неприменимы.
	if p.Preset != "" {
		return fmt.Errorf("поле %s не является телом, preset неприменим", p.Field)
	}
	if p.Length != 0 {
		return fmt.Errorf("поле %s не является телом, длина фейка неприменима", p.Field)
	}
	// Для замены константа должна умещаться в ширину поля. Для дельты (Add)
	// значение трактуется как знаковое смещение по модулю ширины, поэтому
	// границу не проверяем. Для порчи значение игнорируется.
	if p.Mode == TamperReplace {
		if max, ok := p.Field.maxValue(); ok && p.Value > max {
			return fmt.Errorf("значение %d не умещается в поле %s (макс. %d)", p.Value, p.Field, max)
		}
	}
	return nil
}

// requiredCapabilities сообщает, какие возможности нужны для этой правки.
func (p *TamperParams) requiredCapabilities() core.PrimitiveSet {
	set := core.PrimitiveSet(0).With(core.CapTamper)
	// Правка поля контрольной суммы означает намеренно неверную сумму (верную
	// проще получить обычным пересчётом). Это требует контроля над пакетами.
	if fi, ok := p.Field.info(); ok && fi.isChecksum {
		set = set.With(core.CapTamperChecksumCorrupt)
	}
	return set
}

// FragProto — на каком уровне разрезается пакет примитивом Fragment.
type FragProto uint8

const (
	// FragTCP — разрез на границе сегментов TCP.
	FragTCP FragProto = iota
	// FragIP — фрагментация на уровне IP.
	FragIP
	// FragTLSRecord — разрез на границе TLS-записей.
	//
	// В отличие от FragTCP, обе части остаются ВАЛИДНЫМИ TLS-записями: исходная
	// одна запись (ClientHello) распадается на две. Каждая несёт свой заголовок
	// TLS (0x16 0x03 0x01 LLLL) и часть содержимого. Сервер принимает оба и
	// склеивает — HandshakeMessage собирается нормально. DPI часто смотрит
	// только на первую TLS-запись: если SNI оказался во ВТОРОЙ, он его не
	// видит.
	//
	// Это НЕ фрагментация на TCP-уровне — оба куска идут в одном TCP-сегменте
	// (или в разных, если выше поставлен FragTCP). Расхождение в именовании с
	// FragTCP/FragIP осознано: FragTCP делит буфер между пакетами, FragTLSRecord
	// — между записями одного протокола внутри буфера. Это ровно то, чем
	// отличается TLS-split zapret'а от простого byedpi-разреза.
	FragTLSRecord
)

const (
	fragTCPText       = "tcp"
	fragIPText        = "ip"
	fragTLSRecordText = "tls_record"
)

// String возвращает токен уровня фрагментации.
func (p FragProto) String() string {
	switch p {
	case FragTCP:
		return fragTCPText
	case FragIP:
		return fragIPText
	case FragTLSRecord:
		return fragTLSRecordText
	default:
		return fmt.Sprintf("FragProto(%d)", uint8(p))
	}
}

// MarshalText сериализует уровень фрагментации как токен.
func (p FragProto) MarshalText() ([]byte, error) {
	switch p {
	case FragTCP, FragIP, FragTLSRecord:
		return []byte(p.String()), nil
	default:
		return nil, fmt.Errorf("strategy: недопустимый уровень фрагментации %d", uint8(p))
	}
}

// UnmarshalText разбирает токен уровня фрагментации.
func (p *FragProto) UnmarshalText(text []byte) error {
	switch string(text) {
	case fragTCPText:
		*p = FragTCP
	case fragIPText:
		*p = FragIP
	case fragTLSRecordText:
		*p = FragTLSRecord
	default:
		return fmt.Errorf("strategy: неизвестный уровень фрагментации %q", string(text))
	}
	return nil
}

// FragOrder — порядок отправки частей после разреза.
type FragOrder uint8

const (
	// FragForward — сначала первая часть (Left), затем вторая (Right) —
	// естественный порядок.
	FragForward FragOrder = iota
	// FragReverse — сначала вторая часть, затем первая. Разупорядоченная
	// отправка требует контроля над пакетами (возможность CapReorder).
	FragReverse
)

const (
	fragForwardText = "forward"
	fragReverseText = "reverse"
)

// String возвращает токен порядка отправки.
func (o FragOrder) String() string {
	switch o {
	case FragForward:
		return fragForwardText
	case FragReverse:
		return fragReverseText
	default:
		return fmt.Sprintf("FragOrder(%d)", uint8(o))
	}
}

// MarshalText сериализует порядок отправки как токен.
func (o FragOrder) MarshalText() ([]byte, error) {
	switch o {
	case FragForward, FragReverse:
		return []byte(o.String()), nil
	default:
		return nil, fmt.Errorf("strategy: недопустимый порядок отправки %d", uint8(o))
	}
}

// UnmarshalText разбирает токен порядка отправки.
func (o *FragOrder) UnmarshalText(text []byte) error {
	switch string(text) {
	case fragForwardText:
		*o = FragForward
	case fragReverseText:
		*o = FragReverse
	default:
		return fmt.Errorf("strategy: неизвестный порядок отправки %q", string(text))
	}
	return nil
}

// FragmentParams — параметры примитива Fragment.
//
// Место разреза задаётся ровно одним из двух способов, и это главное решение
// в описании примитива:
//
//	Offset — числом байт от начала разрезаемой единицы;
//	At     — видом структурной точки сообщения (например, внутри имени сервера).
//
// Два способа существуют потому, что у них разные области применения. Число
// нужно для рукописных стратегий и для разрезов, не связанных со структурой
// (10.2). Вид точки нужен всему остальному: положение значимых границ в
// ClientHello меняется от соединения к соединению, поэтому одно и то же число
// попадает то внутрь имени сервера, то в середину списка шифров. Генератор
// мутирует именно вид, иначе один и тот же ген означал бы разное в разных
// соединениях, и функция приспособленности получила бы шум (см. core.CutKind).
type FragmentParams struct {
	// Proto — уровень разреза (TCP или IP).
	Proto FragProto `json:"proto"`
	// Offset — смещение разреза в байтах от начала разрезаемой единицы.
	// Задаётся, если не задан At.
	Offset int `json:"offset,omitempty"`
	// At — структурная точка разреза. Задаётся, если не задан Offset.
	At core.CutKind `json:"at,omitempty"`
	// Order — порядок отправки частей.
	Order FragOrder `json:"order,omitempty"`
	// DelayMs — пауза перед отправкой второй по порядку части, в миллисекундах.
	//
	// Ноль означает отправку подряд. Пауза нужна против DPI, который собирает
	// поток в ограниченном по времени окне: если окно истечёт до прихода
	// второй части, собрать целое имя сервера он не успеет. Против DPI,
	// собирающего поток без ограничения по времени, не поможет — это
	// измерение пространства поиска, а не приём с гарантией.
	//
	// Отсчитывается относительно порядка отправки, а не ветвей дерева: при
	// обратном порядке (Order) пауза приходится перед той частью, которая
	// уходит второй.
	DelayMs int `json:"delay_ms,omitempty"`
}

// validate проверяет параметры Fragment.
//
// Требование «ровно один способ задания места разреза» проверяется здесь, а не
// типами: алгебраический тип дал бы эту гарантию статически, но мутации и
// скрещивание на нём пишутся заметно сложнее, и выбор сделан в пользу удобства
// генератора (4.3). Цена выбора — вот эта проверка, и её обязаны покрывать
// тесты.
func (p *FragmentParams) validate(limits Limits) error {
	switch p.Proto {
	case FragTCP, FragIP, FragTLSRecord:
	default:
		return fmt.Errorf("недопустимый уровень фрагментации %d", uint8(p.Proto))
	}
	switch p.Order {
	case FragForward, FragReverse:
	default:
		return fmt.Errorf("недопустимый порядок отправки %d", uint8(p.Order))
	}

	hasOffset := p.Offset != 0
	hasAt := p.At != core.CutNone
	switch {
	case hasOffset && hasAt:
		return fmt.Errorf("заданы и смещение %d, и точка разреза %s: нужно ровно одно", p.Offset, p.At)
	case !hasOffset && !hasAt:
		return fmt.Errorf("не задано место разреза: нужно либо offset, либо at")
	case hasAt:
		if !p.At.Valid() {
			return fmt.Errorf("недопустимая точка разреза %d", uint8(p.At))
		}
	default:
		if p.Offset < 0 {
			return fmt.Errorf("смещение разреза должно быть > 0, получено %d", p.Offset)
		}
		if p.Offset > limits.MaxFragmentOffset {
			return fmt.Errorf("смещение разреза %d превышает предел %d", p.Offset, limits.MaxFragmentOffset)
		}
	}

	if p.DelayMs < 0 {
		return fmt.Errorf("пауза не может быть отрицательной, получено %d", p.DelayMs)
	}
	if p.DelayMs > limits.MaxFragmentDelayMs {
		return fmt.Errorf("пауза %d мс превышает предел %d мс", p.DelayMs, limits.MaxFragmentDelayMs)
	}
	return nil
}

// requiredCapabilities сообщает, какие возможности нужны для этого разреза.
func (p *FragmentParams) requiredCapabilities() core.PrimitiveSet {
	var set core.PrimitiveSet
	switch p.Proto {
	case FragTCP:
		set = set.With(core.CapFragmentTCP)
	case FragIP:
		set = set.With(core.CapFragmentIP)
	case FragTLSRecord:
		// Разрез на уровне TLS-записи — чистая правка нагрузки на уровне
		// данных приложения. Пакетного контроля не требует: любой исполнитель
		// (socketexec, packetexec) может переформатировать поток байт перед
		// отправкой. Поэтому отдельной Cap не вводим: приём доступен в режиме
		// прокси этапа 0 и в режиме перехвата этапа 1.
	}
	if p.Order == FragReverse {
		set = set.With(core.CapReorder)
	}
	if p.DelayMs > 0 {
		set = set.With(core.CapDelay)
	}
	return set
}

// TCPOverlapParams — параметры примитива ActionTCPOverlap. Preset задаёт байты
// cover-пакета. Без Offset cover перекрывает конец нагрузки; с Offset используется
// split-seqovl, где cover предшествует началу окна TCP.
type TCPOverlapParams struct {
	// Preset — имя cover-пресета из fakePresets. Валидация требует, чтобы
	// имя было в реестре; её наличие проверяется и при разборе JSON, и при
	// каждом применении (чтобы устаревший конфиг был виден сразу, а не на
	// первом рабочем пакете).
	Preset string `json:"preset"`
	// Offset включает режим split-seqovl: cover ставится перед первыми Offset
	// байтами нагрузки и уходит с отрицательным TCP-смещением. Нулевое значение
	// сохраняет исходный вариант с перекрытием конца всей нагрузки.
	Offset int `json:"offset,omitempty"`
}

// validate проверяет параметры TCPOverlap.
func (p *TCPOverlapParams) validate(limits Limits) error {
	if p.Preset == "" {
		return fmt.Errorf("не задан preset для tcp_overlap")
	}
	if _, ok := fakePresets[p.Preset]; !ok {
		return fmt.Errorf("неизвестный preset %q для tcp_overlap", p.Preset)
	}
	if p.Offset < 0 || p.Offset > limits.MaxFragmentOffset {
		return fmt.Errorf("смещение split-seqovl %d вне допустимых границ", p.Offset)
	}
	return nil
}

// requiredCapabilities сообщает, что для tcp_overlap нужен пакетный контроль
// над TCP seq отдельных сегментов (CapTCPOverlap). В пользовательском
// пространстве (socketexec) приём неисполним — ОС назначает seq сама,
// перекрытие не задать. Это и выражает единственная возвращаемая возможность.
func (p *TCPOverlapParams) requiredCapabilities() core.PrimitiveSet {
	var set core.PrimitiveSet
	return set.With(core.CapTCPOverlap)
}
