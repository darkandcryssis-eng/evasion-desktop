package proxy

import (
	"sync"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// ConnMeta — что известно о соединении на момент выбора стратегии.
//
// Это вход для StrategyProvider. Намеренно минимален и состоит из данных,
// доступных к моменту ClientHello: цель из запроса SOCKS и имя сервера из
// ClientHello.
type ConnMeta struct {
	PayloadLength int
	// Host, Port — цель из запроса SOCKS CONNECT.
	Host string
	Port uint16
	// SNI — имя сервера из ClientHello; пусто, если его нет или это не TLS.
	SNI string
	// IsClientHello — удалось ли распознать ClientHello в начале потока.
	IsClientHello bool
	// LocalPort — исходный (локальный) порт соединения; 0, если неизвестен.
	//
	// Нужен провайдеру песочницы (5.2): там все пробы идут к одной цели, и
	// различить, какую стратегию проверяет данное соединение, можно только по
	// порту, с которого оно инициировано. Продуктовые провайдеры (GroupProvider,
	// policy.Table) поле игнорируют — выбор по радиусу и SNI от него не зависит.
	// Заполняется контуром перехвата, у которого порт уже разобран; в прокси
	// (этап 0) остаётся нулём.
	LocalPort uint16
}

// Selection — результат выбора: стратегия и её идентификатор.
//
// Strategy == nil означает «применять нечего»: соединение проходит без
// изменений. Идентификатор нужен телеметрии, чтобы связать исход соединения с
// применённой стратегией.
type Selection struct {
	Strategy *strategy.Strategy
	ID       core.StrategyID
	// Target — цель радиуса, которой принадлежит запись, давшая этот выбор.
	//
	// Нужна учёту исходов: оценки ключуются целью радиуса («youtube.com»), а
	// соединение приходит к её поддомену («www.youtube.com»). Без этого поля
	// наблюдение пришлось бы относить к имени соединения, то есть к другой
	// четвёрке (6.1), и решения по цели его никогда бы не увидели.
	//
	// Пусто, если выбор сделан не по таблице радиуса (StaticProvider) или
	// совпадения не было.
	Target string
	// Trial — соединение отдано проверяемой стратегии (статус testing), то
	// есть попало в ту долю трафика, на которой кандидат проверяется (5.1).
	//
	// Признак нужен отдельно от идентификатора, хотя по идентификатору статус
	// стратегии тоже можно узнать: статус живёт в контуре управления и к
	// моменту разбора наблюдения успевает измениться. Исход же обязан остаться
	// приписанным той ступени допуска, на которой он получен, — иначе
	// проверочные соединения смешаются с рабочими, и доля 5% перестанет быть
	// проверяемой.
	Trial bool
}

// StrategyProvider выбирает стратегию для соединения.
//
// Это шов между прокси и контуром управления. На этапе 0 (M3) используется
// StaticProvider; на M6 его заменит policy, читающий горячий снимок таблицы, —
// при этом сам proxy не меняется. Реализация обязана быть потокобезопасной и
// быстрой: Select вызывается на каждом соединении в его горячем начале.
type StrategyProvider interface {
	// Select возвращает стратегию для соединения с данными метаданными.
	Select(meta ConnMeta) Selection
}

// StaticProvider всегда возвращает одну и ту же стратегию. Нужен на этапе 0,
// пока нет контура управления: позволяет проверить обход с фиксированной
// стратегией из конфига.
type StaticProvider struct {
	sel Selection
}

// NewStaticProvider создаёт провайдер, отдающий заданную стратегию всем
// соединениям. Идентификатор вычисляется из стратегии, чтобы телеметрия и
// ручная запись совпадали. Стратегия nil означает режим пропуска.
func NewStaticProvider(s *strategy.Strategy) (StaticProvider, error) {
	if s == nil {
		return StaticProvider{}, nil
	}
	id, err := strategy.ComputeID(s)
	if err != nil {
		return StaticProvider{}, err
	}
	return StaticProvider{sel: Selection{Strategy: s, ID: id}}, nil
}

// Select возвращает фиксированную стратегию независимо от метаданных.
func (p StaticProvider) Select(ConnMeta) Selection { return p.sel }

// HostMatcher решает, попадает ли соединение в радиус поражения по имени хоста
// или SNI. Интерфейс узкий намеренно: proxy не должен знать про группы доменов и
// конфиг, ему достаточно ответа «да/нет». Реализация — config.DomainSet.
type HostMatcher interface {
	// Matches сообщает, попадает ли соединение с данными host и sni в радиус.
	Matches(host, sni string) bool
}

// GroupProvider применяет стратегию только к соединениям, попадающим в радиус
// поражения (1.6, 2.3), а остальные пропускает прозрачно.
//
// Это ручная предшественница policy (M6): одна стратегия, ограниченная набором
// доменов. На M6 её заменит снимок горячей таблицы, и сам proxy при этом не
// изменится — обе реализации удовлетворяют StrategyProvider.
type GroupProvider struct {
	sel     Selection
	matcher HostMatcher
}

// NewGroupProvider создаёт провайдер, применяющий стратегию s к соединениям,
// которые matcher относит к радиусу. matcher nil запрещён: это означало бы
// «радиус не задан», а неявно применять стратегию ко всему трафику нельзя —
// радиус указывается явно.
func NewGroupProvider(s *strategy.Strategy, matcher HostMatcher) (GroupProvider, error) {
	if matcher == nil {
		return GroupProvider{}, errNoMatcher
	}
	if s == nil {
		// Стратегии нет — провайдер всегда пропускает. Матчер при этом не нужен,
		// но его наличие не мешает.
		return GroupProvider{matcher: matcher}, nil
	}
	id, err := strategy.ComputeID(s)
	if err != nil {
		return GroupProvider{}, err
	}
	return GroupProvider{sel: Selection{Strategy: s, ID: id}, matcher: matcher}, nil
}

// Select возвращает стратегию только для соединений в радиусе; для остальных —
// пустой выбор (прозрачный пропуск).
func (p GroupProvider) Select(meta ConnMeta) Selection {
	if p.sel.Strategy == nil || !p.matcher.Matches(meta.Host, meta.SNI) {
		return Selection{}
	}
	return p.sel
}

// GroupRule — пара «матчер подгруппы + её стратегии» для MultiGroupProvider.
//
// Матчер — обычно config.DomainSet, построенный из одной группы; стратегия —
// запись из cfg.Strategies для этой же группы. Выделено отдельным типом,
// чтобы конструктор принимал один аргумент-срез, а порядок — определялся
// вызывающим.
//
// Поддерживает ОДНУ стратегию (Strategy) ИЛИ РОТАЦИЮ нескольких (Strategies).
// Ротация даёт DPI разные формы фейка на разных соединениях одной группы —
// без неё однообразный паттерн (например, одинаковый google-ClientHello на
// каждом соединении голоса) сам становится маркером обхода.
type GroupRule struct {
	// Name — имя группы для диагностики. Не используется при выборе; выводится
	// в журнале запуска, чтобы владелец видел, какая стратегия к какой группе
	// привязана.
	Name string
	// Matcher — матчер подгруппы. nil равносилен «ни одно соединение в неё
	// не попадает»: правило игнорируется.
	Matcher HostMatcher
	// Strategy — одиночная стратегия подгруппы. Используется если Strategies
	// пуст. nil равносилен «ничего не применять» — такое правило отбрасывается.
	// Для обратной совместимости с конфигом, где у группы одна стратегия.
	Strategy *strategy.Strategy
	// Strategies — ротация. Если непустой срез, Select чередует стратегии
	// между соединениями подгруппы по хешу (SNI + LocalPort) — та же пара
	// получает тот же выбор (стабильность рукопожатия), разные соединения
	// получают разное (размывание сигнатуры).
	Strategies []*strategy.Strategy
}

// MultiGroupProvider выбирает стратегию по подгруппам радиуса (10.1): каждой
// подгруппе — своя стратегия, и первая подгруппа по порядку, в которую попал
// хост, определяет выбор. Для соединений вне подгрупп применяется запасной
// GroupProvider (общая стратегия по всему радиусу).
//
// Нужен, когда одна и та же стратегия чинит один домен, но ломает другой — у
// владельца это проявилось так: fake-badsum даёт 5/5 для `*.discord.media`,
// но прежняя конфигурация с hosts-fallback роняла с ней discord.com. Разнесение
// по группам снимает конфликт, не трогая остальной движок (choice это только
// StrategyProvider — всё, что ниже, не меняется).
type MultiGroupProvider struct {
	// rules — подгруппы в порядке, который задал вызывающий. Первая, в чей
	// матчер попадает host или SNI, выигрывает.
	rules []groupRuleResolved
	// fallback — запасной провайдер для хостов внутри общего радиуса, не
	// попавших ни в одно правило. Применяется, только если задан.
	fallback GroupProvider
	// hasFallback — задан ли запасной. GroupProvider — значение, zero
	// неотличим от «общий радиус без стратегии»; флаг снимает двусмысленность.
	hasFallback bool
	rotation    *rotationState
}

type rotationState struct {
	mu     sync.Mutex
	offset map[string]uint32
}

const maxRotationOffsets = 4096

// groupRuleResolved — правило с уже посчитанными идентификаторами стратегий.
// Хранится срез Selection (1+ элемент) — для ротации в Select по хешу.
// Пустой срез недопустим: правило без стратегий отбрасывается конструктором.
type groupRuleResolved struct {
	matcher HostMatcher
	sels    []Selection
	name    string
}

// NewMultiGroupProvider собирает провайдер из подгрупповых правил и
// опционального запасного.
//
// rules применяются в порядке передачи: вызывающий сам отвечает за детерминизм
// (обычно сортирует по имени группы). Правила с nil-матчером или nil-стратегией
// отбрасываются ещё здесь, чтобы не тратить время на горячем пути.
//
// fallback (общий радиус + общая стратегия) опционален: если cfg.Strategy пуст,
// то за пределами подгрупп обход не нужен. Если fallback.matcher nil — ошибка,
// как и в NewGroupProvider: радиус неявно считать «всем» нельзя (1.6).
func NewMultiGroupProvider(rules []GroupRule, fallbackStrategy *strategy.Strategy, fallbackMatcher HostMatcher) (MultiGroupProvider, error) {
	out := MultiGroupProvider{rotation: &rotationState{offset: make(map[string]uint32)}}
	for _, r := range rules {
		if r.Matcher == nil {
			continue
		}
		// Собираем список стратегий: приоритет у Strategies (ротация), иначе
		// одиночная Strategy. Пустое правило (ни той ни другой) отбрасываем.
		var stratList []*strategy.Strategy
		switch {
		case len(r.Strategies) > 0:
			for _, s := range r.Strategies {
				if s != nil {
					stratList = append(stratList, s)
				}
			}
		case r.Strategy != nil:
			stratList = []*strategy.Strategy{r.Strategy}
		}
		if len(stratList) == 0 {
			continue
		}
		sels := make([]Selection, 0, len(stratList))
		for _, s := range stratList {
			id, err := strategy.ComputeID(s)
			if err != nil {
				return MultiGroupProvider{}, err
			}
			sels = append(sels, Selection{Strategy: s, ID: id})
		}
		out.rules = append(out.rules, groupRuleResolved{
			matcher: r.Matcher,
			sels:    sels,
			name:    r.Name,
		})
	}
	// Запасной. Матчер обязан быть, даже если стратегии нет: отсутствие
	// матчера значило бы «применять ко всему без радиуса», а это запрещено.
	if fallbackMatcher == nil {
		return MultiGroupProvider{}, errNoMatcher
	}
	fb, err := NewGroupProvider(fallbackStrategy, fallbackMatcher)
	if err != nil {
		return MultiGroupProvider{}, err
	}
	out.fallback = fb
	out.hasFallback = true
	return out, nil
}

// Select идёт по подгрупповым правилам в их порядке; при промахе — к запасному.
//
// Если у подгруппы ротация (len(sels) > 1), выбор стратегии стабилен по паре
// (SNI, LocalPort): один и тот же сервер+локальный порт получит одну и ту же
// стратегию (нужно для стабильности TCP-ретрансмитов), разные пары получат
// разное распределение (размывание DPI-сигнатуры).
func (p MultiGroupProvider) Select(meta ConnMeta) Selection {
	for _, r := range p.rules {
		if r.matcher.Matches(meta.Host, meta.SNI) {
			if len(r.sels) == 1 {
				return r.sels[0]
			}
			offset := uint32(0)
			if p.rotation != nil && meta.SNI != "" {
				p.rotation.mu.Lock()
				offset = p.rotation.offset[meta.SNI]
				p.rotation.mu.Unlock()
			}
			index := (rotationIndex(meta, len(r.sels)) + int(offset%uint32(len(r.sels)))) % len(r.sels)
			return r.sels[index]
		}
	}
	if p.hasFallback {
		return p.fallback.Select(meta)
	}
	return Selection{}
}

func (p MultiGroupProvider) ReportFailure(sni string) {
	if p.rotation == nil || sni == "" {
		return
	}
	for _, r := range p.rules {
		if !r.matcher.Matches("", sni) {
			continue
		}
		if len(r.sels) <= 1 {
			return
		}
		p.rotation.mu.Lock()
		if len(p.rotation.offset) >= maxRotationOffsets {
			clear(p.rotation.offset)
		}
		p.rotation.offset[sni]++
		p.rotation.mu.Unlock()
		return
	}
}

// rotationIndex даёт стабильный индекс в [0, n) по метаданным соединения.
// FNV-1a 32-битный хеш от строки «SNI|port» — быстро, без аллокаций вне
// нужных для построения ключа. При len == 1 вызывающий короткозамкнёт.
func rotationIndex(meta ConnMeta, n int) int {
	if n <= 1 {
		return 0
	}
	const (
		offset32 uint32 = 2166136261
		prime32  uint32 = 16777619
	)
	h := offset32
	for i := 0; i < len(meta.SNI); i++ {
		h ^= uint32(meta.SNI[i])
		h *= prime32
	}
	h ^= uint32(meta.LocalPort >> 8)
	h *= prime32
	h ^= uint32(meta.LocalPort & 0xff)
	h *= prime32
	return int(h % uint32(n))
}

// Rules возвращает имена подгрупповых правил и их идентификаторы стратегий в
// порядке применения — для вывода в status/doctor и диагностики.
//
// Копия, чтобы потребитель не изменил внутреннее состояние. При ротации
// StrategyID содержит id первой стратегии (как «главной»), а StrategyIDs —
// полный список для вывода.
func (p MultiGroupProvider) Rules() []GroupRuleInfo {
	if len(p.rules) == 0 {
		return nil
	}
	out := make([]GroupRuleInfo, 0, len(p.rules))
	for _, r := range p.rules {
		ids := make([]core.StrategyID, 0, len(r.sels))
		for _, s := range r.sels {
			ids = append(ids, s.ID)
		}
		out = append(out, GroupRuleInfo{
			Name:        r.name,
			StrategyID:  ids[0],
			StrategyIDs: ids,
		})
	}
	return out
}

// GroupRuleInfo — диагностический срез одного правила MultiGroupProvider.
//
// StrategyID — главная стратегия (первая в ротации). StrategyIDs — полный
// список при ротации, len == 1 если ротации нет.
type GroupRuleInfo struct {
	Name        string
	StrategyID  core.StrategyID
	StrategyIDs []core.StrategyID
}
