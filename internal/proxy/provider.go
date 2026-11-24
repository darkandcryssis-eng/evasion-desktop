package proxy

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

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
// Поддерживает одну стратегию (Strategy) или ротацию (Strategies). Для группы
// используется одна активная стратегия; следующая включается после отказа
// текущей.
type GroupRule struct {
	// Name — имя группы для диагностики и ключа активной стратегии.
	Name string
	// Matcher — матчер подгруппы. nil равносилен «ни одно соединение в неё
	// не попадает»: правило игнорируется.
	Matcher HostMatcher
	// Strategy — одиночная стратегия подгруппы. Используется если Strategies
	// пуст. nil равносилен «ничего не применять» — такое правило отбрасывается.
	// Для обратной совместимости с конфигом, где у группы одна стратегия.
	Strategy *strategy.Strategy
	// Strategies — список стратегий группы. Все соединения получают текущую
	// активную стратегию; после подтверждённого отказа она переключается.
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
	mu                    sync.Mutex
	active                map[string]int
	advances              map[string][]time.Time
	exhausted             map[string]time.Time
	fallbackBypassEnabled bool
	fallbackFailures      map[string]fallbackFailureState
	onExhausted           func(string)
	onAdvance             func(group, sni string, from, to core.StrategyID)
	now                   func() time.Time
	// scores — счёт удач и срывов стратегий по группам; по нему ротация
	// выбирает, куда уходить после срыва, и когда срыв можно переждать.
	scores map[string]map[core.StrategyID]*strategyScore
	// overrides — стратегия для точного имени узла в обход группы: на таком
	// узле кандидат проверяется, не задевая остальной трафик группы.
	overrides map[string]Selection
}

type strategyScore struct {
	ok, fail float64
	lastFail time.Time
}

// Score — счёт стратегии в группе.
type Score struct {
	OK   float64 `json:"ok"`
	Fail float64 `json:"fail"`
}

// Rate — сглаженная доля удач; без наблюдений 0.5.
func (s Score) Rate() float64 { return (s.OK + 1) / (s.OK + s.Fail + 2) }

const (
	// scoreMemory ограничивает вес прошлого: старые наблюдения затухают, и
	// стратегия, переставшая работать, теряет счёт за десяток срывов.
	scoreMemory = 20.0
	// Стратегию с таким счётом одиночный срыв не сдвигает: у нестабильного
	// фильтра срывается и лучшая, а уход с неё на худшую стоит дороже.
	trustedRate     = 0.75
	trustedOK       = 4.0
	trustedFailSpan = 30 * time.Second
)

func (st *rotationState) scoreLocked(key string, id core.StrategyID) *strategyScore {
	if st.scores == nil {
		st.scores = make(map[string]map[core.StrategyID]*strategyScore)
	}
	group := st.scores[key]
	if group == nil {
		group = make(map[core.StrategyID]*strategyScore)
		st.scores[key] = group
	}
	sc := group[id]
	if sc == nil {
		sc = &strategyScore{}
		group[id] = sc
	}
	return sc
}

func (sc *strategyScore) add(ok bool) {
	if ok {
		sc.ok++
	} else {
		sc.fail++
	}
	if total := sc.ok + sc.fail; total > scoreMemory {
		sc.ok *= scoreMemory / total
		sc.fail *= scoreMemory / total
	}
}

func (sc *strategyScore) rate() float64 { return Score{OK: sc.ok, Fail: sc.fail}.Rate() }

type fallbackFailureState struct {
	firstFailure time.Time
	lastSeen     time.Time
	failures     int
	bypassUntil  time.Time
}

const (
	exhaustionWindow             = 2 * time.Minute
	exhaustionPeriod             = 2 * time.Minute
	fallbackFailureWindow        = 10 * time.Minute
	fallbackBypassDuration       = 10 * time.Minute
	fallbackFailureStateCapacity = 4096
)

// groupRuleResolved — правило с уже посчитанными идентификаторами стратегий.
// Хранится срез Selection (1+ элемент) для выбора активной стратегии.
// Пустой срез недопустим: правило без стратегий отбрасывается конструктором.
type groupRuleResolved struct {
	matcher  HostMatcher
	sels     *atomic.Pointer[[]Selection]
	name     string
	stateKey string
}

// list возвращает действующий список стратегий правила. Список заменяется
// целиком и на месте не правится, поэтому читать его можно без замка.
func (r groupRuleResolved) list() []Selection { return *r.sels.Load() }

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
	out := MultiGroupProvider{rotation: &rotationState{
		active:           make(map[string]int),
		advances:         make(map[string][]time.Time),
		exhausted:        make(map[string]time.Time),
		fallbackFailures: make(map[string]fallbackFailureState),
		now:              time.Now,
	}}
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
		list := new(atomic.Pointer[[]Selection])
		list.Store(&sels)
		out.rules = append(out.rules, groupRuleResolved{
			matcher:  r.Matcher,
			sels:     list,
			name:     r.Name,
			stateKey: ruleStateKey(r.Name, len(out.rules)),
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

func ruleStateKey(name string, index int) string {
	if name != "" {
		return name
	}
	return fmt.Sprintf("#%d", index)
}

// Select идёт по подгрупповым правилам в их порядке; при промахе — к запасному.
// Для группы всегда возвращается её текущая активная стратегия.
func (p MultiGroupProvider) Select(meta ConnMeta) Selection {
	if p.rotation != nil && meta.SNI != "" {
		p.rotation.mu.Lock()
		sel, ok := p.rotation.overrides[meta.SNI]
		p.rotation.mu.Unlock()
		if ok {
			return sel
		}
	}
	for _, r := range p.rules {
		if r.matcher.Matches(meta.Host, meta.SNI) {
			if p.rotation == nil {
				return r.list()[0]
			}
			p.rotation.mu.Lock()
			sels := r.list()
			sel := sels[p.rotation.active[r.stateKey]%len(sels)]
			p.rotation.mu.Unlock()
			return sel
		}
	}
	if p.hasFallback {
		if p.fallbackBypassed(meta.SNI) {
			return Selection{}
		}
		return p.fallback.Select(meta)
	}
	return Selection{}
}

func (p MultiGroupProvider) ReportFailure(sni string, failed core.StrategyID) {
	if p.rotation == nil || sni == "" || failed == "" {
		return
	}
	for _, r := range p.rules {
		if !r.matcher.Matches("", sni) {
			continue
		}
		p.rotation.mu.Lock()
		if len(r.list()) <= 1 {
			p.rotation.mu.Unlock()
			return
		}
		index := p.rotation.active[r.stateKey] % len(r.list())
		if r.list()[index].ID != failed {
			p.rotation.mu.Unlock()
			return
		}
		now := p.rotation.now()
		score := p.rotation.scoreLocked(r.stateKey, failed)
		trusted := score.ok >= trustedOK && score.rate() >= trustedRate &&
			now.Sub(score.lastFail) > trustedFailSpan
		score.add(false)
		score.lastFail = now
		if trusted {
			p.rotation.mu.Unlock()
			return
		}
		// Уходим на стратегию с лучшим счётом; при равенстве — на следующую
		// по порядку, так что без наблюдений это прежний перебор по кругу.
		next := (index + 1) % len(r.list())
		best := p.rotation.scoreLocked(r.stateKey, r.list()[next].ID).rate()
		for step := 2; step < len(r.list()); step++ {
			candidate := (index + step) % len(r.list())
			if rate := p.rotation.scoreLocked(r.stateKey, r.list()[candidate].ID).rate(); rate > best {
				next, best = candidate, rate
			}
		}
		p.rotation.active[r.stateKey] = next
		advanceHook := p.rotation.onAdvance
		advances := p.rotation.advances[r.stateKey]
		cutoff := now.Add(-exhaustionWindow)
		first := 0
		for first < len(advances) && advances[first].Before(cutoff) {
			first++
		}
		advances = append(advances[:0], advances[first:]...)
		advances = append(advances, now)
		p.rotation.advances[r.stateKey] = advances
		var exhaustedHook func(string)
		if len(advances) >= len(r.list()) && !now.Before(p.rotation.exhausted[r.stateKey]) {
			p.rotation.exhausted[r.stateKey] = now.Add(exhaustionPeriod)
			exhaustedHook = p.rotation.onExhausted
		}
		p.rotation.mu.Unlock()
		if advanceHook != nil {
			advanceHook(r.name, sni, failed, r.list()[next].ID)
		}
		if exhaustedHook != nil {
			exhaustedHook(r.name)
		}
		return
	}
	if !p.hasFallback ||
		p.fallback.sel.Strategy == nil || p.fallback.sel.ID != failed ||
		!p.fallback.matcher.Matches("", sni) {
		return
	}
	p.recordFallbackFailure(sni)
}

func (p MultiGroupProvider) fallbackBypassed(sni string) bool {
	if sni == "" || p.rotation == nil {
		return false
	}
	p.rotation.mu.Lock()
	defer p.rotation.mu.Unlock()
	if !p.rotation.fallbackBypassEnabled {
		return false
	}
	state, ok := p.rotation.fallbackFailures[sni]
	if !ok {
		return false
	}
	now := p.rotation.now()
	if now.Before(state.bypassUntil) {
		return true
	}
	if !state.bypassUntil.IsZero() {
		delete(p.rotation.fallbackFailures, sni)
		return false
	}
	if now.Sub(state.firstFailure) > fallbackFailureWindow {
		delete(p.rotation.fallbackFailures, sni)
	}
	return false
}

func (p MultiGroupProvider) recordFallbackFailure(sni string) {
	p.rotation.mu.Lock()
	defer p.rotation.mu.Unlock()
	if !p.rotation.fallbackBypassEnabled {
		return
	}
	now := p.rotation.now()
	state, exists := p.rotation.fallbackFailures[sni]
	if exists && !state.bypassUntil.IsZero() && !now.Before(state.bypassUntil) {
		state = fallbackFailureState{}
		exists = false
	}
	if exists && now.Sub(state.firstFailure) > fallbackFailureWindow {
		state = fallbackFailureState{}
		exists = false
	}
	if !exists && len(p.rotation.fallbackFailures) >= fallbackFailureStateCapacity {
		oldestSNI := ""
		var oldest time.Time
		for key, candidate := range p.rotation.fallbackFailures {
			if oldestSNI == "" || candidate.lastSeen.Before(oldest) {
				oldestSNI = key
				oldest = candidate.lastSeen
			}
		}
		delete(p.rotation.fallbackFailures, oldestSNI)
	}
	if state.failures == 0 {
		state.firstFailure = now
	}
	state.failures++
	state.lastSeen = now
	if state.failures >= 2 {
		state.bypassUntil = now.Add(fallbackBypassDuration)
	}
	p.rotation.fallbackFailures[sni] = state
}

// SetFallbackFailureBypass включает временный обход для упавшего fallback-SNI.
// По умолчанию выключено, чтобы не менять режим groups.
func (p MultiGroupProvider) SetFallbackFailureBypass(enabled bool) {
	if p.rotation == nil {
		return
	}
	p.rotation.mu.Lock()
	p.rotation.fallbackBypassEnabled = enabled
	p.rotation.mu.Unlock()
}

// SetOnAdvance устанавливает необязательный callback на каждую смену активной
// стратегии группы. Вызывается вне внутренней блокировки.
func (p MultiGroupProvider) SetOnAdvance(fn func(group, sni string, from, to core.StrategyID)) {
	if p.rotation == nil {
		return
	}
	p.rotation.mu.Lock()
	p.rotation.onAdvance = fn
	p.rotation.mu.Unlock()
}

// SetOnExhausted устанавливает необязательный callback. Он вызывается вне
// внутренней блокировки после полного цикла подтверждённых отказов.
func (p MultiGroupProvider) SetOnExhausted(fn func(group string)) {
	if p.rotation == nil {
		return
	}
	p.rotation.mu.Lock()
	p.rotation.onExhausted = fn
	p.rotation.mu.Unlock()
}

// ActiveStrategies возвращает копию активных идентификаторов по имени группы.
func (p MultiGroupProvider) ActiveStrategies() map[string]core.StrategyID {
	out := make(map[string]core.StrategyID, len(p.rules))
	if p.rotation == nil {
		return out
	}
	p.rotation.mu.Lock()
	defer p.rotation.mu.Unlock()
	for i := range p.rules {
		r := p.rules[i]
		if r.name == "" {
			continue
		}
		out[r.name] = r.list()[p.rotation.active[r.stateKey]%len(r.list())].ID
	}
	return out
}

// ReportSuccess засчитывает стратегии удачный обмен с узлом.
func (p MultiGroupProvider) ReportSuccess(sni string, id core.StrategyID) {
	if p.rotation == nil || sni == "" || id == "" {
		return
	}
	for _, r := range p.rules {
		if r.matcher.Matches("", sni) {
			p.Record(r.name, id, true)
			return
		}
	}
}

// Record заносит исход проверки стратегии в счёт группы, не трогая выбор.
func (p MultiGroupProvider) Record(group string, id core.StrategyID, ok bool) {
	if p.rotation == nil || group == "" || id == "" {
		return
	}
	for _, r := range p.rules {
		if r.name != group {
			continue
		}
		p.rotation.mu.Lock()
		p.rotation.scoreLocked(r.stateKey, id).add(ok)
		p.rotation.mu.Unlock()
		return
	}
}

// Scores возвращает счёт стратегий группы.
func (p MultiGroupProvider) Scores(group string) map[core.StrategyID]Score {
	out := make(map[core.StrategyID]Score)
	if p.rotation == nil {
		return out
	}
	for _, r := range p.rules {
		if r.name != group {
			continue
		}
		p.rotation.mu.Lock()
		for id, sc := range p.rotation.scores[r.stateKey] {
			out[id] = Score{OK: sc.ok, Fail: sc.fail}
		}
		p.rotation.mu.Unlock()
		break
	}
	return out
}

// SetScore задаёт счёт стратегии в группе — для восстановления сохранённого.
func (p MultiGroupProvider) SetScore(group string, id core.StrategyID, score Score) {
	if p.rotation == nil || id == "" || score.OK < 0 || score.Fail < 0 {
		return
	}
	for _, r := range p.rules {
		if r.name != group {
			continue
		}
		p.rotation.mu.Lock()
		sc := p.rotation.scoreLocked(r.stateKey, id)
		sc.ok, sc.fail = score.OK, score.Fail
		p.rotation.mu.Unlock()
		return
	}
}

// Strategies возвращает стратегии группы в порядке ротации.
func (p MultiGroupProvider) Strategies(group string) []Selection {
	for _, r := range p.rules {
		if r.name == group {
			return append([]Selection(nil), r.list()...)
		}
	}
	return nil
}

// AddStrategy дописывает стратегию в ротацию группы. Возвращает false, если
// группы нет или такая стратегия в ней уже есть.
func (p MultiGroupProvider) AddStrategy(group string, s *strategy.Strategy) (core.StrategyID, bool) {
	if p.rotation == nil || group == "" || s == nil {
		return "", false
	}
	id, err := strategy.ComputeID(s)
	if err != nil {
		return "", false
	}
	for _, r := range p.rules {
		if r.name != group {
			continue
		}
		p.rotation.mu.Lock()
		defer p.rotation.mu.Unlock()
		current := r.list()
		for _, sel := range current {
			if sel.ID == id {
				return id, false
			}
		}
		next := make([]Selection, len(current), len(current)+1)
		copy(next, current)
		next = append(next, Selection{Strategy: s, ID: id})
		r.sels.Store(&next)
		return id, true
	}
	return id, false
}

// RemoveStrategy убирает стратегию из ротации группы. Действующую и
// последнюю оставшуюся не убирает.
func (p MultiGroupProvider) RemoveStrategy(group string, id core.StrategyID) bool {
	if p.rotation == nil || group == "" || id == "" {
		return false
	}
	for _, r := range p.rules {
		if r.name != group {
			continue
		}
		p.rotation.mu.Lock()
		defer p.rotation.mu.Unlock()
		current := r.list()
		active := p.rotation.active[r.stateKey] % len(current)
		if len(current) <= 1 || current[active].ID == id {
			return false
		}
		next := make([]Selection, 0, len(current))
		for _, sel := range current {
			if sel.ID != id {
				next = append(next, sel)
			}
		}
		if len(next) == len(current) {
			return false
		}
		for j, sel := range next {
			if sel.ID == current[active].ID {
				p.rotation.active[r.stateKey] = j
			}
		}
		r.sels.Store(&next)
		delete(p.rotation.scores[r.stateKey], id)
		return true
	}
	return false
}

// SetHostOverride назначает стратегию точному имени узла в обход его группы.
func (p MultiGroupProvider) SetHostOverride(host string, s *strategy.Strategy) (core.StrategyID, bool) {
	if p.rotation == nil || host == "" || s == nil {
		return "", false
	}
	id, err := strategy.ComputeID(s)
	if err != nil {
		return "", false
	}
	p.rotation.mu.Lock()
	if p.rotation.overrides == nil {
		p.rotation.overrides = make(map[string]Selection)
	}
	p.rotation.overrides[host] = Selection{Strategy: s, ID: id}
	p.rotation.mu.Unlock()
	return id, true
}

// ClearHostOverride снимает назначение SetHostOverride.
func (p MultiGroupProvider) ClearHostOverride(host string) {
	if p.rotation == nil {
		return
	}
	p.rotation.mu.Lock()
	delete(p.rotation.overrides, host)
	p.rotation.mu.Unlock()
}

// SetActive назначает известную стратегию группе; при неизвестной группе или
// ID возвращает false.
func (p MultiGroupProvider) SetActive(group string, id core.StrategyID) bool {
	if p.rotation == nil || group == "" || id == "" {
		return false
	}
	for _, r := range p.rules {
		if r.name != group {
			continue
		}
		p.rotation.mu.Lock()
		defer p.rotation.mu.Unlock()
		for i, sel := range r.list() {
			if sel.ID == id {
				p.rotation.active[r.stateKey] = i
				return true
			}
		}
		return false
	}
	return false
}

// Rules возвращает имена подгрупповых правил и их идентификаторы стратегий в
// порядке применения — для вывода в status/doctor и диагностики.
//
// Копия, чтобы потребитель не изменил внутреннее состояние. При ротации
// StrategyID содержит id активной стратегии, а StrategyIDs — полный список.
func (p MultiGroupProvider) Rules() []GroupRuleInfo {
	if len(p.rules) == 0 {
		return nil
	}
	out := make([]GroupRuleInfo, 0, len(p.rules))
	for _, r := range p.rules {
		active := 0
		if p.rotation != nil {
			p.rotation.mu.Lock()
			active = p.rotation.active[r.stateKey] % len(r.list())
			p.rotation.mu.Unlock()
		}
		ids := make([]core.StrategyID, 0, len(r.list()))
		for _, s := range r.list() {
			ids = append(ids, s.ID)
		}
		out = append(out, GroupRuleInfo{
			Name:        r.name,
			StrategyID:  ids[active],
			StrategyIDs: ids,
		})
	}
	return out
}

// GroupRuleInfo — диагностический срез одного правила MultiGroupProvider.
//
// StrategyID — активная стратегия. StrategyIDs — все стратегии группы,
// len == 1 если группа не имеет вариантов отказоустойчивости.
type GroupRuleInfo struct {
	Name        string
	StrategyID  core.StrategyID
	StrategyIDs []core.StrategyID
}
