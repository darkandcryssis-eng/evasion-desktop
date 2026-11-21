package generator

import (
	"errors"
	"fmt"
	"math/rand/v2"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// defaultMaxDepth — глубина порождаемого дерева по умолчанию.
//
// Пять уровней хватает на осмысленные комбинации (фейк из дубликата с правкой
// плюс разрез), а дерево при этом остаётся малым: при двоичном ветвлении до
// 2^5−1 = 31 узла, далеко ниже предела MaxNodes. Глубже — не богаче поиск, а
// дороже исполнение и больше мёртвых ветвей.
const defaultMaxDepth = 5

// Вероятности выбора при построении узла. Вынесены в константы, а не вкраплены
// в код: это параметры поиска, и подбирать их придётся по работе генератора.
const (
	// pBranch — доля случаев, когда на месте, где ветвление ещё допустимо,
	// ставится внутренний узел, а не лист. Смещение к ветвлению нужно, чтобы
	// деревья не вырождались в одиночный Send.
	pBranch = 0.75
	// pDrop — доля листьев Drop среди листьев (когда Drop доступен). Мала:
	// Drop уничтожает пакет, и как корень рвёт соединение; полезен редко.
	pDrop = 0.1
	// pCutByKind — доля разрезов, заданных структурной точкой (а не числом).
	// Смещение к видам точек намеренное: число значит разное в разных
	// соединениях и для поиска хуже (core.CutKind).
	pCutByKind = 0.8
	// maxBuildAttempts — сколько раз пересобрать стратегию, если она не прошла
	// валидацию или вышла за возможности. По построению такого быть не должно;
	// предел — защита от бесконечного цикла при ошибке в правилах построения.
	maxBuildAttempts = 64
)

// Config задаёт рамки поиска.
type Config struct {
	// Caps — возможности исполнителя: генератор строит только из примитивов,
	// которые тот умеет (4.7). Обязателен хотя бы один внутренний примитив,
	// иначе дерево вырождается в один лист.
	Caps core.PrimitiveSet
	// Limits — пределы формы стратегии (из strategy). Ноль недопустим:
	// неограниченное дерево мутаций разрослось бы без предела.
	Limits strategy.Limits
	// MaxDepth — предел глубины порождаемого дерева; 0 означает значение по
	// умолчанию. Не может превышать Limits.MaxDepth.
	MaxDepth int
	// IPVersion ограничивает порождаемые правки полей IP указанной версией
	// (4 или 6); 0 означает «обе».
	//
	// Нужно, чтобы не плодить кандидатов, правящих поле не того протокола, чем
	// идёт трафик: на IPv4-соединении IPv6-поле недоступно, кандидат
	// неприменим, а живые пробы на него тратятся впустую (и часть таких
	// кандидатов рвёт пробу на полуприменении). Версию задаёт вызывающий по
	// сети или конфигу — генератор её не угадывает. Поля TCP и тело от версии
	// не зависят и остаются при любом значении.
	IPVersion int
	// Rand — источник случайности. nil означает свой сид (недетерминированный);
	// тесты передают сюда заданный, чтобы поиск был воспроизводим.
	Rand *rand.Rand
}

// Generator порождает и изменяет стратегии в рамках Config. Не потокобезопасен:
// держит источник случайности; на каждую горутину поиска — свой Generator.
type Generator struct {
	caps      core.PrimitiveSet
	limits    strategy.Limits
	maxDepth  int
	ipVersion int
	rng       *rand.Rand

	// Предвычисленные наборы видов, разрешённых возможностями. Считаются раз
	// при создании: пространство выбора от пакета к пакету не меняется.
	internalKinds []core.ActionKind
	tamperFields  []strategy.FieldID
}

// New собирает генератор, проверив, что из заданных возможностей вообще есть
// что строить.
func New(cfg Config) (*Generator, error) {
	if cfg.Limits.MaxDepth <= 0 || cfg.Limits.MaxNodes <= 0 {
		return nil, errors.New("generator: не заданы пределы формы (Limits)")
	}
	maxDepth := cfg.MaxDepth
	if maxDepth == 0 {
		maxDepth = defaultMaxDepth
	}
	if maxDepth < 2 {
		return nil, fmt.Errorf("generator: глубина %d меньше 2 — дерево не ветвится", maxDepth)
	}
	if maxDepth > cfg.Limits.MaxDepth {
		return nil, fmt.Errorf("generator: глубина %d больше предела валидации %d", maxDepth, cfg.Limits.MaxDepth)
	}
	switch cfg.IPVersion {
	case 0, 4, 6:
	default:
		return nil, fmt.Errorf("generator: версия IP %d недопустима (0, 4 или 6)", cfg.IPVersion)
	}

	rng := cfg.Rand
	if rng == nil {
		rng = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	}

	g := &Generator{
		caps:      cfg.Caps,
		limits:    cfg.Limits,
		maxDepth:  maxDepth,
		ipVersion: cfg.IPVersion,
		rng:       rng,
	}
	g.internalKinds = g.allowedInternalKinds()
	g.tamperFields = g.allowedTamperFields()

	if len(g.internalKinds) == 0 {
		return nil, errors.New("generator: возможности не позволяют ни одного внутреннего примитива — строить нечего")
	}
	return g, nil
}

// allowedInternalKinds отбирает внутренние виды, разрешённые возможностями.
// Берёт перечень из реестра strategy, а не из своего списка (10.3).
func (g *Generator) allowedInternalKinds() []core.ActionKind {
	var out []core.ActionKind
	for _, k := range strategy.Kinds() {
		switch k {
		case core.ActionTamper:
			if g.caps.Has(core.CapTamper) {
				out = append(out, k)
			}
		case core.ActionDuplicate:
			if g.caps.Has(core.CapDuplicate) {
				out = append(out, k)
			}
		case core.ActionFragment:
			if g.caps.Has(core.CapFragmentTCP) || g.caps.Has(core.CapFragmentIP) {
				out = append(out, k)
			}
		case core.ActionTCPOverlap:
			// tcp_overlap исполним только в пакетном пространстве (ОС не даёт
			// задать перекрытие seq из сокета). Берём его в перебор, лишь когда
			// возможность явно есть — иначе поиск порождал бы заведомо
			// неисполнимое и тратил попытки на отбраковке в finalize.
			if g.caps.Has(core.CapTCPOverlap) {
				out = append(out, k)
			}
		}
	}
	return out
}

// allowedTamperFields отбирает поля, пригодные для Tamper при данных
// возможностях: поле контрольной суммы берётся только если исполнитель умеет
// намеренно портить сумму (4.7).
func (g *Generator) allowedTamperFields() []strategy.FieldID {
	var out []strategy.FieldID
	for _, f := range strategy.Fields() {
		if f.IsChecksum() && !g.caps.Has(core.CapTamperChecksumCorrupt) {
			continue
		}
		// Поле не той версии IP, чем идёт трафик, на пакете недоступно — такой
		// правки не порождаем (TCP-поля и тело от версии не зависят).
		if g.ipVersion == 4 && f.IsIPv6() {
			continue
		}
		if g.ipVersion == 6 && f.IsIPv4() {
			continue
		}
		// Опции TCP (MSS, масштаб окна) есть только в SYN, а правила генератора
		// срабатывают на ClientHello (данные) — там опций нет, и правка была бы
		// заведомо неисполнима. Исключаем, пока генератор строит только
		// ClientHello-правила; при появлении SYN-правил это надо будет
		// пересмотреть.
		if f.IsTCPOption() {
			continue
		}
		out = append(out, f)
	}
	return out
}

// Random порождает одну случайную валидную стратегию, исполнимую при заданных
// возможностях. Правило одно: исходящий ClientHello — туда, где применяется
// десинк; множественные правила и иные триггеры — отдельным расширением.
func (g *Generator) Random() (*strategy.Strategy, error) {
	for attempt := 0; attempt < maxBuildAttempts; attempt++ {
		root := g.randomAction(g.maxDepth)
		s := &strategy.Strategy{Rules: []strategy.Rule{{
			Direction: core.DirectionOutbound,
			Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
			Action:    root,
		}}}
		if finalized, ok := g.finalize(s); ok {
			return finalized, nil
		}
	}
	return nil, errors.New("generator: не удалось построить валидную стратегию за отведённые попытки")
}

// randomAction строит случайный узел с запасом глубины depthBudget (корень —
// полный maxDepth). При исчерпании запаса или по жребию ставится лист.
func (g *Generator) randomAction(depthBudget int) *strategy.Action {
	canBranch := depthBudget > 1
	if !canBranch || g.rng.Float64() >= pBranch {
		return g.randomLeaf()
	}
	kind := g.internalKinds[g.rng.IntN(len(g.internalKinds))]
	switch kind {
	case core.ActionTamper:
		return &strategy.Action{
			Kind:   core.ActionTamper,
			Params: g.randomTamperParams(),
			Left:   g.randomAction(depthBudget - 1),
		}
	case core.ActionDuplicate:
		return &strategy.Action{
			Kind:  core.ActionDuplicate,
			Left:  g.randomAction(depthBudget - 1),
			Right: g.randomAction(depthBudget - 1),
		}
	case core.ActionFragment:
		return &strategy.Action{
			Kind:   core.ActionFragment,
			Params: g.randomFragmentParams(),
			Left:   g.randomAction(depthBudget - 1),
			Right:  g.randomAction(depthBudget - 1),
		}
	case core.ActionTCPOverlap:
		// tcp_overlap — лист: вся механика в двух пакетах, поддеревьев нет.
		// Запас глубины не тратится (ветвей не порождаем).
		return &strategy.Action{
			Kind:   core.ActionTCPOverlap,
			Params: g.randomTCPOverlapParams(),
		}
	default:
		// Недостижимо: internalKinds содержит только три вида выше.
		return g.randomLeaf()
	}
}

// randomLeaf возвращает терминальный лист: обычно Send, изредка Drop (если
// исполнитель умеет и выпал жребий).
func (g *Generator) randomLeaf() *strategy.Action {
	if g.caps.Has(core.CapDrop) && g.rng.Float64() < pDrop {
		return &strategy.Action{Kind: core.ActionDrop}
	}
	return &strategy.Action{Kind: core.ActionSend}
}

// randomTamperParams собирает валидные параметры правки: поле из разрешённых,
// режим и значение — по правилам поля.
func (g *Generator) randomTamperParams() *strategy.TamperParams {
	f := g.tamperFields[g.rng.IntN(len(g.tamperFields))]
	if f.IsPayload() {
		// Тело правится только подменой на фейк заданной длины.
		return &strategy.TamperParams{
			Field:  f,
			Mode:   strategy.TamperReplace,
			Length: 1 + g.rng.IntN(g.fakeLenCap()),
		}
	}
	switch g.rng.IntN(3) {
	case 0:
		// Замена константой в пределах ширины поля.
		p := &strategy.TamperParams{Field: f, Mode: strategy.TamperReplace}
		if max, ok := f.MaxValue(); ok {
			p.Value = g.boundedValue(max)
		}
		return p
	case 1:
		// Прибавление небольшой знаковой дельты (трактуется по модулю ширины).
		return &strategy.TamperParams{Field: f, Mode: strategy.TamperAdd, Value: uint64(1 + g.rng.IntN(8))}
	default:
		// Порча: значение не используется.
		return &strategy.TamperParams{Field: f, Mode: strategy.TamperCorrupt}
	}
}

// randomTCPOverlapParams выбирает cover-пресет для tcp_overlap из набора
// пресетов фиксированного размера (CoverPresetNames). Перебираются только
// они, а не все пресеты фейка: механика overlap завязана на единую длину
// cover'а, и пресет переменного размера сломал бы расчёт смещения. Разные
// имена дают разный SNI прикрытия — именно это и есть полезная степень
// свободы для поиска.
func (g *Generator) randomTCPOverlapParams() *strategy.TCPOverlapParams {
	names := strategy.CoverPresetNames()
	return &strategy.TCPOverlapParams{Preset: names[g.rng.IntN(len(names))]}
}

// randomFragmentParams собирает валидные параметры разреза: ровно один способ
// задания места (вид точки или смещение), допустимые уровень и порядок.
func (g *Generator) randomFragmentParams() *strategy.FragmentParams {
	p := &strategy.FragmentParams{Proto: g.randomFragProto(), Order: g.randomFragOrder()}
	// Место разреза — ровно одно из двух (строгое требование validate).
	cuts := core.CutKinds()
	if len(cuts) > 0 && g.rng.Float64() < pCutByKind {
		p.At = cuts[g.rng.IntN(len(cuts))]
	} else {
		// Смещение от 1: ноль означал бы «не задано» и отвергался бы валидацией.
		p.Offset = 1 + g.rng.IntN(g.offsetCap())
	}
	return p
}

// randomFragProto выбирает уровень фрагментации из доступных возможностями.
// Предпочитает TCP (этап 1 всегда его умеет); IP берёт, только если TCP нет.
func (g *Generator) randomFragProto() strategy.FragProto {
	if g.caps.Has(core.CapFragmentTCP) {
		return strategy.FragTCP
	}
	return strategy.FragIP
}

// randomFragOrder выбирает порядок отправки: обратный только если исполнитель
// умеет переупорядочивать (4.7).
func (g *Generator) randomFragOrder() strategy.FragOrder {
	if g.caps.Has(core.CapReorder) && g.rng.Float64() < 0.5 {
		return strategy.FragReverse
	}
	return strategy.FragForward
}

// finalize валидирует стратегию, проверяет её исполнимость при возможностях и
// проставляет идентификатор. Второй результат — годится ли стратегия.
func (g *Generator) finalize(s *strategy.Strategy) (*strategy.Strategy, bool) {
	if err := strategy.Validate(s, g.limits); err != nil {
		return nil, false
	}
	if !g.caps.Contains(strategy.RequiredCapabilities(s)) {
		return nil, false
	}
	id, err := strategy.ComputeID(s)
	if err != nil {
		return nil, false
	}
	s.ID = id
	return s, true
}

// fakeLenCap — верхняя граница длины фейка тела: не больше предела и не
// абсурдно большая (типичный ClientHello — сотни байт).
func (g *Generator) fakeLenCap() int {
	const typical = 512
	if g.limits.MaxFakePayload < typical {
		return g.limits.MaxFakePayload
	}
	return typical
}

// offsetCap — верхняя граница числового смещения разреза: небольшая, чтобы
// разрез попадал в начало сообщения, где и лежат значимые границы.
func (g *Generator) offsetCap() int {
	const typical = 256
	if g.limits.MaxFragmentOffset < typical {
		return g.limits.MaxFragmentOffset
	}
	return typical
}

// boundedValue возвращает случайное значение в [0, max], не раздувая его до
// полной ширины широких полей (для seq/ack полная ширина не нужна поиску).
func (g *Generator) boundedValue(max uint64) uint64 {
	const cap64 = 1 << 16
	if max > cap64 {
		max = cap64
	}
	return g.rng.Uint64N(max + 1)
}
