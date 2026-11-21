package control

import (
	"sort"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/policy"
	"github.com/fitting-1c/evasion/internal/scoring"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// PlanInput — вход для решения по всему радиусу сразу.
type PlanInput struct {
	// Vantage — точка наблюдения.
	Vantage core.VantageID
	// Targets — радиус поражения: цели, по которым принимается решение.
	// Повторы допустимы (одна цель может входить в две группы) и сводятся.
	Targets []string
	// States — память контура по целям. Отсутствие записи означает «ничего не
	// применялось», и это законно для новой цели.
	States map[string]TargetState
	// Pins — закрепления по целям.
	Pins map[string]core.StrategyID
	// Portfolio — стратегии движка: деревья, ступени жизненного цикла,
	// побочный вред. policy нужен сам объект стратегии, а таблица оценок знает
	// только идентификаторы, поэтому разрешение одного в другое делается здесь.
	Portfolio Portfolio
	// Coverage — какие домены покрывает решение по цели: цель (представитель
	// группы) → все домены группы, включая саму цель.
	//
	// Существует потому, что не всякий домен радиуса можно прозондировать.
	// "googlevideo.com" не разрешается по своему имени (там динамические
	// хосты), и независимой оценки у него быть не может. Но стратегия,
	// обошедшая DPI на "youtube.com", обходит его и на "googlevideo.com" —
	// это один и тот же цензор и один приём. Поэтому решение принимается по
	// представителю группы, а применяется ко всей группе.
	//
	// Оценки при этом остаются честными: меряется реально "youtube.com", и
	// наблюдения копятся по нему. Разворот на группу — это применение (policy),
	// а не измерение (scoring); разнесены они намеренно. Пусто для цели
	// означает «покрывает только саму себя» — поведение прежнего, подоменного
	// решения.
	Coverage map[string][]string
	// Now — время решения.
	Now time.Time
}

// Plan — решения по радиусу, готовые записи снимка и предложения по статусам.
//
// Всё вместе не для удобства: записи показывают, что получит трафик, решения —
// почему именно, предложения по статусам — что изменится в портфеле. Без
// второго снимок невозможно объяснить, а объяснять придётся часто, потому что
// при отсутствии положительного сигнала почти все решения будут «оставить как
// есть».
type Plan struct {
	// Decisions — решения в порядке целей (цели отсортированы).
	Decisions []Decision
	// Entries — записи для policy.NewSnapshot, по одной на каждую цель.
	Entries []policy.Entry
	// Transitions — предлагаемые смены ступеней жизненного цикла (4.5).
	// Сводит их в итоговые статусы Merge.
	Transitions []Transition
	// Blackout — полный обвал: в радиусе нет ни одной действующей стратегии
	// (5.8). Это признак для громкой тревоги в журнале и в status, а не
	// внутреннее дело плана, поэтому он здесь, а не в логах.
	Blackout bool
	// TrialPermille — доля, фактически отданная проверке. При обвале она
	// повышенная (5.8), поэтому её надо знать, а не вычислять заново.
	TrialPermille int
}

// Changes возвращает решения, меняющие действующую стратегию.
func (p Plan) Changes() []Decision {
	var out []Decision
	for _, d := range p.Decisions {
		if d.Changes() {
			out = append(out, d)
		}
	}
	return out
}

// Trials возвращает решения, в которых идёт проверка на доле трафика.
func (p Plan) Trials() []Decision {
	var out []Decision
	for _, d := range p.Decisions {
		if d.Trial != "" {
			out = append(out, d)
		}
	}
	return out
}

// BuildPlan принимает решения по всему радиусу и собирает записи снимка.
//
// Порядок целей — отсортированный, а не как пришло: обход карт в Go случаен, а
// план попадает и в журнал, и в сравнение «что изменилось». Невоспроизводимый
// порядок сделал бы оба бесполезными.
//
// Правильность доменных имён здесь не проверяется: это правило принадлежит
// policy (единственное место, где оно живёт), и policy.NewSnapshot отвергнет
// негодную запись при публикации. Дублировать проверку значило бы завести
// второй набор правил нормализации имён — ровно то, чего пакет policy избегает
// согласованием построения и чтения.
//
// Два прохода, а не один. Доля проверки зависит от состояния всего радиуса:
// при полном обвале она повышается (5.8). Узнать про обвал можно только после
// того, как решения по всем целям приняты, поэтому сначала решения, затем
// доля, затем записи.
func (d *Decider) BuildPlan(t *scoring.Table, in PlanInput) Plan {
	targets := dedupSorted(in.Targets)

	plan := Plan{
		Decisions: make([]Decision, 0, len(targets)),
		Entries:   make([]policy.Entry, 0, len(targets)),
	}

	// Проход первый: решения по целям.
	anyActive := false
	for _, target := range targets {
		dec := d.Decide(t, Input{
			Target:    target,
			Vantage:   in.Vantage,
			State:     in.States[target],
			Pinned:    in.Pins[target],
			Portfolio: in.Portfolio,
			Now:       in.Now,
		})
		// Разрешаем идентификатор в стратегию. Пропажа стратегии из портфеля —
		// дефект контура (стратегию вывели, но цель на неё ещё ссылается), и
		// ронять из-за него весь план нельзя: остальные цели не виноваты.
		// Поэтому цель деградирует в прозрачный пропуск, но причина видна в
		// решении, а не теряется.
		if id := dec.Effective(); id != "" && in.Portfolio.Strategy(id) == nil {
			dec.Action = ActionDisable
			dec.StrategyID = ""
			dec.Reason = ReasonUnknownStrategy
		}
		if dec.Effective() != "" {
			anyActive = true
		}
		plan.Decisions = append(plan.Decisions, dec)
	}

	// Обвал портфеля: радиус есть, а применять нечего нигде.
	//
	// Свежий движок, у которого ещё нет ни одной доказанной стратегии, под это
	// определение тоже попадает — и это намеренно. Отличать «всё сломалось» от
	// «ещё ничего не нашлось» здесь незачем: действия в обоих случаях
	// одинаковы (прозрачный пропуск, тревога, повышенная доля эксперимента), а
	// состояние «движок сейчас не применяет ничего» в status обязано быть
	// видно в обоих.
	plan.Blackout = len(targets) > 0 && !anyActive
	plan.TrialPermille = d.cfg.TrialPermille
	if plan.Blackout {
		plan.TrialPermille = d.cfg.BlackoutTrialPermille
	}

	// Проход второй: доля проверки и записи снимка.
	for i := range plan.Decisions {
		dec := &plan.Decisions[i]

		// Bootstrap обвала (5.8): когда не работает ничего и обычный порог
		// кандидата на долю не пустил, допускаем лучшего кандидата с успехами
		// сразу. Делается здесь, во втором проходе, а не в Decide, потому что
		// обвал — свойство всего радиуса и известно только после решений по
		// всем целям. За пределами обвала этот код не срабатывает, поэтому на
		// штатную лестницу допуска (5.1) он не влияет.
		if plan.Blackout && dec.Trial == "" && dec.Effective() == "" {
			if id, ok := d.blackoutBootstrap(t, in, dec.Target); ok {
				dec.Trial = id
				dec.TrialReason = ReasonBlackoutBootstrap
			}
		}

		var trial *strategy.Strategy
		if dec.Trial != "" {
			if trial = in.Portfolio.Strategy(dec.Trial); trial == nil {
				// Кандидат пропал из портфеля между выбором и сборкой —
				// проверять нечего.
				dec.Trial = ""
				dec.TrialReason = ReasonUnknownStrategy
			}
		}
		if trial != nil && plan.TrialPermille <= 0 {
			// Доля выключена настройкой: кандидат есть, но отдавать ему
			// соединения запрещено. Запись с нулевой долей policy отвергнет,
			// и правильно — она ничего не проверяет.
			trial = nil
			dec.Trial = ""
			dec.TrialReason = ReasonTrialDisabled
		}
		if trial != nil {
			dec.TrialPermille = plan.TrialPermille
		}

		// Запись появляется всегда, в том числе пустая: цель без стратегии
		// обязана получить исключение, иначе на неё подействовала бы запись
		// более общего домена того же радиуса (см. doc.go).
		//
		// Решение представителя разворачивается на все домены его группы
		// (Coverage): одна и та же стратегия и доля ложатся на каждый домен.
		// Так вся группа (youtube.com + googlevideo.com + ytimg.com) обходится
		// единым приёмом, доказанным на представителе.
		mainStrat := in.Portfolio.Strategy(dec.Effective())
		for _, domain := range coveredDomains(dec.Target, in.Coverage) {
			plan.Entries = append(plan.Entries, policy.Entry{
				Domain:        domain,
				Strategy:      mainStrat,
				Trial:         trial,
				TrialPermille: dec.TrialPermille,
			})
		}

		plan.Transitions = append(plan.Transitions, transitionsFor(*dec, in.Portfolio)...)
	}

	return plan
}

// transitionsFor выводит предлагаемые смены ступеней из одного решения.
//
// Предложения выводятся из решения, а не принимаются вместе с ним, потому что
// статус у стратегии один, а решений по ней столько, сколько целей (4.5).
// Сведение — забота Merge и владельца портфеля.
func transitionsFor(dec Decision, p Portfolio) []Transition {
	var out []Transition

	// Кандидат, допущенный к доле трафика, переходит в testing.
	if dec.Trial != "" {
		if from := p.Status(dec.Trial); from == core.StatusCandidate {
			out = append(out, Transition{
				StrategyID: dec.Trial, Target: dec.Target,
				From: from, To: core.StatusTesting, Reason: dec.TrialReason,
			})
		}
	}

	// Применённая стратегия переходит в active.
	if dec.Action == ActionApply && dec.StrategyID != "" {
		if from := p.Status(dec.StrategyID); from != core.StatusActive {
			out = append(out, Transition{
				StrategyID: dec.StrategyID, Target: dec.Target,
				From: from, To: core.StatusActive, Reason: dec.Reason,
			})
		}
	}

	// Прежняя стратегия, если её сменили или сняли, уходит с ступени active.
	// Куда именно — зависит от причины, и это разные вещи: сорвавшаяся
	// стратегия деградировала (её нельзя предлагать как резерв), а
	// вытесненная лучшей просто отставлена и продолжает затухать (5.1).
	if dec.Previous != "" && dec.Previous != dec.Effective() {
		to := core.StatusBenched
		switch dec.Reason {
		case ReasonBrokenReplaced, ReasonBrokenDisabled:
			to = core.StatusDegraded
		case ReasonCollateralReplaced, ReasonCollateralDisabled:
			// Вредившая стратегия уходит не на полку, а в degraded: полка —
			// это резерв, из которого берут замену, и предлагать оттуда
			// стратегию, ломающую чужой трафик, нельзя.
			to = core.StatusDegraded
		}
		if from := p.Status(dec.Previous); from != to && from != core.StatusUnset {
			out = append(out, Transition{
				StrategyID: dec.Previous, Target: dec.Target,
				From: from, To: to, Reason: dec.Reason,
			})
		}
	}

	return out
}

// blackoutBootstrap выбирает кандидата на долю проверки при полном обвале:
// лучшего по оценке, кому доля разрешена ступенью (5.1), кто не сорван, не
// вредит контрольным целям и имеет хотя бы один успех.
//
// Условие успеха отсекает заведомо негодных кандидатов (ноль успехов):
// ставить наугад нельзя даже в обвале — это жгло бы соединения без пользы
// (5.8). Порог объёма (5.5) здесь не применяется сознательно: именно его снятие
// и есть смысл bootstrap — дать лучшему известному кандидату долю, пока он
// добирает доказательства в песочнице до полного трафика.
// bootstrapMinConclusive — сколько определённых проверок обязан иметь кандидат,
// прежде чем попасть на долю обвала. Защита от «везучего» единичного успеха: на
// одной-двух пробах нижняя граница ничего не значит, и выбор по ней дёргался бы
// от шума. Три — минимальный объём, при котором граница уже о чём-то говорит,
// и при этом он набирается за считанные круги песочницы.
const bootstrapMinConclusive = 3

func (d *Decider) blackoutBootstrap(t *scoring.Table, in PlanInput, target string) (core.StrategyID, bool) {
	if t == nil {
		return "", false
	}
	// Выбираем по нижней границе доли успехов (Wilson), а не по сырой оценке:
	// граница устойчива на малых числах и сходится к реально лучшему приёму,
	// поэтому выбор на доле не дёргается от круга к кругу. Сырой счёт на первых
	// пробах шумит, и по нему кандидат на доле менялся каждый пересчёт —
	// соединения пользователя получали то работающий приём, то слабый.
	var bestID core.StrategyID
	bestLower := -1.0
	for _, r := range t.Rank(target, in.Vantage, in.Now) {
		id := r.Key.StrategyID
		// Только свежие ступени: candidate и testing. Деградировавшая стратегия
		// (ранее срывалась или вредила) сюда НЕ входит, хотя доля ей в принципе
		// разрешена (trialAllowed). Её историю обвал не отменяет: она требует
		// повышенного объёма наблюдений (5.5) именно потому, что прежний успех
		// мог быть везением, а прежний вред — повториться. Обвал оправдывает
		// эксперимент с неизвестным, а не повторную ставку на уже подводившее.
		// Вернуться degraded может, но через штатный (поднятый) порог, а не
		// через этот обход.
		if st := in.Portfolio.Status(id); st != core.StatusCandidate && st != core.StatusTesting {
			continue
		}
		if in.Portfolio.blockedByCollateral(id) {
			continue
		}
		k := scoring.Key{StrategyID: id, Target: target, VantageID: in.Vantage}
		if t.Broken(k) {
			continue
		}
		est, ok := t.Estimate(k, in.Now)
		if !ok || est.Successes == 0 || est.Conclusive < bootstrapMinConclusive {
			continue
		}
		if lower := t.SuccessLowerBound(k); lower > bestLower {
			bestLower = lower
			bestID = id
		}
	}
	return bestID, bestID != ""
}

// coveredDomains возвращает домены, которые покрывает решение по цели: список
// из Coverage, если он задан, иначе сама цель. Представитель всегда входит в
// своё покрытие; если вызывающий забыл его включить, добавляем — цель обязана
// получить запись (иначе на неё подействовал бы более общий домен радиуса).
func coveredDomains(target string, coverage map[string][]string) []string {
	list := coverage[target]
	if len(list) == 0 {
		return []string{target}
	}
	for _, d := range list {
		if d == target {
			return list
		}
	}
	return append([]string{target}, list...)
}

// dedupSorted возвращает отсортированные цели без повторов, не изменяя вход.
func dedupSorted(targets []string) []string {
	if len(targets) == 0 {
		return nil
	}
	out := make([]string, len(targets))
	copy(out, targets)
	sort.Strings(out)

	n := 0
	for i, v := range out {
		if i > 0 && v == out[i-1] {
			continue
		}
		out[n] = v
		n++
	}
	return out[:n]
}
