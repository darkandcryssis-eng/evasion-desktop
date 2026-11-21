// Прогон: измерение целей на чистой обстановке.
//
// Это тот прогон, который отвечает на главный практический вопрос: работает ли
// стратегия у этого провайдера прямо сейчас. Все средства перехвата на время
// измерения выключаются и возвращаются обратно — иначе измеряется сумма двух
// воздействий, и отличить «сработала наша стратегия» от «сработал zapret»
// нельзя.
//
// Важная особенность: прогон НЕ требует, чтобы цели открывались. Провал — это
// тоже измерение, и притворяться, будто заблокированная цель означает дефект
// движка, нельзя. Прогон падает только тогда, когда виноват движок:
// контрольные цели перестали работать (значит стратегия вредит) или исходы не
// дошли до контура (значит автопилот не учится).
//
// Цели берутся из конфига репозитория (examples/config.json), чтобы измерялось
// то же, что движок обходит в работе.
package main

import (
	"strings"
	"time"

	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/tests/harness"
)

// requestTimeout — срок на один запрос.
//
// Заблокированная цель обычно не отвечает вовсе, и ждать её долго незачем:
// провал должен разрешаться за секунды, иначе измерение десятка целей займёт
// минуты (5.3).
const requestTimeout = 12 * time.Second

func main() {
	run := harness.StartRun(
		"targets-measured-without-interference",
		"цели конфига измеряются при выключенных средствах перехвата; контрольные цели обязаны уцелеть")
	defer run.Finish()

	cfg, err := config.Load("examples/config.json")
	if err != nil {
		run.Fail("конфиг примера не прочитан: %v", err)
		return
	}

	// Радиус измерения — цели из групп конфига. К ним добавляются контрольные
	// цели: по ним видно побочный вред (4.5), то есть не ломает ли стратегия
	// то, что обязано работать всегда.
	targets := map[string][]string{}
	for name, domains := range cfg.Groups {
		targets[name] = domains
	}
	controls := cfg.ControlTargets
	if len(controls) == 0 {
		controls = []string{"example.com"}
	}
	targets["control"] = controls

	hcfg := harness.DefaultConfig("", targets)
	hcfg.ControlTargets = controls
	eng, err := harness.StartEngine(hcfg)
	if err != nil {
		run.Fail("движок не запустился: %v", err)
		return
	}
	defer eng.Cleanup()
	defer eng.Stop()
	run.Step("движок запущен, прокси на %s, стратегия — разрез ClientHello по смещению 5", eng.Listen)

	// Измеряются и цели групп, и контрольные: исход у них разный по смыслу, но
	// способ один.
	type probe struct {
		host    string
		control bool
	}
	var list []probe
	for name, domains := range cfg.Groups {
		for _, d := range domains {
			// Запрос идёт к самому домену: поддомены вроде www добавлять
			// незачем, движок всё равно относит их к записи радиуса.
			list = append(list, probe{host: d, control: name == "control"})
		}
	}
	for _, d := range controls {
		list = append(list, probe{host: d, control: true})
	}

	okControls, brokenControls, unreachableProxy := 0, 0, 0
	for _, p := range list {
		code, err := eng.Get("https://"+p.host+"/", requestTimeout)
		kind := "цель"
		if p.control {
			kind = "контрольная цель"
		}
		switch {
		case err != nil && code == 0:
			run.Fact("%s %s: %s", kind, p.host, reason(err))
		default:
			run.Fact("%s %s: код %d", kind, p.host, code)
		}
		// Недоступность самого прокси — это неисправность измерительного
		// прибора, а не измерение. Считается отдельно: без этого различения
		// отказ локального сокета попадал бы в «сломанные контрольные цели»,
		// то есть выглядел бы побочным вредом стратегии.
		if err != nil && isProxyUnreachable(err) {
			unreachableProxy++
			continue
		}
		if p.control {
			if code >= 200 && code < 500 {
				okControls++
			} else {
				brokenControls++
			}
		}
	}

	// Прибор проверяется раньше измерения.
	//
	// Если прокси не отвечает, стратегия не применялась ни разу, и судить по
	// такому прогону нельзя ни о целях, ни о вреде. Прежде прогон этого не
	// различал и объявлял «стратегия вредит тому, что должно работать» —
	// ложная тревога о побочном вреде, то есть о самом признаке, которому
	// обязано доверять автоматическое решение (4.5). Такая тревога хуже
	// молчания: она обесценивает настоящую.
	if !run.Require(unreachableProxy == 0,
		"прокси движка (%s) не ответил на %d запросов из %d: измерение не состоялось, "+
			"о вреде и о целях по этому прогону судить нельзя",
		eng.Listen, unreachableProxy, len(list)) {
		run.Fact("журнал движка:\n%s", eng.Logs())
		return
	}

	// Контрольные цели — единственное жёсткое требование прогона: если при
	// нашей стратегии ломается то, что обязано работать, виноват движок, а не
	// сеть (4.5).
	if !run.Require(brokenControls == 0,
		"контрольных целей сломано %d из %d: стратегия вредит тому, что должно работать",
		brokenControls, okControls+brokenControls) {
		run.Fact("журнал движка:\n%s", eng.Logs())
	}

	// Наблюдения обязаны дойти до контура: иначе измерение состоялось, а
	// движок из него ничего не узнал.
	deadline := time.Now().Add(5 * time.Second)
	st, _ := eng.Status()
	for time.Now().Before(deadline) && st.Intake.Accepted < int64(len(list)) { //nolint:staticcheck // ждём не меньше числа запросов
		time.Sleep(200 * time.Millisecond)
		st, _ = eng.Status()
	}
	// Соединений бывает больше, чем запросов: перенаправление открывает новое
	// соединение, и каждое даёт своё наблюдение. Поэтому «принято» с числом
	// запросов не сравнивается — сравнение вводило бы в заблуждение.
	run.Fact("наблюдений принято %d (запросов %d, перенаправления добавляют соединения), непригодных %d, оценок %d",
		st.Intake.Accepted, len(list), st.Intake.Invalid, st.Intake.Estimates)
	run.Require(st.Intake.Accepted > 0,
		"ни одно наблюдение не дошло до контура: автопилот не учится на живом трафике")
	run.Require(st.Intake.Invalid == 0,
		"непригодных наблюдений %d: исход не удалось отнести к цели радиуса", st.Intake.Invalid)

	// Итог измерения по целям — из оценок контура, а не из кодов ответа:
	// именно оценки движок и будет использовать для решений.
	for _, t := range st.Targets {
		run.Fact("цель %s: действует %s, причина %q, проверка %q",
			t.Target, shortID(t.Active), t.Reason, t.TrialReason)
	}
	if st.Blackout {
		run.Fact("ТРЕВОГА: обвал портфеля — ни одной действующей стратегии")
	}
}

// isProxyUnreachable сообщает, что не ответил сам прокси движка, а не цель.
//
// Различать обязательно: отказ локального сокета означает, что измерение не
// состоялось, а провал цели — что состоялось и дало отрицательный результат.
// Смешав их, прогон объявляет побочный вред там, где стратегия не применялась
// ни разу.
//
// Признак берётся по тексту ошибки, и это осознанная слабость: сетевые ошибки
// Go не несут машинного кода, пригодного для такой проверки на всех
// платформах. Поэтому перечислены формулировки обеих систем — «connection
// refused» на Unix и «actively refused it» на Windows, — и к ним добавлен
// адрес прослушивания как дополнительный признак.
func isProxyUnreachable(err error) bool {
	s := err.Error()
	return hasAny(s,
		"connection refused", // Unix
		"actively refused",   // Windows (connectex)
		"No connection could be made",
		"socket is not connected",
		"connect: ")
}

// hasAny сообщает, встречается ли в строке хоть одна из подстрок.
func hasAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// reason объясняет отсутствие ответа коротко: полный текст ошибки Go содержит
// адреса и внутренние детали, которые в отчёте только мешают.
func reason(err error) string {
	s := err.Error()
	switch {
	case hasAny(s, "context deadline exceeded", "timeout", "i/o timeout"):
		return "истёк срок ожидания — цель молчит"
	case hasAny(s, "x509", "failed to verify certificate"):
		// Важное различие: сертификат проверяется нами, а не DPI. Если дело
		// дошло до проверки сертификата, значит рукопожатие TLS состоялось —
		// то есть DPI соединение не сорвал. Для измерения обхода это успех,
		// и называть его «ответа нет» было бы ложью в самую важную сторону.
		return "рукопожатие прошло, но сертификат не для этого имени — обход сработал"
	case hasAny(s, "connection reset", "reset by peer"):
		return "соединение сброшено"
	case hasAny(s, "прокси отказал в CONNECT"):
		// До стратегии дело не дошло: прокси не смог даже установить
		// соединение. Чаще всего имя не разрешается, то есть цель в конфиге
		// указана как суффикс, а сайта с таким именем нет.
		return "соединение не установлено (имя не разрешается или порт закрыт) — стратегия не проверялась"
	case hasAny(s, "EOF"):
		return "соединение закрыто без ответа"
	default:
		return s
	}
}

// shortID укорачивает идентификатор стратегии для отчёта.
func shortID(id core.StrategyID) string {
	s := id.String()
	const keep = 12
	switch {
	case s == "":
		return "—"
	case len(s) <= keep:
		return s
	default:
		return s[:keep]
	}
}
