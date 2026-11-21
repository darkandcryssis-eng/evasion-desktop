package harness

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fitting-1c/evasion/internal/interception"
)

// Run — ход одного прогона: что проверялось, что вышло, чем это объясняется.
//
// Отдельный тип, а не печать в stdout по ходу дела, потому что у прогона два
// читателя: человек, который смотрит отчёт, и общий запуск (run-all), которому
// нужен итог. Печать по ходу устроила бы первого и ничего не дала бы второму.
type Run struct {
	// Name — имя прогона, оно же имя его папки.
	Name string
	// Purpose — что именно проверяется. Пишется для человека, который увидит
	// отчёт через полгода.
	Purpose string

	steps  []string
	facts  []string
	failed []string
	start  time.Time
	icept  *Interception
}

// StartRun начинает прогон: останавливает средства перехвата и запоминает, что
// именно остановил.
//
// Остановка идёт здесь, в самом начале, а не в каждом прогоне по отдельности:
// забыть её значило бы измерить сумму двух воздействий и не узнать об этом.
func StartRun(name, purpose string) *Run {
	r := &Run{Name: name, Purpose: purpose, start: time.Now()}

	icept, err := StopInterception()
	if err != nil {
		r.Fail("остановка средств перехвата: %v", err)
		return r
	}
	r.icept = icept
	r.Step("%s", icept.Report())
	if icept.Stopped() && !icept.Elevated {
		// Это не придирка: при работающем перехватчике измерение
		// недостоверно, и назвать его успешным нельзя (9.3).
		r.Fail("средства перехвата остановить не удалось — нужны права администратора; измерение было бы суммой двух воздействий")
	}
	return r
}

// Step записывает выполненный шаг — что прогон сделал.
func (r *Run) Step(format string, args ...any) {
	r.steps = append(r.steps, fmt.Sprintf(format, args...))
}

// Fact записывает измеренное — что прогон увидел. Отдельно от шагов, потому
// что факты и есть результат, а шаги лишь путь к ним.
func (r *Run) Fact(format string, args ...any) {
	r.facts = append(r.facts, fmt.Sprintf(format, args...))
}

// Fail записывает несоответствие. Прогон не прерывается: остальные проверки
// тоже стоит выполнить, иначе придётся гонять его по одному дефекту за раз.
func (r *Run) Fail(format string, args ...any) {
	r.failed = append(r.failed, fmt.Sprintf(format, args...))
}

// Require проверяет условие и записывает несоответствие, если оно не
// выполнено. Возвращает само условие, чтобы можно было прекратить проверку,
// когда дальше смотреть нечего.
func (r *Run) Require(ok bool, format string, args ...any) bool {
	if !ok {
		r.Fail(format, args...)
	}
	return ok
}

// Finish возвращает средства перехвата на место, печатает отчёт и завершает
// процесс кодом возврата.
//
// Возврат перехватчиков — первым делом и всегда: прогон мог провалиться, но
// оставить человека без обхода он права не имеет.
func (r *Run) Finish() {
	RestoreInterception(r.icept)

	// Невозвращённый перехватчик — провал прогона, и провал громкий. Прогон,
	// оставивший человека без обхода, не выполнил работу, а навредил:
	// измерение он, может, и сделал, но доступ в сеть сломал. У владельца это
	// случилось по-настоящему — zapret остался выключенным, и прогон при этом
	// доложил «пройден». Больше так не будет.
	if r.icept != nil {
		for _, t := range r.icept.Found {
			if !t.Restored {
				r.Fail("СРЕДСТВО ПЕРЕХВАТА НЕ ВОЗВРАЩЕНО: %s — %s. Запустите его сами: %s",
					t.Name, t.RestoreErr, restoreHint(t))
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "=== прогон: %s ===\n", r.Name)
	fmt.Fprintf(&b, "проверяется: %s\n\n", r.Purpose)

	if len(r.steps) > 0 {
		b.WriteString("ход:\n")
		for _, s := range r.steps {
			fmt.Fprintf(&b, "  • %s\n", s)
		}
		b.WriteString("\n")
	}
	if len(r.facts) > 0 {
		b.WriteString("измерено:\n")
		for _, f := range r.facts {
			fmt.Fprintf(&b, "  • %s\n", f)
		}
		b.WriteString("\n")
	}
	if r.icept != nil && r.icept.Stopped() {
		fmt.Fprintf(&b, "перехватчики: %s\n\n", r.icept.Report())
	}

	fmt.Fprintf(&b, "длительность: %v\n", time.Since(r.start).Round(time.Millisecond))

	if len(r.failed) == 0 {
		b.WriteString("ИТОГ: прогон пройден\n")
		fmt.Print(b.String())
		return
	}

	b.WriteString("ИТОГ: прогон НЕ пройден\n")
	for _, f := range r.failed {
		fmt.Fprintf(&b, "  ✗ %s\n", f)
	}
	fmt.Print(b.String())
	os.Exit(1)
}

// restoreHint подсказывает, чем вернуть средство перехвата вручную.
//
// Подсказка нужна именно в тексте провала: человек читает отчёт прогона, а не
// исходники, и к моменту чтения у него уже нет обхода. Команда должна быть
// под рукой, а не в документации.
func restoreHint(t Tool) string {
	switch {
	case t.Command != "":
		return t.Command
	// Сравнение с машинным видом, а не с подписью: подпись меняется вместе с
	// языком отчёта, а ветвление по ней молча перестаёт срабатывать. Прежде
	// здесь стояло t.Kind == "служба", и после перевода вида в машинный токен
	// подсказка для службы тихо подменилась бы общей.
	case t.Kind == interception.KindService:
		return "sc start " + t.Name
	default:
		return "запустите " + t.Name + " обычным способом"
	}
}

// NewRun начинает прогон, НЕ трогая средства перехвата.
//
// Нужен тому единственному прогону, для которого остановка перехватчиков —
// сам предмет проверки, а не подготовка к ней. Всем остальным нужен StartRun:
// забыть остановку значило бы молча измерять сумму двух воздействий.
func NewRun(name, purpose string) *Run {
	return &Run{Name: name, Purpose: purpose, start: time.Now()}
}
