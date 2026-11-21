package harness

import (
	"fmt"
	"strings"

	"github.com/fitting-1c/evasion/internal/interception"
)

// Tool — обнаруженное средство перехвата вместе с судьбой его возврата.
//
// Обёртка над interception.Tool, а не свой тип: правила обнаружения
// принадлежат продукту (пакет interception), а признаки возврата —
// исключительно прогону. Движок чужие процессы не останавливает и возвращать
// их не умеет, поэтому Restored и RestoreErr в продуктовом типе были бы полями
// без хозяина.
type Tool struct {
	interception.Tool
	// Restored — удалось ли вернуть после прогона.
	Restored bool
	// RestoreErr — почему не удалось остановить или вернуть.
	RestoreErr string
}

// String описывает средство для отчёта прогона.
//
// Человекочитаемые подписи живут здесь, а не в продукте: движок возвращает
// данные, а не представление (2.2). Прежде вид средства хранился строкой
// «служба»/«процесс» и по ней же шло ветвление — подпись работала машинным
// значением; теперь вид машинный, а перевод на русский делается при выводе.
func (t Tool) String() string {
	s := fmt.Sprintf("%s %s", kindLabel(t.Kind), t.Name)
	if t.Command != "" {
		s += fmt.Sprintf(" (запуск: %s)", shorten(t.Command))
	}
	return s
}

// kindLabel переводит вид средства в подпись для отчёта.
func kindLabel(k interception.Kind) string {
	switch k {
	case interception.KindService:
		return "служба"
	case interception.KindProcess:
		return "процесс"
	default:
		return string(k)
	}
}

// shorten укорачивает длинную командную строку для отчёта.
func shorten(s string) string {
	const max = 120
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// Interception — состояние перехватчиков на время прогона.
//
// Зачем это вообще нужно. Средства обхода вроде zapret применяют свой десинк
// поверх нашего, и прогон при них измеряет сумму двух воздействий, а не
// стратегию движка. Отличить «сработала наша стратегия» от «сработал zapret»
// в такой обстановке нельзя — а именно это измерение и есть смысл прогона.
//
// Поэтому прогон останавливает перехватчики на время работы и возвращает их
// обратно. Возврат обязателен: zapret нужен владельцу для повседневной работы,
// и оставить его выключенным значило бы сломать человеку доступ в сеть ради
// своего измерения.
type Interception struct {
	// Found — что было обнаружено и остановлено.
	Found []Tool
	// Elevated — хватало ли прав на остановку.
	Elevated bool
	// Searched — поиск был применим и прошёл полностью.
	//
	// Нужен затем, чтобы отчёт не выдавал «ничего не нашли» за «обстановка
	// чистая». На не-Windows поиск не применим вовсе, а на Windows он может
	// пройти не до конца (отказ системной команды), и в обоих случаях
	// утверждать чистоту измерения нельзя.
	Searched bool
	// Notes — пометки поиска: что именно опросить не удалось.
	Notes []string
}

// Stopped сообщает, было ли что-то остановлено.
func (i *Interception) Stopped() bool { return i != nil && len(i.Found) > 0 }

// Report описывает, что произошло с перехватчиками, — для отчёта прогона.
func (i *Interception) Report() string {
	if i == nil {
		return "поиск средств перехвата не выполнялся"
	}
	if len(i.Found) == 0 {
		if !i.Searched {
			// Честнее сказать «не проверено», чем «чисто»: пустой ответ
			// неприменимого поиска измерением не является.
			s := "средства перехвата не проверялись — чистоту измерения подтвердить нечем"
			if len(i.Notes) > 0 {
				s += ": " + strings.Join(i.Notes, "; ")
			}
			return s
		}
		return "средств перехвата не обнаружено — измерение чистое"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "остановлено средств перехвата: %d\n", len(i.Found))
	for _, t := range i.Found {
		status := "возвращено"
		if !t.Restored {
			status = "НЕ ВОЗВРАЩЕНО"
			if t.RestoreErr != "" {
				status += ": " + t.RestoreErr
			}
		}
		fmt.Fprintf(&b, "  %s — %s\n", t, status)
	}
	return strings.TrimRight(b.String(), "\n")
}
