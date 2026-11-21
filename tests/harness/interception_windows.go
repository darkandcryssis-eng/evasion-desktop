//go:build windows

package harness

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/fitting-1c/evasion/internal/interception"
)

// stopDelay — сколько ждать после остановки, прежде чем считать перехватчик
// выключенным. Драйверу и процессу нужно время отпустить трафик, и начав
// измерять сразу, прогон поймал бы хвост чужого воздействия.
const stopDelay = 1500 * time.Millisecond

// StopInterception останавливает средства перехвата на время прогона.
//
// Обнаружение берётся у продуктового пакета interception: правила опознания
// одни и те же у движка (команда doctor) и у прогонов, и второго набора в
// репозитории быть не должно. Остановка остаётся здесь — движок чужие процессы
// не выключает и такой возможности не имеет вовсе.
//
// Порядок: службы раньше процессов, потому что служба может перезапустить свой
// процесс, и обратный порядок дал бы бесконечную гонку. Поиск отдаёт их уже в
// этом порядке.
//
// Не сумев остановить, прогон не притворяется: признак Elevated и отчёт
// скажут, что измерение проходило при перехватчике, и верить ему нельзя.
func StopInterception() (*Interception, error) {
	found := interception.Find()
	res := &Interception{
		Elevated: true,
		// Чистым поиск считается только тогда, когда он применим и прошёл
		// полностью. Находки при этом не мешают: обстановку делает чистой их
		// остановка, а не их отсутствие.
		Searched: found.Supported && !found.Partial,
		Notes:    found.Notes,
	}

	for _, t := range found.Tools {
		tool := Tool{Tool: t}
		if err := stop(t); err != nil {
			res.Elevated = false
			tool.RestoreErr = fmt.Sprintf("остановить не удалось: %v", err)
		}
		res.Found = append(res.Found, tool)
	}

	if len(res.Found) > 0 {
		time.Sleep(stopDelay)
	}
	return res, nil
}

// stop останавливает одно средство перехвата.
func stop(t interception.Tool) error {
	switch t.Kind {
	case interception.KindService:
		out, err := run("sc", "stop", t.Name)
		if err != nil {
			return fmt.Errorf("%v (%s)", err, interception.FirstLine(out))
		}
		return nil
	case interception.KindProcess:
		out, err := run("taskkill", "/IM", t.Name, "/T", "/F")
		if err != nil {
			return fmt.Errorf("%v (%s)", err, interception.FirstLine(out))
		}
		return nil
	default:
		return fmt.Errorf("неизвестный вид средства %q", t.Kind)
	}
}

// RestoreInterception возвращает остановленные средства перехвата.
//
// Это обязательная часть прогона, а не вежливость: zapret нужен владельцу для
// повседневной работы. Поэтому возврат вызывается через defer и выполняется
// даже тогда, когда прогон провалился.
//
// Процесс возвращается его же командной строкой, снятой при обнаружении — до
// остановки, потому что мёртвый процесс о себе ничего не расскажет. Если
// узнать её не удалось, прогон честно сообщает, что вернуть не смог, и
// называет имя: внятная строка в отчёте лучше тихо выключенного обхода.
func RestoreInterception(i *Interception) {
	if i == nil {
		return
	}
	for idx := range i.Found {
		t := &i.Found[idx]
		switch t.Kind {
		case interception.KindService:
			if out, err := run("sc", "start", t.Name); err != nil {
				t.RestoreErr = fmt.Sprintf("%v (%s)", err, interception.FirstLine(out))
				continue
			}
			t.Restored = true
		case interception.KindProcess:
			if t.Command == "" {
				t.RestoreErr = "команда запуска неизвестна: запустите средство перехвата сами"
				continue
			}
			if err := relaunch(t.Command); err != nil {
				t.RestoreErr = err.Error()
				continue
			}
			t.Restored = true
		}
	}
}

// run выполняет внешнюю команду и возвращает её вывод, переведённый в UTF-8.
//
// Перевод берётся у interception: системные команды Windows (sc, taskkill)
// пишут по-русски в кодовой странице консоли, и без него сообщение об ошибке
// попадает в отчёт кашей. Владелец такую строку и увидел, когда возврат zapret
// не сработал.
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return interception.DecodeConsole(out), err
}
