//go:build windows

package interception

import (
	"fmt"
	"os/exec"
)

// Find ищет запущенные средства перехвата.
//
// Порядок: сначала службы, потом процессы. Так же порядок важен и
// останавливающему потребителю (служба может перезапускать свой процесс), и
// держать здесь тот же порядок дешевле, чем объяснять, почему он другой.
//
// Команда запуска спрашивается **только у найденных** процессов. Прежде в
// прогонах она спрашивалась у всех известных имён сразу, то есть пять вызовов
// PowerShell происходили всегда — в том числе на чистой машине, где находок
// нет вовсе. Для doctor это секунды ожидания без всякой пользы.
//
// Отказ системной команды не считается отсутствием средства: он помечает
// результат неполным (Partial). Иначе нехватка прав выглядела бы чистой
// обстановкой — то есть ровно наоборот.
func Find() Result {
	res := Result{Supported: true}

	for _, name := range interceptServices {
		running, err := serviceRunning(name)
		if err != nil {
			res.Partial = true
			res.Notes = append(res.Notes, fmt.Sprintf("служба %s: опросить не удалось: %v", name, err))
			continue
		}
		if running {
			res.Tools = append(res.Tools, Tool{Kind: KindService, Name: name})
		}
	}

	for _, name := range interceptProcesses {
		running, err := processRunning(name)
		if err != nil {
			res.Partial = true
			res.Notes = append(res.Notes, fmt.Sprintf("процесс %s: опросить не удалось: %v", name, err))
			continue
		}
		if !running {
			continue
		}
		res.Tools = append(res.Tools, Tool{
			Kind:    KindProcess,
			Name:    name,
			Command: processCommand(name),
		})
	}
	return res
}

// serviceRunning сообщает, запущена ли служба.
//
// Ошибка возвращается отдельно от ответа «не запущена»: у sc один и тот же
// ненулевой код и для отсутствующей службы, и для отказа в правах, и
// смешивать их нельзя — первое означает «её нет», второе «мы не знаем».
// Различаются они по тексту: отсутствующая служба опознаётся кодом 1060.
func serviceRunning(name string) (bool, error) {
	out, err := run("sc", "query", name)
	running, notInstalled := parseServiceQuery(out)
	if err != nil && !notInstalled {
		// Ненулевой код без признака «службы нет» означает, что опрос не
		// состоялся: чаще всего это отказ в правах. Принять такое за «не
		// запущена» значило бы объявить обстановку чистой, не проверив её.
		return false, fmt.Errorf("%v (%s)", err, firstLine(out))
	}
	return running, nil
}

// processRunning сообщает, запущен ли процесс с таким именем.
//
// tasklist при отсутствии совпадений завершается успешно и печатает сообщение
// «нет запущенных задач», поэтому ответ определяется наличием имени в выводе,
// а не кодом возврата.
func processRunning(name string) (bool, error) {
	out, err := run("tasklist", "/FI", "IMAGENAME eq "+name, "/NH")
	if err != nil {
		return false, fmt.Errorf("%v (%s)", err, firstLine(out))
	}
	return containsFold(out, name), nil
}

// processCommand узнаёт командную строку запущенного процесса.
//
// Через PowerShell и CIM, а не через wmic: wmic объявлен устаревшим и в новых
// сборках Windows отсутствует.
//
// Неудача возвращает пустую строку, а не ошибку: команда запуска нужна только
// тому, кто собирается средство вернуть, и её отсутствие он обязан обработать
// сам (пустое Command означает «вернуть автоматически нельзя»). Делать из
// этого неполноту всего поиска было бы неверно — средство-то обнаружено.
func processCommand(name string) string {
	script := fmt.Sprintf(
		"(Get-CimInstance Win32_Process -Filter \"Name='%s'\" | Select-Object -First 1 -ExpandProperty CommandLine)",
		name)
	out, err := run("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return ""
	}
	return firstLine(out)
}

// run выполняет внешнюю команду и возвращает её вывод, переведённый в UTF-8.
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return oemToUTF8(out), err
}
