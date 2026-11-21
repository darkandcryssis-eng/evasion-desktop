//go:build windows

package harness

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// relaunch запускает процесс по его исходной командной строке.
//
// Почему не через `cmd /c start`. Именно так и было сделано сначала, и это
// сломало возврат zapret у владельца: командная строка уже содержит свои
// кавычки ("C:\Zapret\...\Zapret.exe"), а start трактует первый кавыченный
// аргумент как заголовок окна и калечит путь. В отчёте это выглядело как «не
// удалось найти файл \C:\Zapret\...\.», а на деле перехватчик остался
// выключенным — то есть прогон сломал человеку доступ в сеть, чего делать не
// имел права.
//
// Правильный способ — отдать командную строку ядру без всякого разбора:
// CreateProcess принимает её целиком, и Go даёт это сделать через
// SysProcAttr.CmdLine. Исполняемый файл при этом нужен отдельно, и он
// извлекается из первого токена: если он в кавычках — берётся содержимое
// кавычек, иначе — текст до первого пробела.
//
// Рабочий каталог ставится в каталог самого файла: средства перехвата обычно
// ищут рядом с собой конфиги и списки, и запуск из чужого каталога их ломает.
func relaunch(commandLine string) error {
	commandLine = strings.TrimSpace(commandLine)
	if commandLine == "" {
		return errors.New("пустая командная строка")
	}

	exe, err := executableFrom(commandLine)
	if err != nil {
		return err
	}
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("исполняемый файл %s: %w", exe, err)
	}

	cmd := exec.Command(exe)
	cmd.Dir = filepath.Dir(exe)
	// CmdLine передаётся как есть: разбирать кавычки самим значило бы
	// повторять ошибку, из-за которой возврат и не сработал.
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: commandLine}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск %s: %w", exe, err)
	}
	// Процесс намеренно не ожидается: перехватчик работает долго, а прогону
	// нужно лишь вернуть его на место. Связь с ним обрывается сразу.
	go func() { _ = cmd.Wait() }()
	return nil
}

// executableFrom извлекает путь к исполняемому файлу из командной строки.
func executableFrom(commandLine string) (string, error) {
	if strings.HasPrefix(commandLine, `"`) {
		if end := strings.Index(commandLine[1:], `"`); end >= 0 {
			return commandLine[1 : 1+end], nil
		}
		return "", fmt.Errorf("незакрытая кавычка в командной строке %q", shorten(commandLine))
	}
	if idx := strings.IndexByte(commandLine, ' '); idx > 0 {
		return commandLine[:idx], nil
	}
	return commandLine, nil
}
