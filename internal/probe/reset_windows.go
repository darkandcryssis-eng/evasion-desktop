//go:build windows

package probe

import (
	"errors"
	"syscall"
)

// Коды ошибок сокетов Windows, означающие сброс соединения.
//
// Числа, а не именованные константы стандартной библиотеки, по двум причинам.
// Во-первых, syscall.ECONNRESET на Windows имеет иное значение, чем код,
// который фактически возвращают сокеты: сеть отдаёт WSAECONNRESET, и сравнение
// с переносимой константой не срабатывает. Во-вторых, именованные значения
// WSAE* лежат в golang.org/x/sys/windows, а это внешняя зависимость, которых в
// проекте держится минимум (3.1).
//
// Значения взяты из перечня кодов ошибок Windows Sockets и неизменны с
// момента его появления.
const (
	// wsaeConnReset (10054) — соединение сброшено другой стороной.
	wsaeConnReset = syscall.Errno(10054)
	// wsaeConnAborted (10053) — соединение прервано локальной стороной,
	// обычно по ошибке протокола или таймауту подтверждений.
	wsaeConnAborted = syscall.Errno(10053)
)

// isResetPlatform распознаёт сброс соединения по кодам Windows.
func isResetPlatform(err error) bool {
	return errors.Is(err, wsaeConnReset) || errors.Is(err, wsaeConnAborted)
}
