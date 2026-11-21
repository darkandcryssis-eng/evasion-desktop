package windivert

import (
	"errors"
	"fmt"
	"syscall"
)

type OpenError struct {
	Code  uint32
	Cause error
}

func (e *OpenError) Unwrap() error { return e.Cause }
func (e *OpenError) Error() string {
	message := "Windows не смогла открыть сетевой драйвер. Откройте раздел «Диагностика»."
	switch e.Code {
	case 1058:
		message = "Windows не разрешает запуск службы драйвера. Перезагрузите Windows и запустите Evasion от имени администратора без других программ обхода. Если ошибка повторится, откройте «Диагностика»."
	case 1072:
		message = "Служба драйвера ожидает удаления. Завершите программы обхода и перезагрузите Windows."
	case 5:
		message = "Недостаточно прав для сетевого драйвера. Запустите Evasion от имени администратора."
	case 2, 3, 126:
		message = "Не найдены файлы драйвера или его библиотеки. Повторно распакуйте официальную сборку Evasion и проверьте журнал защиты Windows."
	case 577:
		message = "Windows не приняла цифровую подпись драйвера. Проверьте журнал защиты Windows и используйте официальную сборку Evasion."
	case 1275:
		message = "Windows заблокировала загрузку драйвера. Причину можно проверить в журнале защиты Windows."
	case 1753, 1068:
		message = "Недоступна служба Windows, необходимая сетевому драйверу. Откройте «Диагностика» и проверьте базовую фильтрацию BFE."
	case 87:
		message = "Windows отклонила параметры сетевого фильтра. Используйте совместимые файлы WinDivert.dll и WinDivert64.sys из одной сборки Evasion."
	}
	return fmt.Sprintf("WinDivert — код %d. %s", e.Code, message)
}
func newOpenError(err error) error {
	var code syscall.Errno
	errors.As(err, &code)
	return &OpenError{Code: uint32(code), Cause: err}
}
