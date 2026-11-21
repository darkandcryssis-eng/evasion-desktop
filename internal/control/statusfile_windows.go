//go:build windows

package control

import (
	"errors"
	"syscall"
)

// Коды Windows, означающие «файл занят другим процессом».
//
// Числами, а не именами из golang.org/x/sys: внешних зависимостей по минимуму
// (3.1), а эти два кода стабильны с времён Windows NT.
const (
	errorSharingViolation syscall.Errno = 32
	errorLockViolation    syscall.Errno = 33
)

// transientIO сообщает, что неудача обращения к файлу временная.
//
// На Windows открытый файл блокирует замену, а открытие файла в момент замены
// даёт ошибку совместного доступа. Обе ошибки проходят сами, если подождать
// единицы миллисекунд, и считать их отказом нельзя: состояние выкладывается
// каждые две секунды, а читает его отдельный процесс (команда status).
//
// Сравнение по коду, а не по тексту сообщения: текст переведён на язык
// системы, и опора на него развалилась бы на любой нерусской Windows — тот же
// класс ошибки, из-за которого разбор состояния службы опирается на код 4, а
// не на слово RUNNING.
func transientIO(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == errorSharingViolation || errno == errorLockViolation
}
