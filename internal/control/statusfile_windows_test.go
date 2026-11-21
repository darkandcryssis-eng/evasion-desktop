//go:build windows

package control

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// TestTransientIORecognizesBusyFile — «файл занят» отличается от прочих
// неудач.
//
// Единственный windows-only тест в проекте, и он здесь не для полноты.
// Распознавание опирается на числовые коды Windows, а не на текст сообщения
// (текст переведён на язык системы), и ошибка в коде была бы молчаливой: при
// слишком узком условии команда status время от времени отвечала бы «процесс
// не может получить доступ к файлу» вместо состояния, при слишком широком —
// движок пять раз подряд пережидал бы настоящую нехватку прав, пряча причину.
//
// Код 5 («отказано в доступе») намеренно НЕ считается временным, и это
// измеренное решение, а не осторожность. Прогон у владельца показал, что
// замена файла отказывает именно с кодом 5, пока файл открыт читателем, — но
// тот же код даёт и настоящая нехватка прав на каталог, и различить их по
// ошибке невозможно. Поэтому ответ движка на код 5 — не повторять в этом
// тике, а попробовать на следующем (publishStatus не снимает отметку
// statusStale), и свежесть страдает на пару секунд вместо того, чтобы прятать
// настоящую неполадку за повторами.
func TestTransientIORecognizesBusyFile(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		transient bool
	}{
		{
			name:      "файл занят другим процессом (32)",
			err:       &os.PathError{Op: "open", Path: "status.json", Err: syscall.Errno(32)},
			transient: true,
		},
		{
			name:      "область файла заблокирована (33)",
			err:       &os.PathError{Op: "open", Path: "status.json", Err: syscall.Errno(33)},
			transient: true,
		},
		{
			name: "отказано в доступе (5) — неотличимо от нехватки прав",
			err:  &os.PathError{Op: "rename", Path: "status.json", Err: syscall.Errno(5)},
		},
		{
			name: "файла нет (2) — полноценный ответ, ждать нечего",
			err:  &os.PathError{Op: "open", Path: "status.json", Err: syscall.Errno(2)},
		},
		{
			name: "обычная ошибка без кода",
			err:  errors.New("что-то не вышло"),
		},
		{
			name: "отсутствие ошибки",
			err:  nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := transientIO(c.err); got != c.transient {
				t.Fatalf("transientIO(%v) = %v, ожидалось %v", c.err, got, c.transient)
			}
		})
	}
}
