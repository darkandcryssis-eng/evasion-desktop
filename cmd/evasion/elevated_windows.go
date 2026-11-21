//go:build windows

package main

import "golang.org/x/sys/windows"

// elevated сообщает, запущен ли процесс с повышенными правами.
//
// Берётся признак elevation из токена процесса. Второе значение — удалось ли
// проверку выполнить вообще: отказ открыть токен не то же самое, что «прав
// нет», и смешивать их нельзя — это тот же запрет, что и везде в проекте, где
// неудача измерения не подменяется отрицательным ответом.
func elevated() (ok bool, checked bool) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false, false
	}
	defer token.Close()
	return token.IsElevated(), true
}
