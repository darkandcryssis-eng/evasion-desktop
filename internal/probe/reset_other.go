//go:build !windows

package probe

// isResetPlatform на платформах, кроме Windows, не добавляет ничего к
// переносимой проверке: syscall.ECONNRESET там и есть настоящий код сброса.
//
// Файл существует, чтобы пакет собирался и проверялся вне Windows — без этого
// логика проб тестировалась бы только на целевой платформе, а она же и самая
// неудобная для отладки (8.3).
func isResetPlatform(error) bool { return false }
