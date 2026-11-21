package main

import "time"

// formatNow возвращает текущее время в формате RFC3339. Отдельная функция
// только ради тестов, где удобно подменять время по месту.
func formatNow() string {
	return time.Now().UTC().Format(time.RFC3339)
}
