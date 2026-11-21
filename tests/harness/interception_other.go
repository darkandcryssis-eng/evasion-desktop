//go:build !windows

package harness

import "github.com/fitting-1c/evasion/internal/interception"

// StopInterception на не-Windows ничего не останавливает.
//
// Средства, из-за которых прогон измерял бы сумму двух воздействий (zapret,
// GoodbyeDPI, byedpi), — windows-only, как и сам движок на этапе 0. Пустая
// реализация нужна, чтобы прогоны собирались и выполнялись и в песочнице
// разработки: там они проверяют логику движка.
//
// Признак Searched берётся у поиска, а не ставится истиной: вне Windows поиск
// неприменим, и объявлять обстановку чистой на этом основании нельзя. Отчёт
// скажет «не проверялись», и это будет правдой — в отличие от «не
// обнаружено», которое звучало бы как результат измерения.
func StopInterception() (*Interception, error) {
	found := interception.Find()
	return &Interception{
		Elevated: true,
		Searched: found.Supported && !found.Partial,
		Notes:    found.Notes,
	}, nil
}

// RestoreInterception на не-Windows возвращать нечего.
func RestoreInterception(*Interception) {}
