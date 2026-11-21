//go:build !windows

package main

// Трей есть только в Windows-сборке (см. tray_windows.go). Заглушки держат
// модуль собираемым и проверяемым на прочих ОС.

func (a *App) startTray()                  {}
func (a *App) trayQuit()                   {}
func (a *App) showWindow()                 {}
func (a *App) setTraySkinIcon(string)      {}
