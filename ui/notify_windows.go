//go:build windows

package main

import (
	"sync"

	toast "git.sr.ht/~jackmordaunt/go-toast/v2"
)

const (
	toastAppID = "Evasion"
	toastGUID  = "{682E81F5-F19E-47D0-BCBB-F38B65B0146D}"
)

var toastSetup sync.Once

// notifyUpdate показывает уведомление Windows о новой версии; клик по нему
// открывает окно. Сбой уведомления не важен: плашка в окне остаётся.
func (a *App) notifyUpdate(latest string) {
	defer func() { _ = recover() }()
	toastSetup.Do(func() {
		exe, _ := currentExecutable()
		_ = toast.SetAppData(toast.AppData{AppID: toastAppID, GUID: toastGUID, ActivationExe: exe})
		toast.SetActivationCallback(func(string, []toast.UserData) { a.showWindow() })
	})
	n := toast.Notification{
		AppID:          toastAppID,
		Title:          "Доступно обновление Evasion " + latest,
		Body:           "Откройте Evasion и нажмите «Обновить».",
		ActivationType: toast.Foreground,
		Audio:          toast.Default,
	}
	if err := n.Push(); err != nil {
		a.engine.consumeLogLine("Уведомление об обновлении не показано: " + err.Error())
	}
}
