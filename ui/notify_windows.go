//go:build windows

package main

import (
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	toast "git.sr.ht/~jackmordaunt/go-toast/v2"
)

const (
	toastAppID = "Evasion"
	toastGUID  = "{682E81F5-F19E-47D0-BCBB-F38B65B0146D}"
)

//go:embed build/appicon.png
var toastIcon []byte

var (
	toastSetup sync.Once
	toastIconPath string // задаётся до первого уведомления той же горутиной
	toastQueue = make(chan string, 4)
)

// notifyUpdate показывает уведомление Windows о новой версии; клик по нему
// открывает окно. Сбой уведомления не важен: плашка в окне остаётся.
func (a *App) notifyUpdate(latest string) {
	// WinRT инициализируется для одного потока, поэтому все уведомления
	// отправляет одна горутина, привязанная к своему потоку.
	toastSetup.Do(func() {
		go func() {
			runtime.LockOSThread()
			// ActivationExe не задаём: закрытое приложение Windows запустить
			// не сможет, ему нужны права администратора.
			data := toast.AppData{AppID: toastAppID, GUID: toastGUID}
			// Значок Windows берёт только из файла.
			icon := filepath.Join(dataDir(), "icon.png")
			if os.MkdirAll(dataDir(), 0o755) == nil && os.WriteFile(icon, toastIcon, 0o644) == nil {
				data.IconPath = icon
				toastIconPath = icon
			}
			_ = toast.SetAppData(data)
			toast.SetActivationCallback(func(string, []toast.UserData) { a.showWindow() })
			for v := range toastQueue {
				a.pushUpdateToast(v)
			}
		}()
	})
	select {
	case toastQueue <- latest:
	default:
	}
}

func (a *App) pushUpdateToast(latest string) {
	defer func() { _ = recover() }()
	n := toast.Notification{
		AppID:          toastAppID,
		Title:          "Доступно обновление Evasion " + latest,
		Body:           "Откройте Evasion и нажмите «Обновить».",
		Icon:           toastIconPath,
		ActivationType: toast.Foreground,
		Audio:          toast.Default,
	}
	if err := n.Push(); err != nil {
		a.engine.consumeLogLine("Уведомление об обновлении не показано: " + err.Error())
	}
}
