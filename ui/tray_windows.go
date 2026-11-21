//go:build windows

package main

import (
	_ "embed"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/energye/systray"
	wr "github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"
)

// trayIcon — иконка в системном трее. Заменяется вместе с иконкой приложения.
//
//go:embed assets/tray.ico
var trayIcon []byte

// One cat identity for the executable, taskbar, Alt+Tab and tray.
//
//go:embed build/windows/icon.ico
var windowIcon []byte

func trayIconBytes() []byte {
	return trayIcon
}

// startTray поднимает значок в системном трее. Нужен, потому что окно умеет
// сворачиваться в трей (диалог закрытия), а Wails v2 своего трея не имеет.
// systray.Run блокирует собственным циклом сообщений, поэтому — в горутине.
func (a *App) startTray() {
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		// Трей — вторичная функция: его сбой не должен ронять окно.
		defer func() { _ = recover() }()
		systray.Run(a.trayReady, func() {})
	}()
}

func (a *App) trayReady() {
	startTrayPopup(a.trayView, a.trayAction, a.tray.attach, a.tray.detach)
	systray.SetIcon(trayIconBytes())
	systray.SetTitle("")
	systray.SetTooltip("Evasion — обход DPI")
	a.trayAvailable.Store(true)

	mOpen := systray.AddMenuItem("Открыть Evasion", "Показать окно")
	mQuit := systray.AddMenuItem("Выход", "Остановить движок и закрыть")

	systray.SetOnClick(func(systray.IMenu) { a.showWindow() })
	systray.SetOnRClick(func(menu systray.IMenu) {
		if !a.tray.show() {
			_ = menu.ShowMenu()
		}
	})
	mOpen.Click(func() { a.showWindow() })
	mQuit.Click(a.ExitApplication)
}

// Keep the API compatible with older preferences; landscape skins are retired.
func (a *App) setTraySkinIcon(_ string) {
	setWindowSkinIcon(false)
	if !a.trayAvailable.Load() {
		return
	}

	systray.SetIcon(trayIcon)
}

var lastWindowIcons [2]uintptr
var windowIconMu sync.Mutex
var windowIconSync atomic.Uint64

// iconFromICO выбирает из .ico-файла кадр поближе к size и создаёт HICON.
func iconFromICO(data []byte, size int32) uintptr {
	image := iconImage(data, int(size))
	if len(image) == 0 {
		return 0
	}
	return trayU("CreateIconFromResourceEx", uintptr(unsafe.Pointer(&image[0])), uintptr(len(image)), 1, 0x30000, trayInt(size), trayInt(size), 0)
}

// mainWindow находит верхнеуровневое окно приложения (не трей-панель).
// Точный заголовок исключает скрытую трей-панель и служебные окна WebView.
func mainWindow() uintptr {
	pid := windows.GetCurrentProcessId()
	hwnd := trayU("FindWindowW", 0, uintptr(unsafe.Pointer(trayString("Evasion"))))
	if hwnd != 0 {
		var owner uint32
		trayU("GetWindowThreadProcessId", hwnd, uintptr(unsafe.Pointer(&owner)))
		if owner == pid {
			return hwnd
		}
	}
	var found uintptr
	cb := windows.NewCallback(func(candidate uintptr, _ uintptr) uintptr {
		var owner uint32
		trayU("GetWindowThreadProcessId", candidate, uintptr(unsafe.Pointer(&owner)))
		if owner != pid || trayU("IsWindowVisible", candidate) == 0 {
			return 1
		}
		var buf [128]uint16
		trayU("GetClassNameW", candidate, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		class := windows.UTF16ToString(buf[:])
		if strings.HasPrefix(class, "Evasion.TrayPanel.") {
			return 1
		}
		if class == "wailsWindow" {
			found = candidate
			return 0
		}
		return 1
	})
	trayU("EnumWindows", cb, 0)
	return found
}

// setWindowSkinIcon подменяет значок окна на панели задач и в Alt+Tab.
// Повторные отложенные применения перекрывают собственную установку иконки Wails
// при раскрытии стартового окна; generation отбрасывает устаревшие вызовы.
func setWindowSkinIcon(natural bool) {
	generation := windowIconSync.Add(1)
	apply := func() {
		if windowIconSync.Load() == generation {
			applyWindowSkinIcon(natural)
		}
	}
	apply()
	time.AfterFunc(150*time.Millisecond, apply)
	time.AfterFunc(650*time.Millisecond, apply)
}

func applyWindowSkinIcon(_ bool) {
	windowIconMu.Lock()
	defer windowIconMu.Unlock()
	data := windowIcon
	hwnd := mainWindow()
	if hwnd == 0 {
		return
	}
	icons := [2]uintptr{iconFromICO(data, 16), iconFromICO(data, 32)}
	if icons[0] == 0 || icons[1] == 0 {
		for _, h := range icons {
			if h != 0 {
				trayU("DestroyIcon", h)
			}
		}
		return
	}
	const (
		wmSetIcon   = 0x0080
		gclpHIcon   = -14
		gclpHIconSM = -34
	)
	// Wails использует значок класса при части оконных операций. Обновляем оба
	// Win32-пути: иначе панель задач может сохранять прежний значок.
	trayU("SetClassLongPtrW", hwnd, trayInt(gclpHIcon), icons[1])
	trayU("SetClassLongPtrW", hwnd, trayInt(gclpHIconSM), icons[0])
	trayU("SendMessageW", hwnd, wmSetIcon, 0, icons[0])
	trayU("SendMessageW", hwnd, wmSetIcon, 1, icons[1])
	for i, h := range lastWindowIcons {
		if h != 0 {
			trayU("DestroyIcon", h)
		}
		lastWindowIcons[i] = icons[i]
	}
}

// showWindow возвращает окно из трея/свёрнутого состояния на передний план.
func (a *App) showWindow() {
	if a.tray != nil {
		a.tray.dismiss()
	}
	if a.ctx == nil {
		return
	}
	wr.WindowShow(a.ctx)
	wr.WindowUnminimise(a.ctx)
	wr.EventsEmit(a.ctx, "evasion:window", "shown")
}

func (a *App) trayQuit() {
	a.trayAvailable.Store(false)
	trayAnimation.Add(1)
	if a.tray != nil {
		a.tray.close()
	}
	systray.Quit()
}
