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

//go:embed assets/tray-natural.ico
var trayIconNatural []byte

// Промежуточные кадры для мягкого переливания розового в зелёный и обратно.
//
//go:embed assets/tray-morph-1.ico
var trayMorph1 []byte

//go:embed assets/tray-morph-2.ico
var trayMorph2 []byte

//go:embed assets/tray-morph-3.ico
var trayMorph3 []byte

// Полные иконки окна (панель задач, Alt+Tab) под оба пейзажа.
//
//go:embed build/windows/icon.ico
var windowIconSakura []byte

//go:embed build/windows/icon-natural.ico
var windowIconNatural []byte

// trayIconActive — набор байт иконки, который сейчас рисует трей-панель.
var trayIconActive atomic.Pointer[[]byte]
var traySkin atomic.Value
var trayAnimation atomic.Uint64

func trayIconBytes() []byte {
	if p := trayIconActive.Load(); p != nil {
		return *p
	}
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

// setTraySkinIcon меняет иконку трея, трей-панели и окна под пейзаж оформления.
// В трее смена проходит через три смешанных кадра, остальные поверхности
// обновляются сразу, чтобы не отставать от интерфейса.
func (a *App) setTraySkinIcon(skin string) {
	if skin != "natural" {
		skin = "sakura"
	}
	natural := skin == "natural"
	previous := traySkin.Load()
	traySkin.Store(skin)
	if natural {
		trayIconActive.Store(&trayIconNatural)
	} else {
		trayIconActive.Store(&trayIcon)
	}
	setWindowSkinIcon(natural)
	if !a.trayAvailable.Load() {
		return
	}

	generation := trayAnimation.Add(1)
	final := trayIconBytes()
	if previous == nil || previous.(string) == skin {
		systray.SetIcon(final)
		return
	}
	go func() {
		frames := [][]byte{trayMorph1, trayMorph2, trayMorph3}
		if previous.(string) == "natural" {
			frames[0], frames[2] = frames[2], frames[0]
		}
		for _, frame := range frames {
			if trayAnimation.Load() != generation || !a.trayAvailable.Load() {
				return
			}
			systray.SetIcon(frame)
			time.Sleep(85 * time.Millisecond)
		}
		if trayAnimation.Load() == generation && a.trayAvailable.Load() {
			systray.SetIcon(final)
		}
	}()
}

var lastWindowIcons [2]uintptr
var windowIconMu sync.Mutex
var windowIconSync atomic.Uint64

// iconFromICO выбирает из .ico-файла кадр поближе к size и создаёт HICON.
func iconFromICO(data []byte, size int32) uintptr {
	if len(data) < 6 {
		return 0
	}
	count := int(data[4]) | int(data[5])<<8
	best, distance := -1, int(^uint(0)>>1)
	for i := 0; i < count; i++ {
		at := 6 + i*16
		if at+16 > len(data) {
			break
		}
		s := int(data[at])
		if s == 0 {
			s = 256
		}
		d := s - int(size)
		if d < 0 {
			d = -d
		}
		if d < distance {
			distance, best = d, at
		}
	}
	if best < 0 {
		return 0
	}
	length := int(uint32(data[best+4]) | uint32(data[best+5])<<8 | uint32(data[best+6])<<16 | uint32(data[best+7])<<24)
	offset := int(uint32(data[best+8]) | uint32(data[best+9])<<8 | uint32(data[best+10])<<16 | uint32(data[best+11])<<24)
	if offset+length > len(data) || length <= 0 {
		return 0
	}
	return trayU("CreateIconFromResourceEx", uintptr(unsafe.Pointer(&data[offset])), uintptr(length), 1, 0x30000, trayInt(size), trayInt(size), 0)
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

func applyWindowSkinIcon(natural bool) {
	windowIconMu.Lock()
	defer windowIconMu.Unlock()
	data := windowIconSakura
	if natural {
		data = windowIconNatural
	}
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
