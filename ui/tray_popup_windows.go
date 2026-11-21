//go:build windows

package main

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	trayToggleMessage = 0x8001 + iota
	trayRefreshMessage
	trayHideMessage
	trayDestroyMessage
)

var (
	trayUser           = windows.NewLazySystemDLL("user32.dll")
	trayGDI            = windows.NewLazySystemDLL("gdi32.dll")
	trayKernel         = windows.NewLazySystemDLL("kernel32.dll")
	trayShcore         = windows.NewLazySystemDLL("shcore.dll")
	trayWindows        sync.Map
	trayWindowCallback = syscall.NewCallback(trayWindowProc)
)

type trayPoint struct{ X, Y int32 }
type trayMessage struct {
	Window         uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Point          trayPoint
	Private        uint32
}
type trayWindowClass struct {
	Size, Style                        uint32
	Proc                               uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Name                         *uint16
	SmallIcon                          uintptr
}
type trayPaint struct {
	DC              uintptr
	Erase           int32
	Rect            trayRect
	Restore, Update int32
	Reserved        [32]byte
}
type trayDrawItem struct {
	Type, ID, Item, Action, State uint32
	Window, DC                    uintptr
	Rect                          trayRect
	Data                          uintptr
}
type trayMonitorInfo struct {
	Size          uint32
	Monitor, Work trayRect
	Flags         uint32
}

type trayPopup struct {
	hwnd          uintptr
	buttons       map[int]uintptr
	view          func() trayView
	action        func(string)
	state         trayView
	dpi           int32
	width, height int32
	fonts         [3]uintptr
	visible       bool
	preview       bool
}

func trayCall(dll *windows.LazyDLL, name string, args ...uintptr) uintptr {
	r, _, _ := dll.NewProc(name).Call(args...)
	return r
}
func trayU(name string, args ...uintptr) uintptr { return trayCall(trayUser, name, args...) }
func trayG(name string, args ...uintptr) uintptr { return trayCall(trayGDI, name, args...) }
func trayString(value string) *uint16            { p, _ := windows.UTF16PtrFromString(value); return p }
func trayInt(value int32) uintptr                { return uintptr(int64(value)) }
func trayColor(hex uint32) uint32                { return (hex>>16)&255 | hex&0xff00 | (hex&255)<<16 }

func (p *trayPopup) px(value int32) int32 { return (value*p.dpi + 48) / 96 }

// Each popup owns a separate UI thread; the Wails window keeps its size and state.
func startTrayPopup(view func() trayView, action func(string), ready func(toggle, refresh, hide, quit func()), done func(), preview ...bool) {
	go func() {
		defer func() { _ = recover() }()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if done != nil {
			defer done()
		}
		p := &trayPopup{view: view, action: action, dpi: 96, width: trayPanelWidth, height: trayPanelHeight, buttons: map[int]uintptr{}}
		p.preview = len(preview) > 0 && preview[0]
		className := trayString(fmt.Sprintf("Evasion.TrayPanel.%d", windows.GetCurrentProcessId()))
		instance := trayCall(trayKernel, "GetModuleHandleW", 0)
		wc := trayWindowClass{Style: 0x20000, Proc: trayWindowCallback, Instance: instance, Name: className, Cursor: trayU("LoadCursorW", 0, 32512)}
		wc.Size = uint32(unsafe.Sizeof(wc))
		if trayU("RegisterClassExW", uintptr(unsafe.Pointer(&wc))) == 0 {
			return
		}
		defer trayU("UnregisterClassW", uintptr(unsafe.Pointer(className)), instance)
		// Tool window: no taskbar button, no Alt-Tab entry, no native title bar.
		exStyle := uintptr(0x00010088)
		if p.preview {
			exStyle = 0x00050008
		}
		p.hwnd = trayU("CreateWindowExW", exStyle, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(trayString("Evasion — быстрый доступ"))), 0x82000000, 0, 0, trayPanelWidth, trayPanelHeight, 0, 0, instance, 0)
		if p.hwnd == 0 {
			return
		}
		trayWindows.Store(p.hwnd, p)
		defer trayWindows.Delete(p.hwnd)
		defer p.releaseResources()
		for _, id := range []int{trayDPIButton, trayTelegramButton, trayDiagnoseButton, trayOpenButton, trayExitButton} {
			h := trayU("CreateWindowExW", 0, uintptr(unsafe.Pointer(trayString("BUTTON"))), 0, 0x5001000b, 0, 0, 10, 10, p.hwnd, uintptr(id), instance, 0)
			if h == 0 {
				trayU("DestroyWindow", p.hwnd)
				return
			}
			p.buttons[id] = h
		}
		p.makeFonts()
		p.update()
		post := func(message uintptr) func() { return func() { trayU("PostMessageW", p.hwnd, message, 0, 0) } }
		ready(post(trayToggleMessage), post(trayRefreshMessage), post(trayHideMessage), post(trayDestroyMessage))
		var msg trayMessage
		for {
			result := int32(trayU("GetMessageW", uintptr(unsafe.Pointer(&msg)), 0, 0, 0))
			if result <= 0 {
				break
			}
			if msg.Message == 0x100 && msg.WParam == 27 {
				p.hide()
				continue
			}
			if trayU("IsDialogMessageW", p.hwnd, uintptr(unsafe.Pointer(&msg))) != 0 {
				continue
			}
			trayU("TranslateMessage", uintptr(unsafe.Pointer(&msg)))
			trayU("DispatchMessageW", uintptr(unsafe.Pointer(&msg)))
		}
	}()
}

func trayWindowProc(hwnd uintptr, message uint32, wparam, lparam uintptr) (result uintptr) {
	defer func() {
		if recover() != nil {
			result = 0
		}
	}()
	v, ok := trayWindows.Load(hwnd)
	if !ok {
		return trayU("DefWindowProcW", hwnd, uintptr(message), wparam, lparam)
	}
	p := v.(*trayPopup)
	switch message {
	case trayToggleMessage:
		if p.visible {
			p.hide()
		} else {
			p.show()
		}
		return 0
	case trayRefreshMessage:
		if p.visible {
			p.update()
		}
		return 0
	case trayHideMessage, 0x10:
		p.hide()
		return 0
	case trayDestroyMessage:
		trayU("DestroyWindow", hwnd)
		return 0
	case 2:
		trayU("PostQuitMessage", 0)
		return 0
	case 6:
		if wparam&0xffff == 0 && !p.preview {
			p.hide()
		}
		return 0
	case 0x14:
		return 1
	case 0x113:
		p.update()
		return 0
	case 0xf:
		var ps trayPaint
		dc := trayU("BeginPaint", hwnd, uintptr(unsafe.Pointer(&ps)))
		p.paint(dc)
		trayU("EndPaint", hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0
	case 0x2b:
		var item trayDrawItem
		var read uintptr
		// Copy the native message payload without retaining a foreign pointer.
		if windows.ReadProcessMemory(windows.CurrentProcess(), lparam, (*byte)(unsafe.Pointer(&item)), unsafe.Sizeof(item), &read) == nil && read == unsafe.Sizeof(item) && item.Type == 4 && p.buttons[int(item.ID)] != 0 {
			p.paintButton(&item)
		}
		return 1
	case 0x111:
		id := int(wparam & 0xffff)
		if id == 2 {
			p.hide()
			return 0
		}
		if wparam>>16 == 0 {
			kind := map[int]string{trayDPIButton: "dpi", trayTelegramButton: "telegram", trayDiagnoseButton: "diagnose", trayOpenButton: "open", trayExitButton: "quit"}[id]
			if kind != "" {
				p.action(kind)
			}
		}
		return 0
	case 0x2e0:
		p.dpi = int32(wparam & 0xffff)
		p.makeFonts()
		p.layout()
		return 0
	}
	return trayU("DefWindowProcW", hwnd, uintptr(message), wparam, lparam)
}

func (p *trayPopup) show() {
	var cursor trayPoint
	if trayU("GetCursorPos", uintptr(unsafe.Pointer(&cursor))) == 0 {
		return
	}
	monitor := trayU("MonitorFromPoint", uintptr(uint64(uint32(cursor.X))|uint64(uint32(cursor.Y))<<32), 2)
	info := trayMonitorInfo{Size: uint32(unsafe.Sizeof(trayMonitorInfo{}))}
	if trayU("GetMonitorInfoW", monitor, uintptr(unsafe.Pointer(&info))) == 0 {
		return
	}
	dpi := uint32(96)
	var vertical uint32
	if proc := trayShcore.NewProc("GetDpiForMonitor"); proc.Find() == nil {
		_, _, _ = proc.Call(monitor, 0, uintptr(unsafe.Pointer(&dpi)), uintptr(unsafe.Pointer(&vertical)))
	}
	if dpi < 96 || dpi > 768 {
		dpi = 96
	}
	if p.dpi != int32(dpi) {
		p.dpi = int32(dpi)
		p.makeFonts()
	}
	bounds := placeTrayPanel(cursor.X, cursor.Y, p.px(trayPanelWidth), p.px(trayPanelHeight), p.px(10), info.Work)
	p.width, p.height = bounds.Right-bounds.Left, bounds.Bottom-bounds.Top
	trayU("SetWindowPos", p.hwnd, ^uintptr(0), trayInt(bounds.Left), trayInt(bounds.Top), trayInt(p.width), trayInt(p.height), 0x10)
	p.layout()
	p.update()
	p.visible = true
	trayU("ShowWindow", p.hwnd, 5)
	trayU("SetForegroundWindow", p.hwnd)
	trayU("SetFocus", p.buttons[trayDPIButton])
	trayU("SetTimer", p.hwnd, 1, 1000, 0)
}

func (p *trayPopup) hide() {
	if p.visible {
		p.visible = false
		trayU("KillTimer", p.hwnd, 1)
		trayU("ShowWindow", p.hwnd, 0)
	}
}

// box converts a rectangle in panel units to device pixels.
func (p *trayPopup) box(b trayBox) trayRect {
	return trayRect{p.px(int32(b.X)), p.px(int32(b.Y)), p.px(int32(b.X + b.W)), p.px(int32(b.Y + b.H))}
}

func (p *trayPopup) layout() {
	for id, box := range trayBoxes {
		r := p.box(box)
		trayU("MoveWindow", p.buttons[id], trayInt(r.Left), trayInt(r.Top), trayInt(r.Right-r.Left), trayInt(r.Bottom-r.Top), 1)
		trayU("SendMessageW", p.buttons[id], 0x30, p.fonts[1], 0)
	}
	radius := p.px(trayPanelRadius)
	region := trayG("CreateRoundRectRgn", 0, 0, trayInt(p.width+1), trayInt(p.height+1), trayInt(radius*2), trayInt(radius*2))
	if region != 0 && trayU("SetWindowRgn", p.hwnd, region, 1) == 0 {
		trayG("DeleteObject", region)
	}
}

func (p *trayPopup) update() {
	next := p.view()
	if next == p.state {
		return
	}
	p.state = next
	dpiLabel := "Обход DPI. " + p.state.DPI + ". Включить"
	if p.state.DPIOn {
		dpiLabel = "Обход DPI. " + p.state.DPI + ". Выключить"
	}
	tgLabel := "Telegram. " + p.state.Telegram + ". Включить"
	if p.state.TelegramOn {
		tgLabel = "Telegram. " + p.state.Telegram + ". Выключить"
	}
	labels := map[int]string{trayDPIButton: dpiLabel, trayTelegramButton: tgLabel, trayDiagnoseButton: "Проверить связь. " + p.state.Diagnostic, trayOpenButton: "Открыть Evasion", trayExitButton: "Выход из Evasion"}
	if p.state.Error != "" {
		labels[trayDiagnoseButton] += ". Ошибка: " + p.state.Error
	}
	if p.state.ResultsReady {
		labels[trayOpenButton] = "Открыть результаты диагностики"
	}
	for id, text := range labels {
		trayU("SetWindowTextW", p.buttons[id], uintptr(unsafe.Pointer(trayString(text))))
		enabled := uintptr(1)
		if id == trayDPIButton && p.state.DPIBusy || id == trayTelegramButton && p.state.TelegramBusy || id == trayDiagnoseButton && p.state.Diagnosing {
			enabled = 0
		}
		trayU("EnableWindow", p.buttons[id], enabled)
		trayU("InvalidateRect", p.buttons[id], 0, 0)
	}
	trayU("InvalidateRect", p.hwnd, 0, 0)
}

func (p *trayPopup) makeFonts() {
	for _, font := range p.fonts {
		if font != 0 {
			trayG("DeleteObject", font)
		}
	}
	for i, item := range []struct {
		size, weight int32
		italic       uintptr
		face         string
	}{{17, 600, 0, "Segoe UI"}, {13, 600, 0, "Segoe UI"}, {11, 400, 0, "Segoe UI"}} {
		p.fonts[i] = trayG("CreateFontW", trayInt(-p.px(item.size)), 0, 0, 0, trayInt(item.weight), item.italic, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(trayString(item.face))))
	}
}

func (p *trayPopup) releaseResources() {
	for _, font := range p.fonts {
		if font != 0 {
			trayG("DeleteObject", font)
		}
	}
}

type trayBitmapInfo struct {
	Size                   uint32
	Width, Height          int32
	Planes, BitCount       uint16
	Compression, SizeImage uint32
	XPerMeter, YPerMeter   int32
	ClrUsed, ClrImportant  uint32
}

// trayBlit copies a rendered canvas (top-down BGRX) onto a device context.
func trayBlit(dc uintptr, c *trayCanvas) {
	info := trayBitmapInfo{Width: int32(c.w), Height: -int32(c.h), Planes: 1, BitCount: 32}
	info.Size = uint32(unsafe.Sizeof(info))
	trayG("SetDIBitsToDevice", dc, 0, 0, uintptr(c.w), uintptr(c.h), 0, 0, 0, uintptr(c.h), uintptr(unsafe.Pointer(&c.pix[0])), uintptr(unsafe.Pointer(&info)), 0)
	runtime.KeepAlive(c)
}

// labels lays system text over the picture; originX/originY is the device
// position of the surface being painted inside the panel.
func (p *trayPopup) labels(dc uintptr, id int, disabled bool, originX, originY int32) {
	for _, l := range trayLabels(p.state, id, disabled) {
		r := p.box(trayBox{l.X, l.Y, l.W, l.H})
		rect := trayRect{r.Left - originX, r.Top - originY, r.Right - originX, r.Bottom - originY}
		flags := uintptr(0x20 | 0x8000 | 0x800 | 4)
		if l.Center {
			flags |= 1
		}
		old := trayG("SelectObject", dc, p.fonts[l.Font])
		trayG("SetBkMode", dc, 1)
		trayG("SetTextColor", dc, uintptr(trayColor(l.Tone.hex())))
		trayU("DrawTextW", dc, uintptr(unsafe.Pointer(trayString(l.Text))), ^uintptr(0), uintptr(unsafe.Pointer(&rect)), flags)
		trayG("SelectObject", dc, old)
	}
}

func (p *trayPopup) paint(target uintptr) {
	// Двойная буферизация: без мерцания при обновлении раз в секунду.
	dc := trayG("CreateCompatibleDC", target)
	bitmap := trayG("CreateCompatibleBitmap", target, trayInt(p.width), trayInt(p.height))
	oldBitmap := trayG("SelectObject", dc, bitmap)
	defer func() {
		trayG("BitBlt", target, 0, 0, trayInt(p.width), trayInt(p.height), dc, 0, 0, 0x00cc0020)
		trayG("SelectObject", dc, oldBitmap)
		trayG("DeleteObject", bitmap)
		trayG("DeleteDC", dc)
	}()
	canvas := newTrayCanvas(int(p.width), int(p.height), 0, 0, float64(p.dpi)/96)
	paintTray(canvas, p.state, trayPress{})
	trayBlit(dc, canvas)
	p.labels(dc, 0, false, 0, 0)
}

func (p *trayPopup) paintButton(item *trayDrawItem) {
	w, h := item.Rect.Right-item.Rect.Left, item.Rect.Bottom-item.Rect.Top
	dc := trayG("CreateCompatibleDC", item.DC)
	bitmap := trayG("CreateCompatibleBitmap", item.DC, trayInt(w), trayInt(h))
	oldBitmap := trayG("SelectObject", dc, bitmap)
	defer func() {
		trayG("BitBlt", item.DC, 0, 0, trayInt(w), trayInt(h), dc, 0, 0, 0x00cc0020)
		trayG("SelectObject", dc, oldBitmap)
		trayG("DeleteObject", bitmap)
		trayG("DeleteDC", dc)
	}()
	id := int(item.ID)
	origin := p.box(trayBoxes[id])
	// The button shows its own part of the panel picture, so edges line up exactly.
	canvas := newTrayCanvas(int(w), int(h), int(origin.Left), int(origin.Top), float64(p.dpi)/96)
	paintTray(canvas, p.state, trayPress{id: id, focused: item.State&0x10 != 0, pressed: item.State&1 != 0})
	trayBlit(dc, canvas)
	p.labels(dc, id, item.State&4 != 0, origin.Left, origin.Top)
}
