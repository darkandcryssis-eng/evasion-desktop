//go:build windows

package main

import (
	"fmt"
	"runtime"
	"slices"
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
	trayProcs          sync.Map
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
	press         trayPress
	dpi           int32
	width, height int32 // window size, shadow margin included
	fonts         [3]uintptr
	visible       bool
	preview       bool
	keyboard      bool // focus ring only after keyboard navigation
	down          int  // control the pointer went down on, when the panel itself got the click
	parked        int  // control that lost the focus by being disabled

	// The picture lives in a DIB section that is handed to the layered window.
	dc, bitmap, oldBitmap uintptr
	bits                  unsafe.Pointer
	bitsW, bitsH          int32
}

// The wrappers take pointers converted to uintptr; uintptrescapes keeps those
// objects on the heap and alive for the call, as (*LazyProc).Call does.
//
//go:uintptrescapes
func trayCall(dll *windows.LazyDLL, name string, args ...uintptr) uintptr {
	proc, ok := trayProcs.Load(name)
	if !ok {
		proc, _ = trayProcs.LoadOrStore(name, dll.NewProc(name))
	}
	r, _, _ := proc.(*windows.LazyProc).Call(args...)
	return r
}

//go:uintptrescapes
func trayU(name string, args ...uintptr) uintptr { return trayCall(trayUser, name, args...) }

//go:uintptrescapes
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
		wc := trayWindowClass{Proc: trayWindowCallback, Instance: instance, Name: className, Cursor: trayU("LoadCursorW", 0, 32512)}
		wc.Size = uint32(unsafe.Sizeof(wc))
		if trayU("RegisterClassExW", uintptr(unsafe.Pointer(&wc))) == 0 {
			return
		}
		defer trayU("UnregisterClassW", uintptr(unsafe.Pointer(className)), instance)
		// Layered tool window: per-pixel alpha, no taskbar button, no Alt-Tab entry.
		exStyle := uintptr(0x00090088)
		if p.preview {
			exStyle = 0x000d0008
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
			switch msg.Message {
			case 0x100, 0x104:
				p.keyboard = true
				if p.key(msg.WParam) {
					continue
				}
			case 0x201:
				p.keyboard = false
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
		if wparam == 2 {
			p.track()
		} else {
			p.update()
		}
		return 0
	case 0xf:
		// The layered surface is pushed by render; just validate.
		var ps trayPaint
		trayU("BeginPaint", hwnd, uintptr(unsafe.Pointer(&ps)))
		trayU("EndPaint", hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0
	case 0x2b:
		// Owner-drawn buttons stay for clicks, keyboard and screen readers;
		// their picture is part of the panel surface.
		return 1
	case 0x201:
		// Reached only if the click was not taken by a button window.
		if id := p.hit(); id != 0 && trayU("IsWindowEnabled", p.buttons[id]) != 0 {
			p.down = id
			trayU("SetCapture", hwnd)
			p.track()
		}
		return 0
	case 0x202:
		id := p.down
		p.down = 0
		trayU("ReleaseCapture")
		if id != 0 && p.hit() == id {
			trayU("SetFocus", p.buttons[id])
			p.action(trayKinds[id])
		}
		p.track()
		return 0
	case 0x111:
		id := int(wparam & 0xffff)
		if id == 2 {
			p.hide()
			return 0
		}
		if wparam>>16 == 0 {
			kind := trayKinds[id]
			if kind != "" {
				p.action(kind)
			}
		}
		return 0
	case 0x2e0:
		// Scaling changed under an open panel: the next open measures again.
		p.hide()
		return 0
	}
	return trayU("DefWindowProcW", hwnd, uintptr(message), wparam, lparam)
}

// key handles what the dialog manager gets wrong for this panel: Esc with no
// focused control, Enter on an owner-drawn button, and the first Tab or arrow
// while no control has the focus yet.
func (p *trayPopup) key(code uintptr) bool {
	if !p.visible {
		return false
	}
	if int16(trayU("GetKeyState", 18)) < 0 {
		return false
	}
	focus := trayU("GetFocus")
	if focus == 0 {
		focus = p.hwnd
		trayU("SetFocus", p.hwnd)
	}
	at := 0
	for id, h := range p.buttons {
		if h == focus {
			at = id
		}
	}
	switch code {
	case 27:
		p.hide()
		return true
	case 13:
		if at != 0 && trayU("IsWindowEnabled", focus) != 0 {
			p.action(trayKinds[at])
		}
		return true
	case 9, 37, 38, 39, 40:
		if at != 0 {
			return false
		}
		order := []int{trayDPIButton, trayTelegramButton, trayDiagnoseButton, trayOpenButton, trayExitButton}
		if code == 37 || code == 38 || code == 9 && int16(trayU("GetKeyState", 16)) < 0 {
			slices.Reverse(order)
		}
		for _, id := range order {
			if trayU("IsWindowEnabled", p.buttons[id]) != 0 {
				trayU("SetFocus", p.buttons[id])
				break
			}
		}
		return true
	}
	return false
}

var trayKinds = map[int]string{trayDPIButton: "dpi", trayTelegramButton: "telegram", trayDiagnoseButton: "diagnose", trayOpenButton: "open", trayExitButton: "quit"}

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
	// The panel sits by the tray; the window is larger by the shadow margin.
	bounds := placeTrayPanel(cursor.X, cursor.Y, p.px(trayPanelWidth), p.px(trayPanelHeight), p.px(10), info.Work)
	m := p.px(trayShadow)
	p.width, p.height = bounds.Right-bounds.Left+2*m, bounds.Bottom-bounds.Top+2*m
	trayU("SetWindowPos", p.hwnd, ^uintptr(0), trayInt(bounds.Left-m), trayInt(bounds.Top-m), trayInt(p.width), trayInt(p.height), 0x10)
	p.layout()
	p.keyboard, p.down, p.parked, p.press = false, 0, 0, trayPress{}
	p.visible = true
	p.sync(p.view())
	trayU("ShowWindow", p.hwnd, 5)
	trayU("SetForegroundWindow", p.hwnd)
	// No control is focused until the keyboard is used, so a stray Space does nothing.
	trayU("SetFocus", p.hwnd)
	trayU("SetTimer", p.hwnd, 1, 1000, 0)
	trayU("SetTimer", p.hwnd, 2, 30, 0)
}

func (p *trayPopup) hide() {
	if p.visible {
		p.visible = false
		trayU("KillTimer", p.hwnd, 1)
		trayU("KillTimer", p.hwnd, 2)
		trayU("ShowWindow", p.hwnd, 0)
	}
}

// box converts a rectangle in panel units to window pixels.
func (p *trayPopup) box(b trayBox) trayRect {
	m := p.px(trayShadow)
	return trayRect{m + p.px(int32(b.X)), m + p.px(int32(b.Y)), m + p.px(int32(b.X+b.W)), m + p.px(int32(b.Y+b.H))}
}

func (p *trayPopup) layout() {
	for id, box := range trayBoxes {
		r := p.box(box)
		trayU("MoveWindow", p.buttons[id], trayInt(r.Left), trayInt(r.Top), trayInt(r.Right-r.Left), trayInt(r.Bottom-r.Top), 0)
	}
}

// hit names the control under the pointer.
func (p *trayPopup) hit() int {
	var at trayPoint
	if trayU("GetCursorPos", uintptr(unsafe.Pointer(&at))) == 0 || trayU("ScreenToClient", p.hwnd, uintptr(unsafe.Pointer(&at))) == 0 {
		return 0
	}
	for id, box := range trayBoxes {
		if r := p.box(box); at.X >= r.Left && at.X < r.Right && at.Y >= r.Top && at.Y < r.Bottom {
			return id
		}
	}
	return 0
}

// track follows the pointer and keyboard focus and repaints when they move:
// the buttons are not drawn by Windows, so the panel shows their feedback.
func (p *trayPopup) track() {
	if !p.visible {
		return
	}
	var next trayPress
	if id := p.hit(); id != 0 && trayU("IsWindowEnabled", p.buttons[id]) != 0 {
		next.hover = id
		if p.down == id || trayU("SendMessageW", p.buttons[id], 0xf2, 0, 0)&4 != 0 {
			next.pressed = id
		}
	}
	if p.keyboard {
		focus := trayU("GetFocus")
		for id, h := range p.buttons {
			if h == focus {
				next.focus = id
			}
		}
	}
	if next != p.press {
		p.press = next
		p.render()
	}
}

func (p *trayPopup) update() {
	if next := p.view(); next != p.state {
		p.sync(next)
	}
}

// sync applies a view: control names and availability, then the picture.
func (p *trayPopup) sync(next trayView) {
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
		if (trayU("IsWindowEnabled", p.buttons[id]) != 0) != (enabled == 1) {
			// Disabling the focused control would leave the panel without keyboard
			// focus; park it on the panel and hand it back when the control returns.
			if enabled == 0 && trayU("GetFocus") == p.buttons[id] {
				p.parked = id
				trayU("SetFocus", p.hwnd)
			}
			trayU("EnableWindow", p.buttons[id], enabled)
			if enabled == 1 && p.parked == id {
				p.parked = 0
				if p.visible && trayU("GetFocus") == p.hwnd {
					trayU("SetFocus", p.buttons[id])
				}
			}
		}
	}
	p.render()
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
	p.dropSurface()
}

type trayBitmapInfo struct {
	Size                   uint32
	Width, Height          int32
	Planes, BitCount       uint16
	Compression, SizeImage uint32
	XPerMeter, YPerMeter   int32
	ClrUsed, ClrImportant  uint32
}

func (p *trayPopup) dropSurface() {
	if p.dc != 0 {
		trayG("SelectObject", p.dc, p.oldBitmap)
		trayG("DeleteObject", p.bitmap)
		trayG("DeleteDC", p.dc)
	}
	p.dc, p.bitmap, p.oldBitmap, p.bits, p.bitsW, p.bitsH = 0, 0, 0, nil, 0, 0
}

// surface returns the pixels (top-down BGRA) of a DIB section the size of the window.
func (p *trayPopup) surface() []byte {
	if p.bits == nil || p.bitsW != p.width || p.bitsH != p.height {
		p.dropSurface()
		info := trayBitmapInfo{Width: p.width, Height: -p.height, Planes: 1, BitCount: 32}
		info.Size = uint32(unsafe.Sizeof(info))
		p.dc = trayG("CreateCompatibleDC", 0)
		p.bitmap = trayG("CreateDIBSection", p.dc, uintptr(unsafe.Pointer(&info)), 0, uintptr(unsafe.Pointer(&p.bits)), 0, 0)
		if p.dc == 0 || p.bitmap == 0 || p.bits == nil {
			if p.bitmap != 0 {
				trayG("DeleteObject", p.bitmap)
			}
			if p.dc != 0 {
				trayG("DeleteDC", p.dc)
			}
			p.dc, p.bitmap, p.bits = 0, 0, nil
			return nil
		}
		p.oldBitmap = trayG("SelectObject", p.dc, p.bitmap)
		p.bitsW, p.bitsH = p.width, p.height
	}
	return unsafe.Slice((*byte)(p.bits), int(p.bitsW)*int(p.bitsH)*4)
}

// labels lays system text over the picture.
func (p *trayPopup) labels(id int, disabled bool) {
	for _, l := range trayLabels(p.state, id, disabled) {
		rect := p.box(trayBox{l.X, l.Y, l.W, l.H})
		flags := uintptr(0x20 | 0x8000 | 0x800 | 4)
		if l.Center {
			flags |= 1
		}
		old := trayG("SelectObject", p.dc, p.fonts[l.Font])
		trayG("SetBkMode", p.dc, 1)
		trayG("SetTextColor", p.dc, uintptr(trayColor(l.Tone.hex())))
		trayU("DrawTextW", p.dc, uintptr(unsafe.Pointer(trayString(l.Text))), ^uintptr(0), uintptr(unsafe.Pointer(&rect)), flags)
		trayG("SelectObject", p.dc, old)
	}
}

// render paints the panel, its text and its shadow and hands the result to
// the layered window, so edges are anti-aliased against whatever is behind.
func (p *trayPopup) render() {
	pix := p.surface()
	if pix == nil {
		return
	}
	clear(pix)
	m := int(p.px(trayShadow))
	canvas := &trayCanvas{pix: pix, w: int(p.bitsW), h: int(p.bitsH), originX: -m, origY: -m, scale: float64(p.dpi) / 96}
	paintTray(canvas, p.state, p.press)
	p.labels(0, false)
	for id, h := range p.buttons {
		p.labels(id, trayU("IsWindowEnabled", h) == 0)
	}
	trayG("GdiFlush")
	canvas.seal()
	size := trayPoint{p.bitsW, p.bitsH}
	var origin trayPoint
	// AC_SRC_OVER with per-pixel alpha, fully opaque overall.
	blend := [4]byte{0, 0, 255, 1}
	trayU("UpdateLayeredWindow", p.hwnd, 0, 0, uintptr(unsafe.Pointer(&size)), p.dc, uintptr(unsafe.Pointer(&origin)), 0, uintptr(unsafe.Pointer(&blend)), 2)
}
