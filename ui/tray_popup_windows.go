//go:build windows

package main

import (
	"encoding/binary"
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
const (
	trayDPIButton = 1001 + iota
	trayTelegramButton
	trayDiagnoseButton
	trayOpenButton
	trayExitButton
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

type trayPalette struct {
	background, surface, border, ink, muted, accent, track, knob, warning uint32
	top, bottom, accentInk, hover                                         uint32
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
	icon          uintptr
	visible       bool
	preview       bool
	tops          map[int]int32
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
func (p *trayPopup) palette() trayPalette {
	if p.state.Natural {
		if p.state.Dark {
			// Ночной лес: мох на тёмной хвое.
			return trayPalette{background: 0x0a1108, surface: 0x141f0e, border: 0x2a3d1e, ink: 0xf2f0e2, muted: 0xa9b795, accent: 0xa9d489, track: 0x2c4018, knob: 0xf6fbec, warning: 0xffc58a,
				top: 0x16240e, bottom: 0x070b05, accentInk: 0x16240e, hover: 0x1c2a12}
		}
		// Солнечные кроны: свежая зелень на молочном свете.
		return trayPalette{background: 0xf4faf0, surface: 0xffffff, border: 0xdcebcd, ink: 0x1d2a17, muted: 0x68795a, accent: 0x2f7a3e, track: 0xd9e8cc, knob: 0xffffff, warning: 0x9c4f00,
			top: 0xe4f2d6, bottom: 0xf3f6ea, accentInk: 0xf6fcf2, hover: 0xf2f9ea}
	}
	if p.state.Dark {
		// Ночная сакура.
		return trayPalette{background: 0x160b12, surface: 0x26151f, border: 0x3e2533, ink: 0xfbeff4, muted: 0xc2a3b2, accent: 0xff9fc4, track: 0x4a3040, knob: 0xfff6fa, warning: 0xffc58a,
			top: 0x2a1222, bottom: 0x0f070c, accentInk: 0x3a0d22, hover: 0x30202b}
	}
	// Дневная сакура.
	return trayPalette{background: 0xfdf3f5, surface: 0xffffff, border: 0xf0d6e0, ink: 0x3a1b27, muted: 0x8c6876, accent: 0xc0306a, track: 0xead4dd, knob: 0xffffff, warning: 0x9c4f00,
		top: 0xfde4ec, bottom: 0xf6f3ea, accentInk: 0xfff8fb, hover: 0xfff6f9}
}

// bgAt — цвет фона панели на высоте y (для подложки кнопок).
func (p *trayPopup) bgAt(y int32) uint32 {
	c := p.palette()
	if p.height <= 0 {
		return c.background
	}
	return mixColor(c.top, c.bottom, float64(y)/float64(p.height))
}

// Each popup owns a separate UI thread; the Wails window keeps its size and state.
func startTrayPopup(view func() trayView, action func(string), ready func(toggle, refresh, hide, quit func()), done func(), preview ...bool) {
	go func() {
		defer func() { _ = recover() }()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if done != nil {
			defer done()
		}
		p := &trayPopup{view: view, action: action, dpi: 96, width: 352, height: 348, buttons: map[int]uintptr{}}
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
		p.hwnd = trayU("CreateWindowExW", exStyle, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(trayString("Evasion — быстрый доступ"))), 0x82000000, 0, 0, 352, 348, 0, 0, instance, 0)
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
		p.makeIcon()
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
			p.makeIcon()
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
		p.makeIcon()
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
		p.makeIcon()
	}
	bounds := placeTrayPanel(cursor.X, cursor.Y, p.px(352), p.px(348), p.px(10), info.Work)
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

func (p *trayPopup) layout() {
	for _, item := range []struct {
		id         int
		x, y, w, h int32
	}{{trayDPIButton, 16, 78, 320, 62}, {trayTelegramButton, 16, 148, 320, 62}, {trayDiagnoseButton, 16, 218, 320, 62}, {trayOpenButton, 16, 292, 214, 38}, {trayExitButton, 238, 292, 98, 38}} {
		w := p.px(item.w)
		if item.id <= trayDiagnoseButton {
			w = p.width - 2*p.px(16)
		}
		if p.tops == nil {
			p.tops = map[int]int32{}
		}
		p.tops[item.id] = p.px(item.y)
		trayU("MoveWindow", p.buttons[item.id], trayInt(p.px(item.x)), trayInt(p.px(item.y)), trayInt(w), trayInt(p.px(item.h)), 1)
		trayU("SendMessageW", p.buttons[item.id], 0x30, p.fonts[1], 0)
	}
	radius := p.px(22)
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
	}{{22, 500, 1, "Georgia"}, {13, 600, 0, "Segoe UI"}, {11, 400, 0, "Segoe UI"}} {
		p.fonts[i] = trayG("CreateFontW", trayInt(-p.px(item.size)), 0, 0, 0, trayInt(item.weight), item.italic, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(trayString(item.face))))
	}
}

func (p *trayPopup) makeIcon() {
	if p.icon != 0 {
		trayU("DestroyIcon", p.icon)
		p.icon = 0
	}
	iconData := trayIconBytes()
	if len(iconData) < 6 {
		return
	}
	count := int(binary.LittleEndian.Uint16(iconData[4:6]))
	best := -1
	distance := int(^uint(0) >> 1)
	for i := 0; i < count; i++ {
		at := 6 + i*16
		if at+16 > len(iconData) {
			break
		}
		size := int(iconData[at])
		if size == 0 {
			size = 256
		}
		delta := size - int(p.px(32))
		if delta < 0 {
			delta = -delta
		}
		if delta < distance {
			distance = delta
			best = at
		}
	}
	if best < 0 {
		return
	}
	offset := int(binary.LittleEndian.Uint32(iconData[best+8:]))
	length := int(binary.LittleEndian.Uint32(iconData[best+4:]))
	if offset+length > len(iconData) {
		return
	}
	p.icon = trayU("CreateIconFromResourceEx", uintptr(unsafe.Pointer(&iconData[offset])), uintptr(length), 1, 0x30000, trayInt(p.px(32)), trayInt(p.px(32)), 0)
}

func (p *trayPopup) releaseResources() {
	for _, font := range p.fonts {
		if font != 0 {
			trayG("DeleteObject", font)
		}
	}
	if p.icon != 0 {
		trayU("DestroyIcon", p.icon)
	}
}

func trayRound(dc uintptr, rect trayRect, radius int32, fill, border uint32) {
	brush := trayG("CreateSolidBrush", uintptr(trayColor(fill)))
	pen := trayG("CreatePen", 0, 1, uintptr(trayColor(border)))
	oldBrush := trayG("SelectObject", dc, brush)
	oldPen := trayG("SelectObject", dc, pen)
	trayG("RoundRect", dc, trayInt(rect.Left), trayInt(rect.Top), trayInt(rect.Right), trayInt(rect.Bottom), trayInt(radius*2), trayInt(radius*2))
	trayG("SelectObject", dc, oldBrush)
	trayG("SelectObject", dc, oldPen)
	trayG("DeleteObject", brush)
	trayG("DeleteObject", pen)
}

func (p *trayPopup) text(dc uintptr, text string, x, y, width, height int32, font int, color uint32, center bool) {
	rect := trayRect{x, y, x + width, y + height}
	flags := uintptr(0x20 | 0x8000 | 0x800)
	if center {
		flags |= 1 | 4
	}
	old := trayG("SelectObject", dc, p.fonts[font])
	trayG("SetBkMode", dc, 1)
	trayG("SetTextColor", dc, uintptr(trayColor(color)))
	trayU("DrawTextW", dc, uintptr(unsafe.Pointer(trayString(text))), ^uintptr(0), uintptr(unsafe.Pointer(&rect)), flags)
	trayG("SelectObject", dc, old)
}

func (p *trayPopup) paint(target uintptr) {
	c := p.palette()
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
	trayGradient(dc, trayRect{0, 0, p.width, p.height}, c.top, c.bottom)
	drawTrayImage(dc, trayHeader(p.state.Dark, p.state.Natural), 0, 0, p.width, p.px(74))
	trayOutline(dc, trayRect{0, 0, p.width, p.height}, p.px(22), c.border)
	if p.icon != 0 {
		trayU("DrawIconEx", dc, trayInt(p.px(18)), trayInt(p.px(20)), p.icon, trayInt(p.px(34)), trayInt(p.px(34)), 0, 0, 3)
	}
	p.text(dc, "evasion", p.px(62), p.px(14), p.px(200), p.px(30), 0, c.ink, false)
	status, dot := "Обход выключен", c.muted
	switch {
	case p.state.DPIBusy:
		status, dot = p.state.DPI, c.accent
	case p.state.DPIOn:
		status, dot = "Обход работает", c.accent
	}
	dx, dy := p.px(64), p.px(48)
	trayRound(dc, trayRect{dx, dy, dx + p.px(7), dy + p.px(7)}, p.px(4), dot, dot)
	p.text(dc, status, p.px(76), p.px(43), p.px(240), p.px(17), 2, c.muted, false)
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
	c := p.palette()
	id := int(item.ID)
	top := p.tops[id]
	// Подложка повторяет градиент панели, чтобы углы карточек не выделялись.
	trayGradient(dc, trayRect{0, 0, w, h}, p.bgAt(top), p.bgAt(top+h))
	focused := item.State&0x10 != 0
	pressed := item.State&1 != 0
	disabled := item.State&4 != 0

	switch id {
	case trayOpenButton:
		fill := c.accent
		if pressed {
			fill = mixColor(c.accent, c.bottom, .25)
		}
		trayRound(dc, trayRect{0, 0, w, h}, h/2, fill, fill)
		if focused {
			trayOutline(dc, trayRect{p.px(2), p.px(2), w - p.px(2), h - p.px(2)}, h/2-p.px(2), c.accentInk)
		}
		label := "Открыть Evasion"
		if p.state.ResultsReady {
			label = "Результаты диагностики"
		}
		p.text(dc, label, 0, 0, w, h, 1, c.accentInk, true)
		return
	case trayExitButton:
		fill, border := c.surface, c.border
		if pressed || focused {
			border = c.accent
		}
		trayRound(dc, trayRect{0, 0, w, h}, h/2, fill, border)
		p.text(dc, "Выход", 0, 0, w, h, 1, c.muted, true)
		return
	}

	fill, border := c.surface, c.border
	if focused {
		fill, border = c.hover, c.accent
	}
	if pressed {
		border = c.accent
	}
	trayRound(dc, trayRect{0, 0, w, h}, p.px(16), fill, border)

	label, detail := "Обход DPI", p.state.DPI
	on, busy := p.state.DPIOn, p.state.DPIBusy
	if id == trayTelegramButton {
		label, detail = "Telegram", p.state.Telegram
		on, busy = p.state.TelegramOn, p.state.TelegramBusy
	}
	if id == trayDiagnoseButton {
		label, detail = "Проверить связь", p.state.Diagnostic
		busy = p.state.Diagnosing
		on = false
		if busy {
			label = "Проверяем связь…"
		}
	}
	if p.state.Error != "" && id == trayDiagnoseButton {
		detail = p.state.Error
	}
	// Иконка в круглой подложке; у включённого — акцентная.
	cx, cy := p.px(31), h/2
	badge, glyph := mixColor(c.surface, c.border, .7), c.muted
	if on {
		badge, glyph = mixColor(c.surface, c.accent, .22), c.accent
	}
	r := p.px(17)
	trayRound(dc, trayRect{cx - r, cy - r, cx + r, cy + r}, r, badge, badge)
	p.symbol(dc, id, cx, cy, glyph)

	inkColor := c.ink
	if disabled {
		inkColor = c.muted
	}
	p.text(dc, label, p.px(58), p.px(11), w-p.px(124), p.px(20), 1, inkColor, false)
	detailWidth := w - p.px(124)
	if id == trayDiagnoseButton {
		detailWidth = w - p.px(70)
	}
	color := c.muted
	if id == trayDiagnoseButton && p.state.Error != "" {
		color = c.warning
	}
	p.text(dc, detail, p.px(58), p.px(32), detailWidth, p.px(17), 2, color, false)
	if id == trayDiagnoseButton {
		if !busy {
			p.text(dc, "↗", w-p.px(42), 0, p.px(26), h, 1, c.accent, true)
		}
		return
	}
	track := c.track
	if on {
		track = c.accent
	}
	if busy {
		track = mixColor(c.track, c.accent, .45)
	}
	x, y := w-p.px(60), (h-p.px(26))/2
	trayRound(dc, trayRect{x, y, x + p.px(44), y + p.px(26)}, p.px(13), track, track)
	knobX := x + p.px(3)
	if on {
		knobX = x + p.px(21)
	}
	trayRound(dc, trayRect{knobX, y + p.px(3), knobX + p.px(20), y + p.px(23)}, p.px(10), c.knob, c.knob)
}

func (p *trayPopup) symbol(dc uintptr, id int, x, y int32, color uint32) {
	pen := trayG("CreatePen", 0, trayInt(max(1, (p.px(3)+1)/2)), uintptr(trayColor(color)))
	old := trayG("SelectObject", dc, pen)
	line := func(points ...trayPoint) {
		for i, point := range points {
			if i == 0 {
				trayG("MoveToEx", dc, trayInt(x+p.px(point.X)), trayInt(y+p.px(point.Y)), 0)
			} else {
				trayG("LineTo", dc, trayInt(x+p.px(point.X)), trayInt(y+p.px(point.Y)))
			}
		}
	}
	switch id {
	case trayDPIButton:
		line(trayPoint{0, -9}, trayPoint{0, -1})
		line(trayPoint{-5, -6}, trayPoint{-8, -2}, trayPoint{-7, 5}, trayPoint{-2, 8}, trayPoint{4, 7}, trayPoint{8, 3}, trayPoint{8, -2}, trayPoint{5, -6})
	case trayTelegramButton:
		line(trayPoint{-9, -3}, trayPoint{9, -9}, trayPoint{5, 9}, trayPoint{-1, 4}, trayPoint{-3, 7}, trayPoint{-3, 1}, trayPoint{5, -5})
		line(trayPoint{-9, -3}, trayPoint{-3, 1})
	default:
		line(trayPoint{-9, 0}, trayPoint{-5, 0}, trayPoint{-2, -7}, trayPoint{2, 7}, trayPoint{5, 0}, trayPoint{9, 0})
	}
	trayG("SelectObject", dc, old)
	trayG("DeleteObject", pen)
}
