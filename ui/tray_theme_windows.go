//go:build windows

package main

import "unsafe"

// A flat surface replaces the legacy landscape header and gradients.
func trayFill(dc uintptr, rect trayRect, color uint32) {
	brush := trayG("CreateSolidBrush", uintptr(trayColor(color)))
	trayU("FillRect", dc, uintptr(unsafe.Pointer(&rect)), brush)
	trayG("DeleteObject", brush)
}

func mixColor(a, b uint32, t float64) uint32 {
	t = max(0, min(1, t))
	ch := func(s uint) uint32 {
		x, y := float64(a>>s&255), float64(b>>s&255)
		return uint32(x+(y-x)*t+0.5) << s
	}
	return ch(16) | ch(8) | ch(0)
}

func trayOutline(dc uintptr, rect trayRect, radius int32, color uint32) {
	pen := trayG("CreatePen", 0, 1, uintptr(trayColor(color)))
	oldPen := trayG("SelectObject", dc, pen)
	oldBrush := trayG("SelectObject", dc, trayG("GetStockObject", 5))
	trayG("RoundRect", dc, trayInt(rect.Left), trayInt(rect.Top), trayInt(rect.Right), trayInt(rect.Bottom), trayInt(radius*2), trayInt(radius*2))
	trayG("SelectObject", dc, oldBrush)
	trayG("SelectObject", dc, oldPen)
	trayG("DeleteObject", pen)
}
