package main

import (
	"context"
	"fmt"
	"unsafe"

	wr "github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"
)

var windowDPI = trayUser.NewProc("GetDpiForWindow")

func configureWindowCorners(ctx context.Context) {
	wr.WindowExecJS(ctx, fmt.Sprintf("document.documentElement.style.setProperty('--window-corner-radius', '%dpx')", mainCornerRadius))
	hwnd := mainWindow()
	if hwnd == 0 {
		return
	}
	// The WebView reports physical size changes after Windows applies the new DPI.
	const event = "evasion:window-bounds"
	wr.EventsOff(ctx, event)
	wr.EventsOn(ctx, event, func(...interface{}) { roundWindow(hwnd) })
	roundWindow(hwnd)
}

func roundWindow(hwnd uintptr) {
	var bounds windows.Rect
	if trayU("IsIconic", hwnd) != 0 || trayU("GetWindowRect", hwnd, uintptr(unsafe.Pointer(&bounds))) == 0 {
		return
	}
	width, height := bounds.Right-bounds.Left, bounds.Bottom-bounds.Top
	if width <= 0 || height <= 0 {
		return
	}
	dpi := uintptr(96)
	if windowDPI.Find() == nil {
		if value, _, _ := windowDPI.Call(hwnd); value != 0 {
			dpi = value
		}
	}
	diameter := (2*mainCornerRadius*dpi + 48) / 96
	// WebView2 paints the antialiased curve. Keep the binary hit region two
	// physical pixels outside it so it cannot cut through a blended edge.
	const pad = 2
	region := trayG("CreateRoundRectRgn", trayInt(-pad), trayInt(-pad), uintptr(width+pad+1), uintptr(height+pad+1), diameter, diameter)
	if region == 0 {
		return
	}
	rect := trayG("CreateRectRgn", 0, 0, uintptr(width), uintptr(height))
	if rect == 0 {
		trayG("DeleteObject", region)
		return
	}
	const rgnAnd = 1
	clipped := trayG("CombineRgn", region, region, rect, rgnAnd)
	trayG("DeleteObject", rect)
	if clipped == 0 || trayU("SetWindowRgn", hwnd, region, 1) == 0 {
		// On success Windows owns the region.
		trayG("DeleteObject", region)
	}
}
