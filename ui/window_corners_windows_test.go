package main

import (
	"math"
	"runtime"
	"testing"
	"unsafe"
)

func TestRoundedWindowRegion(t *testing.T) {
	// A hidden window lets us check the real Win32 region without starting Evasion.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hwnd := trayU("CreateWindowExW", 0, uintptr(unsafe.Pointer(trayString("STATIC"))), 0, 0x80000000, 0, 0, mainWindowWidth, mainWindowHeight, 0, 0, 0, 0)
	if hwnd == 0 {
		t.Fatal("create hidden window")
	}
	defer trayU("DestroyWindow", hwnd)
	region := trayG("CreateRectRgn", 0, 0, 1, 1)
	if region == 0 {
		t.Fatal("create region")
	}
	defer trayG("DeleteObject", region)

	radius := float64(mainCornerRadius)
	if windowDPI.Find() == nil {
		if dpi, _, _ := windowDPI.Call(hwnd); dpi != 0 {
			radius *= float64(dpi) / 96
		}
	}
	for _, size := range [][2]uintptr{{mainWindowWidth, mainWindowHeight}, {1125, 875}} {
		width, height := size[0], size[1]
		if trayU("SetWindowPos", hwnd, 0, 0, 0, width, height, 0x16) == 0 {
			t.Fatal("set window bounds")
		}
		roundWindow(hwnd)
		if trayU("GetWindowRgn", hwnd, region) == 0 {
			t.Fatal("window has no region")
		}
		for _, pt := range [][2]uintptr{{4, 4}, {width - 5, 4}, {4, height - 5}, {width - 5, height - 5}, {width, height / 2}, {width / 2, height}} {
			if trayG("PtInRegion", region, pt[0], pt[1]) != 0 {
				t.Errorf("%dx%d includes outside point %v", width, height, pt)
			}
		}
		for _, pt := range [][2]uintptr{{width / 2, 0}, {0, height / 2}, {width - 1, height / 2}, {width / 2, height - 1}} {
			if trayG("PtInRegion", region, pt[0], pt[1]) == 0 {
				t.Errorf("%dx%d clips edge point %v", width, height, pt)
			}
		}
		// Every pixel touched by the rendered arc must survive the native mask.
		for y := 0; y < int(radius); y++ {
			for x := 0; x < int(radius); x++ {
				if math.Hypot(radius-float64(x+1), radius-float64(y+1)) >= radius {
					continue
				}
				for _, px := range []uintptr{uintptr(x), width - 1 - uintptr(x)} {
					for _, py := range []uintptr{uintptr(y), height - 1 - uintptr(y)} {
						if trayG("PtInRegion", region, px, py) == 0 {
							t.Fatalf("%dx%d clips blended pixel (%d, %d)", width, height, px, py)
						}
					}
				}
			}
		}
	}
}
