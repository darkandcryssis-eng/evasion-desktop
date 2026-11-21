//go:build windows

package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"io"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Оформление трей-панели «Сакура»: градиентный фон, шапка с кадром из видеофона
// темы (BGRA с предумноженной альфой, рисуется AlphaBlend), акцентные элементы.

//go:embed assets/tray-header-dark.bgra.gz
var trayHeaderDark []byte

//go:embed assets/tray-header-light.bgra.gz
var trayHeaderLight []byte

//go:embed assets/tray-header-natural-dark.bgra.gz
var trayHeaderNaturalDark []byte

//go:embed assets/tray-header-natural-light.bgra.gz
var trayHeaderNaturalLight []byte

var trayImg = windows.NewLazySystemDLL("msimg32.dll")

type trayImage struct {
	w, h int32
	px   []byte
}

var (
	trayHeaderOnce sync.Once
	trayHeaders    [4]*trayImage // 0 — сакура день, 1 — сакура ночь, 2 — природа день, 3 — природа ночь
)

func decodeTrayImage(gz []byte) *trayImage {
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil
	}
	raw, err := io.ReadAll(r)
	if err != nil || len(raw) < 8 {
		return nil
	}
	w, h := int32(binary.LittleEndian.Uint32(raw)), int32(binary.LittleEndian.Uint32(raw[4:]))
	if w <= 0 || h <= 0 || int(w*h*4) != len(raw)-8 {
		return nil
	}
	return &trayImage{w: w, h: h, px: raw[8:]}
}

func trayHeader(dark, natural bool) *trayImage {
	trayHeaderOnce.Do(func() {
		trayHeaders[0] = decodeTrayImage(trayHeaderLight)
		trayHeaders[1] = decodeTrayImage(trayHeaderDark)
		trayHeaders[2] = decodeTrayImage(trayHeaderNaturalLight)
		trayHeaders[3] = decodeTrayImage(trayHeaderNaturalDark)
	})
	if natural {
		if dark {
			return trayHeaders[3]
		}
		return trayHeaders[2]
	}
	if dark {
		return trayHeaders[1]
	}
	return trayHeaders[0]
}

type trayBitmapInfo struct {
	Size                       uint32
	Width, Height              int32
	Planes, BitCount           uint16
	Compression, SizeImage     uint32
	XPels, YPels, Used, Import uint32
	Colors                     [1]uint32
}

// drawTrayImage растягивает изображение в прямоугольник с альфа-смешиванием.
func drawTrayImage(dc uintptr, img *trayImage, x, y, w, h int32) {
	if img == nil || w <= 0 || h <= 0 {
		return
	}
	info := trayBitmapInfo{Size: 40, Width: img.w, Height: -img.h, Planes: 1, BitCount: 32}
	var bits unsafe.Pointer
	bmp := trayG("CreateDIBSection", dc, uintptr(unsafe.Pointer(&info)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 || bits == nil {
		return
	}
	defer trayG("DeleteObject", bmp)
	copy(unsafe.Slice((*byte)(bits), len(img.px)), img.px)
	src := trayG("CreateCompatibleDC", dc)
	defer trayG("DeleteDC", src)
	old := trayG("SelectObject", src, bmp)
	defer trayG("SelectObject", src, old)
	blend := uintptr(0 | 0<<8 | 255<<16 | 1<<24) // AC_SRC_OVER, 255, AC_SRC_ALPHA
	trayCall(trayImg, "AlphaBlend", dc, trayInt(x), trayInt(y), trayInt(w), trayInt(h), src, 0, 0, trayInt(img.w), trayInt(img.h), blend)
}

type trayVertex struct {
	X, Y                    int32
	Red, Green, Blue, Alpha uint16
}

// trayGradient — вертикальный градиент top→bottom в прямоугольнике.
func trayGradient(dc uintptr, rect trayRect, top, bottom uint32) {
	v := [2]trayVertex{
		{X: rect.Left, Y: rect.Top, Red: uint16(top>>16&255) << 8, Green: uint16(top>>8&255) << 8, Blue: uint16(top&255) << 8},
		{X: rect.Right, Y: rect.Bottom, Red: uint16(bottom>>16&255) << 8, Green: uint16(bottom>>8&255) << 8, Blue: uint16(bottom&255) << 8},
	}
	mesh := [2]uint32{0, 1}
	trayCall(trayImg, "GradientFill", dc, uintptr(unsafe.Pointer(&v[0])), 2, uintptr(unsafe.Pointer(&mesh[0])), 1, 1)
}

// mixColor — цвет градиента на доле t∈[0,1].
func mixColor(a, b uint32, t float64) uint32 {
	if t < 0 {
		t = 0
	} else if t > 1 {
		t = 1
	}
	ch := func(s uint) uint32 {
		x, y := float64(a>>s&255), float64(b>>s&255)
		return uint32(x+(y-x)*t+0.5) << s
	}
	return ch(16) | ch(8) | ch(0)
}

// trayOutline — контур скруглённого прямоугольника без заливки.
func trayOutline(dc uintptr, rect trayRect, radius int32, color uint32) {
	pen := trayG("CreatePen", 0, 1, uintptr(trayColor(color)))
	oldPen := trayG("SelectObject", dc, pen)
	oldBrush := trayG("SelectObject", dc, trayG("GetStockObject", 5))
	trayG("RoundRect", dc, trayInt(rect.Left), trayInt(rect.Top), trayInt(rect.Right), trayInt(rect.Bottom), trayInt(radius*2), trayInt(radius*2))
	trayG("SelectObject", dc, oldBrush)
	trayG("SelectObject", dc, oldPen)
	trayG("DeleteObject", pen)
}
