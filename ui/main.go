// Evasion UI — десктопная оболочка движка evasion.
//
// Оболочка несёт движок внутри себя (payload/), распаковывает его рядом с
// Evasion.exe и управляет им как подпроцессом; подробности — app.go.
package main

import (
	"embed"
	"log"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

const (
	mainWindowWidth  = 780
	mainWindowHeight = 500
	mainCornerRadius = 24 // logical pixels
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	waitForPreviousCopy(os.Args[1:])
	app := NewApp()
	err := wails.Run(&options.App{
		Title:            "Evasion",
		Width:            mainWindowWidth,
		Height:           mainWindowHeight,
		MinWidth:         mainWindowWidth,
		MinHeight:        mainWindowHeight,
		MaxWidth:         mainWindowWidth,
		MaxHeight:        mainWindowHeight,
		DisableResize:    true,
		Frameless:        true,
		StartHidden:      false,
		BackgroundColour: &options.RGBA{R: 5, G: 5, B: 6, A: 255},
		AssetServer:      &assetserver.Options{Assets: assets},
		Windows: &windows.Options{
			WebviewIsTransparent:              true,
			WindowIsTranslucent:               true,
			BackdropType:                      windows.None,
			DisableFramelessWindowDecorations: true,
		},
		OnStartup:     app.startup,
		OnDomReady:    configureWindowCorners,
		OnShutdown:    app.shutdown,
		OnBeforeClose: app.beforeClose,
		Bind:          []interface{}{app},
		// Один экземпляр: вторая копия завершается, а запущенная поднимает окно.
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               "com.evasion.ui.single-instance",
			OnSecondInstanceLaunch: app.onSecondInstance,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
