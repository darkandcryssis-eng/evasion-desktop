// Evasion UI — десктопная оболочка движка evasion.
//
// Оболочка несёт движок внутри себя (payload/), распаковывает его рядом с
// Evasion.exe и управляет им как подпроцессом; подробности — app.go.
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()
	err := wails.Run(&options.App{
		Title:            "Evasion",
		Width:            420,
		Height:           300,
		MinWidth:         420,
		MinHeight:        300,
		DisableResize:    false,
		Frameless:        true,
		StartHidden:      false,
		BackgroundColour: &options.RGBA{R: 15, G: 18, B: 27, A: 255},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		OnBeforeClose:    app.beforeClose,
		Bind:             []interface{}{app},
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
