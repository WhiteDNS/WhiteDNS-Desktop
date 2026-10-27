package main

import (
	"embed"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed all:clients
var clientAssets embed.FS

//go:embed all:cores
var coreAssets embed.FS

//go:embed filtered_ipv4.csv
var defaultIPv4RangeAssets embed.FS

func main() {
	resume, resumeDir, err := prepareTunResume(os.Args[1:])
	if err != nil {
		println("Startup error:", err.Error())
		return
	}
	var app *App
	if resume != nil {
		app, err = newAppInConfigDir(resumeDir)
	} else {
		app, err = NewApp()
	}
	if err != nil {
		println("Startup error:", err.Error())
		return
	}
	app.tunResume = resume

	err = wails.Run(&options.App{
		Title:                    "WhiteDNS Desktop",
		Width:                    1280,
		Height:                   820,
		MinWidth:                 860,
		MinHeight:                620,
		HideWindowOnClose:        false,
		EnableDefaultContextMenu: true,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 252, G: 252, B: 252, A: 1},
		OnStartup:        app.startup,
		OnDomReady:       app.domReady,
		OnShutdown:       app.shutdown,
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
