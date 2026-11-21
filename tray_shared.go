package main

import (
	"os"
	"path/filepath"

	"github.com/egoist/mygo"
)

// showWindow brings the main window back from the tray or menu bar, and puts
// the Dock icon back on macOS.
func (a *app) showWindow() {
	if a.win == nil || a.win.IsDestroyed() {
		a.tunLogf("showWindow: 重建主窗口")
		a.createWindow()
	}
	a.showFromTray()
}

// quitFromTray quits for real, instead of hiding the window.
func (a *app) quitFromTray() { a.askQuit() }

// askQuit opens the confirmation instead of closing the app at once.
func (a *app) askQuit() {
	if a.win != nil {
		a.showWindow()
	}
	a.win.Update(func() { a.quitAsk = true })
	a.invalidate()
}

// doQuit really ends the process.
func (a *app) doQuit() {
	a.quitRequested = true
	mygo.App.Quit()
}

// loadAppIconPNG returns the tray icon bytes.
func loadAppIconPNG() []byte {
	if len(embeddedAppIcon) > 0 {
		return embeddedAppIcon
	}
	var paths []string
	if dir, err := mygo.App.Path(mygo.PathResources); err == nil && dir != "" {
		// PathResources 在 Linux 上就是可执行文件所在目录，而打包把图标放在
		// 其下的 resources/，两个位置都试。
		paths = append(paths,
			filepath.Join(dir, "icon.png"),
			filepath.Join(dir, "resources", "icon.png"))
	}
	paths = append(paths, filepath.Join("resources", "icon.png"))
	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return data
		}
	}
	return nil
}
