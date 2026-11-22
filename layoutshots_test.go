package main

// 视觉回归用的截图生成器：默认跳过，需要时设置 EASYCONNECT_SHOTS=1 运行，
// 会在 build/shots 下把四个页面与四个弹窗渲染成 PNG，方便逐张核对样式。
//
//	EASYCONNECT_SHOTS=1 go test -run TestLayoutShots .
//
// 与普通单元测试分开：它写文件、只适合人工看，不适合 CI。

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

func TestLayoutShots(t *testing.T) {
	if os.Getenv("EASYCONNECT_SHOTS") != "1" {
		t.Skip("设置 EASYCONNECT_SHOTS=1 才渲染截图")
	}
	a := layoutApp(t)
	a.bus.Add(vpn.AccessFail, "生产报表数据库 127.0.0.1:3306 本地端口被占用")
	a.bus.Add(vpn.AccessFail, "IntelliJ IDEA 接管失败：出口接入点已失效")

	out, err := filepath.Abs(filepath.Join("build", "shots"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	shot := func(name string, tab int, dark bool, w, h int) {
		a.tab = tab
		tt := ui.NewTester(a.view, w, h)
		tt.SetDark(dark)
		tt.Frame()
		f, err := os.Create(filepath.Join(out, name+".png"))
		if err != nil {
			t.Fatal(err)
		}
		if err := png.Encode(f, tt.Image()); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
		t.Logf("wrote %s.png (%dx%d dark=%v)", name, w, h, dark)
	}

	shot("01-points", 0, false, 1120, 780)
	shot("02-resources", 1, false, 1120, 780)
	shot("03-access", 2, false, 1120, 780)
	shot("04-localapps", 3, false, 1120, 780)
	shot("05-points-narrow", 0, false, 880, 560)
	shot("06-localapps-narrow", 3, false, 880, 560)
	shot("07-points-dark", 0, true, 1120, 780)
	shot("08-localapps-dark", 3, true, 1120, 780)
	shot("09-resources-dark", 1, true, 1120, 780)
	shot("25-points-min", 0, false, 720, 520)
	shot("26-resources-min", 1, false, 720, 520)
	shot("27-access-dark", 2, true, 880, 560)
	shot("28-localapps-min", 3, false, 720, 520)

	a.openLocalAppEditor(a.cfg.LocalApps[0].ID)
	shot("10-dialog-localapp-editor", 3, false, 1120, 780)
	shot("15-dialog-localapp-editor-min", 3, false, 880, 560)
	a.localEditor.open = false

	a.openSettingsAt(settingGeneral)
	shot("11-settings-general", 0, false, 1120, 780)
	shot("12-settings-general-dark", 0, true, 1120, 780)
	shot("16-settings-general-min", 0, false, 880, 560)
	a.openSettingsAt(settingNetwork)
	shot("18-settings-network", 0, false, 1120, 780)
	a.openSettingsAt(settingLogs)
	shot("19-settings-logs", 0, false, 1120, 780)
	a.openSettingsAt(settingAbout)
	shot("20-settings-about", 0, false, 1120, 780)
	a.settings.open = false
	a.quitAsk = true
	shot("29-dialog-quit-dark", 0, true, 720, 520)
	a.quitAsk = false

	// 接管胶囊展开的样子：就地切换不进设置页，也留一条进设置的深链接。
	a.captureMenuOpen = true
	shot("21-capture-menu", 0, false, 1120, 780)
	shot("22-capture-menu-dark", 0, true, 1120, 780)
	a.captureMenuOpen = false

	// 三套色系各出一张，加绿色系的深色一张：同一份代码、不同的色板。
	for _, name := range themeNames() {
		a.cfg.Settings.Theme = name
		shot("23-theme-"+name, 0, false, 1120, 780)
	}
	a.cfg.Settings.Theme = themeGreen
	shot("24-theme-green-dark", 0, true, 1120, 780)
	a.cfg.Settings.Theme = themeBlue

	if apps := a.allApps(); len(apps) > 0 {
		a.openAppDetail(apps[0])
		shot("13-dialog-app-detail", 1, false, 1120, 780)
		a.detailOpen = false
	}
	if v, ok := a.mgr.View(a.cfg.Points[0].ID); ok {
		a.openEditor(v)
		shot("14-dialog-point-editor", 0, false, 1120, 780)
		shot("17-dialog-point-editor-min", 0, false, 880, 560)
		a.editor.open = false
	}
	t.Logf("shots dir: %s", out)
}
