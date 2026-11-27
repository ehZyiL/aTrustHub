package desktop

import (
	"errors"
	"fmt"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"log"
	"runtime"
	"time"
)

// setupMenu installs the app menu. It keeps the usual App/Edit/Window menus
// and adds a 视图 menu whose 开发者工具 item (F12) opens the login window's
// inspector on request. On macOS, this becomes the global menu bar; on other
// platforms, the window has no top-level menu bar to keep the UI clean.
func (a *app) setupMenu() {
	if runtime.GOOS != "darwin" {
		return
	}
	menu := mygo.NewMenu([]*mygo.MenuItem{
		{Role: mygo.RoleAppMenu},
		{Role: mygo.RoleEditMenu},
		{Label: "视图", Submenu: []*mygo.MenuItem{
			{Label: "开发者工具（登录窗口）", Accelerator: "F12", Click: func(*mygo.MenuItem, *mygo.Window) {
				a.openLoginDevTools()
			}},
			{Label: "开发者工具", Accelerator: "CmdOrCtrl+Shift+I", Click: func(*mygo.MenuItem, *mygo.Window) {
				a.openLoginDevTools()
			}},
			mygo.Separator(),
			{Role: mygo.RoleViewMenu},
		}},
		{Role: mygo.RoleWindowMenu},
	})
	mygo.App.SetMenu(menu)
}

// setLoginPage records (or clears) the page of the login window on screen.
func (a *app) setLoginPage(p *mygo.Page) {
	a.loginPageMu.Lock()
	a.loginPage = p
	a.loginPageMu.Unlock()
}

// openLoginDevTools opens the developer tools of the login window: what F12 in
// the 视图 menu does. Opening it unprompted froze the whole app, so the user
// asks for it.
func (a *app) openLoginDevTools() {
	a.loginPageMu.Lock()
	p := a.loginPage
	a.loginPageMu.Unlock()
	if p == nil {
		a.toast = "先打开一个接入点的登录窗口"
		a.win.Update(func() {})
		return
	}
	p.OpenDevTools()
}

func (a *app) start() {
	a.createWindow()

	// ZJU-Connect logs through the standard logger. Show its lines in the
	// app's own log panel, with the time the bus adds, not two timestamps.
	log.SetFlags(0)
	a.bus.SetSink(a.logFile)
	a.bus.Add("app", fmt.Sprintf("Connect Hub %s 启动（窗口就绪），数据目录 %s", appBuild, a.dir))
	for _, warning := range a.loadWarnings {
		a.bus.Add("app", "配置："+warning)
		a.toast = warning
	}
	log.SetOutput(a.bus.Writer("zju"))
	a.bus.SetNotify(a.onLogEvent)
	go a.tailAccessLog()
	a.mgr.SetDataDir(a.dir)
	// 上一轮如果被强杀，root helper 可能还占着 127.0.0.1:53。
	a.cleanupStaleHelper()
	a.mgr.Start()
	// A share switched on before the restart resumes here; one that was
	// switched off stays off, and an offline access point leaves it waiting.
	a.resumeLANShare()
	// Recovery runs before the app decides whether it currently owns the system
	// proxy, and it never depends on the aggregate listener: the recorded address
	// is read from the record. Both recoveries are idempotent, so a clean start
	// costs two stat calls.
	if err := a.recoverSystemProxy(); err != nil {
		a.tunLogf("系统代理恢复：%v", err)
		// A value another program owns is normal and self-heals on the next
		// explicit takeover, so it stays in the log. A record that cannot be read
		// is worth telling the user about.
		if !errors.Is(err, errProxyOwnedElsewhere) {
			a.toast = "上次的系统代理未能恢复：" + err.Error()
		}
	}
	if runtime.GOOS == "windows" {
		if err := recoverResourceProxy(a.dir); err != nil {
			a.tunLogf("系统捕获代理恢复：%v", err)
		}
		a.sysProxyOn.Store(systemProxyOwned(a.systemProxyAddress()))
	}

	// 状态机独立于重绘：每秒推进一次 TUN / 代理保活与流量计时，
	// 窗口藏在托盘时也照跑，只是不画。
	go a.startStateTicker()
	a.startUpdateScheduler()

	// A slow tick makes TUN follow the online set even when no log line or
	// click happens to trigger a repaint.
	go func() {
		last := time.Now()
		lastDNSCheck := time.Now()
		dnsFails := 0
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			select {
			case <-a.tickersStop:
				return
			default:
			}
			a.reconcileLocalApps()
			a.maybeRefreshTUN()
			a.checkTunnels()
			a.guardSystemProxy()
			a.maybeRestoreCaptureMode()
			a.maybeAutoRestoreAppCapture()
			// TUN 把系统 DNS 指向自己；它一旦不应答，整台机器就上不了网。
			// 连续两次检查失败就主动关掉 TUN，把网络还给系统。
			if a.tunOn.Load() && time.Since(lastDNSCheck) > 20*time.Second {
				lastDNSCheck = time.Now()
				if snapshot, _ := a.tunPointsA.Load().(string); snapshot != "" {
					name := a.dnsProbeName(firstPointID(snapshot))
					if helperAnswersDNS(3*time.Second, name) {
						dnsFails = 0
					} else {
						dnsFails++
						a.tunLogf("DNS 自检失败（%d/3，探测 %s）", dnsFails, name)
						if dnsFails >= 3 {
							dnsFails = 0
							a.tunLogf("TUN 的 DNS 不再应答，自动关闭 TUN 以恢复系统网络")
							go a.stopTUNSerialized()
							a.win.Update(func() {
								a.toast = "TUN 的 DNS 停止应答，已自动关闭 TUN 以恢复网络"
							})
						}
					}
				}
			}
			if time.Since(last) > 60*time.Second {
				last = time.Now()
				a.tunLogf("旧版 TUN 巡检：on=%v pending=%v 已建=%q 当前=%q", a.tunOn.Load(), a.tunPending.Load(), func() string { s, _ := a.tunPointsA.Load().(string); return s }(), a.onlineSnapshot())
				// 重绘统计：验证「隐藏时重绘 0 次」不用靠感觉。
				fast, slow, draws, coalesced, gated := a.redrawCounts()
				a.tunLogf("重绘统计：共 %d 帧（快 %d / 慢 %d），合并 %d 条，隐藏丢弃 %d 条",
					draws, fast, slow, coalesced, gated)
			}
		}
	}()

	// Ask GitHub for a newer release in the background, so a blocked mirror
	// can never hold up the window.
	a.setupMenu()
	// Desktop quick-login diagnostics go to the same log the user reads.
	wecomLogHook = func(line string) { a.bus.Add("app", line) }
	a.ghReachable = true
	// 稍等一下再查：启动时刚把系统 DNS 还回去，立刻查询多半还没通。
	// This fork has no release feed yet. Do not offer the original app's
	// binary as an update to an EasyConnect build.

	// Make sure the first window is on screen even if the remembered state or
	// an early activation left it hidden.
	a.win.Show()
	a.win.Focus()
}

// createWindow builds the main window and its handlers. It runs again when a
// stale window was destroyed, so the app can always be reopened.
func (a *app) createWindow() {
	a.win = mygo.NewWindow(mygo.WindowOptions{
		Title:           appName,
		Width:           880,
		Height:          600,
		MinWidth:        720,
		MinHeight:       520,
		StateKey:        "main",
		BackgroundColor: "light-dark(#f7f7f9, #17181a)",
		Content:         ui.View(a.view),
		AutoHideMenuBar: true,
	})
	if iconBytes := loadAppIconPNG(); len(iconBytes) > 0 {
		_ = a.win.SetIcon(iconBytes)
	}
	// Closing the window hides it instead of quitting: tunnels, TUN and the
	// tray/menu bar icon stay alive. Only 退出 really quits.
	// 窗口生命周期与重绘门控绑在一起：藏进托盘或最小化都停止重绘，
	// 回到前台/还原时补一帧。
	a.win.OnMinimize(a.onWindowMinimized)
	a.win.OnRestore(a.onWindowRestored)
	a.win.OnClose(func(e *mygo.CloseEvent) {
		a.tunLogf("OnClose: quitRequested=%v", a.quitRequested.Load())
		if a.quitRequested.Load() {
			return
		}
		// 托盘可能在上次启动时没建起来（图标缺失、扩展刚装上），关窗前
		// 在 Linux 上再试一次；建不起来就按「关窗即退出」处理。
		// macOS 不走这条路：它的菜单栏图标只在隐藏 Dock 图标时才建，
		// 由 hideToTray → updateDockVisibility 自己决定。
		if runtime.GOOS == "linux" {
			a.setupTray()
		}
		// 三种习惯（Linux/Windows 可配 / macOS 隐藏）统一在这里决定。
		switch closeActionFor(runtime.GOOS, a.cfg.Settings.QuitOnClose, a.hasActiveWork(), a.tray != nil) {
		case closeQuit:
			a.quitRequested.Store(true)
			a.shutdown()
			mygo.App.Quit()
		case closeConfirm:
			// 还有连接在跑：先弹确认，取消时窗口会重新回到前台。
			e.PreventDefault()
			a.askQuit()
		default:
			e.PreventDefault()
			a.hideToTray()
		}
	})
	// A window on screen means a Dock icon, whatever the closing behaviour is.
	a.updateDockVisibility(false)
	a.startupTray()
}

func (a *app) shutdown() {
	a.shutdownOnce.Do(func() {
		// Stop the background loops first: they read the manager and the data
		// directory that the rest of this function is about to dismantle.
		if a.tickersStop != nil {
			close(a.tickersStop)
			a.tickersStop = nil
		}
		// 先把排队的重绘停掉：窗口马上要销毁，别再排新的帧。
		a.stopPainting()
		a.shutdownCleanup()
		if a.resourceTUN != nil {
			if err := a.resourceTUN.Close(); err != nil {
				a.tunLogf("系统捕获清理未完成：%v", err)
				a.sysProxyOn.Store(false)
			}
		}
		a.closeCaptureSetup()
		// A real quit: window closes must go through, or macOS cancels the
		// termination and the process stays alive with no usable UI.
		a.quitRequested.Store(true)
		if a.dnsProbe.cancel != nil {
			a.dnsProbe.cancel()
		}
		if a.certificateProbe.cancel != nil {
			a.certificateProbe.cancel()
		}
		// 退出时两件事必须做到：TUN 的 utun/路由/DNS 全部还原，系统代理关掉。
		// 否则用户下次开机就是「没网」，而且看不出是谁干的。
		// Stop the share before the VPN sessions it borrows go away, keeping
		// the enable intent so the next start resumes it.
		a.shutdownLANShare()
		a.teardownTUNOnExit()
		a.disableSystemProxyOnExit()
		if a.local != nil {
			_ = a.local.Close()
		}
		if a.mgr != nil {
			a.mgr.Close()
		}
		if a.logFile != nil {
			_ = a.logFile.Close()
		}
	})
}
