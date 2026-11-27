// easyConnect logs in to several aTrust access points at the same time and
// serves one SOCKS5 proxy for each of them and one over all of them. It is
// a mygo desktop app, and the VPN side is ZJU-Connect's aTrust client.
package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/transfer"
	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/localapps"
	"github.com/ehzyil/connect-hub/internal/model"
	relayclient "github.com/ehzyil/connect-hub/internal/relay/client"
	relaycontract "github.com/ehzyil/connect-hub/internal/relay/contract"
	"github.com/ehzyil/connect-hub/internal/relay/discovery"
	relayfirewall "github.com/ehzyil/connect-hub/internal/relay/firewall"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/vpn"
	appresources "github.com/ehzyil/connect-hub/resources"
)

// version is the app's version.
const version = "0.2.0"

const appName = "Connect Hub"

// app is everything the window shows and the manager that does the work.
// appBuild is shown in the footer and the startup log so an old running
// instance is easy to tell apart from a freshly built one.
const appBuild = "0.2.0"

var embeddedAppIcon = appresources.IconPNG

type app struct {
	win   *mygo.Window
	store *store.Store
	mgr   *vpn.Manager
	bus   *vpn.LogBus
	// lanShare owns A's 局域网分享 lifecycle; lanShareUI and relayImport are its
	// panel drafts (UI thread only).
	lanShare      relayclient.Controller
	lanShareUI    lanShareDraft
	relayImport   relayImportDraft
	relayDiagnose relayDiagnoseDraft
	relayCheck    func(context.Context, relaycontract.ShareCode) ([]string, error)
	relayPoint    relayPointDraft
	// lanDisc is the discovery side of 局域网分享: the publisher that follows the
	// share and the browser that lives only while its page is open.
	lanDisc *lanDiscovery
	// discoveryBackend is the platform seam: nil means real multicast DNS.
	// Tests replace it with an in-memory one, the same way fwExec is replaced.
	discoveryBackend discovery.Backend
	// relayExecutable is an optional test override; production resolves the
	// adjacent core/connect-hub-relay component.
	relayExecutable string
	// askingClearRelayHistory is the node whose protection the user is about to
	// drop; it drives the confirmation dialog.
	askingClearRelayHistory string
	// firewallBusy / firewallNotice / firewallErr are the Windows firewall action
	// state; the fields exist on every platform so the panel code is portable.
	firewallBusy   bool
	firewallNotice string
	firewallErr    string
	// fwOnce/fwRules own every firewall rule this app creates; fwSeen remembers
	// the share state whose rules were already reconciled.
	fwOnce  sync.Once
	fwExec  relayfirewall.FirewallExecutor
	fwRules *relayfirewall.Rules
	fwSeen  fwSeenState
	fwQueue firewallQueue
	// cfg is what the UI thread reads and writes. Background loops must use
	// configForBackground: a whole-struct reassignment while another goroutine
	// reads a field is a data race, and Settings/Points/LocalApps are big enough
	// to tear.
	cfg   model.Config
	cfgMu sync.RWMutex
	// cfgReload asks the UI thread to re-read the Store because a background
	// write made the in-memory copy stale. It is a flag, not a queued value: a
	// queued snapshot could overwrite an edit the user saved in the meantime.
	cfgReload    atomic.Bool
	local        *localapps.Manager
	resourceTUN  *resourceTUNController
	localEditor  localAppDraft
	localCatalog installedAppsCatalog
	localDelete  string
	// localQuery filters the project list by name, target or access point.
	localQuery string
	// captureMenuOpen 是顶栏接管胶囊的下拉是否展开。
	captureMenuOpen bool
	// localCollapsed remembers which access points' project groups are folded
	// (true = folded). A group starts out open.
	localCollapsed map[string]bool
	revealPointID  string // One-time scroll target from a shortcut.
	// windowH is the window content height from the last frame; dialogs use it
	// to size their scrolling body so the footer stays inside the panel.
	windowH   float32
	localLife sync.Mutex
	captureUI platformCaptureSetup
	dir       string
	// keepAlive 记住每个隧道连续探测失败的次数。
	keepAlive tunKeepAlive
	icon      ui.ImageSource
	// qr is the running WeCom QR login drawn in the main window, if any.
	// (qr field removed: WeCom QR login uses a WebView popup now.)
	// ghReachable records whether github.com answered the update check; the
	// footer icon sends the browser to a mirror when it did not.
	ghReachable    bool
	updateRetried  atomic.Bool
	updateChecking atomic.Bool
	// sysProxyOn is whether the app turned the system proxy on. Read by the state
	// ticker and written by the UI thread, so it is atomic.
	sysProxyOn atomic.Bool
	// captureRestored 表示启动后已经试过按记住的接管方式恢复；重试由 3 秒 tick 驱动，
	// 入口一旦监听就不再重复写系统设置。
	captureRestored bool
	// autoCapture 是「启动/登录后自动恢复应用接管」的状态机。
	autoCapture autoCaptureState
	// tray is the notification-area icon that keeps the app alive when the
	// window is closed (Windows), and quitRequested says a quit is intended.
	tray          *mygo.Tray
	quitRequested atomic.Bool
	// heartbeatOnce keeps one goroutine refreshing the helper's alive file.
	heartbeatOnce sync.Once
	cleanup       cleanupState
	// Global TUN state.
	// tunOn / tunPending are read by the background loops and written by the UI
	// thread, so they are atomic; there is no separate mirror to keep in sync.
	tunOn atomic.Bool
	// tunPID is read by shutdownHelper, which can run from a worker goroutine.
	tunPID atomic.Int64
	tunID  string
	// tunWanted is the remembered switch position: after a restart, TUN is
	// resumed for this point once it logs in, so the switch reflects intent.
	tunWanted      atomic.Bool
	tunResumeTried bool
	// captureHiddenLog 记录上一次写进运行日志的「被隐藏档位 + 原因」，
	// 用于去重：同一组原因不重复刷日志。
	captureHiddenLog string
	// tunResumeAt throttles restoring the remembered switch position, so a
	// helper that cannot start is not retried on every tick.
	tunResumeAt time.Time
	// tunResumeFails stops the automatic restore after repeated failures; a
	// fresh login or a switch flip clears it.
	tunResumeFails int
	// probeMu serialises tunnel probes: the helper answers one request file,
	// and two parallel tests would overwrite each other's request.
	probeMu sync.Mutex
	// browserLoginMu keeps one browser login at a time: a second one would
	// launch a browser on a profile the first one already holds.
	browserLoginMu sync.Mutex
	// loginPage is the page of the login window on screen, so the menu can open
	// its developer tools.
	loginPage   *mygo.Page
	loginPageMu sync.Mutex
	// logoutAsk holds the point waiting for the "forget authentication"
	// confirmation.
	logoutAsk string
	// quitAsk shows the confirmation before the app really exits.
	quitAsk bool
	// update holds the newer release found at startup, if any.
	update *updateInfo
	// tunPoints is the online-point snapshot the helper was started with.
	tunPoints string
	// tunDiag rate-limits the rebuild diagnostics to state changes.
	tunDiag string
	// tunGate makes sure only one automatic rebuild runs at a time.
	tunGate atomic.Bool
	// tunSeq serializes starting and stopping the helper.
	tunSeq sync.Mutex
	// Mirrors of the TUN state, so a background goroutine can read it without
	// hopping to the UI thread (win.Update from a plain goroutine can block).
	tunPointsA atomic.Value
	tunIDA     atomic.Value
	// tunPending is true while a start/stop is in flight, so the switch keeps
	// the position the user chose until the async result lands.
	tunPending atomic.Bool
	// tunSwitch / sysProxySwitch are the switch bindings (see the view).
	tunSwitch      bool
	sysProxySwitch atomic.Bool

	// editor is the add/edit dialog.
	editor           editorDraft
	authMu           sync.Mutex
	authRequest      *authenticationRequest
	authDraft        authenticationDraft
	dnsProbe         dnsProbeDraft
	routes           routeDraft
	routeDetailOpen  bool
	routeDetail      string
	certificateProbe certificateProbeDraft
	// settings is the settings dialog.
	settings settingsDraft
	// deleting is the ID whose deletion the app asks about.
	deleting string

	logsOpen bool
	toast    string
	logFile  *os.File

	// tab is 0 for the access points and 1 for the application workbench.
	tab int
	// appQuery filters the workbench.
	appQuery string
	// appSwitch holds one stable boolean per application for its switch:
	// binding a widget to a local makes the click write to a dead address.
	appSwitch map[string]*bool
	// appFilter narrows the workbench to enabled or disabled applications:
	// "all", "on" or "off". appFilterIndex is the segmented control's choice.
	appFilter      string
	appFilterIndex int
	accessFilter   int
	// appCollapsed remembers which access points' app groups are collapsed
	// (true = collapsed). A point is expanded by default.
	appCollapsed map[string]bool
	// siteURL 是简单模式「内网网站」页输入框里的地址，不落盘：
	// 它只是这一次想打开的地址，不是配置。
	siteURL string
	// detailOpen shows one application's details.
	detailOpen    bool
	detailApp     vpn.App
	detailPoint   string
	detailPointID string
	appTestFor    string
	appTestMsg    string
	appTesting    bool

	// loginSem holds the one WeCom login window; see externalLogin.
	loginSem chan struct{}

	// windowHidden 是重绘门控信号：窗口藏在托盘时为 true。
	// 只由 OnClose / showWindow 两处置位，view() 在主线程上用框架的
	// IsVisible() 校正一次，避免两边说法不一致。
	windowHidden atomic.Bool
	// minimized 是第二个门控信号：窗口最小化到任务栏也算不可见。
	// 它与 windowHidden 区分开，因为最小化的窗口 IsVisible() 仍为 true。
	minimized atomic.Bool
	// hiddenSince 等字段收在 idleState 里：它被 UI 线程与 1 秒 ticker 同时访问，
	// 自带锁，外部不直接碰字段。
	idle idleState
	// trimMemoryFn 是测试注入点；生产走 runtime + 平台钩子。
	trimMemoryFn func()

	// redrawOnce 惰性建两档重绘调度器；测试里的 app 没走 newApp。
	redrawOnce sync.Once
	redrawFast *redrawScheduler
	redrawSlow *redrawScheduler
	// logViewActive 是「这一帧的日志面板是否在画」的主线程快照：
	// 日志回调跑在 logger 的 goroutine 上，不能直读 settings/tab。
	logViewActive atomic.Bool

	shutdownOnce sync.Once
	// tickersStop ends the state ticker and the slow maintenance loop; a
	// time.Tick channel can never be released, so both loops own a ticker they can
	// stop.
	tickersStop chan struct{}
	// loadWarnings holds what loading the configuration had to correct, so
	// start() can show it once the log sink exists.
	loadWarnings []string
}

type editorDraft struct {
	protocol               string
	healthTarget           string
	remoteDNS              string
	internalDomains        string
	certificateSHA256      string
	certificateToken       string
	certificateAddress     string
	certificateAcceptedPin string
	advanced               bool
	detailsOpen            bool
	open                   bool
	editingID              string
	name                   string
	address                string
	username               string
	authMode               string
	authModeLabel          string
	cred                   string
	totp                   string
	domain                 string
	socksPort              string
	inPool                 bool
	autoConnect            bool
	// autoPick lets detection choose the auth mode: what a point saved by an
	// older version (mode "auto") gets when it is opened.
	autoPick     bool
	monitor      bool
	monitorEvery string
	secretStore  string
	clearTOTP    bool
	hasPassword  bool
	hasTOTP      bool
	detected     []string
	detecting    bool
	detectGen    int
	detectErr    string
	err          string
}

type settingsDraft struct {
	open bool
	// section 是设置页的当前分区（通用/网络与接管/日志/关于）。
	section int
	// mode 是接管方式下拉的绑定值，每帧从真实状态回读。
	mode string
	// autoRestoreAppCapture 是「启动/登录后自动恢复应用接管」的草稿值。
	autoRestoreAppCapture bool
	// appearance 是颜色模式下拉的草稿值（跟随系统 / 浅色 / 深色）。
	appearance string
	// theme 是主题色系的草稿值（blue / green / purple）。
	theme string
	// quitOnClose 是「关闭主窗口时退出程序」的草稿值（仅 Windows）。
	quitOnClose bool
	host        string
	port        string
	// proxyUser / proxyPass guard the listeners when host is not loopback.
	proxyUser     string
	proxyPass     string
	interval      string
	routing       string
	aggregate     bool
	autoReconnect bool
	secretStore   string
	// hideDock hides the macOS Dock icon; the menu bar icon takes over.
	hideDock bool
	// simpleMode 是简单模式开关的绑定值。它只是界面绑定：真正的持久化与
	// 概念收敛在 setSimpleMode 里，所以它不参与 settingsDirty。
	simpleMode      bool
	autoCheckUpdate bool
	err             string
}

// Run starts the Connect Hub desktop application.
func Run() {
	// 软内存上限：将异常膨胀线设为 128MB，GOGC 适度设为 80，兼顾 CPU 调度与堆常驻规模。
	debug.SetMemoryLimit(memoryLimitBytes)
	debug.SetGCPercent(80)
	// The proxy watchdog is a child of this same executable: it must run before the
	// single-instance lock, otherwise it would just wake the running window.
	if len(os.Args) >= 2 && os.Args[1] == proxyWatchdogFlag {
		runProxyWatchdog(os.Args[2:])
		return
	}
	if runCaptureLauncher() {
		return
	}
	if len(os.Args) == 2 && os.Args[1] == localapps.BrowserSupervisorFlag {
		if err := localapps.RunBrowserSupervisor(os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		return
	}
	mygo.App.SetName(appName)
	mygo.App.SetVersion(version)
	if !mygo.App.RequestSingleInstanceLock() {
		return
	}

	a, err := newApp()
	if err != nil {
		log.Fatalf("Connect Hub: %v", err)
	}
	// Clicking the Dock icon with the window hidden reopens it.
	mygo.App.OnActivate(func(hasVisibleWindows bool) {
		if !hasVisibleWindows {
			a.showWindow()
		}
	})
	mygo.App.OnSecondInstance(func([]string, string) { a.showWindow() })
	mygo.App.WhenReady(a.start)
	mygo.App.OnBeforeQuit(func(e *mygo.QuitEvent) {
		// Cmd+Q and the Dock's 退出 land here too. Ask once, then let the
		// confirmed quit through. If a dialog is already open the request came
		// from the system (logout, shutdown), so do not block it.
		if !a.quitRequested.Load() && !a.quitAsk {
			e.PreventDefault()
			a.askQuit()
			return
		}
		a.shutdown()
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}

func newApp() (*app, error) {
	dir, err := resolveDataDir()
	if err != nil {
		return nil, err
	}
	// New profiles use the OS credential store, falling back to memory only.
	// Preserve an explicit legacy file-store choice without copying it elsewhere.
	secretKind := model.SecretStoreKeychain
	if b, rerr := os.ReadFile(filepath.Join(dir, "config.json")); rerr == nil {
		var pre model.Config
		if json.Unmarshal(b, &pre) == nil && pre.Settings.SecretStore == model.SecretStoreFile {
			secretKind = model.SecretStoreFile
		}
	}
	var secrets store.SecretStore = store.NewSessionSecrets(keychainSecrets{})
	if secretKind == model.SecretStoreFile {
		secrets, err = store.NewFileSecrets(dir)
		if err != nil {
			return nil, err
		}
	}
	st, err := store.Open(dir, secrets)
	if err != nil {
		return nil, err
	}

	a := &app{
		store:     st,
		dir:       dir,
		bus:       vpn.NewLogBus(600),
		loginSem:  make(chan struct{}, 1),
		icon:      loadAppIcon(),
		appSwitch: map[string]*bool{},
		appFilter: "all",
		// A configuration that had to be corrected (for example a LAN
		// listener without credentials) is reported in start(), not swallowed.
		loadWarnings: st.Warnings(),
	}
	logPath := os.Getenv("EASYCONNECT_LOG")
	if logPath == "" {
		logPath = filepath.Join(dir, "app.log")
	}
	// Panics print to stderr, which goes nowhere when the app is started from
	// Finder. Point the descriptor at a file so a crash is never a mystery.
	if errF, err := os.OpenFile(filepath.Join(dir, "stderr.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		redirectStderr(errF)
	}

	// Append, not truncate: restarting the app used to wipe the record of what
	// went wrong right before the restart. Keep the file at a sane size.
	if st, err := os.Stat(logPath); err == nil && st.Size() > 4<<20 {
		_ = os.Rename(logPath, logPath+".1")
	}
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		a.logFile = f
	}
	a.setConfig(st.Config())
	a.tickersStop = make(chan struct{})
	// The system proxy only changes through applySystemProxyFn, and on Windows that
	// function journals what it replaces into this directory.
	setSystemProxyJournalDir(dir)
	a.autoCapture.enabled = a.cfg.Settings.AutoRestoreAppCapture
	a.local = localapps.NewManager(func() {
		// 本机项目的流量通知最多 250ms 一次，属事件源：合并后再画，
		// 且要经门控——不能让托盘里的窗口因流量重建整树。
		a.invalidateCoalesced()
	}, a.logLocalAccess)
	a.local.SetErrorHandler(a.logLocalAppError)
	a.sysProxyOn.Store(systemProxyOwned(a.systemProxyAddress()))
	a.tunWanted.Store(a.cfg.Settings.TunEnabled)
	a.bus.Add("app", fmt.Sprintf("Connect Hub %s 启动，数据目录 %s", appBuild, dir))
	a.mgr = vpn.NewManager(
		vpn.NewProtocolConnector(vpn.ZJUOptions{
			DataDir: dir,
			Debug:   os.Getenv("EASYCONNECT_DEBUG") != "",
		}, a.relayConnector()),
		a.credentials,
		a.bus,
		// 接入点状态变化也是事件源：合并到 33ms 一帧，交互路径另走即时。
		a.invalidateCoalesced,
	)
	a.mgr.Apply(a.cfg)
	a.setupLANShare()
	// Load attribution history before anything may connect or be taken over:
	// a missing or broken cache must be known before the first dial decides
	// whether an unowned target may go direct.
	a.loadRelayKnown()
	a.setupResourceTUN()
	return a, nil
}

// loadAppIcon reads the icon mygo packages as resources/icon.png, for the
// window header. The Dock icon comes from the same file at build time.
func loadAppIcon() ui.ImageSource {
	if len(embeddedAppIcon) > 0 {
		if src, err := ui.DecodeBitmap(embeddedAppIcon); err == nil {
			return src
		}
	}
	var paths []string
	if dir, err := mygo.App.Path(mygo.PathResources); err == nil && dir != "" {
		paths = append(paths, filepath.Join(dir, "icon.png"))
	}
	paths = append(paths, filepath.Join("resources", "icon.png"))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if src, err := ui.DecodeBitmap(data); err == nil {
			return src
		}
	}
	return nil
}

func resolveDataDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("CONNECT_HUB_HOME")); dir != "" {
		return dir, os.MkdirAll(dir, 0o700)
	}
	if dir := strings.TrimSpace(os.Getenv("EASYCONNECT_HOME")); dir != "" {
		return dir, os.MkdirAll(dir, 0o700)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	targetDir := filepath.Join(base, "connect-hub")
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		// 自动检查并迁移所有可能存在的历史旧目录（带空格或老名字）
		for _, oldName := range []string{"EasyConnectHub", "EasyConnect Hub", "Connect Hub"} {
			oldDir := filepath.Join(base, oldName)
			if fi, err := os.Stat(oldDir); err == nil && fi.IsDir() {
				if renameErr := os.Rename(oldDir, targetDir); renameErr == nil {
					break
				}
			}
		}
	}
	return targetDir, os.MkdirAll(targetDir, 0o700)
}

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

// 状态机由后台 ticker 驱动（见 startStateTicker），重绘走 redraw.go：
// invalidate 只负责「画」，不再推进任何业务状态。

// maybeResumeTUN re-opens global TUN whenever the remembered switch position
// is "on" and an access point is online again. The position is recorded when
// the switch is flipped, so turning TUN off survives a restart and a new login,
// while turning it on means the next login brings it back.
func (a *app) maybeResumeTUN() {
	if !a.canUseGlobalTUN() {
		return
	}
	if !a.tunWanted.Load() || a.tunOn.Load() || a.tunPending.Load() {
		return
	}
	if time.Now().Before(a.tunResumeAt) {
		return
	}
	if a.tunResumeFails >= 3 {
		return
	}
	id := pickResumePoint(a.configForBackground().Settings.TunPointID, a.mgr.Views())
	if id == "" {
		// 没有在线接入点：把失败计数清零，等下一次登录再试。
		a.tunResumeFails = 0
		return
	}
	a.tunResumeAt = time.Now().Add(30 * time.Second)
	a.tunResumeFails++
	a.tunLogf("按上次的状态恢复全局 TUN（%s，第 %d 次尝试）", id, a.tunResumeFails)
	go a.startGlobalTUN(id)
}

// credentials reads what the manager needs for one login.
//
// The flow follows the configured auth mode, so the same "登录" button
// works everywhere: the password mode signs in by itself, WeCom opens the
// QR popup, and third-party SSO resumes the session the browser login
// saved.
func (a *app) credentials(id string) (vpn.Credentials, error) {
	cfg := a.configForBackground()
	point := cfg.Find(id)
	mode := model.AuthModePassword
	if point != nil && point.AuthMode != "" {
		mode = model.AuthMode(point.AuthMode)
	}
	var external func(context.Context, string) (string, error)
	if point != nil && (mode == model.AuthModeAuto || mode == model.AuthModeWeCom) {
		name, server := point.Name, point.Server
		// WeCom always uses the app's own popup now. Only a legacy "auto"
		// point keeps the old "hand over to the system browser" switch.
		inBrowser := mode == model.AuthModeAuto && point.LoginInBrowser
		external = func(ctx context.Context, loginURL string) (string, error) {
			cb, err := a.externalLogin(ctx, name, server, loginURL, inBrowser)
			if errors.Is(err, errWeComLocalUnavailable) && point != nil && browserExecutable() != "" {
				// 客户端只把本地桥开放给浏览器，本程序直接连会被重置；这时
				// 交给真实浏览器，页面自己会去敲本地桥并弹确认框。
				a.tunLogf("[%s] 本地企业微信认证不可用，改用系统浏览器完成", name)
				return a.cdpLoginCallback(ctx, point, loginURL)
			}
			return cb, err
		}
	}
	switch mode {
	case model.AuthModeWeCom:
		if external == nil {
			return vpn.Credentials{}, vpn.ErrNoCredentials
		}
		return vpn.Credentials{ExternalLogin: external}, nil
	case model.AuthModeSSO:
		// 这里没有账号密码：由真正的浏览器走完单点登录并交回授权码，
		// 登录本身仍由客户端完成，隧道才用得上它自己的设备号与签名。
		if browserExecutable() != "" {
			return vpn.Credentials{ExternalLogin: func(cbCtx context.Context, loginURL string) (string, error) {
				return a.cdpLoginCallback(cbCtx, point, loginURL)
			}}, nil
		}
		// 没有 Chromium 时退回应用内置窗口，走同一条单点登录。
		if external != nil {
			return vpn.Credentials{ExternalLogin: external}, nil
		}
		return vpn.Credentials{}, nil
	}

	cred, err := a.store.Password(id)
	if err != nil {
		if strings.Contains(err.Error(), "User canceled") || strings.Contains(err.Error(), "-128") {
			return vpn.Credentials{}, errors.New("读取密码失败：钥匙串访问被取消。请重新登录，并在系统弹窗点「允许」，或编辑接入点重新输入密码")
		}
		if errors.Is(err, store.ErrSecretNotFound) {
			if mode == model.AuthModeAuto {
				// Auto can still use an external login.
				return vpn.Credentials{ExternalLogin: external}, nil
			}
			return vpn.Credentials{}, vpn.ErrNoCredentials
		}
		return vpn.Credentials{}, err
	}
	// EasyConnect requests fresh codes through its challenge handler. A missing
	// or locked keyring must not block a password kept in the session fallback.
	var totp string
	if point == nil || point.Protocol != model.ProtocolEasyConnect {
		totp, err = a.store.TOTP(id)
		if err != nil && !errors.Is(err, store.ErrSecretNotFound) {
			return vpn.Credentials{}, err
		}
	}
	creds := vpn.Credentials{Login: cred, TOTP: totp, ExternalLogin: external}
	// 短信 / 动态口令 / RADIUS 验证码由 zju-connect 的 auth 包主动询问。
	// 不接这里，它就去读标准输入；GUI 子系统进程（Windows 的
	// -H windowsgui）根本没有 stdin，登录会永远卡在 read /dev/stdin。
	codeName := id
	if point != nil && point.Name != "" {
		codeName = point.Name
	}
	creds.PromptCode = func(ctx context.Context, req vpn.CodeRequest) (string, error) {
		// 没人理这个弹窗时不要拖到连接的 5 分钟超时：那会把登录信号量
		// 也一直占着，后面的重试只能干等。
		ctx, cancel := context.WithTimeout(ctx, loginCodeTimeout)
		defer cancel()
		return a.requestAuthentication(ctx, codeName, codeChallenge(req))
	}
	if point != nil && point.Protocol == model.ProtocolEasyConnect {
		name := point.Name
		creds.Challenge = func(ctx context.Context, ch vpn.Challenge) (string, error) {
			return a.requestAuthentication(ctx, name, ch)
		}
	}
	return creds, nil
}

// loginCodeTimeout bounds how long a code dialog may stay unanswered before
// the login gives up. It is shorter than the 5-minute connect deadline on
// purpose: one abandoned dialog must not hold the login slot for the whole
// connection attempt. A variable so the guard is testable.
var loginCodeTimeout = 3 * time.Minute

// codeChallenge turns one login code request into the shape the app's
// authentication dialog already draws: the same modal asks for EasyConnect
// captchas and for aTrust SMS/TOTP/RADIUS codes.
func codeChallenge(req vpn.CodeRequest) vpn.Challenge {
	kind := "totp"
	switch req.Kind {
	case vpn.CodeSMS, vpn.CodeCustomSMS:
		kind = "sms"
	case vpn.CodeRADIUS:
		kind = "radius"
	}
	return vpn.Challenge{Kind: kind, Tip: req.Tip}
}

func (a *app) hasPassword(id string) bool {
	_, err := a.store.Password(id)
	return err == nil
}

func (a *app) hasTOTP(id string) bool {
	_, err := a.store.TOTP(id)
	return err == nil
}

// saveConfig writes the in-memory configuration and tells the manager.
func (a *app) saveConfig() error {
	if err := a.store.Save(); err != nil {
		return err
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	return nil
}

func (a *app) copyText(text string) {
	if text == "" {
		return
	}
	if err := mygo.Clipboard.Write(transfer.TextData(text)); err != nil {
		a.toast = "复制失败：" + err.Error()
		a.invalidate()
		return
	}
	// Keep the notice short: showing the copied text itself made the toast
	// cover the window when a whole log was copied.
	if lines := strings.Count(text, "\n") + 1; lines > 1 {
		a.toast = fmt.Sprintf("已复制 %d 行", lines)
	} else {
		a.toast = "已复制：" + shortText(text, 40)
	}
	a.invalidate()
}

// shortText clips s for a one-line notice.
func shortText(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len([]rune(s)) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "…"
}

// setConfig publishes a new configuration. Every writer must go through it so a
// background reader can take a consistent copy instead of racing a whole-struct
// reassignment.
func (a *app) setConfig(cfg model.Config) {
	a.cfgMu.Lock()
	a.cfg = cfg
	a.cfgMu.Unlock()
}

// requestConfigReload tells the UI thread that the persisted configuration
// changed and asks for a repaint. Background code calls this instead of writing
// a.cfg: the UI thread owns that struct, and every reader of it (labels,
// panels, the whole render pass) would otherwise race a background write.
func (a *app) requestConfigReload() {
	a.cfgReload.Store(true)
	a.invalidate()
}

// applyPendingConfigReload runs on the UI thread before anything renders from
// a.cfg. It re-reads the Store at that moment rather than accepting a copy
// captured earlier, so a stale notification can never roll back a newer edit.
func (a *app) applyPendingConfigReload() {
	if !a.cfgReload.Swap(false) {
		return
	}
	if a.store == nil {
		return
	}
	next := a.store.Config()
	a.setConfig(next)
	if a.mgr != nil {
		a.mgr.Apply(next)
	}
}

// configForBackground returns a copy for goroutines that are not the UI thread.
// It runs at most a few times per second, so the copy is cheap next to the probe
// or dial it precedes.
func (a *app) configForBackground() model.Config {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.cfg.Clone()
}

// localAppIDsForBackground returns just the local-app IDs. The state ticker asks
// for them once a second, and cloning the whole configuration (access points,
// route policies, DNS bindings, every argument list) to read a handful of IDs is
// pure garbage — worse, that cost grows with the user's configuration, not with
// the work actually done.
func (a *app) localAppIDsForBackground() []string {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	ids := make([]string, len(a.cfg.LocalApps))
	for i := range a.cfg.LocalApps {
		ids[i] = a.cfg.LocalApps[i].ID
	}
	return ids
}

// mutateConfig edits the in-memory configuration under the write lock. It is for
// the settings the app changes outside Store.Update (auto restore intent).
func (a *app) mutateConfig(fn func(*model.Config)) {
	a.cfgMu.Lock()
	fn(&a.cfg)
	a.cfgMu.Unlock()
}

func (a *app) describeProgress() string {
	online, connecting, total := a.mgr.Counts()
	switch {
	case total == 0:
		return "还没有接入点"
	case connecting > 0:
		return fmt.Sprintf("%d 个在线，%d 个登录中", online, connecting)
	default:
		return fmt.Sprintf("%d / %d 个在线", online, total)
	}
}

// guardSystemProxy turns the system proxy back off when the unified entry it
// points at is no longer listening. Leaving it on would cut the whole machine
// off, which is worse than losing the VPN.
func (a *app) guardSystemProxy() {
	if a.resourceTUNActive() {
		return
	}
	if !a.sysProxyOn.Load() {
		return
	}
	if a.releaseLostSystemProxy() {
		return
	}
	agg := a.mgr.Aggregate()
	if agg.Running && agg.Addr != "" {
		if conn, err := net.DialTimeout("tcp", agg.Addr, 1500*time.Millisecond); err == nil {
			_ = conn.Close()
			return
		}
	}
	_ = applySystemProxyFn("127.0.0.1:0", false)
	a.sysProxyOn.Store(false)
	a.sysProxySwitch.Store(false)
	// 这是本应用自己关的（入口死了），不是用户放弃接管：入口回来后
	// maybeRestoreCaptureMode 要能把它接回来。用户手动关代理走的是
	// releaseLostSystemProxy，不会走到这里，所以不会被反复抢回去。
	a.captureRestored = false
	a.tunLogf("统一入口已停止监听，已自动关闭系统代理以恢复网络")
	a.toast = "统一入口已停止，已自动关闭系统代理"
	a.invalidate()
}

// maybeRestoreCaptureMode 在启动后按记住的接管方式接管系统代理。默认（也是首次运行）
// 是系统代理：统一入口一开始监听就把它指过去。全局 TUN 有自己的 tunEnabled 恢复路径；
// 应用接管的自动恢复由 auto_capture.go 的独立开关负责，不在这里处理——但这里负责
// 说清楚「上次用的是应用接管、这次为什么不接管」（否则会静默停在「不使用」）。
func (a *app) maybeRestoreCaptureMode() {
	if a.captureRestored {
		return
	}
	// 记着 TUN 意图时让路：TUN 自带 30 秒/3 次的限流重试，别让系统代理抢在它
	// 前面接管。这里也不标记已处理——TUN 因为环境原因放弃后，后续还能再判断。
	cfg := a.configForBackground()
	if cfg.Settings.TunEnabled {
		return
	}
	// 这一档的自动恢复只认「上次生效的就是系统代理」。其它档位在这里让路，
	// 但要先把话说明白：只提示一次，不改变任何接管行为。
	if cfg.Settings.CaptureMode != model.CaptureModeSystem {
		a.noticeAppCaptureNotRestored(cfg)
		a.captureRestored = true
		return
	}
	// macOS 写系统代理要一次管理员授权，每次启动弹密码不可接受；Linux 没有这一档。
	if !supportsAutoSystemProxy() {
		a.captureRestored = true
		return
	}
	// 已经有别的接管方式在负责流量，或者系统代理本来就指着本应用：不用再动。
	if a.tunOn.Load() || a.tunPending.Load() || a.resourceTUNActive() || a.sysProxyOn.Load() {
		a.captureRestored = true
		return
	}
	agg := a.mgr.Aggregate()
	if !cfg.Settings.AggregateEnabled {
		a.captureRestored = true
		a.tunLogf("未自动开启系统代理：统一入口已在设置里关闭")
		return
	}
	if agg.Error != "" {
		a.captureRestored = true
		a.tunLogf("未自动开启系统代理：统一入口不可用（%s）", agg.Error)
		return
	}
	if !agg.Running || agg.Addr == "" {
		return // 入口还没监听，下一轮再看
	}
	// 指到一个没人听的端口会让整台机器断网：先确认它真的在听。
	conn, err := net.DialTimeout("tcp", agg.Addr, 2*time.Second)
	if err != nil {
		return
	}
	_ = conn.Close()
	_, port, err := net.SplitHostPort(agg.Addr)
	if err != nil {
		a.captureRestored = true
		a.tunLogf("未自动开启系统代理：入口地址无法解析（%s）", agg.Addr)
		return
	}
	a.captureRestored = true
	a.enableSystemProxyByDefault(net.JoinHostPort("127.0.0.1", port))
}

// enableSystemProxyByDefault 打开系统代理，但不覆盖别人已经设好的代理：系统代理
// 全机只有一份，抢过来等于替用户改掉了他自己的分流。
//
// 没接管成功时日志和界面提示都写一次：日志在设置页的「状态与日志」里，而用户这
// 一刻看的是首屏，只说在日志里，“登录后没接管”就像是本应用没干活。
func (a *app) enableSystemProxyByDefault(target string) {
	if systemProxyForeignFn(target) {
		// 带上实测值：否则“已被其他软件设置”无法区分是谁占着、占着哪个地址。
		// 再点明它是 Windows 全局设置：删掉应用的数据目录不会影响它，不说清用户会
		// 以为“清空数据 = 恢复默认”，然后觉得提示在胡说。
		detail := systemProxyStateFn(target)
		a.tunLogf("系统代理已被其他软件设置，未自动开启（%s；本应用入口 %s）。"+
			"系统代理是 Windows 全局设置，与数据目录无关；要接管请先关掉占用它的软件，再到下拉里选「系统代理」",
			detail, target)
		a.setToast("系统代理是 Windows 全局设置，现被其他软件占用（" + detail +
			"，本应用入口 " + target + "），本次未自动接管；要接管请先关掉那个软件的系统代理")
		return
	}
	if err := applySystemProxyFn(target, true); err != nil {
		a.tunLogf("自动开启系统代理失败：%v", err)
		a.setToast("自动开启系统代理失败：" + err.Error())
		return
	}
	a.sysProxyOn.Store(true)
	a.tunLogf("网络接管：已按默认设置开启系统代理 %s", target)
	a.invalidateCoalesced()
}

// firstPointID returns the first id of a comma-joined snapshot.
func firstPointID(snapshot string) string {
	for _, id := range strings.Split(snapshot, ",") {
		if id = strings.TrimSpace(id); id != "" {
			return id
		}
	}
	return ""
}

// teardownTUNOnExit stops the helper, makes sure the system DNS is not left
// pointing at 127.0.0.1, and clears the control files.
func (a *app) teardownTUNOnExit() {
	pidPath := filepath.Join(a.dir, "tun.pid")
	_, pidErr := os.Stat(pidPath)
	if !a.tunOn.Load() && pidErr != nil && a.tunPID.Load() <= 0 {
		// 没开过 TUN，但上一次可能被强杀留下了 DNS 劫持，仍然兜底一次。
		return
	}
	// 给 helper 足够时间自己退出：它会在退出前把 DNS 交还系统。
	if !a.shutdownHelper(6 * time.Second) {
		a.tunLogf("退出：helper 未在 6 秒内退出，强制结束后重置 DNS")
	}
	// helper 被强杀时来不及恢复 DNS，这里再兜底一次。
	a.tunOn.Store(false)
	a.tunPID.Store(0)
	for _, name := range []string{"tun.stop", "tun.pid", "tun.reload", "tun.probe", "tun.probe.result"} {
		_ = os.Remove(filepath.Join(a.dir, name))
	}
	a.tunLogf("退出：TUN 已清理，DNS 已交还系统")
}

// disableSystemProxyOnExit turns the system proxy off before quitting, retrying
// once because a failed revert leaves the machine with no usable network.
func (a *app) disableSystemProxyOnExit() {
	if !a.sysProxyOn.Load() {
		return
	}
	if a.releaseLostSystemProxy() {
		return
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := applySystemProxyFn("127.0.0.1:0", false); err == nil {
			a.sysProxyOn.Store(false)
			a.tunLogf("退出：已关闭系统代理")
			return
		} else {
			a.tunLogf("退出：关闭系统代理失败（第 %d 次）：%v", attempt+1, err)
		}
	}
}
