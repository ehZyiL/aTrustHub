package desktop

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/localapps"
	"github.com/ehzyil/connect-hub/internal/localapps/takeover"
	"github.com/ehzyil/connect-hub/internal/model"
	relayclient "github.com/ehzyil/connect-hub/internal/relay/client"
	relaycontract "github.com/ehzyil/connect-hub/internal/relay/contract"
	"github.com/ehzyil/connect-hub/internal/relay/discovery"
	relayfirewall "github.com/ehzyil/connect-hub/internal/relay/firewall"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/vpn"
	appresources "github.com/ehzyil/connect-hub/resources"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	pairStart     func(context.Context, relaycontract.PairTarget, string) (relaycontract.PairAttempt, error)
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
	resourceTUN  *takeover.Controller
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
