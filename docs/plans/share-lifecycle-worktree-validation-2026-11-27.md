# 独立 worktree：共享生命周期与 UI 响应验证

日期：2026-11-27。测试分支：`test/share-lifecycle-20261127`。
结论：既有回归、资源启停和配套构建通过；新增诊断稳定发现共享启动期间的 UI 锁等待，尚未修复。

## 相关文件

本轮新增：

- `scripts/test-share-ui.ps1`：通过 Go overlay 单独加载诊断，记录日志并保留测试退出码。
- `scripts/diagnostics/share_ui_test.go.txt`：启动状态读取、启动绘制和关闭绘制三个探针。
- `docs/plans/share-lifecycle-worktree-validation-2026-11-27.md`：本报告。

分析及参考文件：

- `internal/relay/controller.go`：状态读取、启用和 reconcile 的锁范围。
- `internal/relay/process/process.go`、`command.go`：组件版本探测、启动和命令构造。
- `internal/relay/firewall/firewall_windows.go`：防火墙说明查询的实现。
- `internal/desktop/view.go`、`lanshare_firewall.go`：每帧读取共享状态的调用链。
- `internal/desktop/view_test.go`、`lanshare_view_test.go`、`lan_discovery_test.go`：既有 app、控制器和等待 fixture。
- `internal/desktop/lan_discovery_async_test.go`、`pairing_test.go`、`optional_lifecycle_test.go`、`resource_baseline_test.go`：异步阻塞、配对、启停和资源测量模式。
- `scripts/build.ps1`、`scripts/buildtool/main.go`：统一构建和 manifest。
- `docs/plans/fix-relay-import-2026-11-27.md`、`lan-invitation-pairing-fixes-2026-11-27.md`、`p6-resource-validation-2026-11-27.md`：前次修复、边界和验证方法。

原始日志与构建目录位于 `build/`，按仓库规则不纳入提交。

## 来源与隔离

```text
原工作区：D:\Programming\Projects\Go\easy-connect\aTrustHub
新 worktree：D:\Programming\Projects\Go\easy-connect\aTrustHub-wt-share-lifecycle
起点：a2bc55f9e4c726f3781245cf7ee921c606298482
诊断与构建提交：f36e5ce0881e40064a450dda6bf97a85cc87b722
固定内核：5929e30fd988f7e3efd3fbbbfffc7a7087e26f44
环境：Go 1.27.4，Windows/amd64，PowerShell 7，GOWORK=off
```

起点包含邀请配对、取消邮箱隔离、未认证连接回收及已配对通道回归。
本轮只新增测试诊断与记录，没有修改生产实现、合并回原分支或替换运行中的程序。
原工作区当前另有未提交修改及未跟踪的 `go.work`、`go.work.sum`，不属于本次被测快照。

## 已执行检查

| 检查 | 次数 | 结果 | 日志 |
|---|---:|---|---|
| 重点回归 | 3 | 4 个包，累计 138 个测试项通过，零失败 | `build/share-lifecycle-checks/focused.jsonl` |
| 默认全量 | 1 | 30 个测试包，1146 个测试项通过，9 个跳过，零失败 | `build/share-lifecycle-checks/full.jsonl` |
| go vet | 1 | 通过 | `build/share-lifecycle-checks/vet.log` |
| opt-in 资源与生命周期 | 3 | 三个用例各运行三次，累计 9 项通过 | `build/share-lifecycle-checks/resources.jsonl` |
| 单独 UI 阻塞诊断 | 3 | 启动状态读取和绘制各失败三次；关闭对照通过三次 | `build/share-lifecycle-checks/share-ui-probe.log` |

测试项计数包含子测试。默认全量测试不包含通过 overlay 加载的诊断，不能将全量通过解释为共享启动流畅性验收通过。

```powershell
$env:GOWORK = 'off'
go test -json -mod=readonly ./internal/desktop ./internal/relay ./internal/relay/discovery ./internal/relay/process `
  -run 'TestRelayImport|TestRelayCommand|TestDiscoveryProcess|TestDiscoveryRuntime|TestOptionalResources|TestUnusedSharing|TestIdleDiscovery|TestPairing|Test.*(Reclaim|Unauthenticated|Cancel)' `
  -count=3 -timeout=180s
go test -json -mod=readonly ./... -count=1 -timeout=180s
go vet -mod=readonly ./...

$env:CONNECT_HUB_MEASURE_RESOURCES = '1'
go test -json -mod=readonly ./internal/desktop `
  -run '^(TestOptionalResourceBaseline|TestUnusedSharingHasNoBackgroundTasks|TestOptionalResourcesStopAndRestartTenTimes)$' `
  -count=3 -timeout=90s
Remove-Item Env:CONNECT_HUB_MEASURE_RESOURCES
```

默认跳过项为两项 live CDP、两项浏览器启动/关闭、布局截图、打包清理检查、防火墙辅助程序路径、relay 资源 profile 和可选资源 baseline。
最后一项随后通过 opt-in 单独执行；其余跳过项没有据此声称通过。

## 新发现：启动期间状态读取阻塞

复现命令：

```powershell
./scripts/test-share-ui.ps1 -Count 3
```

当前命令退出码为 **1**，因为诊断断言期望的响应行为尚未满足。
诊断源码仅由该脚本加载到 `internal/desktop`，存放在明确的 diagnostics 目录。
这样保留未修复问题的可运行证据，并明确区别于默认回归；后续修复应将对应断言转为正常回归测试。

探针使用真实 desktop 入口和 relay Controller，在 ServerFactory 内用 channel 挂起启动，
单独检测按钮返回、状态读取和完整 view 构建；关闭对照只挂起 Server.Close。
fixture 使用临时配置、替代 VPN 源与防火墙执行器，不连接真实 VPN，也不修改真实防火墙。

| 场景 | 断言预算 | 三轮结果 |
|---|---:|---|
| 启用按钮返回 | 100 ms | 通过 |
| 启动未完成时 Controller.View | 100 ms | 全部失败，等待状态锁 |
| 启动未完成时 desktop frame | 500 ms | 全部失败，等待同一状态锁 |
| 关闭按钮及关闭期间 Controller.View | 100 ms | 通过 |
| 关闭期间 desktop frame | 500 ms | 通过，约 208–232 ms |

预算用于确定性检测被组件 I/O 拖住的调用，不是原生窗口的端到端性能指标。
完整 frame 包含真实网卡枚举，因此预算比单独状态读取宽。
早期 100 ms 的 frame 探针不足以排除这部分耗时，最终结论以上表的 500 ms 版本为准。

曾区分三个假设：控制器状态锁占用、网卡/防火墙查询慢、后台结果回写阻塞。
单独状态读取探针不经过页面查询和结果消费，却同样稳定阻塞；完整 frame 的超时堆栈与其指向同一把锁：

```text
app.view                         internal/desktop/view.go:45
syncLanShareFirewallIfNeeded      internal/desktop/lanshare_firewall.go:72
lanShareViewState                 internal/desktop/lanshare_firewall.go:110
Controller.View                  internal/relay/controller.go:101
sync.Mutex.Lock
```

`Controller.Enable`（`controller.go:229`）持有 `c.mu` 进入 `reconcileLocked`（`:650`），
后者在锁内调用 `c.serverFactory`（`:736`）。生产进程工厂包含版本探测、进程启动与握手等待。
按钮虽已后台执行，下一帧仍需同一把状态锁，因而会随组件启动等待。
关闭对照没有复现这条锁等待路径。

这确认了被注入慢启动时的阻塞机制，尚未测量其在真实组件启动中的持续时间，
也没有以该探针代替用户机器上的点击验收或认定所有卡顿都只有这一原因。
建议下一任务优先缩短 Controller 状态锁的持有范围，让组件启动等待不占用 UI 状态读取所需的锁，
并验证启动失败、关闭/退出并发及迟到启动结果的资源回收。

## 资源观测

复用已有 baseline：真实本机分享监听器、替代 VPN/组播后端；页面预热后 GC 与十轮启停后 GC 对比。

| 轮次 | 预热后 HeapAlloc 字节 | 十轮后 HeapAlloc 字节 | 增量字节 |
|---|---:|---:|---:|
| 1 | 7061880 | 7057744 | -4136 |
| 2 | 7094632 | 7087256 | -7376 |
| 3 | 7081016 | 7111200 | 30184 |

最大正增量约 29.48 KiB。30 个“Disable 开始至公告已撤销”样本为 3.078–7.372 ms；
不将该耗时等同于全部资源释放时间。未使用时没有功能专用常驻任务和十轮启停回收的断言均通过。
本轮没有与旧分支配对测量，不据此声称内存节省比例、真实进程树内存降低或长期无泄漏。

## 配套构建

```powershell
./scripts/build.ps1 -development -out build/share-lifecycle-development
```

构建成功，日志：`build/share-lifecycle-checks/build.log`。
manifest 的 Hub 来源为 `f36e5ce0881e40064a450dda6bf97a85cc87b722`，Hub 与内核来源均干净，
固定内核仍为 `5929e30fd988f7e3efd3fbbbfffc7a7087e26f44`；后续报告提交不混写为构建来源。

产物包括 `connect-hub.exe`、`core/connect-hub-{worker,capture,relay,cleanup}.exe`、图标及模块清单。
manifest 中五个 EXE 和两份模块清单的 SHA256 全部逐项匹配，IPC 生成一致性检查通过，
临时图标 `.syso` 已移除。这份构建保留了尚未修复的启动锁等待，仅供对应快照复测。

## 验收范围

原生 GUI 控制通道此前已连续失败，本轮没有重试或绕过，使用 `ui.NewTester` 验证页面代码路径。
原生点击观感、真实 VPN、跨机共享、提权及持续业务流量均未验收。
测试不操作用户正在运行的程序，不改系统代理或清理环境。
本轮交付为独立 worktree、可复现诊断、测试报告及配套构建；共享启动响应问题仍待后续修复。
