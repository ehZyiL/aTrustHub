# 修复：导入同事分享卡顿与 Windows 控制台闪窗

日期：2026-11-27。基于 `refactor/component-boundaries` 的 `a7ed7e1`。

## 相关文件

生产修改：

- `internal/desktop/import_relay.go`：导入对话框入口。
- `internal/desktop/lan_discovery.go`：后台浏览请求、结果消费、代次和关闭。
- `internal/desktop/lan_interfaces.go`：发现页面只读取网卡缓存。
- `internal/desktop/lan_discovery_view.go`：启动期间禁用刷新按钮。
- `internal/relay/process/command.go`、`command_windows.go`、`command_other.go`：统一子进程构造。
- `internal/relay/process/discovery.go`、`process.go`、`import_session.go`：发现、分享和导入会话使用统一构造。

回归与配套检查：

- `internal/desktop/lan_discovery_async_test.go`：阻塞启动、渲染、关闭、重开、切网卡、刷新、退出和失败结果。
- `internal/desktop/lan_discovery_test.go`：既有验收用例等待后台启动结果后投递记录。
- `internal/desktop/optional_lifecycle_test.go`：纳入新工作协程，十轮启停实际等待浏览启动。
- `internal/desktop/resource_baseline_test.go`：采样前等待浏览真正启动。
- `internal/relay/process/command_windows_test.go`：实际发现进程配置、无控制台子进程及协议输出、取消。

定位参考：`internal/desktop/discovery_assembly.go`、`hidecmd_windows.go`、`redraw.go`、
`view.go`、`view_test.go`、`lanshare_view.go`、`lanshare_view_test.go`、`README.md`；
`internal/relay/client/discovery.go`、`internal/relay/discovery/browser.go`、
`internal/relay/firewall/firewall.go`、`internal/relay/process/process_test.go`、
`internal/cleanup/client/process_windows.go`、`scripts/build.ps1`、
`scripts/buildtool/main.go`、`docs/DEVELOPMENT.md` 和既有 P6 验证记录。

## 复现与原因

点击“导入同事分享”原先同步执行网卡枚举、子网查询和 `Browser.Start`。
进程浏览器又同步探测协议版本、启动 relay 并等待握手/命令确认，耗时直接落在 UI 线程。
Windows 下探测命令和正式命令均未配置隐藏控制台。

先加入测试，再实际执行：

```powershell
$env:GOWORK = 'off'
go test -mod=readonly ./internal/desktop ./internal/relay/process `
  -run 'TestRelayImportDoesNotWaitForDiscoveryStartup|TestDiscoveryProcessDoesNotCreateConsole' -count=1
```

修复前两项均失败：

```text
opening import blocks the UI while discovery starts
discovery child can create a visible Windows console
```

UI 测试在真实导入入口注入阻塞浏览器，以 100 毫秒内返回为断言。
这是确定性阻塞回归门槛，不是用户机器的端到端点击耗时测量。
控制台检查实际发现进程的创建配置；另用 Windows 子进程查询
`GetConsoleWindow`，验证无窗口时 stdout 协议和 Context 取消仍然可用。

## 修复边界

- 先显示对话框，浏览请求交由按需启动的单个工作协程串行执行；没有请求就退出。
- 合并尚未执行的请求，只接受当前代次的结果；旧启动完成后仍执行最新关闭或重开请求。
- UI 不读可能被进程启动锁阻塞的 `Browser.Snapshot`，只消费后台结果和发现快照。
- 页面渲染、网卡选择列表和本机地址过滤只读缓存；打开、切网卡和手动刷新在后台查询。
- 没有可浏览网卡时转到粘贴口令，不启动发现组件；启动失败不恢复旧会话候选。
- 发现、分享和导入会话的版本探测及正式命令统一设置 `HideWindow` 和 `CREATE_NO_WINDOW`。
  relay 仍作为命令行程序构建，保留协议管道及诊断用途。
- 关闭浏览不关闭分享；退出等待已在执行的工作收尾，并阻止晚到的打开请求重新启动。

## 验证

- 原始两个失败用例修复后通过；导入交互与控制台测试重复三次通过。
- 全量 `go test -json -mod=readonly ./... -count=1 -timeout=180s`：30 个测试包、1091 个测试项
  （含子测试）通过，零失败。日志：`build/import-discovery-checks/tests.jsonl`。
- `go vet -mod=readonly ./...` 通过。
- Linux/amd64、macOS/amd64 的 Hub、relay，以及 desktop/process 测试二进制交叉编译通过。
- 生命周期与资源用例另行运行；只用于确认按需启动及回收，不据此声称内存降低比例。

本轮没有原生窗口的自动点击录像；GUI 自动化通道此前不可用，未绕过失败重试限制。
需要在配套构建上人工确认实际点击观感和无黑窗。没有连接真实 VPN、改系统代理、
防火墙或清理环境；原有 `go.work`、`go.work.sum` 与固定内核子模块保持不变。

修复版整套构建使用独立目录 `build/fix-relay-import-development/`，实际来源与组件哈希
以该目录的 `build-manifest.json` 为准。
