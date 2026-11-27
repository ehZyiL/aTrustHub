# 邀请码交付前 P1/P2 修复与验证

日期：2026-11-27。状态：**needs_review，等待用户验收**。原授权实现 `4950d77`、实现记录 `df668f5`；修复工单 `tk_f1bf29a7d16140e68623df3bbfa88d58`，复核工单 `tk_90e6dddcb3d643a882a23499a35adc21`。没有修改原实施工单状态，没有推送、发布或另派审查。

## 相关文件

本次新增/修改的全部文件：

- `internal/relay/listener.go`（新增）：未认证回收、认证分类迁移、关闭归属、响应关闭头。
- `internal/relay/listener_test.go`（新增）：8 个监听器回归测试，仅本进程 loopback。
- `internal/relay/server.go`：接入连接上下文与状态、HTTP 期限、v1/租约认证迁移、CONNECT 失败释放、Close 尊重调用方 context。
- `internal/relay/device_auth.go`：验证签名及设备授权后迁移控制预算。
- `internal/relay/pairing_wire.go`：配对握手期限及 KE3 成功后的独立 WebSocket 预算。
- `internal/desktop/pairing_view.go`：停止时失效邮箱、进度及临时节点 ID，新尝试取消旧尝试，迟到 start 资源回收。
- `internal/desktop/import_relay.go`：记录结果邮箱作为尝试身份的约束，沿用现有标签/关闭入口的 stop 调用。
- `internal/desktop/pairing_test.go`：3 个新增回归函数、10 个交错子场景；成功领取测试改为在关闭清理前保存检查点 ID。
- `docs/plans/lan-invitation-pairing-2026-11-27.md`：更新实际资源策略、边界及本记录索引。
- `docs/plans/lan-invitation-pairing-fixes-2026-11-27.md`（新增）：本记录。

核对过的现有参考模式：`internal/relay/server_test.go`（loopback fixture 与凭据/隧道验证）、`server_lifecycle_test.go`（生命周期和并发关闭）、`pairing_test.go`、`pairing_lifecycle_test.go`、`pairing_security_test.go`（真实 PAKE、持久化和隔离）；`controller_test.go`、`pairing_controller.go`（暂停/恢复）；`internal/desktop/lan_discovery.go`（旧异步结果失效）、`pairing_test.go`（存储检查点和 fake attempt）；`internal/relay/process/pairing.go`、`pairing_test.go`（真实 sidecar 的取消/领取/撤销）；`internal/relay/client.go`、`contract/protocol.go`（v1/v2、租约/DNS/业务限额）；`go.mod`、`scripts/buildtool/main.go`、`docs/design/lan-relay-sharing-implementation-2026-11-24.md`（模块和统一构建边界）。另读完整复核证据与原实现说明，按适用 AGENTS 和 diagnosing-bugs 的红测流程执行。

## 红测及原因

在 `df668f5` 原实现上先添加永久回归并运行：

```powershell
$env:GOWORK='off'
go test -mod=readonly ./internal/relay ./internal/desktop -run 'TestUnauthenticatedSocketsCannotBlockPairedReconnect|TestCloseWithSaturatedListenerReturnsWithinContext|TestPairCancelledClaimCannotFinishNewTab' -count=1 -timeout=35s
```

结果 exit 1：relay 的已配对重连在 1 秒 context 内 `context deadline exceeded`；UI 迟到成功实际 `open=false toast="设备授权已保存，正在连接共享主机"`，迟到失败覆盖为旧的 `injected ack response loss`。关闭用例初版没有稳定逼出原阻塞，后续补了同步控制 Accept 交接与缩小预算的确定性测试，不把该初版通过当作反证。

P1 原因是整个 TCP 生命周期共用 288 个许可，认证不转移，而且 Accept 在拿到 socket 后无取消地等许可。修复不再等待许可：最多 32 个未认证连接；满额关闭最旧未认证连接，为新认证留出接收路径。认证成功后在同一锁内转移计数，关闭、到期和转移共享同一状态，重复释放无副作用。

P2 原因是停止没有失效结果邮箱。每次 start/Ack 均有独立邮箱；stop 先解除当前邮箱引用，再取消/关闭资源并清空进度、PIN、临时节点 ID。drain 只能读当前尝试的邮箱，旧成功/失败都不能触发 finish 或覆盖新界面。取消与 start 发布交错时，由 context 回调关闭迟到 attempt；正确性不依赖关闭 goroutine 抢先执行。已落盘的配置与 SecretStore 检查点保留，可从节点列表重连。

修复过程中原有远程管理隔离测试曾出现 EOF：只在 StateIdle 关闭未认证 socket 会与下一次 POST 复用竞争。已在未认证响应头显式写入 `Connection: close`，该测试及后续全包验证恢复通过。新增测试初次编译的 DNS 调用名、以及测试中 interface 与 typed-nil 比较也已修正；没有把这些中间失败标为通过。

## 计数、关闭归属及限制

| 阶段 | 预算/期限 | 释放与归属 |
| --- | --- | --- |
| raw TCP、TLS、初始 HTTP | 未认证 32；接收起 5 秒 | 满额回收最旧未认证；期限到期、连接关闭、listener 关闭释放 |
| 未认证 HTTP 404/失败 | 仍属未认证 32 | 显式关闭响应头；StateIdle 补充关闭；不保留空闲 keep-alive |
| v1 token / v2 已授权签名 / 租约控制 | 独立控制 40；普通 HTTP 读取 5 秒、空闲 15 秒 | 验证成功后迁移并释放未认证额度；v2 新签名连接仍按原协议关闭 |
| CONNECT | 独立隧道 256；业务表仍为总 256 / 每租约 64 | 认证后迁移；错误响应关闭；成功 hijack 的 socket 由 connTable 和 listener 双重关闭归属、一次计数释放 |
| 配对 KE3 之前 | 未认证 TCP 32 + 原独立 PAKE 8；进入配对处理后 20 秒 | hijack 不丢失 listener 跟踪；取消、到期、失败关闭；旧定时回调会复查延长后的期限 |
| 配对 KE3 之后 | 独立配对 WebSocket 16 + 原请求 16 | 转移后不占未认证/PAKE；原请求期限、ws.Close、根 context 或 listener 关闭释放 |
| 停机/暂停/恢复 | Close 不等容量；监听器持有所有登记 socket | 同锁移除并关闭，包含未交付及 hijack；调用方 context 限制后续等待；恢复使用新 listener |

被登记 TCP 上限为 32+40+256+16=344；内核 accept backlog 和一次接收/回收交接另计。未提高业务、DNS、在线设备或协议额度：业务 256/64、DNS 16/4、在线 10、v1 HTTP/1.1、v2 exporter 证明均保留。

只解决可复现的有限未认证占位与应用层资源耦合。持续新连接竞争可能淘汰合法但尚未认证的握手；内核、CPU、带宽、文件描述符与已认证预算仍有限。没有声称在任意洪泛下无条件可用，也没有向用户正在运行的分享发送探针。

## 永久回归与验证

监听器回归覆盖：原规模有限占位后的 v2 新证明/控制/隧道与 v1 新认证；旧隧道、另一设备控制/隧道/DNS；两个已认证配对 WebSocket 继续轮询；404 强制关闭；缩小预算的转移与满额回收；50 次并发转移/关闭/到期；已接受未交付 socket 关闭；旧定时回调与配对延长；满额 Close、Pause 及恢复。UI 覆盖：切换粘贴标签、关闭重开、新尝试与旧 Ack 成功/失败、旧 start 缓冲/迟到成功/失败，且检查凭据仍存储。已有正向成功领取、保存故障、丢失响应重连与已确认节点保护继续执行。

所有 Go 命令 `GOWORK=off -mod=readonly`。Windows Go 1.27.4；无 Windows C 编译器，race 使用现有 WSL Go 1.27.4 与 gcc，没有安装工具。

| 范围 | 实际结果 |
| --- | --- |
| 红测后定向 relay/desktop 配对和 listener 回归 | 通过 |
| Windows `go test ./internal/relay/... ./internal/desktop -count=1 -timeout=180s` | 通过；relay 16.938s，process 31.546s，desktop 35.759s，含真实 sidecar 两项配对/撤销与其余生命周期测试 |
| WSL `go test -race ./internal/relay/... ./internal/store ./internal/model -count=1 -timeout=240s` | 通过；relay 24.158s，process 59.351s，无 race 报告 |
| WSL 最终源码定向 relay/desktop race（下列过滤器） | 通过；relay 16.507s，desktop 16.115s，无 race 报告 |
| 最后补强的已认证 WebSocket 占位保护断言 | Windows listener 定向 2.474s 通过；WSL listener 定向 race 5.282s 通过，无 race 报告 |
| Windows `go test -mod=readonly ./... -count=1 -timeout=240s` | 全通过；desktop 35.147s，relay 15.700s，process 30.225s，vpn 11.106s，e2e 13.891s |
| Windows `go vet -mod=readonly ./...` | exit 0，通过 |
| Windows 5 项组件/页面边界定向检查 | 5/5 通过，desktop 2.059s |
| `go run -mod=readonly ./scripts/buildtool -development -out build/pairing-fix-tk-f1bf29a7-20261127` | exit 0，Windows/amd64 五组件、协议生成一致性及固定内核校验通过 |
| `CGO_ENABLED=0 GOOS=linux/darwin GOARCH=amd64 go build -mod=readonly`：Hub 与 relay | 四项交叉构建全通过，未运行这些二进制 |
| `git diff --check` | 通过 |

```powershell
$env:GOWORK='off'
go test -mod=readonly ./internal/relay ./internal/desktop -run 'TestUnauthenticated|TestListener|TestCloseWithSaturated|TestPauseWithSaturated|TestPair|TestConnect|TestConcurrentConnect' -count=1 -timeout=90s
go test -mod=readonly ./... -count=1 -timeout=240s
go vet -mod=readonly ./...
go run -mod=readonly ./scripts/buildtool -development -out build/pairing-fix-tk-f1bf29a7-20261127
git diff --check
```

交叉构建命令（仅写入新输出目录）：

```powershell
$env:GOWORK='off'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
foreach($targetOS in @('linux','darwin')) {
  $env:GOOS=$targetOS
  $cross="build/pairing-fix-tk-f1bf29a7-20261127/cross/$targetOS-amd64"
  New-Item -ItemType Directory -Path $cross -Force | Out-Null
  go build -mod=readonly -o "$cross/connect-hub" ./cmd/connect-hub
  if($LASTEXITCODE -ne 0){throw 'Hub cross build failed'}
  go build -mod=readonly -o "$cross/connect-hub-relay" ./cmd/app-relay
  if($LASTEXITCODE -ne 0){throw 'Relay cross build failed'}
}
```

```powershell
$wslGo='/home/ehzyil/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.4.linux-amd64/bin'
wsl --cd /mnt/d/Programming/Projects/Go/easy-connect/aTrustHub --exec env GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=1 "PATH=${wslGo}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$wslGo/go" test -race -mod=readonly ./internal/relay/... ./internal/store ./internal/model -count=1 -timeout=240s
wsl --cd /mnt/d/Programming/Projects/Go/easy-connect/aTrustHub --exec env GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=1 "PATH=${wslGo}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$wslGo/go" test -race -mod=readonly ./internal/relay ./internal/desktop -run 'TestPair|TestUnauthenticated|TestListener|TestCloseWithSaturated|TestPauseWithSaturated|TestConnect|TestConcurrentConnect|TestDiscoveryPairing|TestCoreDependencyGraphExcludesOptionalRuntime|TestDesktopDoesNotLinkCleanupService|TestDesktopLivesBehindCmdEntryPoint|TestSharePageAcceptsClientAndShowsUnavailableState' -count=1 -timeout=180s
```

修复提交：`fa4d567`（UI）；`e1ce571`（listener）。构建与日志目录：`build/pairing-fix-tk-f1bf29a7-20261127`（新目录）。最终文档提交另见 git log。

Windows 成品为根目录 `connect-hub.exe` 及 `core/connect-hub-{worker,capture,relay,cleanup}.exe`，附 `build-manifest.json`、模块清单和图标。manifest 记录运行代码提交 `e1ce571eaaa1899fe0d883108a49cc12aaa9fdc0`、内核 `5929e30fd988f7e3efd3fbbbfffc7a7087e26f44` 和构建时尚未提交的两份文档；之后仅补强测试断言/记录，运行代码未改变。Windows 全量测试、边界、构建日志保存在 `validation/`。新目录未替换任何正在运行的可执行文件。

## 验收边界

本工单仅源码和测试监听器验证，未停止、重启、修改或访问用户当前程序的邀请、凭据、VPN 或分享设置。`go.work`、`go.work.sum` 保持未跟踪、不纳入提交；禁止操作的审查残留目录未触碰。

没有开展 DS 指定的真实实测，没有跨机/真实 VPN、系统凭据库、macOS/Linux 运行验收。前次已作基线对照的 WSL 两项桌面全量失败不在本次重跑范围，不声称 WSL desktop 全量 race 通过。覆盖率未测量，不声称 80%。自动测试/复核不等于用户验收，本工单交付保持 needs_review，不标 done。

Host 状态写入限制：执行者尝试 `tickets show` 与 `tickets update ... --status needs_review` 均被明确返回 `dispatch_worker_forbidden`（exit 1），不是成功回执。未绕过；本交付要求调度方保持 **needs_review**，不能宣称执行者已直接更新数据库状态。原实施工单、复核工单及 DS 工单均未改变。

## 主机授权面板刷新后续修复（2026-11-27）

用户报告“邀请码与设备授权”中的生成、取消和暂停等控件每秒刷新。本次代码与测试提交：`207f5b6db7539e6e7e4f3c969af700a1a7bb3cef`；只修复主机管理面板，不改变配对协议、设备授权格式或客户端每秒查询配对结果的策略。跨机及真实窗口验收仍待执行。

本次相关文件：

- `internal/desktop/pairing_view.go`：读取与显式操作分开计忙；每次请求拥有独立结果邮箱；显式操作取消后台读取，迟到结果无法覆盖当前状态；通过框架 `Context.After` 独立续订重绘，并检查窗口可见性。读取失败保留当前快照，取消失败保留仍有效的邀请码。暂停态清除邀请码和临时请求的显示，保留设备列表。
- `internal/desktop/lanshare.go`：保存管理请求的邮箱与取消函数；在 UI 线程读取结果；重开面板、关闭共享及暂停操作完成时处理相应刷新生命周期。
- `internal/desktop/lanshare_view.go`：面板关闭时取消并解除当前管理请求，关闭面板保持原有共享生命周期。
- `internal/desktop/pairing_manage_test.go`（新增）：9 个测试函数、20 个场景，执行真实 UI 渲染、点击与结果处理。覆盖生成/取消后的持续刷新、后台读取期间的生成/取消/批准/拒绝/撤销/暂停、慢读取不重叠、迟到成功/错误、关闭重开、显式操作互斥、隐藏/最小化及恢复、取消失败、暂停后的设备展示。
- `internal/relay/pairing_lifecycle_test.go`：补充不重启即暂停时清除临时状态、恢复后不恢复旧邀请/请求的断言，沿用真实 loopback 配对与持钥重连。
- `docs/plans/lan-invitation-pairing-2026-11-27.md`：分别说明主机与客户端的两种轮询；明确暂停使当前邀请码和临时请求失效；补充面板刷新验收项。
- `docs/plans/lan-invitation-pairing-fixes-2026-11-27.md`：本记录。

参考现有 `internal/desktop/redraw{,_test}.go` 的可见性门控及可控时钟、`lan_discovery{,_async_test}.go` 的后台查询与迟到结果隔离、`import_relay.go` 与 `pairing_test.go` 的独立结果邮箱。另核对 `lanshare_view_test.go`、`app.go`、`state_ticker.go`、`window_lifecycle.go`、`view_test.go`，以及 `internal/relay/pairing_{controller,state,test}.go`、`process/pairing.go`、`client/share.go`、`contract/controller.go`、`go.mod` 与 `scripts/buildtool/main.go`。框架 API 以固定依赖 MyGo v0.7.3 的 `ui/{context,headless,runtime,window}.go` 和 `internal/raster/team.go` 为准。

### 红测与根因

在生产代码未修改时，使用 `testing/synctest` 与真实 `ui.Tester`，在初次读取后 500ms 点击生成/取消，再让原定时重绘在操作后不到一秒触发。已有定时器到期时，新的 `pairAt` 尚未满一秒，条件分支不再续订后续重绘；同时后台 `list` 与显式操作共用 `pairBusy`，使按钮随每秒读取反复禁用。

红测命令（当时后台读取测试名为 `TestPairManageBackgroundRefreshAllowsInvitationActions`，扩展覆盖后改名为 `TestPairManageBackgroundRefreshAllowsActions`）：

```powershell
$env:GOWORK='off'
go test -mod=readonly ./internal/desktop -run '^TestPairManage(PollingContinuesAfterInvitationAction|BackgroundRefreshAllowsInvitationActions)$' -count=1 -timeout=30s
```

实际 exit 1：生成、取消分别出现 `polling stopped after create/cancel: list calls = 1`；后台读取未完成时分别出现 `background refresh blocked create/cancel: action count = 0`。修复后同一反馈回路转绿。新增可见性回归还曾在托盘、最小化两个场景报 `hidden panel continued polling`；添加可见性检查后转绿。

测试接缝最初遇到 MyGo 常驻光栅化线程不能归属虚拟时钟 bubble 的超时，以及原有 `stopPainting` 调用空取消回调的清理 panic；这两次都不是业务复现。测试局部使用 `GOMAXPROCS(1)` 并恢复原值，避免引入框架常驻线程；清理由该测试拥有的管理请求和可见性标志负责。没有修改框架或无关重绘实现。

### 本次验证

实际环境：Windows Go 1.27.4；race 使用现有 WSL Go 1.27.4 与 gcc。所有 Go 命令均为 `GOWORK=off -mod=readonly`，没有并发执行构建和全量测试。

| 范围 | 结果 |
| --- | --- |
| Windows 主机面板与暂停生命周期定向回归 | 通过；desktop 0.279s，relay 0.395s |
| Windows `go test ./... -count=1 -timeout=240s` | 全通过；desktop 26.587s，relay 12.367s，process 21.578s，vpn 9.009s，e2e 6.878s |
| Windows `go vet ./...` | exit 0 |
| WSL 定向 `go test -race`：主机面板、原 UI 展示及暂停/恢复生命周期 | 通过；desktop 1.514s，relay 1.622s，无 race 报告 |
| 新测试对四个主机管理函数的语句覆盖率 | `stopPairManage` 100%；`pairManageAction` 90.9%；`drainPairManageResults` 100%；`pairingManageView` 96.2% |
| Windows/amd64 全组件开发构建 | 通过；协议生成一致性及固定内核检查通过 |
| 构建 manifest 的 SHA-256 校验 | 7/7 通过，包含 5 个可执行组件和 2 个模块清单 |
| `git diff --check` | 通过 |

覆盖率来自仅运行 `TestPairManage` 的定向命令；整个 desktop 包在该命令下是 2.8%，不能把上述函数覆盖率当成全包或全项目覆盖率。

```powershell
$env:GOWORK='off'
go test -mod=readonly ./internal/desktop ./internal/relay -run '^TestPairManage|^TestPairPauseRestartResumePreservesDevicesAndLegacyDisable$' -count=1 -timeout=45s
go test -mod=readonly ./... -count=1 -timeout=240s
go vet -mod=readonly ./...
go test -mod=readonly ./internal/desktop -run '^TestPairManage' -coverprofile=build/pairing-ui-refresh-20261127/validation/desktop-pair-manage.cover -count=1 -timeout=45s
go run -mod=readonly ./scripts/buildtool -development -out build/pairing-ui-refresh-20261127
```

```powershell
$wslGo='/home/ehzyil/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.4.linux-amd64/bin'
wsl --cd /mnt/d/Programming/Projects/Go/easy-connect/aTrustHub --exec env GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=1 "PATH=${wslGo}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$wslGo/go" test -race -mod=readonly ./internal/desktop ./internal/relay -run '^TestPairManage|^TestPairingUIStateAndIndependentDeviceControls$|^TestPairPauseRestartResumePreservesDevicesAndLegacyDisable$' -count=1 -timeout=120s
```

产物：`build/pairing-ui-refresh-20261127/connect-hub.exe` 及相邻 `core/` 中四个组件。manifest 记录运行代码提交 `207f5b6`，Hub 和固定内核输入均无未提交源文件；后续仅补本文档。验证日志与覆盖率保存在同目录 `validation/`。本次没有启动成品、替换当前运行程序或操作用户的 VPN/共享/邀请码/凭据；`go.work`、`go.work.sum` 仍未跟踪，未纳入提交。本轮没有重新执行 WSL desktop 全量 race 或 macOS/Linux 运行验收。

## 共享生命周期与取消后续修复（2026-11-27）

代码及测试提交：`594f8477390b00f63e4830c059b93adab3e544b3`。
修复再次 review 的三个确认项：组件启动占用状态锁；取消请求仍排队并发送；
发现结果与旧面板结果误结束暂停/恢复的忙状态或覆盖新面板。

### 本次相关文件

修改生产文件：

- `internal/relay/controller.go`：保留生命周期串行，锁外准备运行实例；以克隆设置读取，提交时只更新运行相关字段；取消、失败与端口持久化失败均锁外回收资源。
- `internal/relay/pairing_controller.go`：管理、暂停、恢复可取消等待操作锁，取锁后检查取消，不再执行已取消的排队请求。
- `internal/relay/pairing_state.go`：配对状态锁可取消；修改邀请前检查上下文，避免取消后仍创建或取消邀请。
- `internal/relay/process/process.go`：启动上下文贯穿版本探测、握手与初始化写入；取消后回收进程和 broker；IPC 写锁支持可取消等待，终止路径不再等待向阻塞管道写 stop。
- `internal/relay/process/pairing.go`：管理 RPC 注册/发送前检查上下文，使用可取消写锁，退出时移除请求邮箱。
- `internal/relay/server.go`：可选 `StartupContext` 仅控制初始化，设备读取/监听支持取消；已建立服务继续使用独立生命周期。
- `internal/desktop/lanshare.go`：每次打开面板分配新结果邮箱，所有后台任务预先捕获邮箱；按操作归属清除忙状态，单独持有暂停/恢复取消函数。
- `internal/desktop/pairing_view.go`：在 UI 线程创建暂停/恢复上下文和结果发送函数，操作结束重启状态读取。
- `internal/desktop/lan_discovery_view.go`：发现开关、名称及保存重试也捕获当前面板邮箱。
- `internal/desktop/lanshare_view.go`：关闭面板后取消并解除暂停/恢复请求。

新增实现与回归：

- `internal/relay/ctxlock/mutex.go`、`mutex_test.go`：零值可用的可取消互斥锁；等待取消不留下后台取锁任务，并验证互斥与复用。
- `internal/relay/startup_responsiveness_test.go`：首次开启/恢复/暂停后恢复/自动重试 × 慢源/慢工厂；启动时保存发现偏好；失败清理、关闭/退出与迟到资源回收。
- `internal/relay/pairing_cancellation_test.go`：真实邀请上的排队取消、配对状态锁等待取消，以及暂停/恢复排队取消后设置不变。
- `internal/relay/process/pairing_cancellation_test.go`：已取消命令不发送；等待写锁时取消及时返回，不遗留 RPC 或迟到写入。
- `internal/relay/process/startup_cancellation_test.go`：真实 sidecar 的握手/设备读取取消；成功启动后调用上下文取消不结束服务。
- `internal/desktop/share_action_test.go`：真实 UI 点击暂停/恢复，穿插发现结果、关闭重开及迟到成功/错误。
- `internal/desktop/pairing_manage_test.go`：复用真实页面与可控时钟接缝，补充恢复接口及暂停请求清理。
- `docs/plans/lan-invitation-pairing-2026-11-27.md`、本文及 `share-lifecycle-worktree-validation-2026-11-27.md`：修复状态、验收项、来源与验证记录。

核对且未修改的参考/复现文件：`internal/relay/{controller_test,optional_lifecycle_test,pairing_lifecycle_test}.go`、
`internal/relay/contract/{controller,interfaces}.go`、`internal/relay/adapter/source.go`、
`internal/relay/process/{process_test,pairing_test,discovery,command,command_windows,command_windows_test}.go`、
`internal/desktop/{lan_discovery,lan_discovery_async_test,lan_discovery_test,lanshare_view_test,optional_lifecycle_test,resource_baseline_test,relay_assembly,view,lanshare_firewall}.go`、
`go.mod`、`scripts/buildtool/main.go`、`scripts/test-share-ui.ps1` 和 `scripts/diagnostics/share_ui_test.go.txt`。
沿用已有操作锁外关闭资源、可取消源获取、独立结果邮箱及真实 UI 可控时钟四种模式。
独立 `aTrustHub-wt-share-lifecycle` 未修改；未跟踪的 `go.work`、`go.work.sum` 保留未提交。

### 反馈回路与实现边界

原始四项复现先纳入常规回归，修复前全部失败：取消管理请求仍等待操作锁，
解锁后取消真实邀请；预先取消的管理 RPC 仍写入 81 字节；发现回包清除暂停忙状态并允许第二次暂停；
旧暂停错误覆盖重开后的面板。新增启动测试在修复前的八个启动路径和两个取消场景均复现状态读取等待。
修复后相同断言及原完整页面启动探针全部转绿。

生命周期锁覆盖准备、提交及失败清理整个过程；运行实例准备及其失败清理阶段不持有状态锁，
提交仍在状态锁内完成，启动期间保存的发现偏好不会被旧快照覆盖。生产工厂失败返回真正的 nil 接口，避免失败回收访问空指针。
启动上下文不会成为已建立服务的根上下文。取消只保证取消前尚在排队/尚未发送的工作不再派发，
不会撤销已经发送且发生后端副作用的操作；面板结果隔离独立保证旧回包不污染新页面。

初次全量命令还扫描到此前置于忽略目录的三份不同包 `.go` overlay 源，导致测试目录 setup 失败。
已将这些自建诊断源改为 `.go.txt` 并同步原复现脚本；四项原始复现仍可运行，
全量随后重跑通过。这些仅位于 `build/share-review-20261127/`，未纳入源码提交。
原共享 UI 诊断脚本及探针没有修改，继续作为独立反馈回路使用。

### 验证结果

环境：Windows Go 1.27.4；WSL Debian Go 1.27.4 + gcc。Go 命令均显式 `GOWORK=off -mod=readonly`。

| 验证 | 结果 |
| --- | --- |
| 原共享 UI 探针，三轮 | 9/9 通过；状态读取未触发 100 ms 超时；启动页面 46–65 ms，关闭对照 193–217 ms |
| 再次 review 的原四项 overlay 复现，三轮 | 12/12 通过；结果注入仅适配到捕获邮箱的新接口 |
| 新增回归 | 14 个测试函数；定向回归分批通过，并包含三轮重复验证 |
| Windows `go test ./... -count=1 -timeout=240s` | 1,201 项通过、9 项跳过、0 项失败；统计包含测试与子测试事件 |
| 关键包耗时 | desktop 27.656s；relay 12.435s；process 22.866s；vpn 9.380s；e2e 7.506s |
| Windows `go vet ./...` | exit 0，无输出 |
| WSL 定向 race | relay 1.982s、process 14.104s、ctxlock 1.020s、desktop 2.312s；无 race 报告 |
| 十轮资源启停与并发启停 | 包含于 Windows 全量及 WSL 定向 race，通过；没有新增常驻锁等待任务 |
| Windows/amd64 全组件构建 | 通过，协议生成检查和固定内核校验通过 |
| manifest 哈希 | 5 个 EXE、2 份模块清单，7/7 SHA256 匹配 |
| `git diff --check` | 通过 |

```powershell
$env:GOWORK='off'
./scripts/test-share-ui.ps1 -Count 3
./build/share-review-20261127/review.ps1 -Count 3
go test -mod=readonly ./internal/desktop ./internal/relay ./internal/relay/process ./internal/relay/ctxlock -count=1 -timeout=180s
go test -mod=readonly ./... -count=1 -timeout=240s -json
go vet -mod=readonly ./...
go run -mod=readonly ./scripts/buildtool -development -out build/share-lifecycle-fix-20261127
```

```powershell
$taskGoBin='/home/ehzyil/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.4.linux-amd64/bin'
wsl -d Debian --cd /mnt/d/Programming/Projects/Go/easy-connect/aTrustHub --exec env GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=1 "PATH=${taskGoBin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$taskGoBin/go" test -race -mod=readonly ./internal/relay ./internal/relay/process ./internal/relay/ctxlock ./internal/desktop -run '^TestShareRegression|^TestControllerStartup|^TestControllerCancelledStartup|^TestPairControlCancelledWhile|^TestCancelled|^TestRelayStartupContext|^TestMutex|^TestResumeReply|^TestOldPanel|^TestPairManage|^TestPairPauseRestartResume|^TestDisableCancelsAcquire|^TestConcurrentControllerOperations|^TestOptionalResourcesStopAndRestartTenTimes$' -count=1 -timeout=180s
```

新成品位于 `build/share-lifecycle-fix-20261127/connect-hub.exe`，必须保留相邻 `core/` 中四个组件。
manifest 的 Hub 来源为 `594f847`，内核仍为 `5929e30fd988f7e3efd3fbbbfffc7a7087e26f44`，两者无 dirty 条目；
随后仅补充三份文档。日志副本集中在成品目录的 `validation/`，包含全量 JSON、vet 退出记录、
WSL race、原共享探针、原 review 反馈回路及构建日志。临时图标 `.syso` 已移除。

本次没有启动成品、替换运行程序或操作真实 VPN、防火墙、凭据及邀请码。
原生窗口点击、跨机体验和真实持续业务流量仍未验收；本轮没有全包覆盖率测量或 WSL desktop 全量 race 声明。
