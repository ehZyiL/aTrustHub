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
