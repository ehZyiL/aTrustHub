# 生命周期与恢复（核实版）

## 1. 正常退出的清理顺序

`app.shutdown()`（只执行一次）依次：

```
stopPainting()                    // 停止排队重绘
resourceTUN.Close()               // 停系统捕获：撤销路由/DNS/网卡
closeCaptureSetup()
teardownTUNOnExit()               // 停旧 TUN helper，强制时兜底重置 DNS
disableSystemProxyOnExit()        // 关系统代理（失败重试 2 次）
local.Close()                     // 关本机软件/浏览器
mgr.Close()                       // 关全部会话 + 统一入口监听
```

顺序是**故意**的：系统代理先于监听关闭，因此不存在"代理指着一个已死端口"的窗口。

## 2. 事务日志与恢复点（已核实存在）

| 机制 | 载体 | 谁写 | 谁恢复 |
|---|---|---|---|
| 系统 TUN 期间暂停本应用系统代理 | `<数据目录>/system-tun-proxy-recovery.json`（0600，Before/Installed + 指纹） | `resource_proxy.go` | 退出时 `restoreOwnedProxy`；启动时 `recoverResourceProxy` |
| Linux 合成地址映射 | `internal/capture` 的 alias journal（0600，`CLOCK_BOOTTIME`，含休眠时间） | helper | helper 重启 / `--recover` |
| Windows 映射池保留 | HKLM 独立记录 + `mapping_journal_windows.go` | helper | 崩溃后分配前复查，未到期池不复用 |
| Windows NRPT / 路由 | `recovery_windows.go`、`routes_windows.go` | helper | 看门狗 `RunWatchdog` **等 GUI 进程句柄**，GUI 一死（含被 kill）立即 `RecoverOrphanedDNS` |
| 旧 TUN 的 DNS 劫持 | `tun.stop`/`tun.pid` + `gui.alive` 心跳 | GUI / helper | GUI 启动 `cleanupStaleHelper`；helper 见心跳过期自退 |
| 系统代理归属 | 注册表现值比对 | — | `releaseLostSystemProxy`（运行期）、`guardSystemProxy`（每 3 s 探活） |

关键设计：`restoreOwnedProxy` 是三态判断——当前值等于 After 才写回 Before；等于 Before 只删日志；被第三方改过则**保留现状并保留日志**。因此"崩溃在写日志与写注册表之间"是幂等安全的。

## 3. 健康与会话探测

两套独立机制，不要混淆：

| 机制 | 周期 | 判什么 | 失败后的动作 |
|---|---|---|---|
| **会话有效性**（`checkSessions`） | 每 10 s 扫描，按接入点自身间隔（默认 300 s，下限 30 s） | 服务器是否仍认这条登录（账号被别的客户端顶掉时隧道看起来仍健康） | 连续 2 次"失效"才拆会话；第 1 次 10 s 后重试 |
| **隧道健康**（`probeAll`） | 每 15 s 扫描，按接入点空闲时间闸门 | 隧道还能不能载业务（拨一个已授权的应用地址） | 连续 3 次致命失败 + 90 s 内无真实流量 → 重建隧道；最多 3 次 |

两条保护：

- **真实流量保护**：90 s 内有过真实连接就绝不自动拆隧道。
- **远端目标错误不算隧道死亡**：`host unreachable` / `connection refused` 只记降级，不触发重建。

自动重连退避（会话失效/隧道失效）：`15s → 30s → 60s → 120s → 300s`，用完停止并等用户操作；
其中"隧道失效"的第一次重试提前到 `5s`。

## 4. 生效时机（改配置后到底什么时候起作用）

| 改动 | 生效方式 | 需要重连吗 |
|---|---|---|
| 服务器/端口/用户名/认证方式/端口号/协议/证书指纹/内网域名 | `Manager.needsRestart` → 停旧会话重登 | 需要（自动） |
| 是否加入统一入口（`InPool`） | 即时参与选路 | 不需要 |
| 路由策略 / 共享组 / DNS 归属 / 预算 | 即时参与 `Decide` | 不需要 |
| 统一入口开关/端口/监听地址/分流模式 | 重建聚合监听 | 不需要 |
| 停用某个应用（`DisabledApps`） | **见下方缺口** | — |

## 5. 硬杀（任务管理器 / kill / 断电）后的实际结果

| 资源 | 结果 |
|---|---|
| NRPT / 内网 DNS 策略 | ✅ Windows 看门狗等的是进程句柄，GUI 被 kill 也会触发清理 |
| Wintun 网卡 / 路由 | ✅ helper 管道断开即退出并撤销（helper 未被一起杀时） |
| 旧 TUN 的 DNS 劫持 | ✅ `gui.alive` 心跳过期后 helper 自退并交还 DNS |
| 映射池 / 别名日志 | ✅ 有 journal，重启后可判定过期与回收 |
| 我方写入的系统代理 | ✅ 写入时已拉起 watchdog 子进程（`--proxy-watchdog <pid> <dir>`），它等 GUI 的进程句柄，GUI 一消失就按 journal 恢复；GUI 正常退出时先自己恢复，watchdog 随后无事可做 |
| 用户原有代理值（Before） | ✅ 存在 `<数据目录>/system-proxy-recovery.json`（0600），三态恢复；被第三方改写时保留记录不覆盖 |

## 6. 原先的缺口与修复结果

**缺口 A：系统代理档不保存用户原值。** —— 已修复（B2）

实现：`applySystemProxy` 写入前先 `writeSystemProxyRecord`（`<数据目录>/system-proxy-recovery.json`，0600，temp+Sync+rename），
记录 `Before`（用户原 `ProxyServer`/`ProxyOverride`/`ProxyEnable`）与 `Installed`；关闭/退出时三态恢复：
当前==Before → 只删记录；当前==Installed → 写回 Before 并校验；被第三方改过 → **不动对方的设置**，并丢弃这条再也无法安全恢复的记录。

接管的解套规则：如果记录已失效（被第三方改过 / 记录损坏），用户**重新打开「系统代理」档时**不会卡死——
第三方当前值成为新的 `Before`（所以之后关闭仍会还回去），损坏的记录改名成 `*.broken` 留证而不是删除。
`off` 路径遇到第三方占用时**不会**去关闭对方的代理（`releaseSystemProxyJournal` 返回 `disable=false`）。
对照物就是 `resource_proxy.go` 的同一套 journal 语义。

**缺口 B：恢复依赖“统一入口正在监听”。** —— 已修复（B2）

`recoverResourceProxy` 不再要求调用方传入地址，地址从记录自身的 `Installed.Server` 解析；
启动时的调用也不再先 `SplitHostPort(Aggregate().Addr)`。新加的 `recoverSystemProxy()` 同样不碰到监听状态。

**缺口 C：退出时关闭系统代理失败无留痕。** —— 已修复（B2）

退出失败不会删除 journal；下次启动 `recoverSystemProxy()` 会重试，失败时写日志并在界面提示。

**缺口 D：恢复判定早于恢复动作。** —— 已修复（B2）

`start()` 里顺序固定为：`recoverSystemProxy()` → `recoverResourceProxy()` → 重新计算 `a.sysProxyOn`。

**硬杀后的处理（新增）**：写入 journal 成功后拉起一个轻量子进程（`--proxy-watchdog <pid> <dir>`），
用进程句柄等 GUI，GUI 消失（含被 kill）即执行同一套恢复（最多重试 3 s），不需要提权、不是常驻服务。
子进程路径与失败分支见 `systemproxy_windows.go` / `systemproxy_watchdog_windows.go`。

> 修复方向（已与你确认）：仅 Windows 做 journal；恢复无条件执行、地址从 journal 自身取；写入顺序为先 journal(Sync+rename) 再改注册表；三态恢复失败时保留日志并在界面提供手动恢复入口；开启系统代理时拉起 watchdog 覆盖"用户不再打开 App"的分支。

**缺口 E：`DisabledApps`（停用应用）在两条新路径上不生效。** —— 已修复（B3）

协议 v7 的规则带上 `AppId`，Hub 在 `publishResourcesLocked` 单点过滤；改动在 `Manager.Apply` 即时生效，无需重登。
已建立连接不被打断。

**缺口 F：`Manager.Apply` 的重启判据不含 `DisabledApps`。** —— 已修复（B3）

不再需要重启：开关变化直接重发资源快照（`rawResources` → `publishResourcesLocked`）。
