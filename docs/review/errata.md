# 旧文档勘误（对代码核实的结果）

核实方式：把每份文档里的可验证陈述（路径、协议号、能力、开关、行为）逐条对到源码。
只列**与当前代码不符**或**会误导排障**的条目；没列到的部分视为核实通过。

原始文档位置：`easy-connect/docs/`（仓库外，不受版本管理）。本次**不拷贝**它们，
需要追溯现场证据时读原文，需要判断"现在是不是这样"时读本目录。

---

## A. 硬错误：会把排障带错方向

| 出处 | 文档说法 | 源代码实际 |
|---|---|---|
| `DEVELOPMENT.md` §1 架构图 | aTrust 与 EasyConnect 两条协议栈都在 `connect-hub-worker` 里 | aTrust 在 **GUI 进程内**直接 import（`internal/vpn/zju.go`）；worker 只做 EasyConnect，协议里无协议选择字段 |
| `DEVELOPMENT.md` §4.3 | "Linux（Native TUN + Policy Routing）"属于全局 TUN 的一档 | Linux `supportsElevatedTUN() = false`，**没有**全局 TUN 这一档；Linux 只有"应用接管"（`supportsResourceTUN = true`） |
| `DEVELOPMENT.md` §3.2 | Linux 助手 socket 在 `/run/connect-hub/helper.sock` | 实际 `/run/connect-hub-capture-<uid>/control.sock`（`capture.SocketPath`），0600 且 chown 到该 UID |
| `DEVELOPMENT.md` §2 | `go.work` 的 `use` 含 `./tests/e2e` | 该目录**不存在**（曾导致根目录任何 go 命令失败，已修复）；`tests/e2e` 与 harness 已不在仓库 |
| `desktop-status-2026-11-19` | "新接入点默认 EasyConnect" | `model.AccessPoint.Normalize()` 默认 `protocol = atrust`，EasyConnect 必须显式填写 |
| `desktop-status-2026-11-19` | "Linux 关闭窗口退出并清理连接" | 有托盘时关闭是**隐藏到托盘**（`quitclose.go`：linux + trayOK + 未勾选退出 → `closeHide`）；只有检测不到托盘才退出 |
| `desktop-status-2026-11-19` | "未实现的 Linux 系统代理、TUN 不可用" | 系统代理仍不提供；但**应用接管（资源 TUN）在 Linux 可用** |
| `linux-capture-helper-2026-11-20` | 接管入口默认隐藏，需 `EASYCONNECT_EXPERIMENTAL_CAPTURE=1` | 已默认显示；同一批的 `linux-flow-validation` 自己也写了"现在默认显示，无需环境变量"，两份文档互相矛盾 |
| `tun-resource-routing-tasks` §5/§7 | 引用 `tests/e2e/harness/multi_gateway_router.go`、`tests/e2e/tier1_features/...` 作为回归手段 | 文件不存在，"回归通过"无法复跑 |

## B. 已过期：当时对，现在不对

| 出处 | 文档说法 | 现状 |
|---|---|---|
| `implementation-plan` | worker IPC v3，Windows helper v2，Linux helper v5 | **v7 / v7 / v10** |
| 全部 `linux-*` 记录 | helper 协议 v3/v4/v5/v8/v9 | **v10** |
| `tun-resource-routing-plan` §6 | "worker 协议当前是 v5；Windows 助手 v2，Linux 助手 v5" | **v7 / v7 / v10** |
| `desktop-status`、`linux-*` | 产物名 `easyconnect-hub-linux-amd64-*` | 现为 `connect-hub-linux-amd64-*`（本地 `build/` 里只有 `connect-hub-windows-amd64*`） |
| `greenfield-architecture` §2.4 缺陷 2 | "发布包缺 worker（CI 只编 multitun）" | **已修**：两个打包脚本都编 worker，并做空配置 IPC 自检 |
| `greenfield-architecture` §7 | "三处授权判定并存" | **已收敛**：`internal/routing` 是唯一决策点；worker 侧 `ErrACLDenied` 降级为兜底 |
| `greenfield-architecture` §2.6 | 根包 51 个非测试 `.go`、28 个平台后缀、326 KB | 现在 83 个文件 / 14.2k 行 / 471 KB，其中 32 个平台后缀（结论"壳层过重"仍成立，数字需更新） |
| `greenfield-architecture` §10 / `implementation-plan` §9 | `tests/e2e` 只有 `go.mod` | 目录已不存在 |
| `gateway-validation` | "aTrustHub GUI 在 Fedora 构建失败，缺 redirectStderr / systemProxyEnabled / helperSuffix 等符号" | 已补齐（`stderr_linux.go`、`systemproxy_linux.go`、`helperpath_linux.go` 均在） |
| `linux-capture-helper` 等 | "产品辅助服务、受认证的 GUI 控制、提权安装、启动屏障尚未实现" | 已实现（`internal/capture/service_linux.go`、`setup_linux.go`、`launch_linux.go`） |
| `implementation-plan` §3 | "建议目录（新增路径尚未创建）" | 全部已创建 |

## C. 仍然成立（可直接引用，不需要再核实）

| 结论 | 复核位置 |
|---|---|
| 公开混合代理只支持 TCP；UDP 只能走私有的认证数据报通道 | `internal/proxy/socks5.go`、`datagram.go` |
| 网关 B 的异常 SAN 靠 `internal/pinnedcert` + 局部 uTLS 补丁解决，不是标准库 overlay | `zju-connect/internal/pinnedcert`、`third_party/utls` |
| aTrust 协议栈仍使用 `InsecureSkipVerify: true` | `third_party/zju-connect/client/atrust/tls.go:28`、`auth/auth.go:118` |
| cgroup v2 + `nft socket cgroupv2` + TPROXY + 策略路由可实现按软件接管 | `internal/capture/rules_linux.go:346,348` |
| 已知内网 UDP → `port-unreachable`；已知内网 IPv6 → `admin-prohibited` | `internal/capture/guard_linux.go` |
| 只注入资源网段，不装 `0.0.0.0/0` | `internal/wincapture/routes*.go`、`packetstack` |
| ICMP 不转发（本地 echo 会造成假健康） | `internal/packetstack/stack.go:154` 注释 |
| 捕获地址总量上限 1048576 | `internal/netpolicy/prefixes.go:32` |
| 分域 DNS：Windows NRPT 单条并集规则；Linux resolved route-only + `ListDelegates` 冲突检查 | `internal/wincapture/dns_policy.go`、`internal/resolved/link_linux.go:156` |
| 合成地址块 198.19.0.0/16（/20–/24），上游 198.18.0.0/16 不重叠；TTL ≤ 60；单次 ≤ 32 条；池 ≤ 8192 | `internal/dnsmapping/pool.go` |
| 3 个 Windows 普通用户进程测试（`ChildrenOutliveRoot` / `LaunchBarrierChildrenAndDetach` / `CancelledLaunchCreatesNoProcess`）在管理员令牌下不通过 | 代码只能确认这三个用例存在；"需普通桌面令牌"是环境事实，仅与各记录里的 `-skip` 命令一致，本次未能复跑 |
| 外层 `easy-connect/` 不是 git 仓库，只有 `aTrustHub/`、`zju-connect/` 是 | `git` 实测 |

## D. 死链与失效证据

当前 `aTrustHub/build/` 里只有 `connect-hub-windows-amd64/` 目录与 `connect-hub-windows-amd64.zip`。
下列被文档当作"可用证据"的归档**已不存在**，其中的 SHA256 无从复核：

- `windows-system-tun-health-test-v11.zip`（`.11` 配套包）
- `linux-system-tun-health-test-v11.tar.gz`
- `connect-hub-windows-amd64-t17.zip` / `easyconnect-hub-linux-amd64-t17.tar.gz`
- 以及各 `*-v10`、`windows-system-tun-recovery-test`、`linux-system-tun-test.tar.gz` 等

含义：**这些记录的"已核对哈希"不能再作为发布门槛的证据**，需要重新出包并重算。
文档里"两平台配套包已验证"只能理解为历史事实，不代表当前工作区存在可复现产物。

## E. 与本轮修复的交叉点

以下两条已在本轮改掉，旧文档若被外部引用需注意：

1. `scripts/package-linux.sh` 原先把助手编成 `core/connect-hub-capture`，
   而 `packaging/linux/install-capture-helper.sh` 只认 `core/easyconnect-hub-capture`
   → **Linux 上按包内脚本安装特权助手必然失败**。现已把产品名收尾到 `connect-hub`：
   包内二进制、安装路径 `/usr/local/libexec/connect-hub-capture`、systemd 单元
   `connect-hub-capture@<uid>.service`、运行时目录 `/run/connect-hub-capture-<uid>` 全部统一，
   助手协议随之升到 v11；安装脚本会把改名前的 `easyconnect-hub-capture` 单元与二进制先停掉并移除。
2. Windows/Linux 两处 `COMPONENTS.txt` 里的主程序名仍写 `easyconnect-hub(.exe)`，已改为实际的 `connect-hub(.exe)`。

## F. 局域网分享/发现：旧说法与本轮（第十轮复审）修复的交叉点

本节只列**引用后会误导**的旧说法。详细现象、根因与回归用例见
`design/lan-relay-discovery-2026-11-24.md` §19 的 R9-14…R9-23。

| 出处 | 文档说法 | 现状 |
|---|---|---|
| `lan-relay-sharing-implementation` 端点表 `GET /v1/status` | "续租本客户端控制会话"（暗示只有心跳续租） | 现在**任何认证请求**都续租（`authenticateClient` 内 `touch`）。旧实现只有心跳续租，导致只轮询资源/开隧道的客户端在 `ClientLease=15s` 后被静默踢掉（R9-21） |
| 同表 `GET /v1/resources` | "支持 ETag/304" | 当时**并不生效**：服务端 ETag 是 `"<revision>"`，客户端发裸 revision，永不匹配，每次刷新都重传整份快照；现已两端对齐（R9-22） |
| `lan-relay-discovery` §18 / §19 对 `DropUnusableDomains` 的描述 | 清掉"不能当名称使用的域名规则与内部域名" | 漏了 `StaticDNS[].Name`，而 `Validate` 对它跑同一套校验 → 静态 DNS 里只要有一条用 IP 当名字，整份快照仍被拒，同事继续看到「资源域名不能是 IP 地址」（R9-19） |
| 分享身份"绑定一个地址"（`impl`/`plan` 多处） | 身份与监听地址一一对应，地址变化必须给出新口令 | 语义没变，但当时 `DecodeIdentity` 不恢复 `Address`：**重启后监听退化成 `0.0.0.0`（所有网卡）**，且"地址已变化"守卫永不触发；现已从证书唯一 IPv4 SAN 恢复，异常证书拒绝解码（R9-16、R9-18） |
| 客户端错误文案（`impl` 的失败矩阵） | "无法连接分享主机：<原始错误>" | 现在归一为可行动结论（拒绝/不可达/被重置/超时），不再把 `Post` 动词、URL、`dial tcp`、宿主内部 `127.0.0.1:<port>` 与 `unknown error` 送到同事面前（R9-23） |
| `lan-relay-discovery` §9.1.5 / R2-5 | "同 sid 的远端仍显示" | 只在一个 endpoint 可见的前提下成立：同一 instance 同时存在两个存活 A 记录时，装配层只保留一个端点，选哪个由地址字典序决定，本机地址更小时远端会被自己的地址盖住（R9-14，已在设计文档记为已知限制） |