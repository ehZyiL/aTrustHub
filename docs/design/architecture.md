# 架构（核实版）

## 1. 进程模型

```
普通用户权限
├── connect-hub（GUI 主程序，单实例）
│   ├── aTrust 协议栈 —— 进程内（import 固定子模块内的 zju-connect）
│   └── EasyConnect —— 子进程 core/connect-hub-worker，stdio JSON-RPC v7
└── 经提权拉起的网络助手
    ├── Windows: core/connect-hub-capture.exe（UAC），命名管道 v7
    └── Linux:  /usr/local/libexec/connect-hub-capture（systemd），Unix socket v11
```

### 需要纠正的一个长期误解

旧版开发手册曾把 aTrust 与 EasyConnect 都放在 worker 里；P4 已修正文档，当前模型是：

- `internal/vpn/zju.go` 直接 `import` `client/atrust`、`stack/gvisor`、`resolve`、`dial`，在 GUI 进程内建立 aTrust 隧道；
- `zju-connect/internal/desktop`（worker 侧）只处理 EasyConnect 类型，协议里没有协议选择字段。

后果（都在代码里能直接看到，不需要实机）：

| 后果 | 位置 |
|---|---|
| 同一套栈接线写两遍 | `vpn/zju.go` `connectZJU` 与 worker 侧 `desktop/run.go` |
| 加固只覆盖一半 | worker 有 `internal/pinnedcert` 强制校验；进程内 aTrust 用 `InsecureSkipVerify: true` |
| 栈崩溃会带走 UI | `connectZJU` 只能靠 `recover()` 兜 |
| 能力只在一侧实现 | `CheckAlive` / `ClientData` 只有进程内版本，worker 侧靠 `flow_prepare`、`ExchangeCaptureDNS` 等特化消息补齐 |

## 2. 构建上下文：P4 统一内核来源

`third_party/zju-connect` 是固定提交的 Git 子模块，归并 Hub 的 aTrust 补丁与 Worker fork。
Hub 和 Worker 独立编译，但内核及 patched uTLS 来自同一子模块。
`scripts/buildtool` 核对 Go 版本、gitlink、锁文件、干净工作树、IPC 和模块清单；
默认构建无需外层目录，拒绝外部 Worker 覆盖路径。全部命令显式 `GOWORK=off`。

`tests/e2e` 已纳入产品模块，执行 `go test ./...` 会运行真实 Worker 的黑盒 IPC 测试；
缺少子模块直接失败。旧的 multi_gateway_router / tier1 harness 未在本轮恢复。

详见 [P4 归并及验收](../plans/p4-kernel-2026-11-26.md) 和子模块 `PATCHES.md`。

## 3. 模块边界

| 包 | 职责 |
|---|---|
| `internal/model` | 配置模型（AccessPoint / Settings / LocalApp）+ 归一化与校验 |
| `internal/store` | 原子 JSON 配置 + SecretStore（系统凭据 / 文件 / 内存三层） |
| `internal/vpn` | 多接入点会话编排、聚合入口、路由决策接入、健康与会话探测、DNS 别名 |
| `internal/proxy` | SOCKS5 / SOCKS4 / HTTP 混合监听（TCP），私有 UDP 数据报通道 |
| `internal/routing` | 纯函数归属/授权/策略决策，不做 DNS、不拨号 |
| `internal/relay` | 局域网分享：协议 v1 服务端/客户端（严格出口、指纹钉扎、租约、防火墙规则簿记） |
| `internal/relay/discovery` | DNS-SD 发布/浏览、候选装配与缓存上限（不读凭据，平台边界是 `Backend`） |
| `internal/lanname` | 公开名称规则的唯一实现（保存/发布/接收共用） |
| `internal/workeripc` | 与 worker 的 v7 协议类型与流结果校验 |
| `internal/splitdns` | 本地回环 DNS 入口（UDP/TCP）+ 缓存 |
| `internal/dnsmapping` | 会话级 DNS 映射池（合成地址）与别名生命周期 |
| `internal/netpolicy` | 地址区间基础操作（合并、容量、冲突判定） |
| `internal/localapps` | 本机软件：启动、代理浏览器、TCP 转发、系统接管编排 |
| `internal/capture` | Linux 提权助手（systemd 服务）+ GUI 侧客户端 |
| `internal/wincapture` | Windows 提权助手（引擎/协议/NRPT/路由/恢复） |
| `internal/resolved` | Linux systemd-resolved 集成（route-only domain 所有权） |
| `internal/packetstack` | Wintun + gVisor 的最小包适配（只把 TCP/UDP 交给 handler） |
| `internal/cdp` | Chromium DevTools Protocol（浏览器登录回取回调地址） |
| `cmd/app-helper` | 提权助手入口（Windows/Linux 共用一个 main，平台文件分离） |
| `cmd/easyconnect-check` | 无 GUI 的 worker 连通性自检工具 |

根 `main` 包是 UI 与胶水层，**不在**上表内：非测试源码 94 个文件 / ≈18.4k 行，
其中 36 个带 `_{windows,linux,darwin}.go` 平台后缀，`view.go` 单文件近 100 KB。

## 4. 运行时约定

- **单实例**：`mygo.App.RequestSingleInstanceLock()`；第二次启动改为唤起已有窗口。
- **数据目录**：`CONNECT_HUB_HOME` / `EASYCONNECT_HOME` 环境变量优先，否则 `os.UserConfigDir()/connect-hub`
  （Windows `%APPDATA%\connect-hub`，Linux `~/.config/connect-hub`）。目录权限 0700。
- **端口**：
  - 统一入口默认 `127.0.0.1:1080`（`Settings.AggregatePort`）；
  - 每接入点独立端口从 `1081` 起（`Config.NextSocksPort` / `EnsurePorts`）；
  - worker 的私有 SOCKS 端口由 worker 自己绑 `127.0.0.1:0` 后在 `ready` 里回报。
- **凭据**：默认走系统凭据库（`mygo.Secrets`），进程内再套一层 `SessionSecrets`；显式配置 `secretStore=file` 时落 `secrets.json`（0600）。
- **日志**：`<数据目录>/app.log`（超过 4 MB 轮转为 `.1`）、`stderr.log`；访问日志另有独立文件。

## 5. 与旧文档的差异

见 [review/errata.md](../review/errata.md)。与本文件直接相关的三条：

1. aTrust 不在 worker 内（旧架构图错）。
2. P4 已归并两份 fork，以固定子模块作为唯一默认源码来源。
3. `tests/e2e` 已纳入产品模块；历史多网关 harness 仍不存在。
