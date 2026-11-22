# 架构（核实版）

## 1. 进程模型

```
普通用户权限
├── connect-hub（GUI 主程序，单实例）
│   ├── aTrust 协议栈 —— 进程内（import vendor 化的 zju-connect）
│   └── EasyConnect —— 子进程 core/connect-hub-worker，stdio JSON-RPC v7
└── 经提权拉起的网络助手
    ├── Windows: core/connect-hub-capture.exe（UAC），命名管道 v7
    └── Linux:  /usr/local/libexec/connect-hub-capture（systemd），Unix socket v11
```

### 需要纠正的一个长期误解

`DEVELOPMENT.md` 画的图把 aTrust 与 EasyConnect 都放在 worker 里。**实际不是**：

- `internal/vpn/zju.go` 直接 `import` `client/atrust`、`stack/gvisor`、`resolve`、`dial`，在 GUI 进程内建立 aTrust 隧道；
- `zju-connect/internal/desktop`（worker 侧）只处理 EasyConnect 类型，协议里没有协议选择字段。

后果（都在代码里能直接看到，不需要实机）：

| 后果 | 位置 |
|---|---|
| 同一套栈接线写两遍 | `vpn/zju.go` `connectZJU` 与 worker 侧 `desktop/run.go` |
| 加固只覆盖一半 | worker 有 `internal/pinnedcert` 强制校验；进程内 aTrust 用 `InsecureSkipVerify: true` |
| 栈崩溃会带走 UI | `connectZJU` 只能靠 `recover()` 兜 |
| 能力只在一侧实现 | `CheckAlive` / `ClientData` 只有进程内版本，worker 侧靠 `flow_prepare`、`ExchangeCaptureDNS` 等特化消息补齐 |

## 2. 构建上下文：内核代码有两个真源

这是本项目最容易被"在错误目录编译"坑到的地方。

| 上下文 | 内容 | 谁在用 |
|---|---|---|
| `easy-connect/go.work` | `use ./aTrustHub`；`replace utls => ./zju-connect/third_party/utls` | 从仓库根执行的命令 |
| `aTrustHub/go.work` | 仅 `use .` | **在 `aTrustHub/` 内执行的命令**（就近命中，屏蔽根 workspace 的 replace） |
| `aTrustHub/go.mod` | `replace zju-connect => ./third_party/zju-connect` | Hub 自己的 aTrust 依赖（Fork A） |
| `zju-connect/`（独立模块） | `GOWORK=off` 编译 worker | 打包脚本 `scripts/package-*.sh` |

由此产生两个必须知道的后果：

1. **同一 commit 从不同目录构建，链接到不同 uTLS**：根目录构建用 patched 版（`zju-connect/third_party/utls`），`aTrustHub/` 内构建用上游 `v1.8.2`。Hub 的 `wecom_quicklogin.go` 直接 import utls。
2. **aTrust 内核有两份源码**：`aTrustHub/third_party/zju-connect`（随 Hub 提交，无独立 git）与 `zju-connect/`（独立仓库，worker 来源）。二者已相互漂移，谁都不是超集。

worker 必须用 `GOWORK=off` 从 `zju-connect/` 构建，否则会解析到 Hub 的 patched 模块而链接失败或行为错乱。

> 历史记录里"根 `go.work` 曾引用 `./tests/e2e` 导致根目录 go 命令全部失败"的问题已修复（该目录不存在，相关 e2e 模块与 harness 已不在仓库内）。`tests/e2e` 现在**不存在**，任何引用它的文档/脚本都失效。

## 3. 模块边界

| 包 | 职责 |
|---|---|
| `internal/model` | 配置模型（AccessPoint / Settings / LocalApp）+ 归一化与校验 |
| `internal/store` | 原子 JSON 配置 + SecretStore（系统凭据 / 文件 / 内存三层） |
| `internal/vpn` | 多接入点会话编排、聚合入口、路由决策接入、健康与会话探测、DNS 别名 |
| `internal/proxy` | SOCKS5 / SOCKS4 / HTTP 混合监听（TCP），私有 UDP 数据报通道 |
| `internal/routing` | 纯函数归属/授权/策略决策，不做 DNS、不拨号 |
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

根 `main` 包是 UI 与胶水层，**不在**上表内：非测试源码 83 个文件 / 14.2k 行 / 471 KB，
其中 32 个带 `_{windows,linux,darwin}.go` 平台后缀，`view.go` 单文件近 100 KB。

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
2. "协议栈单一真源"目前**不成立**（两份 fork 并存）。
3. `tests/e2e` 模块与 harness 已不存在（旧任务清单 §5/§7 引用了它们）。
