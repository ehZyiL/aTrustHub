# Connect Hub 文档（核实版）

现状文档只收**已对源码逐条核实的结论**，不收历史过程记录。
`plans/` 单独保存方案、验收门禁及阶段实施记录；其中未完成的目标结构和任务不能作为已实现能力引用。

历史过程记录（19 份带日期的验收/实施记录）仍留在仓库外的 `easy-connect/docs/`，
它们没有搬进来，原因是：内容大量互相覆盖、协议版本号已过期、部分结论与当前代码相反。
这些记录的**每一条错误与过期项**已整理到 [review/errata.md](review/errata.md)，
需要追溯现场证据时去原始文件，需要判断"现在到底是不是这样"时看本目录。

## 核实基线

| 项 | 值 | 出处 |
|---|---|---|
| Worker IPC | **v7** | `internal/workeripc/protocol.go` `Version = 7` |
| Windows 提权助手 | **v7** | `internal/wincapture/protocol.go` `ProtocolVersion = 7` |
| Linux 提权助手 | **v11** | `internal/capture/protocol_linux.go` `ProtocolVersion = 11` |
| 局域网分享协议 | **v1** | `internal/relay/protocol.go` `ProtocolVersion = 1` |
| 局域网发现草案 | **v1** | `internal/relay/discovery/types.go` `DraftVersion = 1` |
| Hub 模块 | `GO 1.27.3` | `aTrustHub/go.mod` |
| 应用构建标识 | `0.2.0` | `internal/desktop/app.go` `version` / `appBuild` |

任何给出不同协议号的文档（v3/v4/v5/v8/v9 等）都已过期，不要据此排障。

**最近一次实机验证**（含分享链路、闭共享、口令时序）：
[design/lan-relay-discovery-2026-11-24.md §19.1](design/lan-relay-discovery-2026-11-24.md)。
该节同时列出了**仍未验证**的项（跨机发现、Windows 入站 5353、macOS 分支、规模），
引用之前先看那张表。

## 目录结构

```text
docs/
├── README.md            本文件：索引、核实基线、平台能力矩阵
├── DEVELOPMENT.md       开发、测试与打包手册
├── WINDOWS-QUICKSTART.md / LINUX-QUICKSTART.md  平台入门（同时装入发行包）
├── WINDOWS-IMPLEMENTATION.md  Windows 技术实现说明
├── design/              设计（已核实）—— 回答“具体怎么实现的”
│   ├── architecture.md  进程模型、构建上下文、模块边界、运行时约定
│   ├── networking.md    四种接管方式、路由与 DNS 归属、范围边界
│   ├── recovery.md      退出顺序、事务日志、生效时机、硬杀矩阵、已知缺口
│   ├── lan-relay-sharing-plan-2026-11-24.md          局域网分享：需求与 UI/UX（已实现）
│   ├── lan-relay-sharing-implementation-2026-11-24.md 局域网分享：协议/生命周期/验收（已实现）
│   └── lan-relay-discovery-2026-11-24.md             局域网分享自动发现：协议/缓存/生命周期（已实现）
├── review/
│   └── errata.md        旧文档勘误 —— 回答“旧说法哪里不对”
├── plans/               方案与阶段记录 —— 回答“接下来怎么改、如何验收”
│   ├── component-boundaries-2026-11-26.md  项目结构与可选组件重构方案
│   ├── p5-relay-process-2026-11-27.md       Relay 子进程边界与验证记录
│   ├── p6-desktop-layout-2026-11-27.md      桌面包与根目录整理方案及验收
│   ├── p6-desktop-followup-2026-11-27.md    桌面主文件职责拆分
│   ├── p6-lan-desktop-followup-2026-11-27.md LAN 职责整理与依赖检查
│   └── p6-resource-validation-2026-11-27.md 当前版本配套构建与资源复测
├── roadmap.md           未完成事项 —— 回答“还差什么”（拆成代码可判定 / 待实机）
└── assets/              README 引用的 4 张界面截图
```

分类原则：按“打开它要回答什么问题”分——**怎么实现**（design）/**哪里不对**（review）/**怎么改与验收**（plans）/**还差什么**（roadmap）/**素材**（assets）。

## 文档地图

| 文档 | 回答什么问题 |
|---|---|
| [DEVELOPMENT.md](DEVELOPMENT.md) | 如何开发、测试和打包；所有命令在产品根目录执行 |
| [WINDOWS-QUICKSTART.md](WINDOWS-QUICKSTART.md) / [LINUX-QUICKSTART.md](LINUX-QUICKSTART.md) | 如何安装与使用 |
| [WINDOWS-IMPLEMENTATION.md](WINDOWS-IMPLEMENTATION.md) | Windows 平台底层实现 |
| [design/architecture.md](design/architecture.md) | 进程怎么分、谁提权、内核源码有几个真源、模块边界、平台能力 |
| [design/networking.md](design/networking.md) | 四种网络接管方式各自怎么实现、路由与 DNS 归属怎么判、范围边界到哪 |
| [design/recovery.md](design/recovery.md) | 正常退出与硬杀分别会清理什么、事务日志在哪、还剩哪些洞 |
| [design/lan-relay-sharing-plan-2026-11-24.md](design/lan-relay-sharing-plan-2026-11-24.md) | 局域网分享要做什么、UI/UX 怎么组织、哪些能力刻意不做 |
| [design/lan-relay-sharing-implementation-2026-11-24.md](design/lan-relay-sharing-implementation-2026-11-24.md) | 分享协议 v1、严格出口边界、启停/恢复顺序，以及当时的验证证据与未验证项（端点表关于租约续期与 ETag 的描述已被后续修复超越，见 [review/errata.md](review/errata.md) F 节） |
| [design/lan-relay-discovery-2026-11-24.md](design/lan-relay-discovery-2026-11-24.md) | 自动发现的后端选型、DNS-SD 协议 v1、缓存上限、发布/浏览生命周期与验收用例；**§19.1 是当前最新的实机验证记录** |
| [review/errata.md](review/errata.md) | 旧文档哪些说法与代码不符、错在哪 |
| [review/lan-relay-sharing-review-e888e47-2026-11-24.md](review/lan-relay-sharing-review-e888e47-2026-11-24.md) | 局域网分享合并前的 10 项审查发现（S1–S3、R1–R7）与复现方式 |
| [review/lan-relay-sharing-remediation-e888e47-2026-11-24.md](review/lan-relay-sharing-remediation-e888e47-2026-11-24.md) | 上述 10 项的处理方案、约束与验收用例 |
| [roadmap.md](roadmap.md) | 哪些"未完成"是代码可判定的、哪些只能等实机 |
| [plans/component-boundaries-2026-11-26.md](plans/component-boundaries-2026-11-26.md) | 从分享分支推进结构重构的阶段、组件边界、资源预算和验收方式（P0/P1 已有实现，后续待实施） |
| [plans/p0-baseline-2026-11-26.md](plans/p0-baseline-2026-11-26.md) | 统一构建入口、固定来源、首次内存对照、生命周期反馈与后续预算（阶段性证据） |
| [plans/p1-lifecycle-2026-11-26.md](plans/p1-lifecycle-2026-11-26.md) | 按需启停、取消与任务退出、十轮回归、P1 内存复测及平台限制 |
| [plans/p5-relay-process-2026-11-27.md](plans/p5-relay-process-2026-11-27.md) | Relay 子进程边界、授权数据通道、按需发现生命周期与自动验证结果 |
| [plans/p6-desktop-followup-2026-11-27.md](plans/p6-desktop-followup-2026-11-27.md) | 桌面主文件按职责拆分、声明等价与回归记录 |
| [plans/p6-lan-desktop-followup-2026-11-27.md](plans/p6-lan-desktop-followup-2026-11-27.md) | LAN 页面、生命周期、网卡与历史保护职责及依赖检查 |
| [plans/p6-resource-validation-2026-11-27.md](plans/p6-resource-validation-2026-11-27.md) | 当前版本配套构建、三轮空闲与十轮启停资源复测及限制 |

## 平台能力矩阵（已核实）

判定来源：`platform_{windows,linux,darwin}.go`、`resource_tun.go`、`capture_mode.go` `captureSupported`。

| 能力 | Windows | Linux | macOS |
|---|---|---|---|
| 独立 SOCKS5/HTTP 端口（每接入点） | ✅ | ✅ | ✅ |
| 统一入口（聚合代理，默认 1080） | ✅ | ✅ | ✅ |
| 系统代理托管（手动切档） | ✅ | ❌ 不提供 | ✅ |
| 启动后自动恢复系统代理 | ✅ | ❌ | ❌（需管理员授权，故意关闭） |
| 全局 TUN（旧，仅 aTrust 会话） | ✅ | ❌ `supportsElevatedTUN=false` | ✅ |
| 应用接管（新，worker 驱动的资源 TUN） | ✅ | ✅ | ❌ `supportsResourceTUN=false` |
| 启动后自动恢复应用接管（开关） | ❌（启动助手每次要过 UAC，`supportsAutoRestoreAppCapture=false`） | ✅（systemd 常驻助手） | ❌（无应用接管） |
| 局域网分享（宿主侧） | ✅ 需 UAC 建防火墙规则；**网络类别为「公用」时规则不生效**，得先把该网络设为「专用」 | ✅ 端口需自行放行（程序不改防火墙） | 未实机验证（打包脚本已声明 `NSLocalNetworkUsageDescription` / `NSBonjourServices`） |
| 局域网分享自动发现（DNS-SD 发布/浏览） | ✅ 同机回环实测；跨机待验证（入站 UDP 5353 是否被系统防火墙拦未知） | ✅ 同机回环实测（WSL 镜像网络，median 1.76ms）；跨机待验证 | 未测（共享 5353 的权限与 responder 共存未验证） |

两个容易搞错的点：

1. **Linux 没有"全局 TUN"这一档**，但**有**"应用接管"。旧文档里"Linux 的 TUN"与"Linux 无 TUN"两种说法都只对了一半。
2. **macOS 有全局 TUN，没有应用接管**。这与"Linux/Windows 才有应用接管"的直觉相反。

## 写作约定

- 每条结论后给代码位置；只有代码能证明的才写成结论。
- 只能靠实机验证的（UAC、Wintun、NRPT、systemd-resolved 宿主行为等）一律标 **待实机**，不写成"已支持"。
- 协议号、文件名、路径必须能在本仓库里 `rg` 到，否则不写。
- `plans/` 必须区分当前事实与目标，并明确标注尚未创建的路径、拟定协议和未执行的验证；实施后再更新现状文档。
