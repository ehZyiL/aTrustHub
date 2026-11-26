# P2 可选功能契约与装配记录

日期：2026-11-26。对应 [分阶段方案](component-boundaries-2026-11-26.md)。

## 实现范围

- `internal/relay/contract` 保存分享配置、状态、错误、资源、协议及 Source 接口；`discovery/contract` 保存发现快照。原运行时保留兼容别名，不修改现有 LAN 分享协议。
- `internal/vpn/contract` 保存会话能力和登录交互类型。relay 连接器迁入 `internal/relay/adapter`；基础工厂只装配 aTrust/EasyConnect，应用通过 `Registration` 显式注入 relay。未知、未安装、重复注册均拒绝，不退回其他登录方式。
- 分享适配器借用 Manager 已授权的 Source，仍由 Manager 校验会话代次和资源权限。严格 TCP/UDP、离线保护和撤销行为保持现有实现。
- 页面通过 `internal/relay/client` 查询和操作；`relay_assembly.go`、`discovery_assembly.go` 负责具体装配。防火墙及恢复日志实现独立至 `internal/relay/firewall`，保留网络助手所有权。
- `internal/components` 定义版本、能力、实例/请求标识、截止时间、有界事件和顺序校验。消息上限 64 KiB、详情 4 KiB；拒绝旧实例、重复、乱序及终态后的事件。取消确认与任务完成分开，修改任务必须在可恢复检查点停下。
- 客户端区分组件缺失、已安装但停用、等待、运行和失败；缺失分享组件仍可使用基础 VPN。

本阶段 relay 仍在 Hub 进程内，其实现暂留 `internal/relay` 根包。页面与核心依赖已经隔离；迁入独立进程及本机传输属于 P5，P2 不声称已经实现 relay IPC。组件控制契约将在 P3 清理任务中首次用于进程通信。

## 验证

Windows Go 1.27.4，`GOWORK=off`：

- `go test ./... -count=1` 通过，记录 `build/p2-tests-windows.log`。
- 依赖图测试实际执行 `go list -deps -json`，验证基础 VPN、store 和页面客户端不传递依赖分享服务、发现后端、防火墙实现或 cleanup service。
- 替代客户端页面测试覆盖组件缺失、安装但停用及业务失败；连接器测试覆盖未安装/未知协议、取消、重复注册，既有分享连接、资源撤销和严格出口测试保留。
- Windows/Linux 统一入口构建检查及 Worker IPC 生成检查通过，产物位于 `build/p2/windows`、`build/p2/linux`。

WSL Debian Go 1.27.4、CGO/gcc：`go test -race ./internal/relay/... ./internal/vpn/... ./internal/components -count=1` 通过。本阶段没有重复把已知环境相关的 Linux GUI 全量失败记作成功，限制见 [P1 记录](p1-lifecycle-2026-11-26.md)。

未执行真实网关登录、系统防火墙修改或 UAC 操作。配置和 LAN 协议格式未改变；可独立回退本阶段提交。
