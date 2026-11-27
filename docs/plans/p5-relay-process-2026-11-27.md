# P5 Relay 进程隔离记录

日期：2026-11-27。产品分支：`refactor/component-boundaries`。

## 结果

`cmd/app-relay` 生成 `core/connect-hub-relay(.exe)`，处理 LAN 分享监听、导入连接会话和 DNS-SD 发布/浏览。Hub 保留 VPN 会话、资源归属、防火墙控制、配置存储和界面；每个分享/导入任务单独启动 relay 进程，发布与浏览共享一个惰性启动的 discovery 进程。任务结束后关闭控制通道，等待子进程退出。发现进程在发布和浏览都空闲后自行退出，后续操作可以重新启动。

relay 与 Hub 使用 stdin/stdout 上的版本化 JSON 控制消息。本机 loopback HTTP 通道使用每进程随机令牌传递受限快照、DNS 与严格拨号请求；TCP 隧道使用独立 hijack 流，不经过 JSON。导入流在资源版本变化、会话关闭或子进程退出时撤销。拨号只通过已有授权会话，不为未知目标或 relay 故障回退直连。防火墙仍由 Hub 和现有特权助手管理。

## 自动验证

- `go test -mod=readonly ./... -count=1` 通过，包含真实本机 mDNS 发布、浏览和加入端到端用例。
- relay 集成测试覆盖 host/import 字节流、DNS 成功与拒绝、未授权目标、过期资源版本、资源更新时断开旧流、正常停止和进程回收。
- discovery 进程测试覆盖惰性启动、空闲自动退出、再次启动和显式关闭。
- Hub 与 `cmd/app-relay` 分别通过 Windows/amd64、Linux/amd64、macOS/amd64 交叉构建。
- `git diff --check` 通过。

## 尚未实测

当前 Windows 环境没有 C 编译器，`go test -race` 因 `-race requires cgo` 无法运行。此次没有启动真实 VPN 登录、修改防火墙或执行清理/重启；跨机发现、Windows 入站 5353、macOS multicast 权限，以及完整进程树的内存/CPU/吞吐/延迟前后对照仍需在对应设备上验证。交叉编译和同机 mDNS 测试不替代这些验收。

## 联调

默认从 Hub 可执行文件旁的 `core/connect-hub-relay(.exe)` 查找组件。可以设置 `EASYCONNECT_RELAY` 指向指定组件；Hub 会在版本握手或任务通道失败时报告错误，不会静默回退到 Hub 内的 relay 实现。
