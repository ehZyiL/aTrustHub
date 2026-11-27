# 桌面应用代码导航

入口为 `cmd/connect-hub/main.go` → `desktop.Run()`。MyGo 配置、Makefile 和统一 builder
都从产品根目录定位此入口；桌面包不依赖当前工作目录来定位源码。

页面仍在同一个 Go 包中，可以使用 `app` 的私有 UI 状态。Go 子目录是包边界，
不要仅为分组把页面移入子目录，再把整个 `app` 导出或传递回去。

| 职责 | 主要文件 |
|---|---|
| 应用状态、启动与服务装配 | `app.go`、`relay_assembly.go`、`discovery_assembly.go` |
| 窗口生命周期、菜单与关闭 | `window_lifecycle.go` |
| 配置同步、凭据桥接与剪贴板 | `config.go`、`credentials.go`、`clipboard.go` |
| 主视图、导航与公共控件 | `view.go`、`widgets.go`、`pagenav.go` |
| 接入点卡片、状态与日志入口 | `access_view.go` |
| 远程应用资源列表、分组与详情 | `apps_view.go` |
| 接入点编辑器与操作 | `editor_view.go`、`editor_actions.go` |
| 设置页、保存与确认弹窗 | `settings_view.go`、`settings_actions.go`、`confirmations_view.go` |
| 简单模式与外观 | `dashboard_simple.go`、`appearance.go` |
| 登录、证书及企业微信 | `login.go`、`authentication.go`、`browserlogin.go`、`certificate.go`、`wecom_*.go` |
| 本机应用与路由展示 | `localapps.go`、`installedapps*.go`、`routeview.go`、`resource_tun.go` |
| 接管模式切换与启动/退出恢复 | `capture_mode.go`、`capture_restore.go` |
| 网络接管及自动恢复装配 | `capture_chip.go`、`auto_capture.go`、`resource_proxy*.go`、`globaltun.go` |
| 分享、发现及导入页面 | `lanshare.go`、`lan_discovery.go`、`import_relay.go`、`lanshare_firewall.go` |
| 清理页面与选择/确认状态 | `cleanupview.go`、`cleanup.go` |
| 托盘、关闭、主题及重绘 | `tray_*.go`、`quitclose*.go`、`theme_soft.go`、`redraw.go`、`state_ticker.go` |
| 系统代理及退出恢复 | `systemproxy*.go` |
| 资源监测与日志 | `memory.go`、`memusage_*.go`、`accesslog_tail.go`、`logsview.go` |

`apps_view.go` 展示网关提供的远程应用资源；`localapps.go` 管理本机应用接管，二者职责不同。
本轮只按职责拆文件：原 `app.go` 1259 行、`view.go` 3166 行，拆分后分别为 462 行和
157 行；其余声明分布到 14 个文件中，165 个非 import 声明保持一致，没有新增包或接口。

以下控制逻辑在独立包维护，桌面只负责装配和消费状态：

- `internal/cleanup/client.TaskController`：清理任务后台运行、取消、代次和单槽快照。
- `internal/localapps/takeover.Controller`：资源 TUN 的启动、运行监控、停止及代理恢复。
- `internal/vpn.Manager`、`internal/localapps.Manager`：既有会话与应用管理。

`*_windows.go`、`*_linux.go`、`*_darwin.go` 保持 Go 的平台构建语义；平台文件不移动到
按平台命名的子目录。控制器测试在各自包内，页面/装配测试留在这里，避免为测试暴露运行状态。

在产品根目录执行：

```bash
GOWORK=off go test -mod=readonly ./internal/desktop
GOWORK=off go test -mod=readonly ./internal/cleanup/client ./internal/localapps/takeover
```

结构与依赖门禁见 `component_boundaries_test.go`。主动渲染截图需设置 `EASYCONNECT_SHOTS=1`，
输出仍在产品根目录的 `build/shots`。完整开发与配套组件构建见 [开发手册](../../docs/DEVELOPMENT.md)。
