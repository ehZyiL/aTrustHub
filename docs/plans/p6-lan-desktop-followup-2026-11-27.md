# P6 后续：LAN 桌面职责与依赖检查

日期：2026-11-27。起点：`a406535`。继续执行用户授权的项目结构整改。
状态：代码整理、依赖检查和自动化验证已完成；原生 UI 人工验收仍待回复。

## 范围与依据

`app.go`、`view.go` 拆分完成后，`lanshare.go` 仍有 1441 行，混合页面、任务交互、
网卡选择、历史归属保护和诊断；`lan_discovery.go` 有 907 行，混合发现生命周期与页面。
现有依赖检查只检查固定六个文件，后续增加文件可能漏检。

参考既有 `editor_view.go` / `editor_actions.go`、`relay_assembly.go` /
`discovery_assembly.go` 及控制器分包模式，按以下顺序继续：

1. 将页面依赖检查扩展到桌面目录所有非测试 Go 文件，包括其他平台的源码。
   保留现有装配入口的精确依赖例外，并用临时源码夹具验证新文件、平台文件及别名导入。
2. 将上述两个 LAN 文件的非 import 声明按职责移动，保持同包、函数签名、调用关系、
   状态所有权及业务行为，不新增接口或运行时组件。
3. 更新导航，完成声明等价审计、全量测试、vet 和跨平台编译，独立提交并推送。

目标文件：

- `lanshare.go`：分享草稿、启停、恢复及 UI 结果消费。
- `lanshare_view.go`：分享状态、表单与管理页面。
- `lan_interfaces.go`：分享与发现共用的网卡枚举、筛选、推荐和缓存。
- `relay_history.go`：历史归属持久化、保护与解除确认。
- `relay_details.go`：导入节点详情、本机与远端诊断。
- `lan_discovery.go`：发现发布、搜索及生命周期协调。
- `lan_discovery_view.go`：发现页面、状态文案及用户操作。

## 验收与限制

- [x] 所有桌面生产 Go 文件均受直接依赖检查覆盖，已知装配例外不能豁免其他运行时。
- [x] 两个原文件的全部非 import 声明逐项一致，无遗漏或重复，初始化行为不变。
- [x] 全量测试、vet，以及 Windows/Linux/macOS 的 Hub、relay 与 desktop 测试二进制编译通过。
- [x] 导航与实际结果已更新，变更可独立回退。
- [ ] 原生 UI 交互及正常退出人工验收：沿用前阶段待回复状态。

原生 UI 自动化管道此前已按技能规定重试失败，本轮不通过其他自动化方式绕过限制。
没有真实 VPN、系统代理、防火墙或清理操作；发行组合继续暂缓；不声称拆文件降低内存。
原有未跟踪的工作区文件、固定内核子模块和忽略目录内既有产物保持不动。

## 实际结果

| 文件 | 行数 |
|---|---:|
| `lanshare.go` | 369 |
| `lanshare_view.go` | 430 |
| `lan_interfaces.go` | 326 |
| `relay_history.go` | 174 |
| `relay_details.go` | 307 |
| `lan_discovery.go` | 484 |
| `lan_discovery_view.go` | 312 |

全部保留在 `internal/desktop` 同包内。94 个声明逐项 token SHA256 一致，
没有缺失、重复或新增包级初始化。审计工具沿用上一轮的 Go parser/scanner 实现，
证据在忽略目录 `build/p6-lan-original.json`、`build/p6-lan-split.json` 和
`build/p6-lan-declaration-audit.json`。

依赖检查在 `8fe2b75` 单独提交：`desktop_imports_test.go` 扫描所有生产 Go 文件，
包括非当前平台文件；14 个临时源码夹具覆盖新增页面、平台约束、别名导入、
实现子包、测试文件排除、允许的契约/客户端，以及装配例外不可扩大权限。
`app.go` 保留 `discovery.Backend` 注入类型的既有例外，未声称其已经完全不依赖发现实现。

本轮机械拆分与上述测试变更分开提交。回退拆分时同步回退导航，不需要修改配置、
子模块或用户备份；依赖检查提交可独立保留。

## 验证记录

- Windows/amd64、Go 1.27.4，所有 Go 命令使用 `GOWORK=off`。
- 依赖检查与核心依赖图测试通过；随后桌面包完整测试通过。
- `go test -mod=readonly ./... -count=1` 通过，30 个有测试包全部成功；
  `go vet -mod=readonly ./...` 通过。日志在 `build/p6-lan-tests.log` 和 `build/p6-lan-vet.log`。
- Windows/amd64、Linux/amd64、macOS/amd64 的 Hub、relay 和 desktop 测试二进制全部编译通过，
  产物在 `build/p6-lan-{windows,linux,darwin}`；不代表目标系统实机验收。
- 本轮未改变构建入口或打包布局，没有重复上一轮完整发行打包。
- 原生 UI 手动验收继续待回复，不用自动化测试或声明等价审计替代原生窗口交互结果。
