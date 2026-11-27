# P6 后续：桌面大文件按职责拆分

日期：2026-11-27。起点：`c80b996`。用户授权完成目录整理后继续后续任务。
状态：拆分与自动化验证完成；提交按本轮独立变更交付。原生 UI 人工验收仍待回复。

## 范围

继续解决桌面源码的可维护性，不恢复暂缓的发行组合、不改网络协议与业务行为。
本轮只拆 `internal/desktop/app.go` 和 `view.go`，保持同包、私有成员和调用关系，
不继续将所有文件分目录或为拆文件新增接口。独立领域控制器沿用 P6 已建立的边界。

目标职责：

- `app.go` 保留应用状态、版本及启动装配；窗口生命周期、配置同步、凭据桥接、
  网络恢复/退出、剪贴板交互分别归入明确文件。
- `view.go` 保留主界面/导航；应用资源列表、接入点卡片、编辑器、设置页、确认弹窗
  及相关交互逻辑按职责归入对应文件。
- 配套测试保持现有语义，更新源码导航；不要求任意单文件行数上限，不把领域紧密
  相连的代码拆成大量只有一两个函数的文件。

## 验收

- [x] 拆分前后所有非 import 的 Go 声明一致（排除文件注释与 import 顺序），确认仅改变位置。
- [x] 全量产品测试、vet 与 Windows/Linux/macOS 构建通过，既有页面与状态机用例继续覆盖。
- [x] 补充源码导航和实际文件规模；本轮变更使用独立提交，可单独回退。
- [ ] 原生 UI 手动验收：继续保留上一轮限制，未收到结果前不将其标记通过。

回退：只回退本轮拆文件提交，不影响前面已验证的 cmd 入口、领域控制器或用户数据。

## 实际文件职责

全部保留在 `internal/desktop` 同一包内。行数包含 import 与注释，不设机械行数上限。

| 文件 | 职责 | 行数 |
|---|---|---:|
| `app.go` | 应用状态、版本、启动和服务装配 | 462 |
| `window_lifecycle.go` | 菜单、窗口、启动与退出 | 276 |
| `credentials.go` | 凭据与验证码等待桥接 | 139 |
| `config.go` | 配置克隆、保存与更新 | 82 |
| `capture_restore.go` | 启动恢复与退出时的网络清理装配 | 215 |
| `clipboard.go` | 剪贴板及简短展示文本 | 36 |
| `view.go` | 主视图、导航、工具栏和进度描述 | 157 |
| `widgets.go` | 公共图标、行与弹窗控件 | 175 |
| `apps_view.go` | 远程应用资源分组、列表、详情与探测 | 539 |
| `capture_mode.go` | 接管能力、切换与持久化 | 411 |
| `access_view.go` | 接入点卡片、状态、banner 与日志 | 495 |
| `editor_view.go` | 编辑器草稿及表单展示 | 340 |
| `editor_actions.go` | 新建、编辑、检测、保存与删除操作 | 435 |
| `settings_view.go` | 设置草稿及各分区展示 | 403 |
| `settings_actions.go` | 设置打开、保存、应用及变更检测 | 188 |
| `confirmations_view.go` | 删除、退出登录与退出应用确认 | 185 |

## 验证记录

- Windows/amd64、Go 1.27.4，所有 Go 命令使用 `GOWORK=off`，未修改原有工作区文件。
- 使用 Go parser/scanner 对拆分前后各声明的 token 序列做 SHA256 比较，忽略注释、
  import 与分号表示差异：165 个声明全部一致，无缺失或重复。
  证据在忽略目录 `build/p6-desktop-declaration-audit.json` 与 `build/p6-desktop-declarations.json`。
- 已检查包级初始化：移动的状态为常量/静态值与 SVG 解析，没有新增初始化操作，
  没有增加 `init`、后台任务或运行时组件。页面和操作仍直接使用原有同包私有状态。
- `go test -mod=readonly ./internal/desktop -count=1` 通过；
  `go test -mod=readonly ./... -count=1` 与 `go vet -mod=readonly ./...` 通过，
  日志在 `build/p6-followup-tests.log`、`build/p6-followup-vet.log`。
- Windows/amd64、Linux/amd64、macOS/amd64 的 Hub、relay 和 desktop 测试二进制全部编译通过。
  产物在 `build/p6-followup-{windows,linux,darwin}`。未将交叉编译记作目标平台实机验收。
- 本轮没有修改构建入口、依赖、内核子模块、组件协议或打包布局；上一轮发行验证见
  [P6 整理记录](p6-desktop-layout-2026-11-27.md)。目录调整没有作为内存节省的证明。
- 原生 UI 自动化管道不可用，人工页面与正常退出结果仍待回复；没有操作真实 VPN、
  系统代理、防火墙或清理环境。

本轮代码与导航已由 `a406535` 提交并推送；后续职责整理见
[LAN 桌面职责与依赖检查](p6-lan-desktop-followup-2026-11-27.md)。
