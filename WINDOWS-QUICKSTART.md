# Windows 软件接管实验版

当前阶段：用户已于 2026-11-20 确认 Windows DBX 软件接管成功。其他软件、断线恢复与长期共存仍需实机验收。

构建标识：`0.1.0-dev-certificate-trust.1`。请完整替换解压目录内的程序。网络助手协议为 2，EasyConnect worker 协议为 5。

本次增加网关证书读取、指纹计算、确认信任和重试登录。主程序与独立 worker 都需要更新。

保留 `windows-capture.3` 的 IPv4 网卡修复：写回前清零 `SitePrefixLength`，并将初始化、路由、管道和进程启动错误细化到操作名称及 Win32 错误码。接管失败也会记录在应用日志中。用户已反馈此前失败的 DBX 接管成功；旧日志仍不足以确定原先具体失败的接口。

## Windows 本机构建

两个仓库保持并列：`aTrustHub` 使用 `feat/easyconnect-desktop`，`zju-connect` 使用 `feat/desktop-worker`（配套 worker 提交 `c8cf566`）。两个仓库都需要拉取更新。安装满足 `go.mod` 要求的 Go 工具链，在 Windows x64 的普通 PowerShell 中进入 `aTrustHub`，逐条运行下面的命令；构建报错时先处理该步。

```powershell
New-Item -ItemType Directory -Force .\build\windows-capture\resources | Out-Null
go build -mod=readonly -trimpath '-ldflags=-H=windowsgui' -o .\build\windows-capture\easyconnect-hub.exe .
go build -mod=readonly -trimpath '-ldflags=-H=windowsgui' -o .\build\windows-capture\easyconnect-hub-capture.exe ./cmd/app-helper
go -C ..\zju-connect build -mod=readonly -trimpath '-ldflags=-H=windowsgui' -o ..\aTrustHub\build\windows-capture\easyconnect-worker.exe ./cmd/easyconnect-worker
Copy-Item .\resources\icon.png .\build\windows-capture\resources\icon.png -Force
go test -mod=readonly -trimpath -c -o .\build\windows-capture\windows-capture-tests.exe ./internal/wincapture
.\build\windows-capture\windows-capture-tests.exe '-test.v' '-test.timeout=60s'
```

退出旧版本后，普通双击 `build\windows-capture\easyconnect-hub.exe`，确认启动日志显示 `0.1.0-dev-certificate-trust.1`。需要同时更新 GUI、`easyconnect-worker.exe` 和 `easyconnect-hub-capture.exe`；证书读取在独立仓库的 worker 中，网卡修复在网络助手中。自测失败时保留完整输出，其他软件的测试按下面的启动步骤进行。

Linux 上交叉编译完整 ZIP 可继续使用 `bash scripts/package-windows.sh`，包含三个程序、自测程序、说明和许可证。

## 启动

1. 解压完整 ZIP 到一个目录，不要只拷贝单独的 EXE。
2. 普通双击 `easyconnect-hub.exe`。不要“以管理员身份运行”主界面。
3. 添加 EasyConnect 接入点，连接后在界面输入当前验证码或动态口令。
4. 打开“本机软件”，添加“软件 TCP 接管”，选择程序的 `.exe`。开始菜单列表支持能解析为 EXE 的桌面软件；无法解析时手动选择程序。
5. 保存工作、退出该软件的已有实例，然后点击启动。系统 UAC 仅提升网络助手，软件本身保持普通权限。
6. 首次先测试一个浏览器或数据库工具。停止接管或断开 VPN 会保留软件进程；再次启用需退出软件并重新启动。

同一个 VPN 会话的多个软件共用助手。实验版一次只接管一个 VPN 会话，其他连接仍可使用代理浏览器或数据库转发。

软件只会在接管规则确认就绪后启动。最后一个软件停止接管后，资源路由和内网域名策略会撤回；若本次会话启用了内网域名，助手和映射地址通道会保留到断开 VPN，以保持重启软件时的域名映射一致。

等待 UAC 时可以取消启动。Windows 的授权提示可能仍显示，请关闭该提示再重试；稍后批准旧提示也不会启动软件或安装网络规则。规则操作已经发出时，停止会等待该次操作完成并撤回，避免影响同一 VPN 下其他软件。

## 网关证书提示

遇到“网关证书的域名字段格式不兼容”时：

1. 点击接入点错误卡片上的 **查看网关证书**。程序自动读取证书并计算 SHA256，无需运行命令查找指纹。
2. 核实接入地址、证书来源和指纹后，勾选 **我已核实网关来源，信任此证书**。
3. 点击 **信任并重试连接**，随后输入图形验证码或动态口令。

编辑接入点 → 高级选项也有 **读取网关证书…**。此入口确认后只填入编辑框，保存接入点后才生效。
读取只做 TLS 握手，不发送账号密码，不会自动信任。首次请通过管理员或其他可信渠道核实；证书名称和颁发者由对端提供。
已保存的指纹只作用于当前接入点。之后证书不一致会停止连接并显示新旧指纹，核实换证后才能替换。
如提示核心不支持读取，请重新构建或替换 `easyconnect-worker.exe`，只更新 GUI 无法添加这个命令。

## 本机自测

在普通 PowerShell 中进入解压目录，执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\test-capture.ps1
```

这个脚本只对本次 PowerShell 设置执行策略，不修改全局执行策略。测试使用专用子进程、loopback 和内存网络栈，不登录 VPN、不修改系统路由/DNS、不关闭已有软件。结果保存在 `capture-selftest.txt`。

验证内容：启动前进程组为空、取消后不创建进程、拒绝重复启动、新子进程归属、完整 TCP 元组、创建时间校验、停止后软件仍存活、共享请求取消、规则回滚、TCP 数据和半关闭、UDP 数据返回。新增模拟 IP Helper 参数回写及错误定位测试，不创建真实网卡。自测不验证真实 UAC、Wintun、NRPT 或真实 VPN。

## 实机验收

已收到用户对 Windows DBX“接管成功”的确认。数据库查询结果、自测脚本输出、具体构建号及下列共存/恢复场景尚未随本次反馈提供，分别保留为待验证项。

- 已选软件访问一个允许测试的内网网页或数据库；项目连接记录应出现对应目标。
- 未选软件的普通上网、本地开发服务和已有 Tailscale 目标保持原路径。
- 同一目标分别从已选和未选软件连接，验证选择生效。
- 测试软件正常退出、只退出启动父进程但子进程继续运行、停止接管、断开 VPN、拒绝 UAC。
- 两个软件同时使用时，停止或取消其中一个，另一个仍能访问；停止最后一个软件后，资源路由和本应用的 NRPT 策略撤回。
- 退出后检查仅本应用的 `ECH-*` 适配器和 `EasyConnectHub:<会话ID>` DNS 策略是否清理；其他软件的路由和 DNS 策略保持原状。

## 当前限制

- 接管 IPv4 TCP。内网 UDP 和 IPv6 不支持；已知 IPv6 资源会拒绝启用。普通公网流量不安装默认接管路由。
- 只覆盖本应用新启动且确认属于 Job Object 的进程。已有后台服务、商店应用、提权程序和绕过 Job 的启动方式不在首版保证范围。
- 路由按目标地址捕获，未选进程访问同一目标也会先经过助手，再按原接口转发。该原接口可以是 Tailscale。
- 与已有等长或更具体资源路由、现有 DNS 命名空间策略冲突时拒绝启动，使用显式代理。需要实机验证后扩展重叠网段支持。
- 内网域名通过本次会话的 NRPT 策略解析；系统范围内未选软件也可能收到短期映射地址。助手通过映射恢复未选软件的原目标。
- 断开 VPN 后最多保留约 60 秒映射转发以等待已返回的 DNS 答案失效。助手异常退出由独立恢复进程清理该会话的 NRPT。断电后下次启用网络助手时，根据不含凭据的恢复记录清理遗留策略；这一路径仍需实机验证，不会在系统启动时自动运行。
- 当前为解压测试包，未实现常驻安装服务、签名安装器或自动更新。

## 开源复用

沿用 aTrustHub 的 GUI、软件项目与代理入口；zju-connect 的认证、会话、资源规则与隧道；sing-tun 的 Wintun 适配；同一依赖树中的 gVisor 网络栈及 sing 的 socket 查询。gVisor 适配层用于兼容现有依赖版本，不自行实现 TCP/IP。许可证位于 `LICENSES/`，模块版本位于 `*-modules.txt`。
