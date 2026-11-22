# Connect Hub · Linux 用户快速入门手册

欢迎使用 **Connect Hub**！本手册介绍 Linux 平台下的解压部署、桌面环境集成、特权辅助服务配置以及网络接管模式的使用方法。

---

## 1. 运行环境与依赖要求

Connect Hub 支持主流 x86_64 Linux 发行版（如 Ubuntu 22.04+、Fedora 38+、Debian 12+、Arch Linux 等）。

### 1.1 系统托盘依赖（推荐安装）
客户端退出窗口时默认隐藏到系统托盘并在后台保持连接。托盘功能基于 `libayatana-appindicator3`：

- **Fedora / RHEL**：
  ```bash
  sudo dnf install libayatana-appindicator-gtk3
  ```
- **Ubuntu / Debian**：
  ```bash
  sudo apt install libayatana-appindicator3-1
  ```
- **Arch Linux**：
  ```bash
  sudo pacman -S libayatana-appindicator
  ```

> [!TIP]
> **GNOME 桌面环境特别说明**：GNOME 默认不显示第三方托盘图标。建议在应用商店或通过包管理器安装并启用 **AppIndicator and KStatusNotifierItem Support** 扩展。若系统未安装托盘支持，程序在关闭窗口时会自动安全退出，杜绝隐式后台残留。

---

## 2. 解压与桌面启动

### 2.1 解压便携包
将下载的发布包解压至当前用户的本地目录（例如 `~/apps/connect-hub`）：

```bash
tar -zxvf connect-hub-linux-amd64.tar.gz
cd connect-hub-linux-amd64
```

包内目录结构如下：
```text
connect-hub-linux-amd64/
├── connect-hub                # 主程序（普通权限运行）
├── start.sh                   # 启动包装脚本（支持单实例唤醒）
├── install-desktop-entry.sh   # 桌面图标与菜单注册脚本
├── core/
│   ├── connect-hub-worker     # VPN 协议引擎 (IPC v7)
│   └── connect-hub-capture    # 操作系统特权助手 (IPC v11；安装后位于 /usr/local/libexec/)
├── share/icons/hicolor/       # 各尺寸高清应用图标
├── resources/                 # 运行时静态资源
├── LICENSES/                  # 开源协议清单
└── README.md                  # 本手册
```

### 2.2 安装桌面图标（无需 root 权限）
运行随包附带的安装脚本，将图标与 `.desktop` 启动器写入用户私有目录（`~/.local/share/applications/`）：

```bash
./install-desktop-entry.sh
```

安装完成后，即可在系统的“应用程序菜单”或“活动视图”中通过应用图标搜索并启动 **Connect Hub**。如需从菜单注销，执行 `./install-desktop-entry.sh --remove` 即可。

### 2.3 终端直接启动
在终端执行：
```bash
./start.sh
```
> **单实例唤醒支持**：若程序已在后台运行但主窗口被隐藏，再次执行 `./start.sh` 会自动唤起并置顶已有窗口，避免重复启动。

---

## 3. 辅助服务与特权安装

Connect Hub 遵循**最小权限原则**：
- **主界面与基础代理**：全程以**当前登录用户权限**运行。
- **本机软件接管 / 系统 TUN 模式**：需要操作 Linux 底层网络接口（TUN 设备、`ip rule` / `ip route` 路由表及 cgroup 流量标记）。

### 安装 / 更新辅助服务
1. 打开 Connect Hub 主界面，进入 **「本机软件」** 或开启 **「全系统 TUN 模式」**。
2. 界面会提示「辅助服务未安装」或「检测到新版本辅助服务（需要协议 v11）」。
3. 点击 **「安装 / 更新辅助服务」**，系统将弹出 PolicyKit 认证对话框，输入管理员密码完成配置。
4. 辅助服务安装后通过私有 Unix Domain Socket 与主程序通信，并在主程序退出或心跳超时后自动清理所有临时路由规则。

---

## 4. 接入点管理与认证

Connect Hub 支持同时登录多个不同单位的网关，代码层面支持深信服 **aTrust** 与 **EasyConnect** 两种网关协议（*注：aTrust 继承自上游代码，本分支 Fork 以后未做实机测试与验证，当前实测完全基于 EasyConnect*）：

1. **添加接入点**：点击左侧导航栏的 **「添加接入点」**，输入网关地址及协议类型。
2. **认证方式**：
   - **账号密码**：支持附加登录域与 TOTP 动态口令。
   - **短信 / 图形验证码**：遇挑战认证时自动弹窗提示。
   - **企业微信扫码**：原生弹窗显示二维码，支持移动端扫码与桌面端快捷确认。
   - **单点登录 (SSO / CAS)**：由独立的沙盒 Chromium 浏览器完成认证并自动回传会话。
3. **网关证书安全提示**：若服务器自签证书或域名不匹配，可通过错误提示中的 **「查看网关证书」** 进行指纹核验并手动确信。

---

## 5. Linux 接管模式说明（支持「不使用」与「应用接管」）

受限于 Linux 桌面环境多样性与权限模型，Connect Hub 在 Linux 平台**不提供系统代理托管功能**（`supportsSystemProxy() = false`，下拉菜单中不展示「系统代理」选项）。

顶栏接管胶囊下拉菜单（以及「设置」→「网络与接管」）提供两种接入模式：

| 模式 | 运行机制 | 适用场景与配置方法 |
| :--- | :--- | :--- |
| **「不使用」** | 纯本地 SOCKS5/HTTP 端口监听，程序完全不触碰系统网络栈与路由表 | 适合习惯手动配置代理的用户。终端工具（curl/Git）、数据库客户端（DBeaver/Navicat）或浏览器代理扩展（如 SwitchyOmega），手动将代理填为 `127.0.0.1:<统一入口或独立接入点端口>` 即可。 |
| **「应用接管」** | 借助特权助手、Linux 原生 TUN 网卡与策略路由，实现内网私有网段与域名 DNS 的透明路由，并支持按软件 cgroup 进行精准流量标记管控 | 绝大多数内网办公推荐模式。无需为软件单独配置代理，整机可透明访问内网域名与 IP；也可在「本机软件」中添加并启动特定工具进行单独隔离管控。 |

> [!NOTE] 提示
> 如果你在 Linux 下需要类似全局代理的效果，推荐直接开启 **「应用接管」**（内网流量走网关，公网流量保持本地直连）；若只想让个别工具走代理，请选择 **「不使用」** 并手动配置该工具的代理设置。

---

## 6. 内存修剪与退出保护

- **自动工作集修剪（Working Set Trim）**：当客户端退至托盘或最小化超过 30 秒且没有活跃网络传输时，系统会自动执行内存修剪，释放闲置堆内存至操作系统，空闲常驻内存降至极低水平。
- **干净退出保证**：在托盘菜单点击 **「退出」** 时，程序会自动停止所有活动隧道、注销虚拟网卡、清除临时路由与规则，恢复系统原状。
