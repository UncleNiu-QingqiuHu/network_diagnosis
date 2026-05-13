# 青丘狐网络工作台

基于 Python 的 **Windows 桌面网络工作台**（tkinter + [ttkbootstrap](https://github.com/israelhudson/ttkbootstrap)），集成网络连通性诊断、子网计算、交换机 Console/SSH、数据库诊断等能力。官方网站：<https://www.qingqiuhu.net>。产品说明与能力范围以设计文档为准：

- [`docs/network-diagnostic-tool-design_v1.5.md`](docs/network-diagnostic-tool-design_v1.5.md)（v1.4 见同目录归档）

## 功能概览

主窗口左侧为功能导航，当前包含：

| 模块 | 说明 |
|------|------|
| **网络诊断** | 双输出：面向非技术用户的 GUI 摘要 + 每次任务一份完整 **Markdown** 技术报告（同源数据模型）。 |
| **子网计算** | IPv4 CIDR / 点分掩码计算；可刷新本机 IPv4、网关、DNS 与公网地址参考信息。 |
| **交换机配置** | 串口 Console 或 **SSH（PTY）** 会话；SSH 未知主机密钥写入可写目录下的 `switch_console/`。 |
| **数据库诊断** | 连接 **SQLite / MySQL / PostgreSQL / SQL Server / Oracle**，运行连通性与信息收集，输出 Markdown；支持周期性监控快照导出。 |
| **使用说明 / 关于 / 许可** | 内置说明页与许可信息。 |

**网络诊断**探测能力简述：

- 本机网络上下文（`ipconfig` 解析）、DNS、可选 ICMP `ping`、多端口 **tcping**、可选 **tshark** 抓包（需本机安装 Wireshark / Npcap）。
- **依赖策略**：`tcping.exe` 随项目放在固定相对路径；`tshark` 从系统标准安装路径探测；可选同捆 Wireshark 安装包引导安装。

**数据库诊断**补充：

- 连接非 SQLite 时需填写可达主机与库名；**SQL Server** 依赖本机 **ODBC 驱动**（`pyodbc`）；**Oracle** 的「库名」请填 **Service Name**（`oracledb` 瘦模式）。
- 各引擎 Python 依赖已在 `pyproject.toml` 中声明；若某引擎暂不使用，可在本地虚拟环境中按需安装子集（团队可自行拆可选依赖组，当前为整包安装）。

## 环境要求

- Windows 10/11（当前脚本与子进程参数按 Windows 优化）。
- **Python 3.10+**（与 `pyproject.toml` 中 `requires-python` 一致）。
- 将 **`tcping.exe`** 放到 `ThirdParty/tcping/tcping.exe`（否则端口探测会降级并在报告中说明）。

## 安装与运行

```powershell
cd E:\Workspace\qqhu_network_diagnosis   # 换成你的克隆路径
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .
```

启动 GUI（注意模块名以 **`n`** 开头）：

```powershell
python -m network_diagnosis
```

或使用控制台入口：

```powershell
network-diagnosis
```

## 报告与数据目录

**网络诊断**每次任务会在**项目根目录**（或打包后 **exe 同目录**）下创建：

```text
reports/<任务短ID>_<时间戳>/
```

其中包含 Markdown 报告、各子进程 stdout/stderr 日志，以及（若启用抓包）pcap 等文件。

**数据库诊断**与监控导出的 Markdown 位于：

```text
reports/db_diagnosis/<任务ID>/
```

**交换机 Console**（如 SSH `known_hosts`）可写数据默认在仓库根下的 `switch_console/`；若使用 PyInstaller 打包，则在 **exe 同目录下的 `switch_console/`**。

以上目录若不存在会在首次使用时创建；`reports/` 已加入 `.gitignore`。

## 第三方资源

| 资源 | 路径 | 说明 |
|------|------|------|
| tcping | `ThirdParty/tcping/tcping.exe` | 必放；应用不依赖系统 PATH。 |
| Wireshark 安装包 | `ThirdParty/Wireshark/*.exe` | 可选；未检测到 `tshark` 时可在界面中打开安装。 |

再分发第三方软件须遵守各自许可证（详见设计文档第 6 节）。

## 仓库结构（节选）

```text
network_diagnosis/       # Python 包：模型、探针、编排、GUI、Markdown 序列化
docs/                    # 设计文档
ThirdParty/              # tcping、Wireshark 安装包放置说明与目录
reports/                 # 默认诊断输出（已加入 .gitignore）
switch_console/          # SSH 等可写数据（已加入 .gitignore；首次运行创建）
pyproject.toml
CHANGELOG.md
```

## 开发

```powershell
.\.venv\Scripts\activate
pip install ruff
python -m ruff check network_diagnosis
```

## 许可证

见仓库根目录 [`LICENSE`](LICENSE)。
