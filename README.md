# 青丘狐网络工作台

[English README](README.en.md)

> 本仓库同时提供了发行版[Github发行版地址](https://github.com/UncleNiu-QingqiuHu/network_diagnosis/releases)以供下载

基于 Python 的 **Windows 桌面网络工作台**（tkinter + [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap)），集成网络连通性诊断、**安全诊断（基线）**、子网计算、交换机 Console/SSH、数据库诊断、**ARP 安全监视**、**Windows 数字签名**等能力。官方网站：<https://www.qingqiuhu.net>。发布版本号以 [`network_diagnosis/version.py`](network_diagnosis/version.py) 中的 `APP_VERSION` 为准。

产品说明与能力范围以设计文档为准（若克隆目录中暂无 `docs/`，请从发布包或团队渠道获取同名文档）：

- [`docs/network-diagnostic-tool-design_v1.5.md`](docs/network-diagnostic-tool-design_v1.5.md)（v1.4 见同目录归档）
- 安全诊断方案：[`docs/network-security-diagnosis-design.md`](docs/network-security-diagnosis-design.md)

## 功能概览

主窗口左侧为功能导航，当前包含：

| 模块 | 说明 |
|------|------|
| **网络诊断** | 双输出：面向非技术用户的 GUI 摘要 + 每次任务一份完整 **Markdown** 技术报告（同源数据模型）。 |
| **子网计算** | IPv4 CIDR / 点分掩码计算；可刷新本机 IPv4、网关、DNS 与公网地址参考信息。 |
| **交换机配置** | 串口 Console 或 **SSH（PTY）** 会话；SSH 未知主机密钥写入可写目录下的 `switch_console/`。 |
| **数据库诊断** | 连接 **SQLite / MySQL / PostgreSQL / SQL Server / Oracle**，运行连通性与信息收集，输出 Markdown；支持周期性监控快照导出。 |
| **ARP 安全** | 以 `arp -a` 轮询本机 ARP 表，对**默认网关 MAC** 做基线对比；异常变化时提示疑似 ARP 欺骗（内网侧轻量监视）。 |
| **安全诊断** | 本机 TCP 监听与 Windows 防火墙只读摘要；本机 CPU/GPU/内存/用户策略与临时清理（Windows）；授权前提下 HTTPS TLS/证书与安全响应头、DNS 对比、**单主机 IPv4 TCP 端口扫描**（Python 默认可选 nmap `-sT`）；详见 [`docs/network-security-diagnosis-design.md`](docs/network-security-diagnosis-design.md)。导出至 `reports/security_diagnosis/`。 |
| **数字签名** | Windows **Authenticode**：`signtool` + PFX 对 exe/dll **仅签名与校验**；exe「详细信息」请在 **Nuitka/PyInstaller 构建时**写入。自签名 PFX 由 **PowerShell / .NET** 一键生成；`signtool` 来自 Windows SDK 或 PATH。 |
| **使用帮助 / 关于 / 许可** | 内置帮助（正文支持 Markdown 渲染）、关于与 MIT 许可原文；静态页在 **首次进入对应导航时** 再构建，以缩短冷启动。 |

**网络诊断**探测能力简述：

- 本机网络上下文（`ipconfig` 解析）、DNS、可选 ICMP `ping`、多端口 **tcping**、可选 **tshark** 抓包（需本机安装 Wireshark / Npcap）。
- 可选 **Traceroute**、**PathPing**、**TCP Traceroute**；可选 **出口探测**、**IPv4 MTU** 探测；可选对目标的 **HTTP(S)/TLS** 探针。
- 带宽：**HTTP 下载测速** 或 **iperf3**（TCP/UDP，可与网络质量综合判定联动）；历史任务索引默认写入 `reports/_diagnosis_history.json`，支持同目标多次报告对比（可在界面关闭）。
- **依赖策略（与 `network_diagnosis/paths.py`、界面「检测」按钮一致）**：`tcping.exe` **仅**从 `ThirdParty/tcping/tcping.exe` 加载（不使用 PATH）；`tshark.exe` 探测 `%ProgramFiles%\Wireshark\` 与 `%ProgramFiles(x86)%\Wireshark\`；**iperf3** 优先 `ThirdParty/iperf3/iperf3.exe`，否则查找 PATH；可选将 Wireshark **官方安装包** 放入 `ThirdParty/Wireshark/` 由界面引导安装。

**数据库诊断**补充：

- 连接非 SQLite 时需填写可达主机与库名；**SQL Server** 依赖本机 **ODBC 驱动**（`pyodbc`）；**Oracle** 的「库名」请填 **Service Name**（`oracledb` 瘦模式）。
- 各引擎 Python 依赖已在 `pyproject.toml` 中声明；若某引擎暂不使用，可在本地虚拟环境中按需安装子集（团队可自行拆可选依赖组，当前为整包安装）。

## 环境要求

- Windows 10/11（当前脚本与子进程参数按 Windows 优化）。
- **Python 3.10+**（与 `pyproject.toml` 中 `requires-python` 一致）。
- 将 **`tcping.exe`** 放到 `ThirdParty/tcping/tcping.exe`（否则端口探测会降级并在报告中说明）。
- 将 **`tshark.exe`** 放到 `ThirdParty/Wireshark/`（否则抓包功能不可用）。
- 将 **`iperf3.exe`** 放到 `ThirdParty/iperf3/`（否则带宽测速功能不可用）。
- 将 **`nmap.exe`** 放到 `ThirdParty/Nmap/`（否则端口扫描功能不可用）。

## 界面截图

![](./readmeimgs/PixPin_2026-05-15_15-59-59.png)
![](./readmeimgs/PixPin_2026-05-15_16-01-08.png)
![](./readmeimgs/PixPin_2026-05-15_16-01-27.png)
![](./readmeimgs/PixPin_2026-05-15_16-01-38.png)
![](./readmeimgs/PixPin_2026-05-15_19-11-05.png)

## 安装与运行

```powershell
cd E:\Workspace\qqhu_network_diagnosis   # 换成你的克隆路径
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .
```

启动 GUI：

```powershell
python -m network_diagnosis
```

或使用控制台入口：

```powershell
network-diagnosis
```

## Windows 打包（PyInstaller）

设计约定见 [`docs/network-diagnostic-tool-design_v1.5.md`](docs/network-diagnostic-tool-design_v1.5.md) 中「打包与分发」。 frozen 模式下 `network_diagnosis.paths.bundle_root()` 指向 **`sys._MEIPASS`**，因此 **`ThirdParty/tcping/tcping.exe`** 与包内资源需通过 **`--add-data`**（或 spec 里 `datas`）打进包内；**`reports/`、`logs/`、`switch_console/`** 仍写在 **exe 同目录**（无需打进包）。

**完整功能分发（推荐）**：若希望在离线环境下直接使用 **带宽 iperf3**、**安全诊断 nmap 后端** 并在内置「许可」页展示 **MIT 正文**，打包时请把仓库根目录 **`LICENSE`**、以及已就绪的 **`ThirdParty/iperf3/`**（至少含 `iperf3.exe`）、**`ThirdParty/Nmap/`**（便携版须保留 **`nmap.exe` 与同目录依赖**，勿只拷单个 exe）一并打进包内（见下文示例）。第三方二进制再分发须遵守各自许可。

### 1. 环境与依赖

在已 `pip install -e .` 的同一虚拟环境中安装打包工具：

```powershell
.\.venv\Scripts\activate
pip install pyinstaller
```

### 2. 推荐：`onedir` + 无控制台窗口

在**仓库根目录**执行（路径请按本机修改）。Windows 下 `--add-data` 使用 **`源路径;包内目标相对路径`**（分号分隔）：

```powershell
cd E:\Workspace\qqhu_network_diagnosis

pyinstaller --noconfirm --windowed --onedir `
  --name qqhu-network-workbench `
  --paths . `
  --collect-all ttkbootstrap `
  --add-data "ThirdParty/tcping/tcping.exe;ThirdParty/tcping" `
  --add-data "network_diagnosis/images;network_diagnosis/images" `
  network_diagnosis/__main__.py
```

产物目录：`dist\qqhu-network-workbench\`，其中 `qqhu-network-workbench.exe` 为可执行文件。首次分发前请在本机实际运行一遍，确认杀毒/策略未拦截。

（**图片资源**：上例对 **`network_diagnosis/images` 使用整目录 `--add-data`**，目录内现有及后续新增的 PNG、ICO 等会一并打入，一般不必对每个文件单独写一行。）

**Wheel / sdist**：`pyproject.toml` 中 `[tool.setuptools.package-data]` 已写 `network_diagnosis = ["images/*"]`，`python -m build` 时会一次性收录包内 `images/` **下一层**文件；若日后把图片放到 `images/` 的子目录里，需相应扩展 glob（例如增加递归匹配）。

**建议与 tcping 一并打入（路径须已存在；缺一可先删掉对应 `--add-data` 行）**

```powershell
# 在上一段 pyinstaller 命令中追加（或单独再打一层 spec），Windows 下 `--add-data` 为「源;包内相对路径」：
--add-data "LICENSE;." `
--add-data "ThirdParty/iperf3;ThirdParty/iperf3" `
--add-data "ThirdParty/Nmap;ThirdParty/Nmap"
```

- **`LICENSE`**：内置「许可」标签页从 `bundle_root()/LICENSE` 读取（PyInstaller 即 `_MEIPASS` 根目录）。
- **iperf3**：目录内需含 **`iperf3.exe`**（与 [`network_diagnosis/paths.py`](network_diagnosis/paths.py) 约定一致）。
- **Nmap**：便携分发时请打入 **整个 `ThirdParty/Nmap/`**（含 **`nmap.exe`** 及同目录 DLL 等），否则勾选「使用 nmap」时可能无法启动。

**其它可选资源**

- **Wireshark 安装包**：体积较大，也可改为**不**打入 `_MEIPASS`，而在发布 zip 中把 `ThirdParty\Wireshark\*.exe` 与 exe **并列**拷贝；程序通过 `bundle_root()` 在开发树或包内查找安装包（与 [`network_diagnosis/paths.py`](network_diagnosis/paths.py) 一致）。若选择打入包内，对目录使用例如：  
  `--add-data "ThirdParty/Wireshark;ThirdParty/Wireshark"`（仅当该目录存在且需随包分发时）

若 PyInstaller 分析阶段漏掉可选驱动，可补 **`--hidden-import`**，例如：`pymysql`、`psycopg`、`pyodbc`、`oracledb`、`paramiko`、`serial`。

### 3. `onefile` 单文件（可选）

增加 `--onefile` 可得到单个 exe，启动时需解压临时目录，冷启动较慢，且杀毒更易误报；资源路径规则与上相同。

### 4. Python  wheel / sdist（库形态）

若仅需可安装的 Python 包（非桌面 exe），在项目根目录：

```powershell
pip install build
python -m build
```

**Wheel** 与 sdist 位于 `dist/`，安装后可通过 **`network-diagnosis`** 命令启动（见 `pyproject.toml` 的 `[project.entry-points.gui_scripts]`）。

## Windows 打包（Nuitka · 目录分发）

不使用 **`--onefile`** 时，Nuitka 生成 **standalone 目录**（整夹 zip 分发），冷启动与排错一般优于单文件 exe。

未走 PyInstaller 时，`network_diagnosis.paths.bundle_root()` 用 **`network_diagnosis/paths.py` 所在位置**推算发行根目录，因此 **`--include-data-dir`** 的**右侧路径**须与仓库内 **`ThirdParty/...`、`network_diagnosis/images/...`** 布局一致（与 [`network_diagnosis/paths.py`](network_diagnosis/paths.py) 一致）。

**完整功能分发（推荐）**：与 PyInstaller 相同，建议将 **`LICENSE`**、**`ThirdParty/iperf3/`**、**`ThirdParty/Nmap/`**（便携 **整目录**）随 standalone 目录一并打入；许可页与第三方探测依赖上述布局。

### 1. 环境与编译器

Windows 上需要 **C 编译器**（Visual Studio Build Tools 或 Nuitka 文档推荐的 MinGW）。配置说明见 [Nuitka User Manual](https://nuitka.net/user-documentation/user-manual.html)。

```powershell
.\.venv\Scripts\activate
pip install nuitka ordered-set zstandard
```

### 2. standalone 目录（推荐）

在**仓库根目录**执行（路径请按本机修改）。**`--file-version` / `--product-version` / `--copyright` 等**建议与 [`network_diagnosis/version.py`](network_diagnosis/version.py) 中的 `APP_VERSION`、`APP_DISPLAY_NAME` 等保持一致，以便 exe「详细信息」与发行版一致；可在本机用 PowerShell 等自行封装一条命令（**仓库不收录**此类脚本，见根目录 `.gitignore`）。

```powershell
cd E:\Workspace\qqhu_network_diagnosis

python -m nuitka `
  --standalone `
  --assume-yes-for-downloads `
  --windows-console-mode=disable `
  --windows-icon-from-ico=network_diagnosis/images/qqhu_black2.ico `
  --enable-plugin=tk-inter `
  --include-package-data=ttkbootstrap `
  --company-name=Qingqiuhu `
  --product-name=青丘狐网络工作台 `
  --file-description=青丘狐网络工作台 `
  --file-version=2.0.2.0 `
  --product-version=2.0.2.0 `
  "--copyright=© Qingqiuhu / 青丘狐。contact@qingqiuhu.net" `
  --include-data-dir=ThirdParty/tcping=ThirdParty/tcping `
  --include-data-dir=ThirdParty/iperf3=ThirdParty/iperf3 `
  --include-data-dir=ThirdParty/Nmap=ThirdParty/Nmap `
  --include-data-files=LICENSE=LICENSE `
  --include-data-dir=network_diagnosis/images=network_diagnosis/images `
  network_diagnosis
```

其中 **`--file-version` / `--product-version`** 须为四段数字（示例与当前 `APP_VERSION` 对齐）；若以 [`network_diagnosis/version.py`](network_diagnosis/version.py) 中的 `APP_VERSION` 为准更改发布号，请同步修改上述两行，或在本机构建脚本中据其自动生成参数。

若本机尚未放置 **iperf3** 或 **Nmap** 目录，请先创建对应 `ThirdParty` 子目录并放入文件后再执行打包；否则请暂时删掉对应的 **`--include-data-dir=...`** 行（避免 Nuitka 因缺路径报错）。**`LICENSE`** 应始终存在于仓库根目录。

**exe 图标**：使用 **`--windows-icon-from-ico=…`** 指定 **`.ico`** 文件，写入生成的 exe 的 **PE 图标资源**（资源管理器 / 任务栏展示）。与 **`--include-data-dir=network_diagnosis/images/...`** 无关：后者供运行时 `try_set_window_icon` 等读取 ICO。**`--onefile`** 打包时同样可带上该参数。路径相对于执行 `nuitka` 时的当前目录（上例为仓库根）。可用 `python -m nuitka --help | findstr /i icon` 核对本机 Nuitka 选项名称。

默认生成 **`__main__.dist`** 目录，内含 **`__main__.exe`** 及依赖 DLL。分发时将整个 **`__main__.dist`** 打成 zip 即可。

若希望 exe 名称更直观，可在仓库根新增 **`launcher.py`**，仅转调入口（例如 `from network_diagnosis.__main__ import main` 后调用 `main()`），再对 **`launcher.py`** 执行同一套参数，产物一般为 **`launcher.dist` / `launcher.exe`**（具体以本机 `python -m nuitka --help` 为准）。

**已写入上方示例的 `--include-data-dir`**

- **iperf3**：`ThirdParty/iperf3/`（内含 `iperf3.exe`）
- **Nmap**：`ThirdParty/Nmap/`（便携版 **整目录**，含 `nmap.exe` 与依赖）
- **LICENSE**：`--include-data-files=LICENSE=LICENSE`（内置许可页）

**其它可选 `--include-data-dir`**

- **Wireshark 安装包**：体积较大时可不打进 standalone，在 zip 中与 **`.dist` 并列**放置 `ThirdParty\Wireshark\`；若打入：  
  `--include-data-dir=ThirdParty/Wireshark=ThirdParty/Wireshark`

若运行时提示缺少数据库驱动等模块，可追加 **`--include-module=...`**（按需，例如 `pymysql`、`psycopg`、`pyodbc`、`oracledb`）。

### 3. 与 PyInstaller 的差异提示

- Nuitka **不提供** `sys._MEIPASS`；资源路径依赖发行目录布局与 `paths.py` 中的推算逻辑。
- 与 PyInstaller 一致：**`reports/`、`logs/`、`switch_console/`** 应位于发行目录下可写路径（通常为 exe 旁）。
- 单文件形态为 **`--onefile`**，启动需解压、排障成本更高；**目录分发建议不要加 `--onefile`**。

## 报告、运行日志与数据目录

约定均实现于 [`network_diagnosis/paths.py`](network_diagnosis/paths.py)：开发时为**仓库根目录**；**PyInstaller / 打包 exe** 时为 **exe 所在目录**（勿写入只读的 `_MEIPASS`）。

### 运行日志

- 目录：**`logs/`**（与 `reports/` 同级规则）。
- 主文件：**`logs/app.log`**，按**自然日午夜**轮转，历史文件带日期后缀（由 `TimedRotatingFileHandler` 管理，默认保留约 90 份）。
- 代码入口：**`network_diagnosis/runtime_log.py`**（`setup_runtime_logging()` 在 GUI `main_gui()` 启动早期调用）；其它模块可使用 `get_logger(__name__)` 写入同一日志树（`qingqiuhu.*`）。

### 诊断报告与其它可写数据

**网络诊断**每次任务会创建：

```text
reports/<任务短ID>_<时间戳>/
```

其中包含 Markdown 报告、各子进程 stdout/stderr 日志，以及（若启用抓包）pcap 等文件。同目标历史索引（若未关闭）位于 **`reports/_diagnosis_history.json`**。

**数据库诊断**与监控导出的 Markdown 位于：

```text
reports/db_diagnosis/<任务ID>/
```

**安全诊断**导出的 Markdown 位于：

```text
reports/security_diagnosis/
```

**交换机 Console**（如 SSH `known_hosts`）默认可写目录：**`switch_console/`**。

以上目录若不存在会在首次使用时创建；**`reports/`、`logs/`、`switch_console/`** 已加入 `.gitignore`。

## 第三方资源

| 资源 | 路径 | 说明 |
|------|------|------|
| tcping | `ThirdParty/tcping/tcping.exe` | 必放；应用不依赖系统 PATH。 |
| iperf3 | `ThirdParty/iperf3/iperf3.exe` | 可选；网络诊断选择「iperf3」带宽时使用；亦可依赖系统 PATH。打包完整分发时建议随包放置（见上文 PyInstaller / Nuitka）。 |
| Wireshark 安装包 | `ThirdParty/Wireshark/*.exe` | 可选；未检测到 `tshark` 时可在界面中打开安装。 |
| Nmap | `ThirdParty/Nmap/*.exe`（安装包）或便携 **`ThirdParty/Nmap/` 整目录**（含 `nmap.exe` 及 DLL） | 可选；安全诊断勾选「使用 nmap」时使用；探测顺序为 PATH → 默认安装目录 → `ThirdParty/Nmap/nmap.exe`（见 `paths.resolve_nmap_exe_path`）。打包时请带入完整便携目录。 |
| LICENSE | 仓库根 `LICENSE` | 内置「许可」页读取；PyInstaller / Nuitka 打包时请按上文一并打入发行包。 |

再分发第三方软件须遵守各自许可证（详见设计文档第 6 节）。

## 仓库结构（节选）

```text
network_diagnosis/       # Python 包：模型、探针、编排、GUI、Markdown 序列化
docs/                    # 设计文档（部分克隆可能未含该目录）
readmeimgs/              # README 用界面截图
ThirdParty/              # tcping、可选 iperf3 / Wireshark / Nmap；打包时建议连同根目录 LICENSE 一并分发
reports/                 # 默认诊断输出（已加入 .gitignore）
logs/                    # 运行日志 app.log（按日轮转；已加入 .gitignore）
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

MIT

见仓库根目录 [`LICENSE`](LICENSE)。
