# QQHu 网络诊断工具

基于 Python 的 **Windows 桌面网络诊断**应用（tkinter + [ttkbootstrap](https://github.com/israelhudson/ttkbootstrap)）。产品说明与能力范围以设计文档为准：

- [`docs/network-diagnostic-tool-design_v1.4.md`](docs/network-diagnostic-tool-design_v1.4.md)

## 功能概览

- **双输出**：面向非技术用户的 GUI 摘要 + 每次任务一份完整 **Markdown** 技术报告（同源数据模型）。
- **探测能力**：本机网络上下文（`ipconfig` 解析）、DNS、可选 ICMP `ping`、多端口 **tcping**、可选 **tshark** 抓包（需本机安装 Wireshark / Npcap）。
- **依赖策略**：`tcping.exe` 随项目放在固定相对路径；`tshark` 从系统标准安装路径探测；可选同捆 Wireshark 安装包引导安装。

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

## 报告输出位置

每次诊断会在**项目根目录**下创建（若不存在则自动创建）：

```text
reports/<任务短ID>_<时间戳>/
```

其中包含 Markdown 报告、各子进程 stdout/stderr 日志，以及（若启用抓包）pcap 等文件。打包为 PyInstaller 可执行文件后，默认在 **exe 同目录下的 `reports/`**。

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
