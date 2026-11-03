# 变更日志

> **版本分线说明**
> 从 4.0.0 起，本项目改用 Rust + Tauri 重写。下方 `3.x` 记录属于 Python + tkinter 实现，
> 该实现已归档到 `legacy/python-v3` 分支，仅保留查阅。

## [4.0.0-alpha.2] — 2026-11-03

### 新增
- **网络诊断**（首个核心探测模块）：
  - 原生 ICMP 探测，输出丢包率、最小/最大/平均 RTT 与逐包序列，**不依赖系统 `ping`**
  - 原生 TCP 端口探测（并发 + 多样本），**不依赖 `tcping.exe`**，可区分拒绝/超时/不可达
  - DNS 解析与耗时统计
  - 链路质量综合评判（极佳/正常/较差/堵塞）与结论摘要、处置建议
  - 界面实时进度推送（`diag-progress` 事件）与 RTT 序列图
- `qqhu-probe` crate：探针层（icmp / tcp / dns / 诊断编排）

### 修复
- 结论判定逻辑：ICMP 可达但端口全不通时，判为「主机可达，端口未响应」（降级），
  不再误判为「链路中断」

### 验证
- M0 spike 结论：Windows 非管理员进程可创建原生 ICMP socket 并完成远端探测
  （实测网关与内网 DNS 服务器 3/3 通）
- 单元测试 38 项通过

---

## [4.0.0-alpha.1] — 2026-11-03

### 新增
- **重写为 Rust + Tauri 2 架构**：`qqhu-core`（领域模型 / 子网计算 / 质量评分，零平台依赖）、
  `qqhu-sys`（平台抽象层 + 能力矩阵）、`qqhu-app`（Tauri IPC 层）。
- **三栏界面**：左侧导航 / 中间模块 / 右侧常驻 AI Agent 侧栏，导航清单由 Rust 按平台能力返回。
- **子网计算**：前缀与点分掩码双模式、12 项推导结果、等长子网划分。
- **关于 / 许可**：应用信息、作者联系方式、运行环境；MIT 全文编译期内嵌。
- **跨平台能力矩阵**：Windows / macOS / Linux 各一份实现，模块可用性由后端统一给出。

### 变更
- 仓库主线切换：`main` 现为 Rust 实现；Python 实现归档至 `legacy/python-v3`。
- 项目更名为「青丘湖网络工作台」。

### 已知限制
- 网络诊断、IP/MAC 扫描、SSL 证书、AI 接入尚未实现。
- 域与策略、数字签名、安全诊断仅计划在 Windows 构建中提供。

---

## [3.4.0] — 2026-05-26

### 新增
- **抓包分析**独立模块：实时抓包（自选网卡、BPF 过滤器、定时/大小限制）、pcap/pcapng 离线分析、Display Filter、报文预览、Markdown 报告（`reports/packet_capture/`）。
- 网络诊断结果区 **「在抓包分析中打开」**，可从诊断历史载入 pcap 深入分析。
- 帮助页新增 **抓包分析** 说明；设计文档 [`docs/packet-capture-design.md`](docs/packet-capture-design.md) 状态更新为 v1 已实现。

---

## [2.1.6] — 2026-05-15

### 新增
- **SSL 证书**模块（导航「SSL证书」）：**Let's Encrypt**（ACME DNS-01，阿里云 DNS / 腾讯云 DNSPod API）；**私有证书**（`cryptography` 根 CA + 站点证书，固定 10 年有效期，可选 PFX）；内置帮助与方案文档 [`docs/ssl_certificate_scheme.md`](docs/ssl_certificate_scheme.md)。
- 依赖：`acme`、`requests`（Let's Encrypt）；延续 `cryptography`（私有证书）。

### 文档
- **打包**：README 中 PyInstaller / Nuitka 长篇说明迁至 [`docs/packaging.md`](docs/packaging.md)，英文 [`docs/packaging.en.md`](docs/packaging.en.md)；README 仅保留摘要与链接。

---

## [2026-05-13] [文档] 设计方案 v1.5

- 新增 `docs/network-diagnostic-tool-design_v1.5.md`：主窗口多模块（子网计算、交换机、数据库诊断）、扩展依赖与 `reports/db_diagnosis/`、`switch_console/` 路径约定；`v1.4` 文档保留并标注归档。
- README、`pyproject.toml`、`network_diagnosis.version.DESIGN_DOC_REF` 引用已同步至 v1.5。

## [2026-05-13] [优化] GUI 左右分栏与运行态

- 主界面改为左右分割（`Panedwindow` 水平）：左侧为探测表单、工具按钮、任务状态与报告入口；右侧为「结论」与「进度与详情」，右侧纵向约 1:4 分配以加高日志区。
- 运行中：`任务状态` 区域高亮、加粗文案，并显示不确定进度条；结束或失败时恢复。

## [2026-05-13] [修复] GUI：Panedwindow 与 Python 3.14 / Tcl 9

- 移除 `paneconfigure` 调用（`ttk::panedwindow` 不再支持该子命令），避免启动即崩溃。

## [2026-05-13] [优化] GUI 布局

- 主界面采用垂直分割（`Panedwindow`）分隔「表单 + 结论」与「日志」；探测目标/选项分组、状态条与操作按钮区对齐优化；默认窗口与分割条比例调整。

## [2026-05-13] [文档] 项目 README

- 新增根目录 `README.md`（安装、运行、报告目录、第三方资源、仓库结构）；`pyproject.toml` 的 `readme` 改为指向该文件。

## [2026-05-13] [变更] 报告默认输出目录

- 诊断任务与 Markdown 默认写入**项目根目录**下 `reports/`（打包后为可执行文件同目录下 `reports/`），不再使用「文档」目录。

## [2026-05-13] [新增] 网络诊断桌面工具 MVP

- 依据 `docs/network-diagnostic-tool-design_v1.4.md` 实现 Python + tkinter + ttkbootstrap GUI。
- 同源诊断模型：DNS、可选 ICMP ping、多端口 tcping、可选 tshark 抓包；双输出 GUI 摘要 + Markdown 技术报告。
- 内置 `ThirdParty/tcping/` 相对路径解析；Wireshark 安装包引导与同捆目录探测。
