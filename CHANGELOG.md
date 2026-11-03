# 变更日志

> **版本分线说明**
> 从 4.0.0 起，本项目改用 Rust + Tauri 重写。下方 `3.x` 记录属于 Python + tkinter 实现，
> 该实现已归档到 `legacy/python-v3` 分支，仅保留查阅。

## [4.0.0-alpha.6] — 2026-11-03

### 新增
- **MAC 扫描模块**（M3 第二块）：本机 ARP 邻居表 + OUI 厂商识别。
  - `qqhu-core::macscan`：ARP 条目模型、MAC 归一化（冒号/短横线/点分/纯十六进制四种写法）、
    OUI 厂商库、本地管理地址（手机随机化 MAC）识别、非主机条目过滤。
  - `qqhu-sys::arp`：三平台采集 —— Windows `GetIpNetTable2`、Linux `/proc/net/arp`、
    macOS `sysctl(NET_RT_FLAGS)`；出口统一过滤广播与全零 MAC。
  - `qqhu-probe::macscan`：可选「先探活再读表」。同网段 ICMP 必经 ARP 解析，
    因此探活能顺带填充邻居表，且全程不需要管理员权限。
    **以 ARP 表为准，探测结果只用于标注在线状态**——没有 MAC 的地址对这一屏没有意义。
  - 界面：探测开关、统计、按 IP/MAC/厂商/接口搜索、仅显示在线、CSV 导出、进度与取消。
- `config/oui.csv` 扩展机制：放入 IEEE 官方 OUI 列表即可补齐全量厂商数据，
  下次扫描生效，无需重启。

### 变更
- 扫描取消入口统一为 `cancelScan`：IP 扫描与 MAC 扫描共用后端同一个取消开关，
  按模块命名会误导。
- 统计卡片在窄容器下改用更紧凑列宽，避免 4 格退化成 2+1 后留出大片空白。

### 修复
- 广播地址 `ff:ff:ff:ff:ff:ff` 因第一字节命中本地管理位而被误标为「随机地址」。
- 子网定向广播（如 /27 的 `.63`）曾混进 ARP 列表，现于采集出口统一过滤。

### 测试
- 新增 16 项：MAC 归一化与 OUI 库 9 项、`/proc/net/arp` 解析 3 项、
  MAC 扫描编排 3 项（只读模式不给在线状态、厂商不猜、探测计数）、
  MAC CSV 格式 1 项。总计 87 项。

### 已知限制
- macOS 的 `sysctl` 路由表解析**未在真机验证**（开发环境为 Windows），仅保证可编译。
  首次在 mac 上使用时需要确认采集结果正确。
- 内置 OUI 库只收录确信的前缀（22 条），未命中显示 6 位前缀原值。
  宁可留空也不给错误归属；需要全量数据请放 `config/oui.csv`。

## [4.0.0-alpha.5] — 2026-11-03

### 新增
- **IP 扫描模块**（M3 第一块）：网段 / 区间 / 单 IP 三种输入，并发 ICMP 探活。
  - `qqhu-core::ipscan`：扫描范围解析（CIDR、闭区间、`192.168.1.10-50` 短写），
    正确排除网络与广播地址，`/31` `/32` 按现代语义处理，单次上限 4096 个地址。
  - `qqhu-probe::ipscan`：共享单个 ICMP Client + 滑动并发窗口，
    支持中途取消（`AtomicBool`）、进度节流回调、结果按地址升序。
  - **TCP 兜底**：ICMP 无响应的地址可再试指定端口，命中即判存活并记录端口；
    解决企业网络禁 ICMP 时「ping 不通 ≠ 主机不在线」的误判。
  - CSV 导出（UTF-8 BOM、`reports/ipscan/`），界面支持搜索过滤、仅显示存活、
    进度条与存活计数。
- 命令行示例 `ipscan_demo`，便于在无 GUI 环境验证与对拍。

### 变更
- 前端版本号改由 `vite define` 从 `package.json` 注入，消除浏览器预览模式下
  硬编码的 `4.0.0-dev` 这一冗余版本来源。

### 修复
- 浏览器预览模式的占位模块清单补齐「关于 / 许可」。

### 测试
- 新增 13 项扫描范围解析测试、6 项扫描引擎测试（含取消、进度顺序、TCP-only 模式）、
  1 项 CSV 导出格式测试。

## [4.0.0-alpha.4] — 2026-11-03

### 变更
- **侧栏改为扁平列表**：取消「核心 / 网络 / 工具 / 信息」分组标题，所有模块同级平铺，
  7 个入口一屏可见，减少纵向空间与视觉层级。
- **每个菜单项配图标**：新增 `src/components/icons.tsx` 图标注册表，采用统一线条风格
  （1.6px 描边、`currentColor` 跟随主题）。后端 `ModuleInfo` 的 `group` 字段替换为
  `icon` 语义名（`wave` / `split` / `radar` / `chip` / `shield` / `info` / `doc`），
  前端按名查表渲染，未登记名称回退默认圆点。
- 选中项增加左侧竖条指示，低对比环境下不必仅靠背景色辨识。
- 浏览器预览模式的占位模块清单补齐「关于 / 许可」，与真实后端保持一致。

### 测试
- 新增 `every_module_has_icon`：防止新增模块时漏写图标名导致侧栏空白位。

## [4.0.0-alpha.3] — 2026-11-03

### 新增
- **诊断报告归档**：每次诊断在 `reports/diagnosis/<task_id>/report.md` 生成完整
  Markdown 技术报告，含任务信息、结论建议、输入参数、解析、ICMP 逐包结果、端口表、
  质量评判、降级事件。
- **历史索引与对比**：`reports/diagnosis/_history.json` 记录同目标历次结果（上限 500 条，
  原子写入，损坏时降级为空不阻断诊断），自动生成「上次 vs 本次」档位、丢包、时延、抖动变化。
- **qqhu-report crate**：`persist()` 统一报告落盘与历史登记，Tauri 命令与 CLI 共用同一路径。
- 界面新增对比卡片与「打开所在目录」，可一键定位报告文件。

### 变更
- `run_diagnosis` 返回结构由 `DiagnosticReport` 改为 `DiagnosisOutcome`
  （含 report / reportPath / compare）。

### 验证
- 单元测试 50 项通过；端到端连跑两次，第二次正确输出对比结论

---

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
