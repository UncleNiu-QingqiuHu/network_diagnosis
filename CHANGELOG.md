# 变更日志

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
