# 变更日志

## [2026-05-13] [新增] 网络诊断桌面工具 MVP

- 依据 `docs/network-diagnostic-tool-design_v1.4.md` 实现 Python + tkinter + ttkbootstrap GUI。
- 同源诊断模型：DNS、可选 ICMP ping、多端口 tcping、可选 tshark 抓包；双输出 GUI 摘要 + Markdown 技术报告。
- 内置 `ThirdParty/tcping/` 相对路径解析；Wireshark 安装包引导与同捆目录探测。
