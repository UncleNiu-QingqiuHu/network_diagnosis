"""应用与报告中的版本标识。

`APP_VERSION` 为**唯一**版本号来源：`pyproject.toml` 通过 setuptools dynamic 读取同一常量；
`runner` / Markdown 报告 / GUI 标题等均应引用此变量，勿在其它文件手写版本字符串。
"""

APP_VERSION = "1.0.0"
DESIGN_DOC_REF = "network-diagnostic-tool-design_v1.4"

APP_DISPLAY_NAME = "网络诊断工具"
APP_DISPLAY_NAME_EN = "QQHU Network Diagnosis"
AUTHOR_SUMMARY = "Mr. Z  ·  mr.zed@qq.com  ·  QQ：40061980"
APP_DESCRIPTION = "Windows 桌面网络与连通性诊断工具（含多模块扩展占位）。"
