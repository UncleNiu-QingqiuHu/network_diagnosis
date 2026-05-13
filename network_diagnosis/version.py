"""应用与报告中的版本标识。

`APP_VERSION` 为**唯一**版本号来源：`pyproject.toml` 通过 setuptools dynamic 读取同一常量；
`runner` / Markdown 报告 / GUI 标题等均应引用此变量，勿在其它文件手写版本字符串。
"""

APP_VERSION = "1.0.0"
DESIGN_DOC_REF = "network-diagnostic-tool-design_v1.5"

APP_DISPLAY_NAME = "青丘狐网络工作台"
APP_DISPLAY_NAME_EN = "Qingqiuhu Network Workbench"
WEBSITE_URL = "https://www.qingqiuhu.net"
WEBSITE_DISPLAY = "www.qingqiuhu.net"
AUTHOR_SUMMARY = "Mr. Z  ·  mr.zed@qq.com  ·  QQ：40061980"
APP_DESCRIPTION = (
    "青丘狐网络工作台（Windows 桌面）：网络连通性诊断（GUI 摘要与 Markdown 技术报告）、子网计算、"
    "交换机串口/SSH Console、多引擎数据库连接诊断与监控导出。"
)
