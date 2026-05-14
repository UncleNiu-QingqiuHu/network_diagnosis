"""应用与报告中的版本标识。

`APP_VERSION` 为**唯一**版本号来源：`pyproject.toml` 通过 setuptools dynamic 读取同一常量；
`runner` / Markdown 报告 / GUI 标题等均应引用此变量，勿在其它文件手写版本字符串。
"""

APP_VERSION = "2.0.1"
DESIGN_DOC_REF = "network-diagnostic-tool-design_v1.5"

APP_DISPLAY_NAME = "青丘狐网络工作台"
APP_DISPLAY_NAME_EN = "Qingqiuhu Network Workbench"
WEBSITE_URL = "https://www.qingqiuhu.net"
WEBSITE_DISPLAY = "www.qingqiuhu.net"
COMMUNITY_URL = "https://www.pheks.com/community/"
COMMUNITY_DISPLAY = "www.pheks.com/community/"
AUTHOR_NAME = "Mr. Z"
AUTHOR_EMAIL = "mr.zed@qq.com"
AUTHOR_QQ_DISPLAY = "40061980"
AUTHOR_QQ_GROUP_DISPLAY = "292621190"
AUTHOR_SUMMARY = (
    f"{AUTHOR_NAME}  ·  {AUTHOR_EMAIL}  ·  QQ：{AUTHOR_QQ_DISPLAY}  ·  QQ群：{AUTHOR_QQ_GROUP_DISPLAY}"
)
APP_DESCRIPTION = (
    "青丘狐网络工作台面向 Windows 桌面场景：提供网络连通性与质量一键诊断（右侧摘要与 Markdown 技术报告）、"
    "IPv4 子网计算、交换机串口与 SSH Console、多引擎数据库连接诊断与监控导出，以及企业向网络安全轻量基线检查"
    "（本机暴露面摘要与授权范围内的 HTTPS/TLS、DNS、TCP 端口探测等）。所有远程探测须在界面勾选有效授权后执行。"
)
