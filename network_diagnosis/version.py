"""应用与报告中的版本标识。

`APP_VERSION` 为**唯一**版本号来源：`pyproject.toml` 通过 setuptools dynamic 读取同一常量；
`runner` / Markdown 报告 / GUI 标题等均应引用此变量，勿在其它文件手写版本字符串。
"""

APP_VERSION = "1.0.0"
DESIGN_DOC_REF = "network-diagnostic-tool-design_v1.4"
