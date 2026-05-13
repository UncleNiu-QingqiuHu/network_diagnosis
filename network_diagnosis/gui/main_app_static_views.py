"""使用说明、关于、许可、占位页等静态视图。"""

from __future__ import annotations

import sys
import tkinter as tk
import webbrowser
from tkinter.scrolledtext import ScrolledText

import ttkbootstrap as ttk
from ttkbootstrap.constants import EW, NSEW, PRIMARY, SECONDARY, W

from network_diagnosis.gui.main_app_common import bind_label_wraplength
from network_diagnosis.paths import bundle_root
from network_diagnosis.version import (
    APP_DESCRIPTION,
    APP_DISPLAY_NAME,
    APP_DISPLAY_NAME_EN,
    APP_VERSION,
    AUTHOR_SUMMARY,
    COMMUNITY_DISPLAY,
    COMMUNITY_URL,
    DESIGN_DOC_REF,
    WEBSITE_DISPLAY,
    WEBSITE_URL,
)


class StaticViewsMixin:
    def _add_placeholder_view(self, module_key: str, title: str) -> None:
        frm = ttk.Frame(self._content_host, padding=(32, 48))
        self._view_frames[module_key] = frm
        frm.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)
        ttk.Label(
            frm,
            text=f"{title}\n\n此功能尚未实现，后续版本补充。\n当前为空白占位页面。",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 13),
            justify=tk.CENTER,
            wraplength=520,
        ).grid(row=0, column=0)

    def _build_guide_view(self) -> None:
        frm = ttk.Frame(self._content_host, padding=(24, 28, 24, 20))
        self._view_frames["guide"] = frm
        frm.rowconfigure(2, weight=1)
        frm.columnconfigure(0, weight=1)

        ttk.Label(
            frm,
            text="使用说明",
            font=("Microsoft YaHei UI", 18, "bold"),
        ).grid(row=0, column=0, sticky=W, pady=(0, 10))

        intro = (
            "左侧「功能导航」可在各模块间切换。下方按标签页分模块说明："
            "「网络诊断」「子网计算」「交换机配置」「数据库诊断」「安全诊断」。"
        )
        ttk.Label(
            frm,
            text=intro,
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 11),
            wraplength=0,
            justify=tk.LEFT,
        ).grid(row=1, column=0, sticky=EW, pady=(0, 10))

        nb = ttk.Notebook(frm, bootstyle=PRIMARY)
        nb.grid(row=2, column=0, sticky=NSEW)

        def add_guide_tab(title: str, body: str) -> None:
            tab = ttk.Frame(nb, padding=(6, 10, 6, 8))
            nb.add(tab, text=title)
            tab.rowconfigure(0, weight=1)
            tab.columnconfigure(0, weight=1)
            st = ScrolledText(
                tab,
                height=22,
                wrap=tk.WORD,
                font=("Microsoft YaHei UI", 11),
                relief=tk.FLAT,
                padx=10,
                pady=10,
            )
            st.grid(row=0, column=0, sticky=NSEW)
            st.insert(tk.END, body)
            st.configure(state=tk.DISABLED)

        body_network = """一、填写探测目标
  • 「主机名或 IP」：填写要排查的网站域名或服务器地址（如 www.baidu.com 或内网 IP）。
  • 「TCP 端口」：可选。留空则不做端口连通测试；多个端口用英文逗号分隔，如 80,443。
  • 「优先 IPv6」：若目标有 AAAA 记录且本机 IPv6 可用，可优先走 IPv6 路径做后续 TCP / 抓包。

二、探测选项（左侧「探测选项」区域）
  • 端口采样次数、TCP 超时：影响 tcping 类端口探测的统计与等待时间。
  • ICMP Ping：开关控制是否发 Ping；可设 Ping 次数或勾选「长 Ping」用时长覆盖次数。
  • 抓包：勾选后会在诊断过程中尝试用 tshark 抓包（需本机安装 Wireshark + Npcap）。
  • 路由追踪：勾选后调用系统 tracert（Windows）等进行路径追踪。
  • 任务状态：诊断运行时此处显示进度提示；右侧「进度详情」为实时文字日志。

三、带宽 / 吞吐（可选）
  • 「不进行测速」：跳过带宽相关步骤。
  • 「HTTP 抽样下载」：按填写的 URL、并发与时长做下载抽样（会消耗流量，请用合规测速地址）。
  • 「iperf3」：向指定 iperf 服务端打流；需本机可运行 iperf3 且对端已启动服务。

四、进阶探测（可选，可能较慢）
  • 指定 DNS：在系统解析之外，向指定 DNS 再解析一次，便于对比解析差异。
  • PathPing / mtr、TCP 路径、HTTPS/TLS、出口与代理、IPv4 MTU、历史记录对比等按需勾选；
    未安装的依赖会在报告与界面中提示降级或跳过。

五、运行与查看结果
  • 点击「开始诊断」启动后台任务；运行期间请勿重复点击（会提示正在运行）。
  • 右侧「诊断结果」为结构化摘要；「进度详情」为步骤日志。
  • 结束后可点「打开技术报告 (Markdown)」或在报告目录中查看完整说明与原始日志路径。

六、外部工具（按需）
  • 端口探测依赖 tcping：可用「检测 Tcping」确认；缺失时请按提示放到 ThirdParty/tcping/。
  • 抓包依赖 tshark：可用「检测 Tshark」或「打开 Wireshark」安装包目录中的安装程序。
  • iperf3 测速：可用「检测 Iperf3」；可执行文件可放在 ThirdParty/iperf3/ 或系统 PATH。

七、其他说明
  • 诊断会调用本机网络栈与若干子进程，请在合规前提下对自有或可授权目标使用。
  • 功能细节与指标含义以设计参考文档及生成的 Markdown 报告为准。"""

        body_subnet = """一、界面布局
  • 左侧：输入区与「计算子网」「计算结果」文本框。
  • 右侧：本机 IPv4、网关、DNS 与公网地址等参考信息；点「刷新」异步拉取（与一次完整「网络诊断」报告不等价）。

二、CIDR 快捷输入
  • 支持「IP/前缀」，例如 192.168.1.10/24。
  • 支持「IP/点分掩码」，例如 192.168.1.10/255.255.255.0。
  • 本栏有有效输入时，以本栏为准，下方「IPv4 + 前缀/掩码」一组可被界面说明忽略。

三、IPv4 + 前缀 / 掩码（分拆输入）
  • 填写 IPv4 地址；前缀长度用 Spinbox 选 0～32；或填写「或掩码」点分十进制掩码。
  • 若「或掩码」非空，优先按掩码计算；掩码留空则使用前缀。
  • 若上方 CIDR 栏已含「/」，请优先用上方栏，避免两套输入混用。

四、计算与结果
  • 点「计算子网」后，「计算结果」区展示网络地址、广播、掩码、wildcard、可用主机区间等。
  • 仅用于运维辅助；生产割接请以官方工具与变更流程为准。

五、注意
  • IPv6、非点分掩码的特例不在本页展开；错误输入会弹窗提示。"""

        body_switch = """一、模式
  • 「串口 (COM)」：经 RS-232/USB 转串口连接设备 Console。
  • 「SSH (PTY)」：经网络登录设备，终端为伪终端文本会话。

二、串口
  • 第一行：端口（下拉或手输）、刷新端口列表、波特率/数据位/校验/停止位。
  • 第二行：XON/XOFF、RTS/CTS 流控开关。
  • 连接前确认独占占用该 COM 口（勿被其它程序占用）。
  • 「串口本地回显」：当设备不在屏幕上回显你键入的字符时可勾选；SSH 模式一般勿开。

三、SSH
  • 第一行：主机、端口、用户名、密码。
  • 第二行：私钥路径（可选，可「浏览…」）、私钥口令；TERM、PTY 列与行。
  • 首次连接未知主机时，程序会把主机密钥写入可写目录下的 known_hosts（见下方路径），仅供本工具使用。

四、终端区与操作
  • 连接后在下方深色区域按键输入；Enter 发送回车。
  • 「连接」「断开」控制会话；切换到其它功能页或退出程序时会自动断开，释放串口或 SSH。

五、数据目录（SSH）
  • 开发运行：项目根目录下 switch_console/（通常已加入 .gitignore）。
  • 打包为 exe：与可执行文件同目录下的 switch_console/。
  • 请勿在多人共用电脑上保存密码；凭证默认仅存于本会话与界面变量。

六、合规
  • 仅对有权管理的设备使用；暴力破解与未授权访问不在本工具用途之内。"""

        body_database = """一、支持引擎
  • SQLite：「主机/路径」填数据库文件路径；端口对 SQLite 无意义（可随界面禁用或忽略）。
  • MySQL / MariaDB、PostgreSQL：填写可达主机、端口、用户名、密码、库名（数据库名）。
  • SQL Server：同上；本机须安装并配置 **ODBC 驱动**（pyodbc 经系统驱动连接）。
  • Oracle：库名/服务字段请填 **Service Name**（非 SID 时请按实际环境核对）；需满足 python-oracledb 与官方文档对运行时的要求（如 Instant Client 等）。

二、表单与提示
  • 切换引擎时，界面提示会说明 non-SQLite 时须填主机与库名等注意点。
  • 连接参数错误、驱动缺失或网络不可达时，报告与弹窗会给出失败原因摘要。

三、诊断与产物
  • 「运行诊断（生成 Markdown）」：后台连接并采集元数据与健康信息，在 reports/db_diagnosis/<任务ID>/ 下写入 Markdown 等文件。
  • 「打开报告目录」「打开上次报告」便于取回刚生成的说明。
  • 报告内容侧重技术人员阅读：版本、会话、对象列表等以实际引擎与权限为准；无权限项会标注跳过。

四、监控
  • 「开始监控」按设定间隔周期性抓取快照；「停止监控」结束轮询。
  • 「导出监控 Markdown」将当前监控采样整理为文档并保存到报告目录。
  • 监控会持续占用连接，请在业务低峰或测试库上使用；长时间轮询注意对库侧负载的影响。

五、安全与边界
  • 请使用只读或专用诊断账号；勿在生产库上使用高权限账户做试验。
  • 本模块为连通性与轻量信息采集，非 SQL 性能压测或审计替代方案。"""

        body_security = """一、定位
  • 面向企业网管在授权范围内的轻量基线核对：本机为只读摘要；对 URL 的 TLS / HTTP 头与 DNS 对比须在勾选授权确认后执行。
  • 方案说明见仓库内 **docs/network-security-diagnosis-design.md**。

二、本机
  • 「刷新 TCP 监听端口」：在 Windows 上通过 PowerShell 枚举 TCP 监听、绑定地址与进程名（依赖 Get-NetTCPConnection 等）。
  • 「刷新防火墙摘要」：各配置文件启用状态 + 入站「允许」规则抽样；精细管理请使用「高级安全 Windows 防火墙」(wf.msc)。

三、授权目标
  • 必须勾选「我已确认对目标的测试已获得有效授权」后，方可点击 HTTPS / DNS 检查。
  • 「检查 TLS 与安全响应头」：建立 TLS、读取服务端证书字段摘要，并用 GET 拉取响应中的常见安全头（如 HSTS、CSP 等）；**不是**漏洞扫描或渗透工具。
  • 「DNS 对比」：将系统解析得到的 IPv4 与指定 DNS 服务器解析结果并列；若不一致可能为 split-DNS 设计或配置问题，需结合现网文档判断。

四、导出
  • 「导出当前结果为 Markdown…」将当前输出区已累积的段落写入 **reports/security_diagnosis/**，便于工单与审计。"""

        add_guide_tab("网络诊断", body_network)
        add_guide_tab("子网计算", body_subnet)
        add_guide_tab("交换机配置", body_switch)
        add_guide_tab("数据库诊断", body_database)
        add_guide_tab("安全诊断", body_security)

    def _build_about_view(self) -> None:
        frm = ttk.Frame(self._content_host, padding=(28, 28, 32, 28))
        self._view_frames["about"] = frm
        frm.columnconfigure(0, weight=1)

        ttk.Label(
            frm,
            text="关于本软件",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 11),
        ).grid(row=0, column=0, sticky=W)
        ttk.Label(
            frm,
            text=APP_DISPLAY_NAME,
            font=("Microsoft YaHei UI", 22, "bold"),
        ).grid(row=1, column=0, sticky=W, pady=(6, 2))
        ttk.Label(
            frm,
            text=APP_DISPLAY_NAME_EN,
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 13),
        ).grid(row=2, column=0, sticky=W, pady=(0, 16))

        lf_ver = ttk.Labelframe(frm, text="版本与文档", padding=(14, 12, 14, 12))
        lf_ver.grid(row=3, column=0, sticky=EW, pady=(0, 10))
        lf_ver.columnconfigure(1, weight=1)

        def meta_pair(parent: ttk.Frame, r: int, key: str, value: str) -> None:
            ttk.Label(
                parent,
                text=key,
                bootstyle=SECONDARY,
                font=("Microsoft YaHei UI", 11),
            ).grid(row=r, column=0, sticky=tk.N + tk.E, padx=(0, 12), pady=(0, 8))
            ttk.Label(
                parent,
                text=value,
                font=("Microsoft YaHei UI", 11),
                wraplength=0,
                justify=tk.LEFT,
            ).grid(row=r, column=1, sticky=W, pady=(0, 8))

        meta_pair(lf_ver, 0, "软件版本", APP_VERSION)
        meta_pair(lf_ver, 1, "设计参考", f"docs/{DESIGN_DOC_REF}.md")
        ttk.Label(
            lf_ver,
            text="官方网站",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 11),
        ).grid(row=2, column=0, sticky=tk.N + tk.E, padx=(0, 12), pady=(0, 8))
        site_lbl = tk.Label(
            lf_ver,
            text=WEBSITE_DISPLAY,
            font=("Microsoft YaHei UI", 11, "underline"),
            fg="#0b5ed7",
            cursor="hand2",
        )
        site_lbl.grid(row=2, column=1, sticky=W, pady=(0, 8))
        site_lbl.bind("<Button-1>", lambda _e: webbrowser.open(WEBSITE_URL))

        ttk.Label(
            lf_ver,
            text="官方社区",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 11),
        ).grid(row=3, column=0, sticky=tk.N + tk.E, padx=(0, 12), pady=(0, 8))
        community_lbl = tk.Label(
            lf_ver,
            text=COMMUNITY_DISPLAY,
            font=("Microsoft YaHei UI", 11, "underline"),
            fg="#0b5ed7",
            cursor="hand2",
        )
        community_lbl.grid(row=3, column=1, sticky=W, pady=(0, 8))
        community_lbl.bind("<Button-1>", lambda _e: webbrowser.open(COMMUNITY_URL))

        lf_intro = ttk.Labelframe(frm, text="简介", padding=(14, 12, 14, 12))
        lf_intro.grid(row=4, column=0, sticky=EW, pady=(0, 10))
        lf_intro.columnconfigure(0, weight=1)
        lbl_about_intro = ttk.Label(
            lf_intro,
            text=APP_DESCRIPTION,
            font=("Microsoft YaHei UI", 11),
            justify=tk.LEFT,
        )
        lbl_about_intro.grid(row=0, column=0, sticky=EW)
        bind_label_wraplength(lbl_about_intro, inset=6)

        lf_contact = ttk.Labelframe(frm, text="作者与联系", padding=(14, 12, 14, 12))
        lf_contact.grid(row=5, column=0, sticky=EW, pady=(0, 10))
        lf_contact.columnconfigure(0, weight=1)
        ttk.Label(
            lf_contact,
            text=AUTHOR_SUMMARY,
            font=("Microsoft YaHei UI", 11),
            wraplength=0,
            justify=tk.LEFT,
        ).grid(row=0, column=0, sticky=W)

        ttk.Separator(frm, orient=tk.HORIZONTAL).grid(row=6, column=0, sticky=EW, pady=(8, 14))

        env = (
            f"运行环境：当前解释器 Python {sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}（建议 3.10+）；界面 ttkbootstrap / Tk。"
        )
        ttk.Label(
            frm,
            text=env,
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 10),
            wraplength=0,
            justify=tk.LEFT,
        ).grid(row=7, column=0, sticky=W)

    def _build_license_view(self) -> None:
        frm = ttk.Frame(self._content_host, padding=(20, 20, 20, 16))
        self._view_frames["license"] = frm
        frm.rowconfigure(1, weight=1)
        frm.columnconfigure(0, weight=1)

        intro = (
            "以下为本仓库根目录中 LICENSE 文件的原文。若以可执行包发布，请一并附带许可证文件；"
            "第三方组件权利见下方说明。"
        )
        ttk.Label(
            frm,
            text=intro,
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 11),
            wraplength=0,
            justify=tk.LEFT,
        ).grid(row=0, column=0, sticky=EW, pady=(0, 10))

        lf = ttk.Labelframe(frm, text="LICENSE（MIT）", padding=(10, 8, 10, 10))
        lf.grid(row=1, column=0, sticky=NSEW, pady=(0, 14))
        lf.rowconfigure(0, weight=1)
        lf.columnconfigure(0, weight=1)

        lic_path = bundle_root() / "LICENSE"
        try:
            body = (
                lic_path.read_text(encoding="utf-8")
                if lic_path.is_file()
                else f"（未在以下路径找到 LICENSE：{lic_path}）"
            )
        except OSError as e:
            body = f"（读取 LICENSE 失败：{e}）"

        txt = ScrolledText(
            lf,
            height=16,
            wrap=tk.WORD,
            font=("Consolas", 10),
            relief=tk.FLAT,
            padx=10,
            pady=10,
        )
        txt.grid(row=0, column=0, sticky=NSEW)
        txt.insert(tk.END, body)
        txt.configure(state=tk.DISABLED)

        lf2 = ttk.Labelframe(frm, text="第三方组件与外部工具（节选说明）", padding=(12, 10))
        lf2.grid(row=2, column=0, sticky=EW)
        third_party = (
            "• GUI 库 ttkbootstrap：MIT License，参见 https://github.com/israel-dryer/ttkbootstrap\n"
            "• 诊断流程可选用 Eli Fulkerson tcping、Wireshark/tshark、iperf3 等；"
            "均为各自版权方软件，再分发或打包时请遵守其许可与商标要求。\n"
            "• 本程序按需调用上述可执行文件，不代表与之存在隶属或担保关系。"
        )
        ttk.Label(
            lf2,
            text=third_party,
            font=("Microsoft YaHei UI", 11),
            justify=tk.LEFT,
            wraplength=0,
        ).pack(fill=tk.X)
