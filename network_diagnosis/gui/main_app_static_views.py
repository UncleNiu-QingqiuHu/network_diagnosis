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

        body_network = """【本模块用途】
  • 对单个主机名或 IP 做一键式连通性与质量探测：DNS、Ping、端口可达（tcping）、可选路由追踪与抓包，
    并可按需叠加带宽抽样与进阶项；结果以右侧摘要 + Markdown 技术报告呈现，便于排障与留痕。

══════════════════════════════════════
一、前置条件与环境准备（建议先自检）
══════════════════════════════════════

  1）总体环境
  • 操作系统：当前界面与脚本适配以 Windows 为主；诊断会调用系统命令（如 tracert）与本机网络栈。
  • 权限与策略：企业环境若限制 ICMP、出站端口或拦截子进程，部分探测会失败或降级；本机防火墙/
    终端防护可能拦截短时并发连接（HTTP 测速、多端口 tcping 等）。
  • 合规：仅对自有或可授权的目标做探测；勿对无关第三方站点滥测。

  2）Tcping（端口探测）
  • 用途：在勾选端口并对端口做采样统计时，依赖 ThirdParty/tcping/tcping.exe（或与界面提示一致的路径）。
  • 准备：将官方/可信来源的 tcping.exe 放到项目内 ThirdParty/tcping/ 目录（与发行说明一致）。
  • 自检：点击左侧「检测 Tcping」。若未找到，按弹窗说明补齐文件后再测。

  3）Wireshark / Npcap / Tshark（抓包）
  • 用途：勾选「抓包」后，诊断阶段会调用 Wireshark 自带的命令行组件「tshark」写入 pcap；
    Npcap 提供 Windows 抓包驱动（安装 Wireshark 时一般一并勾选安装）。
  • 安装建议：
      a. 点击左侧「安装 Wireshark」：若项目在 ThirdParty/Wireshark/ 下已放置官方安装包（.exe），
         程序会直接启动其中最新的安装程序（Windows）；若目录为空，将弹窗提示前往
         https://www.wireshark.org/ 下载并把安装包放入该目录。
      b. 安装向导中务必勾选 Npcap，并允许其安装/更新抓包驱动。
      c. 若机器已安装 Wireshark，请确认「开始菜单」或「C:\\Program Files\\Wireshark\\」下存在 tshark.exe；
         程序也会按常见路径自动探测。
  • 常见限制：部分环境下抓包需「以管理员身份运行」本工具，否则 tshark 无法访问适配器；若抓包失败，
    请查看「进度详情」与 Markdown 报告中的错误摘要。
  • 自检：点击「检测 Tshark」确认本机可被本工具调用。

  4）iperf3（可选带宽打流）
  • 用途：仅在左侧「带宽 / 吞吐」选择「iperf3」时使用；需本机能执行 iperf3 客户端，且对端已启动服务。
  • 准备：可将 iperf3.exe 放到 ThirdParty/iperf3/，或安装到系统 PATH 中。
  • 自检：点击「检测 Iperf3」。

  5）HTTP 测速（可选）
  • 用途：从填写的 URL 拉取数据以估算下载吞吐；会消耗目标站点与本机出口流量。
  • 准备：无需额外 exe；请使用合规、稳定的测速 URL（默认示例仅供演示，生产环境请替换为授权地址）。

══════════════════════════════════════
二、「探测目标」——用途与填写说明
══════════════════════════════════════

  • 「主机名或 IP」
      用途：作为 DNS、Ping、路由追踪及进阶项的目标标识。
      使用：填公网域名、内网主机名或直接填 IPv4/IPv6（视选项而定）。非法或不可解析时会在日志中报错。
  • 「TCP 端口（可选）」
      用途：对列表中的每个端口做 tcping 类连通与延迟统计（需 Tcping 可用）。
      使用：多个端口用英文逗号分隔（如 80,443）。若端口栏「留空」，则整次诊断「不做」端口 tcping 步骤。
  • 「优先 IPv6」
      用途：当目标存在 AAAA 且本机 IPv6 可用时，优先走 IPv6 做后续 TCP / 相关探测路径。
      使用：按需勾选；纯 IPv4 环境可不选。

══════════════════════════════════════
三、「探测选项」——每项用途与使用
══════════════════════════════════════

  • 「端口采样次数」
      用途：每个 TCP 端口重复探测的次数，用于粗略统计成功率与延迟分布。
      使用：默认即可；网络抖动大时可适当增大；过大则任务耗时增加。
  • 「TCP 超时 (ms)」
      用途：单次 tcping 等待上限。
      使用：跨广域网或高延迟链路可适当加大；过小易误判为不通。
  • 「ICMP Ping」
      用途：是否发送 ICMP Echo 探测链路连通与往返延迟。
      使用：关闭则跳过 Ping 步骤（部分网络禁止 ICMP 时可关，以免混淆结论）。
  • 「Ping 次数」/「ICMP 等待 (ms)」
      用途：控制 Ping 的包数量与单次等待时间。
      使用：与下方「长 Ping」二选一逻辑以界面为准；长 Ping 勾选后以秒级时长覆盖次数。
  • 「长 Ping」+ 秒数
      用途：在一段时间内持续 Ping，观察短时丢包或延迟波动。
      使用：勾选并设定秒数；会比固定次数更贴近「盯一段时间线路」的场景。
  • 「抓包」
      用途：在诊断窗口内由 tshark 抓包并生成 pcap，便于与端口/Ping/路由结果对照。
      使用：见上文「Wireshark / Npcap / Tshark」前置条件；磁盘空间与隐私需注意。
  • 「路由追踪 (tracert)」
      用途：调用系统路由追踪查看通往目标的逐跳路径。
      使用：勾选后可调「最大跳数」「每跳超时」；路径过长或防火墙过滤 ICMP/UDP 时可能不完整。
  • 「任务状态」
      用途：显示当前诊断阶段与人可读的状态摘要。
      使用：运行中会配合右侧「进度详情」滚动日志阅读。

══════════════════════════════════════
四、「带宽 / 吞吐（可选）」——用途与使用
══════════════════════════════════════

  • 「不进行测速」：跳过所有带宽相关步骤（默认省时）。
  • 「HTTP 抽样下载」：按 URL、并发连接数、持续时间拉取数据估算下行带宽。
      使用：替换为自有测速或 CDN 提供的授权 URL；注意流量与对端压力。
  • 「iperf3」：向指定服务器与端口发起打流。
      使用：填写可达的 iperf3 服务端地址与端口、时长；确保本机 iperf3 可用（见前置条件）。

══════════════════════════════════════
五、「进阶探测（可选）」——每项用途与使用
══════════════════════════════════════

  • 「指定 DNS（与系统解析对比）」
      用途：除系统解析器外，再向指定 DNS（如 223.5.5.5）查询同一主机名，对比结果是否一致。
      使用：填 IP；留空则仅使用系统解析路径。
  • 「PathPing / mtr」：路径质量与丢包统计（较慢，依系统命令可用性执行）。
  • 「TCP 路径」+「TCP 最大跳数」：基于 TCP 的路径探测（与 tracert 互补，耗时与环境依赖更高）。
  • 「HTTPS/TLS」：对目标 HTTPS 握手与证书等做探测摘要（非漏洞扫描）。
  • 「出口 / 代理」：采集与出口、代理相关的上下文（具体字段见报告）。
  • 「IPv4 MTU」：IPv4 路径 MTU 相关探测（可能需要特定权限或环境）。
  • 「历史记录对比」：与近期本地报告对比关键指标（需在 reports 中有可读历史）。
      使用：按需勾选；未满足的依赖会在界面或报告中标注跳过/降级。

══════════════════════════════════════
六、常用操作按钮（左侧底部）
══════════════════════════════════════

  • 「安装 Wireshark」：若 ThirdParty/Wireshark/ 下已有官方 .exe 安装包，将启动其中最新的安装程序；
    否则弹窗提示下载并放入该目录后再试。
  • 「检测 Tcping」「检测 Tshark」「检测 Iperf3」：一键确认外部工具是否就绪。
  • 「开始诊断」：在参数填写完毕后启动后台任务；运行中请勿重复点击。
  • 「打开技术报告 (Markdown)」：诊断完成后启用，打开最近一次生成的 Markdown；亦可自行打开 reports/ 目录。

══════════════════════════════════════
七、右侧区域与结果阅读
══════════════════════════════════════

  • 「诊断结果」：结构化摘要（结论分级、关键指标等）。
  • 「进度详情」：步骤级文本日志，排障时优先结合此处与 Markdown 中的原始命令/路径。
  • 报告目录：默认位于项目（或打包 exe）旁的 reports/；完整指标含义以 Markdown 报告与设计文档为准。

══════════════════════════════════════
八、其他提示
══════════════════════════════════════

  • 诊断过程会启动多个短生命周期子进程；杀毒软件误报时可对本工具目录加白名单。
  • 功能演进与字段释义以仓库内设计文档及界面版本为准；若与本文措辞不一致，以当前界面标签为准。"""

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
  • Oracle：库名/服务字段请填 **Service Name**（非 SID 时请按实际环境核对）；需满足 python-oracledb 与官方文档对运行时
    的要求（如 Instant Client 等）。

二、表单与提示
  • 切换引擎时，界面提示会说明 non-SQLite 时须填主机与库名等注意点。
  • 连接参数错误、驱动缺失或网络不可达时，报告与弹窗会给出失败原因摘要。

三、诊断与产物
  • 「运行诊断（生成 Markdown）」：后台连接并采集元数据与健康信息，在 reports/db_diagnosis/<任务ID>/ 下写入 Markdown
    等文件。
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
  • 面向企业网管在授权范围内的轻量基线核对：本机多数项为只读摘要；
    **临时文件清理**会在您确认后删除文件，请先预览再谨慎执行。
  • 对 URL 的 TLS / HTTP 头与 DNS 对比须在勾选授权确认后执行。
  • 方案说明见仓库内 **docs/network-security-diagnosis-design.md**。

二、本机
  • 「刷新 TCP 监听端口」：在 Windows 上通过 PowerShell 枚举 TCP 监听、绑定地址与进程名（依赖 Get-NetTCPConnection
    等）。
  • 「刷新防火墙摘要」：各配置文件启用状态 + 入站「允许」规则抽样；精细管理请使用「高级安全 Windows 防火墙」(wf.msc)。
  • 「刷新 CPU / GPU」：处理器型号与摘要；**每个逻辑核心**的利用率（性能计数器 WMI）；显卡摘要；
    若本机存在 NVIDIA 驱动并可在 PATH 中调用 nvidia-smi，则追加 GPU 利用率与显存等字段。
  • 「刷新内存」：操作系统可见内存、占用与空闲；物理内存总量；已安装的物理内存条明细（容量、厂商、速率等，
    受 WMI 可读字段限制）。
  • 「刷新本地用户与密码策略」：域/工作组摘要；本地账户列表（启用状态、密码是否过期、上次登录等）；
    **net accounts**（全局密码策略）、**whoami /groups**（当前用户组）；
    并附组策略（GPO）在图形界面中查看的简要指引。
  • 「临时文件：预览可清理空间」：扫描当前用户 TEMP、LOCALAPPDATA\\Temp 等路径并估算体积；
    界面中会标注 **系统目录 Windows\\Temp** 的统计通常仅供对照，**默认策略不清理该目录**。
  • 「临时文件：执行清理（用户 TEMP）」：经二次确认后，尝试删除上述**当前用户临时目录**下的文件；
    被占用或无权限的文件会自动跳过；**不包含 Windows\\Temp**；建议在关闭无关大型软件后再执行。

三、授权目标
  • 必须勾选「我已确认对目标的测试已获得有效授权」后，方可点击 HTTPS / DNS 检查。
  • 「检查 TLS 与安全响应头」：建立 TLS、读取服务端证书字段摘要，并用 GET 拉取响应中的常见安全头（如 HSTS、CSP 等）；
    **不是**漏洞扫描或渗透工具。
  • 「DNS 对比」：将系统解析得到的 IPv4 与指定 DNS 服务器解析结果并列；若不一致可能为 split-DNS 设计或配置问题，
    需结合现网文档判断。

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
