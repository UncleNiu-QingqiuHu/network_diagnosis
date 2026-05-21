"""使用帮助、关于、许可、占位页等静态视图。"""

from __future__ import annotations

import tkinter as tk
import webbrowser
from tkinter.scrolledtext import ScrolledText

import ttkbootstrap as ttk
from ttkbootstrap.constants import E, EW, NSEW, PRIMARY, SECONDARY, W

from network_diagnosis.gui.main_app_common import (
    bind_label_wraplength,
    fix_primary_notebook_selected_tab_colors,
)
from network_diagnosis.gui.simple_markdown_text import (
    append_simple_markdown,
    configure_simple_markdown_tags,
)
from network_diagnosis.paths import bundle_root
from network_diagnosis.version import (
    APP_DESCRIPTION,
    APP_DISPLAY_NAME,
    APP_DISPLAY_NAME_EN,
    APP_VERSION,
    AUTHOR_EMAIL,
    AUTHOR_NAME,
    AUTHOR_QQ_DISPLAY,
    AUTHOR_QQ_GROUP_DISPLAY,
    COMMUNITY_DISPLAY,
    COMMUNITY_URL,
    DESIGN_DOC_REF,
    GITHUB_REPO_DISPLAY,
    GITHUB_REPO_URL,
    GITCODE_REPO_DISPLAY,
    GITCODE_REPO_URL,
    GITEE_REPO_DISPLAY,
    GITEE_REPO_URL,
    WEBSITE_DISPLAY,
    WEBSITE_URL,
)


class StaticViewsMixin:
    def _ensure_static_module_built(self, module_key: str) -> None:
        """使用帮助 / 关于 / 许可体量较大，延后到首次进入时再构建，缩短启动与切换耗时。"""
        if module_key == "guide" and "guide" not in self._view_frames:
            self._build_guide_view()
        elif module_key == "about" and "about" not in self._view_frames:
            self._build_about_view()
        elif module_key == "license" and "license" not in self._view_frames:
            self._build_license_view()

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
            text="使用帮助",
            font=("Microsoft YaHei UI", 18, "bold"),
        ).grid(row=0, column=0, sticky=W, pady=(0, 10))

        intro = (
            "左侧「功能导航」可在各模块间切换。下方按标签页分模块说明："
            "「网络诊断」「子网计算」「IP扫描」「MAC扫描」「DHCP诊断」「交换机配置」「数据库诊断」「ARP安全」「安全诊断」「数字签名」「SSL证书」。"
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
                highlightthickness=0,
            )
            st.grid(row=0, column=0, sticky=NSEW)
            configure_simple_markdown_tags(
                st,
                base_font=("Microsoft YaHei UI", 11),
                theme_colors=ttk.Style().colors,
            )
            st.configure(state=tk.NORMAL)
            append_simple_markdown(st, body.rstrip() + "\n")
            st.configure(state=tk.DISABLED)

        body_network = """【本模块用途】
  • 对单个主机名或 IP 做一键式连通性与质量探测：DNS、Ping、端口可达（tcping）、可选路由追踪与抓包，
    并可按需叠加带宽抽样与进阶项；结果以右侧摘要 + Markdown 技术报告呈现，便于排障与留痕。
  • 右侧 **网络质量** 会根据 ICMP、tcping（以及可选 **iperf3 UDP**）给出 **极佳 / 正常 / 较差 / 堵塞** 档位；细则见本页「网络质量档位」一节及仓库 **`docs/network-quality-grade-criteria.md`**。

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
  • 用途：在「带宽 / 吞吐」选择「iperf3」时使用。**TCP 多流** 用于吞吐抽样；勾选 UDP 质量项时 **额外** 跑 **UDP**，
    将丢包/抖动并入「网络质量」档位（与 ICMP/tcping **取较差**）。
  • 准备：可将 iperf3.exe 放到 ThirdParty/iperf3/，或安装到系统 PATH；对端须启动 **iperf3 -s**（TCP/UDP 常用同端口，依对端配置为准）。
  • 自检：点击「检测 Iperf3」。

  5）HTTP 测速（可选）
  • 用途：从填写的 URL 拉取数据以估算下载吞吐；会消耗目标站点与本机出口流量。
  • 准备：无需额外 exe；请使用合规、稳定的测速 URL（默认示例仅供演示，生产环境请替换为授权地址）。

  6）外部工具路径说明（与程序探测顺序一致）
  • **根目录约定**：源码运行时 **`ThirdParty`** 位于 **仓库根目录**（与 `network_diagnosis` 包目录同级）；
    打包 exe 时以实际解压/附带目录为准，原则同上。
  • **Tcping**：仅使用 **`ThirdParty\\tcping\\tcping.exe`**；**不会**从系统 PATH 查找。
    请将官方获取的 **tcping.exe** 放入该目录。
  • **tshark（抓包）**：程序探测 **`%ProgramFiles%\\Wireshark\\tshark.exe`**，
    其次 **`%ProgramFiles(x86)%\\Wireshark\\tshark.exe`**。
    请先安装 Wireshark（安装向导勾选 **Npcap**）；路径与权限不足会导致抓包失败。
  • **安装 Wireshark**：将官方 Windows **安装包 `.exe`** 放入 **`ThirdParty\\Wireshark\\`** 后，
    「安装 Wireshark」会启动该目录下 **最新** 的安装程序。
  • **iperf3**：先查找 **`ThirdParty\\iperf3\\iperf3.exe`**；若不存在，再在系统 **PATH** 中查找
    **`iperf3`** 或 **`iperf3.exe`**。

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
      使用：替换为自有测速或 CDN 提供的授权 URL；注意流量与对端压力。**HTTP Mbps 仅写入报告中的带宽说明，不参与「网络质量」档位公式**。
  • 「iperf3」
      — **TCP 吞吐**：反向 `-R`、并行 `-P`（界面「并发流」）、JSON；默认时长 **30** 秒、默认并行 **4**（可调）。
      — **可选 UDP（质量辅助）**：勾选「将 iperf3 UDP 纳入网络质量综合判定」后，在 TCP 之外 **再跑一次** UDP：
        `-u -b <数值>M`、`-t` 与 TCP **相同**、`-R -i 1`，程序加 `-J` 解析 JSON。输入框只填数字，旁注 **M** 表示 **iperf3 `-b` 单位为 Mbps**；默认 **1000**（千兆量级加压，链路不足时 UDP 丢包会升高）。
      — **档位**：UDP 成功时，将其 **丢包率、抖动** 与 Ping/tcping **合并取较差（数值取大）** 后再判档。
      — **说明**：**TCP iperf 的 Mbps 同样只写入带宽说明，不参与档位**；Ping 丢包低而 UDP 丢包高常见于「稀疏 ICMP」与「持续高压 UDP」差异，未必矛盾。

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

  • 「诊断结果」：结构化摘要（整体结论、关键项）；其中 **网络质量** 含档位（极佳/正常/较差/堵塞）与分项指标行。
  • 「进度详情」：步骤级日志；排障时请结合 Markdown 中的命令与原始输出路径。
  • **报告目录**：默认在程序旁的 **reports/**；详细字段以生成的 Markdown 为准。
  • **档位全文**：与源码一致的完整条文见仓库 **`docs/network-quality-grade-criteria.md`**。

══════════════════════════════════════
八、网络质量档位（极佳 / 正常 / 较差 / 堵塞）——摘要
══════════════════════════════════════

  • **前提**：若 **DNS 失败或无地址**，档位直接为 **堵塞**（不再计算时延等）。
  • **参与判定的数据**：丢包率（优先 Ping，否则为 tcping 连接失败占比）、平均时延（Ping RTT 或 tcping RTT）、
    抖动（Ping 的相邻 RTT 差分均值近似，或 tcping RTT 标准差）；若启用 **iperf3 UDP 质量** 且抽样成功，UDP **丢包率、抖动** 与上述同类指标 **取较大值** 再参与判定。
  • **不参与档位**：**HTTP 抽样**与 **iperf3 TCP** 的 Mbps **仅作带宽描述**，不改变档位；UDP 失败时 **不合并**，仍以 ICMP/tcping 为准。

  • **堵塞（满足任一）**：已配置端口且 **全部** 端口非 OK；或 Ping **零回复** 且（无丢包统计或丢包≥**25%**）；或丢包≥**15%**；
    或平均时延≥**400** ms 且 丢包≥**5%**。
  • **较差（未堵塞且满足任一）**：丢包≥**5%**；或平均时延≥**150** ms；或抖动≥**40** ms；
    或存在 **超时/不可达/错误类** 端口；或 Ping **零回复** 且 **未配置** 端口探测。
  • **极佳（未较差/堵塞且同时满足）**：丢包≤**2%**；平均时延≤**70** ms；无抖动样本或抖动≤**25** ms；且无「部分端口异常」。
  • **正常**：其余情况。**注意**：若 **未开 Ping 且端口留空**，探测信息很少，档位也可能为「正常」，**不代表链路已通过充分验证**。

  • **「正常」能否放心用**：表示按本工具规则 **未发现严重异常**，**不保证**视频会议、游戏、大文件等业务均达标；请以指标、带宽抽样及业务实测为准。

══════════════════════════════════════
九、其他提示
══════════════════════════════════════

  • 诊断过程会启动多个短生命周期子进程；杀毒软件误报时可对本工具目录加白名单。
  • 功能演进与字段释义以仓库内设计文档及界面版本为准；若与本文措辞不一致，以当前界面标签为准。"""

        body_subnet = """【本模块用途】
  • 基于标准库 **IPv4 地址模型**做子网解析：由「主机地址 + 前缀/掩码」求所属网络、广播、可用主机区间、通配符掩码（ACL）等；
    可选 **等长子网划分**。右侧异步刷新 **本机 IPv4 / 网关 / DNS** 与 **公网出口** 摘要，便于对照拷贝字段。
  • **不支持 IPv6**；错误格式会弹窗说明。

══════════════════════════════════════
一、界面布局
══════════════════════════════════════

  • **左右分栏**（Panedwindow）：左侧为输入与「计算结果」，右侧为「当前主机与出口」；初次打开约 **各占一半宽度**，可拖动中间分隔条调节。
  • 左侧自上而下：**方式一(推荐)** → **方式二** → **计算子网 / 复制结果** → **可选：等长子网划分** → **计算结果** 文本框。
  • 右侧：**刷新** 按钮 + 「当前主机与出口」文本框（异步加载，加载中会短暂禁用「刷新」）。

══════════════════════════════════════
二、方式一（推荐）
══════════════════════════════════════

  • **单行输入**，支持两种写法（与界面提示一致）：
      — **`IP/前缀`**，例如 **192.168.1.10/24**；
      — **`IP/点分掩码`**，例如 **192.168.1.10/255.255.255.0**。
  • **判定规则**：只要本框内容 **含有字符 `/`**，程序 **仅根据本框** 解析为所属网络，**忽略**下方「方式二」里的 IPv4 / 前缀 / 掩码。
  • 界面默认值一般为 **`192.168.1.10/24`**，可按需修改。

══════════════════════════════════════
三、方式二（仅当方式一不含「/」时使用）
══════════════════════════════════════

  • **IPv4 地址**：合法点分十进制，不能为空（若方式一 **没有** `/`，则用本地址参与计算）。
  • **前缀长度**：Spinbox **0～32**；仅当 **「或掩码」留空** 时生效。
  • **或掩码**：点分十进制掩码（如 `255.255.255.0`）；**一旦填写非空，只按掩码计算**，前缀 Spinbox **不参与**。
  • 勿与方式一混用两套口径：方式一有 `/` 时，整组方式二 **会被忽略**。

══════════════════════════════════════
四、「计算子网」与「复制结果」
══════════════════════════════════════

  • **「计算子网」**：根据上述规则得到一组结果，并 **清空「计算结果」框后写入**（覆盖原有文本）。
  • **「复制结果」**：把当前「计算结果」框 **全文** 写入剪贴板；若为空则提示暂无可复制内容。
  • **典型输出字段含义**（与结果框展示顺序一致）：
      — **输入**：内部采用的 IP/前缀或 IP/掩码接口形式；
      — **地址空间归类**：如 RFC1918 私有、公网、环回、链路本地、CGNAT（100.64.0.0/10）等；
      — **输入 IP 角色**：主机地址 / 网络地址 / 广播地址 / `/31` 点对点 / `/32` 主机路由等；
      — **所属网络（CIDR）、网络地址、广播地址、子网掩码**；
      — **通配符掩码（ACL）**：与掩码 **按位取反** 的写法，常见于 Cisco 类 ACL；
      — **总地址数、可用主机数、首尾可用主机**；
          · **`/32`**：可用主机数按 **1** 处理；
          · **`/31`**：按 **RFC 3021** 语义，可用主机数为 **2**（点对点）；
          · 其它常规前缀：一般为「总地址 − 网络 − 广播」（若为 **0** 则显示 **0**）。
  • 若输入非法，弹窗 **「子网计算」** 并显示具体原因。

══════════════════════════════════════
五、可选：等长子网划分
══════════════════════════════════════

  • **父网 CIDR**：须为合法 **IPv4 CIDR**（如默认 **`192.168.0.0/16`**）。
  • **划至前缀 /**：目标子网前缀须 **严格大于** 父网前缀（例如父 `/16`、子 `/24`）；Spinbox **1～32**。
  • **「生成子网列表」**：列出父网按前缀均匀划分后的全部子网；**最多展示前 64 条**，超出部分以省略行提示总数。
  • **与「计算子网」的关系**：生成列表 **追加** 到「计算结果」框末尾（若已有内容会先换行再接）；**不会**单独清空上方单次计算结果——若需干净版面请先 **「计算子网」** 得到仅含主结果的一段，再点生成列表追加。
  • 错误时弹窗 **「子网划分」**（如父网无效、子前缀不大于父前缀等）。

══════════════════════════════════════
六、右侧「当前主机与出口」
══════════════════════════════════════

  • **数据来源**：IPv4 适配器列表来自 **Windows WMI**（描述、MAC、**IPv4/掩码**、默认网关、DNS）；公网 IPv4 经 **内置出口探测（国内多源）**，仅供对照参考。
  • **代理摘要**：环境变量 **HTTP(S)_PROXY、ALL_PROXY、NO_PROXY** 及 **WinHTTP（netsh）** 节选。
  • **刷新**：后台线程拉取；进行中按钮禁用并在文本框显示「正在读取…」。多块网卡时网关/DNS 可能在多条记录中重复（来自 WMI），文末有简要说明。

══════════════════════════════════════
七、注意
══════════════════════════════════════

  • 本页结论仅供运维规划与 ACL 对照；生产变更请以设备厂商文档为准。
  • 功能与字段若与界面标签不一致，以 **当前程序界面** 为准。"""

        body_ip_scan = """【本模块用途】
  • 对一段 **IPv4** 地址批量发送 **ICMP**（调用 Windows ``ping``）做 **存活探测**，结果表格展示在线/离线及解析到的 RTT。
  • 须在勾选 **授权确认** 后方可开始；请在合规前提下用于本单位内网或测试环境。

══════════════════════════════════════
一、扫描范围写法
══════════════════════════════════════

  • **CIDR**：如 ``192.168.1.0/24``；对常规前缀会使用 ``hosts()`` 语义（不含网络地址与定向广播），**/32** 仅探测该主机。
  • **起止 IP**：``192.168.1.1-192.168.1.254``（允许空格）。
  • **单地址**：``10.0.0.5``。

══════════════════════════════════════
二、参数与限制
══════════════════════════════════════

  • **单次上限**：生成的待探测主机数不得超过该上限（硬上限 **4096**）；超出时请缩小网段或使用起止范围。
  • **并发数**：同时发起的 ping 子进程数；过高可能被本机或对端策略限制。
  • **ICMP 等待**：传给 ``ping -w`` 的单包超时（毫秒）；过小可能误判离线。
  • **停止**：请求中止后，已在执行的 ping 仍会跑完其自然超时；表格保留截至当时的已完成结果。

══════════════════════════════════════
三、与其它模块的关系
══════════════════════════════════════

  • **子网计算**：可先算出本网可用主机区间，再将 **起止 IP** 粘贴到本页扫描。
  • **交换机配置**：扫描确认主机在线后，可切换到交换机 Console/SSH 进一步核查。
  • **网络诊断**：针对 **单个** 主机做 DNS/Ping/端口等综合探测；本页侧重 **网段批量存活**。

══════════════════════════════════════
四、合规
══════════════════════════════════════

  • 批量 ICMP 可能在流量日志或态势感知中留下记录；严禁对未经授权的地址空间扫描。"""

        body_mac_scan = """【本模块用途】
  • 在 **本机所在 IPv4 网段** 内，对指定范围批量 **ICMP** 探测，并读取本机 **ARP 表** 展示 **IP / MAC / 类型 / RTT / 厂商 / 备注**。
  • **不支持跨网段**；多网卡时自动选择覆盖目标的接口。须在勾选 **授权确认** 后方可开始。

══════════════════════════════════════
一、扫描范围
══════════════════════════════════════

  • 与 **IP 扫描** 相同：CIDR、起止 IP、单地址；单次上限硬顶 **4096**。

══════════════════════════════════════
二、结果列说明
══════════════════════════════════════

  • **状态**：ICMP 在线/离线。
  • **MAC / 类型**：`arp -a` 解析；离线或缓存未命中为「—」。
  • **厂商**：内置精简 OUI 表；未命中为「—」。
  • **备注**：自动标注「本机」「网关」「MAC重复」「无MAC」等（可多标签组合）。
  • **解析计算机名**（默认关闭）：可勾选 DNS 反向（作计算机名补充）、NetBIOS（较慢）；开启后增加 **计算机名** 列。

══════════════════════════════════════
三、与其它模块
══════════════════════════════════════

  • **子网计算** → 确定起止 IP → **MAC 扫描** 摸底 → **ARP 安全** 监视网关。
  • **IP 扫描** 侧重存活；本模块侧重二层地址与资产备注。

══════════════════════════════════════
四、合规
══════════════════════════════════════

  • 批量 ICMP 与 ARP 读取可能被记录；仅用于已授权内网。详见 [`docs/mac-scan-design.md`](../docs/mac-scan-design.md)。"""

        body_dhcp_diagnosis = """【本模块用途】
  • **本机 DHCP 客户端诊断**：解析 **ipconfig /all**、DHCP 客户端事件日志，检查 APIPA、租约、网关/DNS、DHCP 服务器可达性等。
  • **多 DHCP 服务器探测（DHCP 污染）**：在勾选授权后，通过 **Nmap broadcast-dhcp-discover** 发送 **DHCP DISCOVER**，
    汇总 OFFER 中的 **Server Identifier**；若同一网段出现 **≥2 个不同 Server ID**，提示 **疑似 DHCP 污染**。
  • 详见设计文档 [`docs/dhcp-diagnosis-design.md`](../docs/dhcp-diagnosis-design.md)。

══════════════════════════════════════
一、参数说明
══════════════════════════════════════

  • **绑定接口**：诊断与探测使用的本机 IPv4 网卡（须在本机所在网段）。
  • **合法 DHCP**：白名单 Server ID（逗号分隔）；不在名单的服务器标为未知/非法。
  • **作用域 CIDR**：可选；用于检测本机 **静态 IP** 是否落在 DHCP 池内。
  • **探测轮次**：默认 3 轮，间隔约 1.5 s，降低误报。
  • **Nmap**：主动探测依赖 **nmap.exe**（PATH / Program Files / ThirdParty/Nmap）。

══════════════════════════════════════
二、结论优先级
══════════════════════════════════════

  1. **疑似 DHCP 污染**（多 Server ID，且非热备白名单场景）
  2. **未知 DHCP 服务器**（仅 1 个响应但不在白名单）
  3. **本机 APIPA / 租约 / 服务器不可达**
  4. **未收到 OFFER**（可能无服务、跨 VLAN 或需管理员运行 Nmap）

══════════════════════════════════════
三、与其它模块
══════════════════════════════════════

  • **子网计算** → 确认网段与 CIDR → **DHCP 诊断**
  • 疑似污染 → **MAC 扫描** 定位非法 Server IP → **交换机配置** 查端口
  • DHCP 服务器不可达 → **网络诊断** Ping 探测

══════════════════════════════════════
四、合规
══════════════════════════════════════

  • 主动 DHCP DISCOVER 可能被安全设备记录；须勾选 **授权确认** 后方可探测。
  • 本工具 **不** 伪造 DHCP ACK、不抢占租约。"""

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
  • 切换引擎时，界面提示会说明各引擎填写规则。
  • **MySQL / PostgreSQL / SQL Server**：填写主机、端口、用户名与密码后，点击「库名」旁的刷新图标（悬停提示「刷新库列表」）可枚举实例上的库名并在下拉中选择（「库名」框仍可手动输入）。
  • Oracle、SQLite 不适用库名枚举：Oracle 填 Service Name；SQLite 填数据库文件路径。
  • 连接参数错误、驱动缺失或网络不可达时，报告与弹窗会给出失败原因摘要。

三、诊断与产物
  • 「运行诊断（生成 Markdown）」：后台连接并采集元数据与健康信息，在 reports/db_diagnosis/<任务ID>/ 下写入 Markdown
    等文件。
  • 「打开报告目录」打开 reports/db_diagnosis；「诊断报告」「监控报告」分别打开最近一次对应 Markdown。
  • 报告内容侧重技术人员阅读：版本、会话、对象列表等以实际引擎与权限为准；无权限项会标注跳过。

四、监控
  • 「开始监控 / 停止监控」按钮切换周期性快照轮询（间隔由「间隔(秒)」设定）。
  • **停止监控后**会自动将本轮成功采样整理为 Markdown，写入 **reports/db_diagnosis/<任务ID>/**；
    实时监控区末尾会提示文件路径，可用「监控报告」或「打开报告目录」取回。
  • 若本轮没有任何成功采样（例如连接始终失败），则不会生成 Markdown 文件。
  • 监控会持续占用连接，请在业务低峰或测试库上使用；长时间轮询注意对库侧负载的影响。

五、安全与边界
  • 请使用只读或专用诊断账号；勿在生产库上使用高权限账户做试验。
  • 本模块为连通性与轻量信息采集，非 SQL 性能压测或审计替代方案。"""

        body_security = """一、定位与合规
  • 面向企业网管在 **授权范围内** 的轻量基线核对：本机多数操作为只读摘要；
    **临时文件清理**会在您确认后删除文件，请先 **预览** 再执行。
  • 对 URL 的 TLS/响应头、DNS 对比与 **TCP 端口扫描**须在勾选「我已确认对目标的测试已获得有效授权」后方可执行。
  • 详细设计与字段说明见仓库 **docs/network-security-diagnosis-design.md**。

二、界面布局
  • **左右两列**：左侧为全部操作区；右侧 **输出结果** 使用 Markdown 渲染（粗体、行内代码、表格等），
    导出与清空在输出区上方。
  • 顶部 **警告** 分组为必读提示（同样支持 Markdown 样式）。
  • **任务状态** 位于 **TCP 端口扫描** 区块下方：就绪时显示文案摘要；
    后台任务运行中会显示 **滚动不定进度条**（与「网络诊断」任务状态类似）。
    上一项任务未完成时不应重复发起。

三、本机
  • 「刷新 TCP 监听端口」：Windows 下通过 PowerShell 枚举 TCP 监听、绑定地址与进程名（依赖 Get-NetTCPConnection 等）。
  • 「刷新防火墙摘要」：各配置文件启用状态与入站「允许」规则抽样；
    精细策略请使用「高级安全 Windows 防火墙」(wf.msc)。
  • 「刷新 CPU / GPU」「刷新内存」「刷新本地用户与密码策略」：型号与利用率、内存条、账户与密码策略等摘要
    （依赖 WMI/CIM；独显显存等字段可能不完整）。
  • 「临时文件：预览可清理空间」「临时文件：执行清理（用户 TEMP）」：针对当前用户 TEMP、LOCALAPPDATA\\Temp 等；
    **不含** Windows\\Temp；执行清理前须二次确认。

四、授权目标（HTTPS / DNS）
  • 填写 **HTTPS URL**、**对比 DNS**，勾选授权后可执行「检查 TLS 与安全响应头」「DNS 对比」。
  • TLS 检查 **不是**漏洞扫描或渗透工具；DNS 对比用于查看系统解析与指定 DNS 的差异。

五、TCP 端口扫描与 Nmap 路径
  • **单主机**、**仅 IPv4**；「扫描目标」默认示例为 **127.0.0.1**。默认 **Python socket** 连接探测。
    支持端口预设或自定义列表（含区间）、同一行内的 **并发**、**超时(s)**；可选 **抓取 Banner**；
    可选 **使用 nmap（-sT）** 改为由 Nmap 做 TCP 连接扫描。
  • **程序查找 `nmap.exe` 的顺序（Windows）**：① 系统 **PATH** 中的 `nmap` / `nmap.exe`；
    ② **`%ProgramFiles%\\Nmap\\nmap.exe`**；③ **`%ProgramFiles(x86)%\\Nmap\\nmap.exe`**；
    ④ 仓库根目录（与 `ThirdParty` 同级）下的 **`ThirdParty\\Nmap\\nmap.exe`**（便携放置）。
    打包发行的程序以实际解压/附带目录为准，原则相同。
  • **手动路径**：在「nmap 路径」中填写 `nmap.exe` 的完整路径（使用 Nmap 后端时优先采用您填写且存在的文件）。
  • **安装 Nmap**：将官方 Windows **安装包 `.exe`** 保存到 **`ThirdParty\\Nmap\\`** 后，点「安装 Nmap」会启动该目录下
    **最新** 的安装程序；也可自行安装到默认目录（通常会出现在上述 **Program Files\\Nmap** 并被自动探测）。
    官方下载：https://nmap.org/download.html
  • 「检测 Nmap」：按上述顺序查找并自动填入路径。
  • 按钮顺序：**检测 Nmap** → **安装 Nmap** → **执行 TCP 端口扫描**（扫描须已勾选授权）。
  • 扫描可能被对端记录；规格见设计文档 §3.4.1。

六、导出
  • 「导出当前结果为 Markdown…」将输出区已累积内容写入 **reports/security_diagnosis/**（开发模式在仓库下 `reports/`；
    打包后在可执行文件旁的 `reports/`）。"""

        body_arp_intranet = """【本模块用途】
  • **ARP 安全**：在本机 **Windows** 上周期性读取 **`arp -a`**，
    对比 **默认网关** 在 ARP 表中的 **MAC** 是否与点击 **「● 开始」** 监视后 **首次成功** 读到的观测一致；若发生变化则提示 **疑似网关 ARP 欺骗**，
    并在中部 **设备定位建议** 中给出交换机侧排查思路（命令示例为通用占位，厂商 CLI 请自行替换）。
  • **Syslog 联动**：当前版本 **未** 接入 Syslog 外发；后续可扩展告警上报。

══════════════════════════════════════
一、界面分区
══════════════════════════════════════

  • **顶部**：单行展示 **本机 IP**、**网关**、**网段**、**设备数**、**异常 IP 数**；无分组标题。
    外框采用 **ttkbootstrap 当前主题的主色** 作为描边（加粗描边），与界面其它控件同源配色。
  • **中部**：三栏 **等宽（1:1:1）**，标题均在各自 **LabelFrame** 的 **左上角**。三栏内部均为 **只读文本区域（Text）**，视觉一致：
    - **实时日志**：等宽字体追加时间戳与轮询结果；异常行前有醒目标记。
    - **异常设备详情**：分段展示异常类型、IP、基线/观测 MAC、首次发现、风险等。
      文末 **状态条幅** 使用主题语义色：**正常**（如「当前网关 MAC 与基线一致」）为 **success** 底色；
      **告警说明**（高危文案）为 **danger** 底色（前景色自动按对比度选取）。
    - **设备定位建议**：监视开始前为默认说明；监视启动且具备网关信息后，可自动填入 **网关 IP / 观测 MAC** 相关示例命令。
  • **底部**：同一行左侧为 **状态** 文案，右侧为 **开始 / 停止合一按钮**（未监视为「● 开始」，监视中为「■ 停止」）以及 **↻ 重启**。

══════════════════════════════════════
二、操作与行为说明
══════════════════════════════════════

  • **切换离开本页**（左侧导航点到其它模块）会自动 **停止监视**，避免后台持续拉起子进程。
  • **重启**：等价于停止后再开始，并 **清空基线**；网关 MAC 将重新以 **本条会话内首次成功读数** 为准。
  • **轮询**：约每 **2.5 秒** 读取一次适配器信息与 **`arp -a`**；日志过长时会丢弃 **较早段落** 以控制占用。

══════════════════════════════════════
三、数据来源与局限
══════════════════════════════════════

  • **本机 IP / 网关 / 掩码**：来自 **WMI/CIM**（与「子网计算」页右侧同源）；取 **第一条带默认网关** 的 IPv4 配置。
  • **ARP 表**：子进程执行 **`arp -a`** 并解析；若网关尚未出现在表中（尚未通信），日志会提示。
  • **基线 MAC**：每次 **开始** 或 **重启** 后，**第一次** 成功读到网关 MAC 即记为基线；之后不一致则告警。
  • **设备数**：当前网段内在 ARP 表中出现过的 IPv4 数量（粗略统计，不等价于全网终端普查）。
  • **非 Windows**：可能无法可靠解析，开始监视时会提示；建议在 Windows 桌面运维场景使用。

══════════════════════════════════════
四、合规与注意
══════════════════════════════════════

  • 仅在对网络 **有管理授权** 的环境中用于自检与排障；本工具 **不作** 远程 MITM 验证。
  • MAC 变化也可能来自 **网关冗余切换、网卡更换、ARP 缓存刷新策略** 等；告警后请结合交换机侧真实网关 MAC 复核。"""

        body_ai_assistant = """【本模块用途】
  • 通过与大模型对话，用自然语言驱动本工作台能力：例如「帮我诊断 www.example.com 的网络」、
    「计算 10.0.0.5/24 子网」等；助手会调用内置 **网络诊断**、**子网计算**、**数据库诊断** 等工具，
    执行后根据结果用中文解读并给出建议。
  • 支持 **OpenAI 兼容** 的 API（OpenAI、DeepSeek、通义千问、Ollama 等）：在页顶配置 **API Base**、
    **API Key**、**模型** 后保存；可用「测试连接」验证。

══════════════════════════════════════
一、配置说明
══════════════════════════════════════

  • **API Base**：服务根地址，例如 https://api.openai.com/v1 ；若服务商给出完整
    /chat/completions 地址也可直接填写。
  • **API Key**：由服务商控制台获取；保存在本机 config/ai_assistant.json，请勿在不可信环境泄露。
  • **模型**：与服务商文档一致，例如 gpt-4o-mini、deepseek-chat 等。

══════════════════════════════════════
二、对话与工具
══════════════════════════════════════

  • 输入框：**Enter** 发送，**Ctrl+Enter** 换行；也可点 **发送**。
  • 模型回复以 **流式** 逐字显示；执行网络诊断等工具时状态栏会提示进度。
  • **Skills**：在项目根目录 ``skills/`` 下添加 ``<名称>/SKILL.md``（或根目录 ``*.md``），
    含 YAML 头 ``name`` / ``description`` 与正文约束；每条用户消息前会自动扫描并注入系统提示。
  • 助手可自动 **切换左侧功能页**（navigate_module），便于你在图形界面查看详细报告。
  • 数据库诊断等需提供连接信息的操作，请在对话中明确给出主机、库名、账号等，并仅在授权环境使用。

══════════════════════════════════════
三、合规
══════════════════════════════════════

  • 发往大模型的内容可能包含诊断摘要；请勿将敏感凭据或未经授权的扫描结果用于公网不可信模型。
  • 安全诊断、端口扫描等仍须遵守本单位授权策略；AI 仅作辅助解读，不替代人工判断。"""

        add_guide_tab("AI助手", body_ai_assistant)
        add_guide_tab("网络诊断", body_network)
        add_guide_tab("子网计算", body_subnet)
        add_guide_tab("IP扫描", body_ip_scan)
        add_guide_tab("MAC扫描", body_mac_scan)
        add_guide_tab("DHCP诊断", body_dhcp_diagnosis)
        add_guide_tab("交换机配置", body_switch)
        add_guide_tab("数据库诊断", body_database)
        add_guide_tab("ARP安全", body_arp_intranet)
        add_guide_tab("安全诊断", body_security)

        body_code_sign = """【本模块用途】
  • 在本机 **Windows** 上调用 **signtool.exe**，使用 **PFX**（含私钥）对 **.exe / .dll** 等 PE 文件执行 **Authenticode** 签名。
  • 支持 **CA / 机构颁发的证书** 导出的 PFX，以及本页 **一键生成自签名代码签名证书**（导出 **PFX + CER**）。

══════════════════════════════════════
一、环境与前置条件
══════════════════════════════════════

  • **操作系统**：Windows；需安装 **Windows SDK**（含签名工具）或已将 **signtool.exe** 加入 **PATH**。页面顶部会显示探测结果。
  • **PFX 密码**：请在安全环境中输入；本界面 **不会** 将证书写入仓库文档。
  • **时间戳**：勾选「附加 RFC3161 时间戳」时需能访问所填 **时间戳 URL**（默认示例为公共 TSA）；纯内网离线构建可取消勾选。

══════════════════════════════════════
二、CA 证书签名（简要）
══════════════════════════════════════

  1. 在「证书」栏 **浏览** 选择厂商提供的 **.pfx / .p12**。  
  2. 填写 **PFX 密码**。  
  3. 「待签名文件」选择目标 **exe**（或 dll）。  
  4. 按需配置时间戳后点击 **执行签名**；完成后可用 **验证签名** 查看 ``signtool verify`` 输出。

══════════════════════════════════════
三、自签名证书（一键生成）
══════════════════════════════════════

  1. 点击 **一键生成自签名证书**，选择保存目录、设置密码与 **Subject**（默认 ``CN=…`` 可按组织修改）。  
  2. 成功后得到 **`codesign-selfsigned.pfx`** 与 **`codesign-selfsigned-public.cer`**；PFX 路径会自动填入签名表单。  
  3. **信任下发**：仅在贵司可控终端上，将 **CER** 导入 **受信任的根证书颁发机构**（或通过 GPO），详见仓库 **`docs/windows-code-signing-automation.md`** **§8**。  
  4. 自签名 **不会** 自动获得与商业 OV/EV 相同的公网 SmartScreen 体验。

══════════════════════════════════════
四、与发版文档的关系
══════════════════════════════════════

  • GitHub Release、校验文件与 manifest 约定见 **`docs/version-update-github.md`**。  
  • 签名命令参数说明、无时间戳场景见 **`docs/windows-code-signing-automation.md`**。

══════════════════════════════════════
五、合规与安全
══════════════════════════════════════

  • **PFX 泄露** 等同私钥泄露，务必限制拷贝范围并及时轮换。  
  • 仅为 **有权处理的二进制** 签名；勿替第三方或未授权软件代签。"""

        add_guide_tab("数字签名", body_code_sign)

        body_ssl_cert = """【本模块用途】
  • **Let's Encrypt**：通过 **DNS-01** 向 Let's Encrypt 申请/续期浏览器信任的 DV 证书；由 **阿里云 DNS** 或 **腾讯云 DNSPod** API 自动写入/清理 `_acme-challenge` TXT。
  • **私有证书**：使用 **cryptography** 在本机生成 **根 CA + 站点证书**，支持 **域名与 IP** 的 SAN，用于内网或开发 HTTPS；可导出 **PFX** 便于 IIS 导入。

══════════════════════════════════════
一、公有证书（Let's Encrypt）
══════════════════════════════════════

  • **前置**：域名 DNS **托管**在对应云平台；API 密钥仅为 **解析管理** 所需最小权限的子账号密钥。
  • **单域名 / 多域名 / 泛域名**：可同时填写多个主机名。**泛域名**（如 ``*.example.com``）Let's Encrypt **可以签发**，但必须走 **DNS-01**（本模块即采用 DNS-01）；历史上 **HTTP-01** 无法用于泛域名，容易误以为 LE「不支持泛域名」。
  • **输出**：默认在用户目录下 `qqhu-letsencrypt`，写入 **privkey.pem**、**fullchain.pem**、**cert.pem**，以及 **letsencrypt-account.pem**（账户密钥，续期务必沿用）。
  • **Staging**：勾选后为 Let's Encrypt **测试目录**，浏览器不信任；排障后可关闭改用 **正式目录**。
  • **部署**：工具 **不负责** Web 服务器绑定与 reload；请将 PEM 配置到 IIS/Nginx 等后自行加载。
  • **续期**：保留同一「账户密钥」与域名列表，再次点击「申请 / 续期」即可覆盖写入证书文件。

══════════════════════════════════════
二、私有证书
══════════════════════════════════════

  • **有效期**：根 CA 与站点证书均为 **10 年（3650 天）**，界面不提供修改。
  • **信任**：客户端需导入生成的 **private-ca.crt.pem** 至「受信任的根证书颁发机构」。
  • **SAN**：务必包含浏览器访问时使用的主机名或 IP。
  • **PFX**：可选密码导出 **private-site.pfx**。
  • **各文件怎么用**：服务端一般为 ``private-site.fullchain.pem``（证书链）+ ``private-site.key.pem``（私钥），例如 Nginx 的 ``ssl_certificate`` / ``ssl_certificate_key``；IIS 导入 ``private-site.pfx``。客户端只需信任 **private-ca.crt.pem**（导入「受信任的根证书颁发机构」）。**private-ca.key.pem** 勿拷贝到对外 Web 服务器。

══════════════════════════════════════
三、合规与安全
══════════════════════════════════════

  • **密钥泄露**：阿里云/腾讯云密钥与 ACME 账户私钥视同高敏，勿提交仓库或截图外发。"""

        add_guide_tab("SSL证书", body_ssl_cert)
        fix_primary_notebook_selected_tab_colors(nb)

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
        title_row = ttk.Frame(frm)
        title_row.grid(row=1, column=0, sticky=EW, pady=(6, 2))
        title_row.columnconfigure(1, weight=1)
        ttk.Label(
            title_row,
            text=APP_DISPLAY_NAME,
            font=("Microsoft YaHei UI", 22, "bold"),
        ).grid(row=0, column=0, sticky=W)
        self._about_update_btn = ttk.Button(
            title_row,
            text="检查更新",
            bootstyle=SECONDARY,
            command=self._on_manual_update_check,
            width=12,
        )
        self._about_update_btn.grid(row=0, column=2, sticky=E)
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
            ).grid(row=r, column=0, sticky=W, padx=(0, 12), pady=(0, 8))
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
        ).grid(row=2, column=0, sticky=W, padx=(0, 12), pady=(0, 8))
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
        ).grid(row=3, column=0, sticky=W, padx=(0, 12), pady=(0, 8))
        community_lbl = tk.Label(
            lf_ver,
            text=COMMUNITY_DISPLAY,
            font=("Microsoft YaHei UI", 11, "underline"),
            fg="#0b5ed7",
            cursor="hand2",
        )
        community_lbl.grid(row=3, column=1, sticky=W, pady=(0, 8))
        community_lbl.bind("<Button-1>", lambda _e: webbrowser.open(COMMUNITY_URL))

        def repo_link_row(r: int, key: str, display: str, url: str) -> None:
            ttk.Label(
                lf_ver,
                text=key,
                bootstyle=SECONDARY,
                font=("Microsoft YaHei UI", 11),
            ).grid(row=r, column=0, sticky=W, padx=(0, 12), pady=(0, 8))
            lbl = tk.Label(
                lf_ver,
                text=display,
                font=("Microsoft YaHei UI", 11, "underline"),
                fg="#0b5ed7",
                cursor="hand2",
            )
            lbl.grid(row=r, column=1, sticky=W, pady=(0, 8))
            lbl.bind("<Button-1>", lambda _e, u=url: webbrowser.open(u))

        repo_link_row(4, "GitCode", GITCODE_REPO_DISPLAY, GITCODE_REPO_URL)
        repo_link_row(5, "Gitee", GITEE_REPO_DISPLAY, GITEE_REPO_URL)
        repo_link_row(6, "GitHub", GITHUB_REPO_DISPLAY, GITHUB_REPO_URL)

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
        lf_contact.columnconfigure(1, weight=1)

        meta_pair(lf_contact, 0, "作者", AUTHOR_NAME)

        ttk.Label(
            lf_contact,
            text="电子邮箱",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 11),
        ).grid(row=1, column=0, sticky=W, padx=(0, 12), pady=(0, 8))
        email_lbl = tk.Label(
            lf_contact,
            text=AUTHOR_EMAIL,
            font=("Microsoft YaHei UI", 11, "underline"),
            fg="#0b5ed7",
            cursor="hand2",
        )
        email_lbl.grid(row=1, column=1, sticky=W, pady=(0, 8))
        email_lbl.bind("<Button-1>", lambda _e: webbrowser.open(f"mailto:{AUTHOR_EMAIL}"))

        meta_pair(lf_contact, 2, "QQ", AUTHOR_QQ_DISPLAY)
        meta_pair(lf_contact, 3, "QQ群", AUTHOR_QQ_GROUP_DISPLAY)

    def _build_license_view(self) -> None:
        frm = ttk.Frame(self._content_host, padding=(20, 20, 20, 16))
        self._view_frames["license"] = frm
        frm.columnconfigure(0, weight=1)

        intro = "上栏为本项目 MIT 许可证原文；若以可执行包分发，请一并附带。"
        ttk.Label(
            frm,
            text=intro,
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 11),
            wraplength=0,
            justify=tk.LEFT,
        ).grid(row=0, column=0, sticky=EW, pady=(0, 10))

        lf = ttk.Labelframe(frm, text="LICENSE（MIT）", padding=(10, 8, 10, 10))
        lf.grid(row=1, column=0, sticky=EW, pady=(0, 14))
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
            height=11,
            wrap=tk.WORD,
            font=("Consolas", 10),
            relief=tk.FLAT,
            padx=10,
            pady=10,
        )
        txt.grid(row=0, column=0, sticky=EW)
        txt.insert(tk.END, body)
        txt.configure(state=tk.DISABLED)

        lf2 = ttk.Labelframe(frm, text="第三方组件与外部工具", padding=(12, 10))
        lf2.grid(row=2, column=0, sticky=EW)
        third_party = (
            "• ttkbootstrap（GUI）：MIT，https://github.com/israel-dryer/ttkbootstrap\n"
            "• 所有依赖均为开源可商用; \n"
            "• 可选 Wireshark/tshark、iperf3、Nmap 为开源工具，tcping为免费工具, 遵守各自许可证即可（含商用）。\n"
            "• 外部工具仅按需调用，与其项目方无隶属或担保关系。"
        )
        ttk.Label(
            lf2,
            text=third_party,
            font=("Microsoft YaHei UI", 11),
            justify=tk.LEFT,
            wraplength=0,
        ).pack(fill=tk.X)
