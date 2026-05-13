"""ttkbootstrap 主界面：工作线程 + 队列回灌。"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
from pathlib import Path
from urllib.parse import urlparse

import tkinter as tk
import tkinter.font as tkfont
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText

import ttkbootstrap as ttk
from ttkbootstrap.constants import (
    BOTH,
    DANGER,
    END,
    EW,
    INFO,
    NSEW,
    OUTLINE,
    PRIMARY,
    SECONDARY,
    SUCCESS,
    WARNING,
    W,
)

from network_diagnosis.model.report import DiagnosticReport, PortFailureClass
from network_diagnosis.paths import (
    bundle_root,
    find_tshark,
    iter_wireshark_installers,
    resolve_iperf3_exe,
    resolve_tcping_exe,
)
from network_diagnosis.probes.dns_probe import pick_tcp_target
from network_diagnosis.runner import RunOptions, run_diagnostic


def _resolve_window_icon_path() -> Path | None:
    """任务栏/标题栏图标：`network_diagnosis/images/qingqiu.ico`（与 `gui` 包同级目录 `images`）。"""
    pkg_root = Path(__file__).resolve().parent.parent
    candidates: list[Path] = [
        pkg_root / "images" / "qingqiu.ico",
    ]
    root = bundle_root()
    candidates.append(root / "network_diagnosis" / "images" / "qingqiu.ico")
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        candidates.extend(
            [
                exe_dir / "network_diagnosis" / "images" / "qingqiu.ico",
                exe_dir / "qingqiu.ico",
            ]
        )
    candidates.append(root / "qingqiu.ico")
    for p in candidates:
        if p.is_file():
            return p
    return None


def _try_set_window_icon(win: tk.Misc) -> None:
    path = _resolve_window_icon_path()
    if path is None:
        return
    try:
        win.iconbitmap(str(path))
    except tk.TclError:
        pass


def _parse_ports(text: str) -> list[int]:
    """
    解析端口列表，支持英文逗号分隔。
    例如：80,443,8080
    返回排序后的端口列表。
    """
    out: list[int] = []
    for part in text.replace(";", ",").split(","):
        p = part.strip()
        if not p:
            continue
        out.append(int(p))
    return sorted(set(out))


_PORT_CLASS_CN: dict[PortFailureClass, str] = {
    PortFailureClass.OK: "连接正常",
    PortFailureClass.TIMEOUT: "超时",
    PortFailureClass.REFUSED: "连接被拒绝",
    PortFailureClass.UNREACHABLE: "不可达或重置",
    PortFailureClass.ERROR: "探测异常",
    PortFailureClass.UNKNOWN: "结果不明确",
}


def _quality_tag_for_grade(grade: str) -> str:
    return {
        "极佳": "quality_grade_exc",
        "正常": "quality_grade_ok",
        "较差": "quality_grade_poor",
        "堵塞": "quality_grade_bad",
    }.get(grade, "quality_grade_ok")


def _gui_oneline_network_quality(rep: DiagnosticReport) -> str:
    nq = rep.network_quality
    parts: list[str] = []
    if nq.loss_pct is not None:
        parts.append(f"丢包约 {nq.loss_pct:.1f}%")
    if nq.avg_latency_ms is not None:
        parts.append(f"平均时延约 {nq.avg_latency_ms:.0f} ms")
    if nq.jitter_ms is not None:
        parts.append(f"抖动约 {nq.jitter_ms:.1f} ms")
    if parts:
        return "，".join(parts) + "。详情见下方「网络质量与指标」。"
    return "详见下方「网络质量与指标」。"


def _gui_oneline_dns(rep: DiagnosticReport) -> str:
    dns = rep.dns
    if dns.error:
        tail = dns.error if len(dns.error) <= 100 else dns.error[:97] + "…"
        return f"失败：{tail}"
    if not dns.addresses:
        return "未得到可用地址。"
    first = dns.addresses[0]
    more = f" 等共 {len(dns.addresses)} 个" if len(dns.addresses) > 1 else ""
    return f"成功，记录族别 {dns.family}，例：{first}{more}。"


def _gui_oneline_ping(rep: DiagnosticReport) -> str:
    if not rep.user_input.enable_ping:
        return "未启用 ICMP Ping。"
    p = rep.ping
    if p is None:
        return "无 Ping 统计数据。"
    if p.attempted <= 0:
        return "未发起 Ping。"
    if p.received == 0:
        return f"无成功回复（已试 {p.attempted} 次，丢失 {p.lost}）。"
    loss = 100.0 * p.lost / p.attempted
    if p.rtts_ms:
        avg = sum(p.rtts_ms) / len(p.rtts_ms)
        return f"收到 {p.received}/{p.attempted}，丢包约 {loss:.0f}%，平均延迟约 {avg:.0f} ms。"
    return f"收到 {p.received}/{p.attempted}，丢包约 {loss:.0f}%。"


def _gui_oneline_traceroute(rep: DiagnosticReport) -> str:
    if not rep.user_input.enable_traceroute:
        return "未启用路由追踪。"
    tr = rep.traceroute
    if tr is None:
        return "无路由追踪输出。"
    lines = [ln for ln in (tr.outline or "").splitlines() if ln.strip()]
    return lines[0] if lines else "已完成，详见下方「路由追踪」。"


def _gui_oneline_ports(rep: DiagnosticReport) -> str:
    ui = rep.user_input
    if not ui.ports:
        return "未填写端口，未做 TCP 连通性测试。"
    if any(d.code == "tcping_missing" for d in rep.degradations):
        return "已填端口，但缺少 tcping.exe，无法探测。"
    if not rep.ports:
        return "未得到端口探测结果。"
    bad = [p for p in rep.ports if p.failure_class != PortFailureClass.OK]
    if not bad:
        return f"所测 {len(rep.ports)} 个端口均可建立连接。"
    return (
        f"{len(bad)}/{len(rep.ports)} 个端口异常（"
        + "、".join(str(p.port) for p in bad)
        + "）。"
    )


def _gui_lines_network_quality(rep: DiagnosticReport) -> list[str]:
    """明细：仅指标行（整体结论中已含评判档位）。"""
    return list(rep.network_quality.metric_lines)


def _gui_lines_dns(rep: DiagnosticReport) -> list[str]:
    ui = rep.user_input
    dns = rep.dns
    fam_cn = {"ipv4": "IPv4", "ipv6": "IPv6", "mixed": "IPv4 / IPv6 混合"}.get(
        dns.family, dns.family
    )
    lines: list[str] = [
        f"目标主机名：{ui.target_host}",
        f"记录族别：{fam_cn}",
        f"优先 IPv6：{'是' if ui.prefer_ipv6 else '否'}",
        f"解析耗时：{dns.elapsed_ms:.1f} ms",
    ]

    def append_specified() -> None:
        opt_srv = (ui.optional_dns_server or "").strip()
        if not opt_srv or rep.dns_specified is None:
            return
        ds = rep.dns_specified
        fam2 = {"ipv4": "IPv4", "ipv6": "IPv6", "mixed": "IPv4 / IPv6 混合"}.get(
            ds.family, ds.family
        )
        lines.append("")
        lines.append(f"指定 DNS（{opt_srv}）解析：")
        lines.append(f"  记录族别：{fam2}，耗时 {ds.elapsed_ms:.1f} ms")
        if ds.error:
            lines.append(f"  失败：{ds.error}")
        elif ds.addresses:
            lines.append("  地址：" + "、".join(ds.addresses))
        else:
            lines.append("  未得到地址。")

    if dns.error:
        lines.append(f"解析失败：{dns.error}")
        append_specified()
        return lines
    if not dns.addresses:
        lines.append("未得到任何解析地址。")
        append_specified()
        return lines
    lines.append("解析到的地址：" + "、".join(dns.addresses))
    tcp_t = pick_tcp_target(dns, prefer_ipv6=ui.prefer_ipv6)
    if tcp_t:
        lines.append(f"本次 TCP / 抓包使用的 IP：{tcp_t}")
    append_specified()
    return lines


def _gui_lines_ping(rep: DiagnosticReport) -> list[str]:
    if not rep.user_input.enable_ping:
        return [
            "本轮未启用 ICMP Ping。",
            "如需测试，请在左侧「探测选项」中勾选「ICMP Ping」。",
        ]
    p = rep.ping
    if p is None:
        return ["未获取到 Ping 统计数据。"]
    ui = rep.user_input
    mode = (
        f"（长 Ping：最长约 {ui.long_ping_seconds} 秒，由程序结束后统计）"
        if ui.ping_long
        else f"（固定次数：{ui.ping_count} 次）"
    )
    lines = [
        f"探测统计：已发送 {p.attempted}，收到 {p.received}，丢失 {p.lost}。{mode}",
    ]
    if p.rtts_ms:
        avg = sum(p.rtts_ms) / len(p.rtts_ms)
        mn = min(p.rtts_ms)
        mx = max(p.rtts_ms)
        lines.append(f"延迟：平均 {avg:.1f} ms，最小 {mn:.1f} ms，最大 {mx:.1f} ms。")
    elif p.received > 0:
        lines.append("延迟：成功样本中未能解析 RTT 数值。")
    if p.attempted and p.received == 0:
        lines.append(
            "说明：无 ICMP 回复时，常见于对端禁 ping 或防火墙策略，不代表 TCP 端口一定不通。"
        )
    return lines


def _gui_lines_traceroute(rep: DiagnosticReport) -> list[str]:
    ui = rep.user_input
    if not ui.enable_traceroute:
        return [
            "本轮未启用路由追踪。",
            "可在「探测选项」中勾选「路由追踪」，将调用 Windows tracert（或 Linux/macOS 的 traceroute）。",
        ]
    tr = rep.traceroute
    if tr is None:
        return ["未获取到路由追踪输出。"]
    out = list((tr.outline or "").splitlines())
    if tr.command:
        out.insert(0, f"命令：{' '.join(tr.command)}")
    if tr.returncode is not None:
        out.append(f"退出码：{tr.returncode}")
    out.append(f"原始 stdout：{tr.raw_stdout_path.resolve()}")
    return out


def _gui_lines_ports(rep: DiagnosticReport) -> list[str]:
    ui = rep.user_input
    degrad_tcping = any(d.code == "tcping_missing" for d in rep.degradations)
    if not ui.ports:
        return ["未填写 TCP 端口，已跳过端口连通性探测。"]
    if not rep.ports:
        if degrad_tcping:
            return [
                "已填写端口，但未找到 tcping.exe，无法执行探测。",
                "请将 tcping.exe 置于 ThirdParty/tcping/ 后重试。",
            ]
        return ["未能得到端口探测结果。"]
    lines: list[str] = []
    for pr in rep.ports:
        ok_n = sum(1 for s in pr.samples if s.success)
        tot = max(len(pr.samples), 1)
        rtts = [s.rtt_ms for s in pr.samples if s.success and s.rtt_ms is not None]
        verdict = _PORT_CLASS_CN.get(pr.failure_class, pr.failure_class.value)
        if pr.failure_class == PortFailureClass.OK:
            detail = f"{ok_n}/{tot} 次成功"
            if rtts:
                detail += f"，平均延迟 {sum(rtts) / len(rtts):.1f} ms"
            lines.append(f"端口 {pr.port}：{verdict}（{detail}）。目标 {pr.target_used}")
        else:
            lines.append(
                f"端口 {pr.port}：{verdict}（成功 {ok_n}/{tot}）。目标 {pr.target_used}"
            )
    return lines


def _gui_lines_capture(rep: DiagnosticReport) -> list[str]:
    ui = rep.user_input
    c = rep.capture
    if not ui.enable_capture:
        return [
            "本轮未启用抓包。",
            "如需抓包，请勾选「抓包」，并确保本机已安装 Wireshark/tshark 与 Npcap。",
        ]
    if c.ran and c.pcap_path is not None:
        lines = [
            "抓包已完成。",
            f"文件：{c.pcap_path}",
        ]
        if c.notes:
            lines.append(c.notes)
        if c.analysis_summary:
            lines.append("")
            lines.append("（以下为抓包内容的通俗解读，由程序根据统计自动生成）")
            lines.extend(c.analysis_summary.splitlines())
        return lines
    lines: list[str] = ["本次未能完成抓包。"]
    if c.notes:
        lines.append(c.notes)
    for d in rep.degradations:
        if d.code in ("capture_unavailable", "tshark_start_failed") and d.detail:
            lines.append(f"补充说明：{d.detail}")
            break
    return lines


def _gui_lines_bandwidth(rep: DiagnosticReport) -> list[str]:
    ui = rep.user_input
    b = rep.bandwidth
    if ui.bandwidth_mode == "off":
        return [
            "本轮未启用带宽/吞吐抽样。",
            "需要时请在左侧选择「HTTP 抽样下载」或「iperf3」（二选一）。",
        ]
    if b is None:
        return ["未得到带宽抽样结果。"]
    lines = [b.summary]
    if b.megabits_per_second is not None:
        lines.append(f"估算平均速率：约 {b.megabits_per_second:.1f} Mbps")
    if b.bytes_total is not None:
        lines.append(f"传输字节（如适用）：{b.bytes_total}")
    if b.parallel_streams is not None:
        lines.append(f"HTTP 并发连接数：{b.parallel_streams}")
    if b.log_stdout_path:
        lines.append(f"详细日志：{b.log_stdout_path}")
    if not b.ok and b.error:
        lines.append(f"错误：{b.error}")
    return lines


def _any_advanced(rep: DiagnosticReport) -> bool:
    ui = rep.user_input
    return bool(
        (ui.optional_dns_server or "").strip()
        or ui.enable_pathping
        or ui.enable_tcp_traceroute
        or ui.enable_http_tls_probe
        or ui.enable_egress_probe
        or ui.enable_mtu_probe
        or ui.enable_history_compare
    )


def _gui_oneline_advanced(rep: DiagnosticReport) -> str:
    ui = rep.user_input
    bits: list[str] = []
    if (ui.optional_dns_server or "").strip():
        ds = rep.dns_specified
        if ds and not ds.error and ds.addresses:
            bits.append("指定 DNS 解析成功")
        elif ds and ds.error:
            bits.append("指定 DNS 解析失败")
        else:
            bits.append("已请求指定 DNS 对比")
    if ui.enable_pathping and rep.path_quality:
        bits.append("PathPing/mtr 已完成")
    elif ui.enable_pathping:
        bits.append("PathPing/mtr 无输出")
    if ui.enable_tcp_traceroute and rep.tcp_path:
        bits.append("TCP 路径探测已完成")
    elif ui.enable_tcp_traceroute:
        bits.append("TCP 路径探测无输出")
    if ui.enable_http_tls_probe and rep.http_tls:
        h = rep.http_tls
        if h.ok:
            bits.append("HTTPS/TLS 正常")
        else:
            bits.append("HTTPS/TLS 异常或未完整")
    elif ui.enable_http_tls_probe:
        bits.append("HTTPS/TLS 无结果")
    if ui.enable_egress_probe and rep.egress:
        e = rep.egress
        if e.public_ip:
            bits.append(f"出口公网 IP {e.public_ip}")
        else:
            bits.append("出口 IP 未取到")
    elif ui.enable_egress_probe:
        bits.append("出口探测无结果")
    if ui.enable_mtu_probe and rep.mtu:
        m = rep.mtu
        if m.implied_ipv4_mtu is not None:
            bits.append(f"估算 MTU {m.implied_ipv4_mtu}")
        else:
            bits.append("MTU 未估出或已跳过")
    elif ui.enable_mtu_probe:
        bits.append("MTU 无结果")
    if ui.enable_history_compare and rep.history_compare:
        hc = rep.history_compare
        if hc.compared and hc.previous_grade:
            bits.append(f"相对上次档位：{hc.previous_grade} → {rep.network_quality.grade}")
        elif hc.lines:
            bits.append("历史：首次或无更早记录")
    elif ui.enable_history_compare:
        bits.append("历史对比未生成")
    if not bits:
        return "未启用进阶项。"
    return "；".join(bits) + "。"


def _gui_lines_advanced(rep: DiagnosticReport) -> list[str]:
    ui = rep.user_input
    out: list[str] = []
    opt_srv = (ui.optional_dns_server or "").strip()
    if opt_srv:
        ds = rep.dns_specified
        out.append(f"指定 DNS：{opt_srv}")
        if ds is None:
            out.append("  （无独立解析结果）")
        elif ds.error:
            out.append(f"  错误：{ds.error}")
        else:
            out.append(f"  地址：{'、'.join(ds.addresses) if ds.addresses else '（无）'}，{ds.elapsed_ms:.1f} ms")
        out.append("")

    def _shell_block(title: str, sp, enabled: bool) -> None:
        if not enabled:
            return
        if sp is None:
            out.append(f"{title}：未得到结果。")
            out.append("")
            return
        out.append(f"{title}：{sp.summary}")
        out.append(f"  命令：{' '.join(sp.command) if sp.command else '—'}")
        out.append(f"  日志：{sp.raw_stdout_path.resolve()}")
        out.append("")

    _shell_block("路径质量（PathPing/mtr）", rep.path_quality, ui.enable_pathping)
    _shell_block("TCP 路径", rep.tcp_path, ui.enable_tcp_traceroute)

    if ui.enable_http_tls_probe:
        h = rep.http_tls
        if h is None:
            out.append("HTTPS/TLS：无结果。")
        else:
            out.append(f"HTTPS/TLS：URL {h.url}")
            if h.tls_handshake_ms is not None:
                out.append(f"  握手约 {h.tls_handshake_ms:.0f} ms")
            if h.http_status is not None:
                out.append(f"  HTTP 状态：{h.http_status}")
            out.append(f"  证书主体：{h.cert_subject or '—'}，有效期至 {h.cert_not_after or '—'}")
            if h.error:
                out.append(f"  错误：{h.error}")
        out.append("")

    if ui.enable_egress_probe:
        e = rep.egress
        if e is None:
            out.append("出口/代理：无结果。")
        else:
            out.append(f"出口公网 IPv4：{e.public_ip or '（未获取）'}")
            if e.ipify_error:
                out.append(f"  查询：{e.ipify_error}")
            proxy_bits = [
                ("HTTP_PROXY", e.http_proxy),
                ("HTTPS_PROXY", e.https_proxy),
                ("ALL_PROXY", e.all_proxy),
            ]
            for k, v in proxy_bits:
                if v:
                    out.append(f"  {k}={v}")
            if e.winhttp_note:
                out.append(f"  WinHTTP：{e.winhttp_note}")
        out.append("")

    if ui.enable_mtu_probe:
        m = rep.mtu
        if m is None:
            out.append("MTU：无结果。")
        else:
            out.append(f"MTU：{m.summary}")
            if m.implied_ipv4_mtu is not None:
                out.append(f"  推算 IPv4 MTU：{m.implied_ipv4_mtu}")
            if m.raw_log_path:
                out.append(f"  日志：{m.raw_log_path.resolve()}")
        out.append("")

    if ui.enable_history_compare:
        hc = rep.history_compare
        if hc is None:
            out.append("历史对比：未生成（已关闭或未写入）。")
        else:
            out.extend(hc.lines)
        out.append("")

    if not out:
        return ["本轮未启用进阶探测（未勾选进阶项且未填写指定 DNS）。"]
    return out


class NetworkDiagnosisApp(ttk.Window):
    """网络诊断工具主界面"""
    def __init__(self) -> None:
        # 主题
        super().__init__(themename="flatly")
        _try_set_window_icon(self)
        # 窗口标题
        self.title("网络诊断工具v1.0.0（作者：Mr. Z  联系方式：mr.zed@qq.com  QQ：40061980）")
        # 最小窗口大小
        self.minsize(1260, 720)
        # 默认窗口大小：每次启动在主屏居中（大于屏幕时先缩放到可放入再居中）
        self.geometry(self._centered_geometry(1800, 1200))

        self._queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._status_font_normal = ("Microsoft YaHei UI", 12)
        self._status_font_running = ("Microsoft YaHei UI", 16, "bold")

        for name in ("TkDefaultFont", "TkTextFont", "TkFixedFont", "TkMenuFont"):
            try:
                f = tkfont.nametofont(name)
                cur = f.actual()
                sz = cur.get("size", 10)
                try:
                    sz_i = int(sz)
                except (TypeError, ValueError):
                    continue
                if sz_i > 0:
                    f.configure(size=max(sz_i + 2, 11))
                elif sz_i < 0:
                    f.configure(size=sz_i - 2)
            except tk.TclError:
                pass
        self.style.configure("TLabelframe.Label", font=("Microsoft YaHei UI", 12, "bold"))
        self.style.configure("TLabel", font=("Microsoft YaHei UI", 11))
        self.style.configure("TButton", font=("Microsoft YaHei UI", 12))
        self.style.configure("TCheckbutton", font=("Microsoft YaHei UI", 11))
        self.style.configure("TRadiobutton", font=("Microsoft YaHei UI", 11))
        self.style.configure("TSpinbox", font=("Microsoft YaHei UI", 11))
        self.style.configure("TEntry", font=("Microsoft YaHei UI", 11))

        outer = ttk.Frame(self, padding=(16, 14, 16, 12))
        outer.pack(fill=BOTH, expand=True)
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)

        pw_main = ttk.Panedwindow(outer, orient=tk.HORIZONTAL)
        pw_main.grid(row=0, column=0, sticky=NSEW)

        left = ttk.Frame(pw_main, padding=(0, 0, 8, 0))
        right = ttk.Frame(pw_main, padding=(8, 0, 0, 0))
        pw_main.add(left, weight=1)
        pw_main.add(right, weight=1)
        self._pw_main = pw_main

        # —— 左侧：表单与控制 ——
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)

        ctrl_panel = ttk.Frame(left)
        ctrl_panel.grid(row=0, column=0, sticky=tk.N + tk.E + tk.W)

        lf_target = ttk.Labelframe(ctrl_panel, text="探测目标", padding=(12, 10, 12, 10))
        lf_target.pack(fill=tk.X, pady=(0, 8))
        lf_target.columnconfigure(1, weight=1)

        ttk.Label(lf_target, text="主机名或 IP", bootstyle=SECONDARY).grid(
            row=0, column=0, sticky=W, padx=(0, 12), pady=(0, 6)
        )
        self.var_host = tk.StringVar(value="www.baidu.com")
        ttk.Entry(lf_target, textvariable=self.var_host, bootstyle=PRIMARY).grid(
            row=0, column=1, sticky=EW, pady=(0, 6)
        )

        ttk.Label(lf_target, text="TCP 端口（可选）", bootstyle=SECONDARY).grid(
            row=1, column=0, sticky=W, padx=(0, 12), pady=(0, 2)
        )
        self.var_ports = tk.StringVar(value="80,443")
        ttk.Entry(lf_target, textvariable=self.var_ports, bootstyle=PRIMARY).grid(
            row=1, column=1, sticky=EW, pady=(0, 2)
        )
        ttk.Label(
            lf_target,
            text="默认 80,443；留空则不测端口；多个端口用英文逗号分隔",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 10),
        ).grid(row=2, column=1, sticky=W)

        lf_opts = ttk.Labelframe(ctrl_panel, text="探测选项", padding=(12, 10, 12, 12))
        lf_opts.pack(fill=tk.X, pady=(0, 8))
        for c in (1, 3):
            lf_opts.columnconfigure(c, weight=1)

        self.var_samples = tk.IntVar(value=10)
        self.var_timeout = tk.IntVar(value=1000)
        self.var_ping_count = tk.IntVar(value=10)
        self.var_ping_long = tk.BooleanVar(value=False)
        self.var_long_ping_sec = tk.IntVar(value=30)
        self.var_ping_wait_ms = tk.IntVar(value=2000)
        self.var_ping = tk.BooleanVar(value=True)
        self.var_capture = tk.BooleanVar(value=False)
        self.var_ipv6 = tk.BooleanVar(value=False)

        ttk.Label(lf_opts, text="端口采样次数").grid(row=0, column=0, sticky=W, padx=(0, 8), pady=4)
        sb_samples = ttk.Spinbox(lf_opts, from_=1, to=50, textvariable=self.var_samples, width=8)
        sb_samples.grid(row=0, column=1, sticky=W, pady=4)

        ttk.Label(lf_opts, text="TCP 超时 (ms)").grid(row=0, column=2, sticky=W, padx=(16, 8), pady=4)
        ttk.Spinbox(
            lf_opts,
            from_=200,
            to=60000,
            increment=100,
            textvariable=self.var_timeout,
            width=10,
        ).grid(row=0, column=3, sticky=W, pady=4)

        ping_row = ttk.Frame(lf_opts)
        ping_row.grid(row=1, column=0, columnspan=4, sticky=W, pady=(8, 0))
        ttk.Label(ping_row, text="Ping 次数").pack(side=tk.LEFT)
        ttk.Spinbox(ping_row, from_=1, to=300, textvariable=self.var_ping_count, width=6).pack(
            side=tk.LEFT, padx=(4, 14)
        )
        ttk.Label(ping_row, text="ICMP 等待 (ms)").pack(side=tk.LEFT)
        ttk.Spinbox(
            ping_row,
            from_=500,
            to=20000,
            increment=100,
            textvariable=self.var_ping_wait_ms,
            width=7,
        ).pack(side=tk.LEFT, padx=(4, 14))
        ttk.Checkbutton(
            ping_row,
            text="ICMP Ping",
            variable=self.var_ping,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(4, 0))

        chk_row = ttk.Frame(lf_opts)
        chk_row.grid(row=2, column=0, columnspan=4, sticky=EW, pady=(10, 0))
        ttk.Checkbutton(
            chk_row,
            text="长 Ping",
            variable=self.var_ping_long,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Spinbox(
            chk_row, from_=5, to=600, textvariable=self.var_long_ping_sec, width=5
        ).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(
            chk_row,
            text="秒（覆盖「Ping 次数」）",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 10),
        ).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(
            chk_row,
            text="抓包",
            variable=self.var_capture,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(
            chk_row,
            text="优先 IPv6",
            variable=self.var_ipv6,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(0, 14))

        tr_row = ttk.Frame(lf_opts)
        tr_row.grid(row=3, column=0, columnspan=4, sticky=W, pady=(8, 0))
        self.var_traceroute = tk.BooleanVar(value=False)
        self.var_tr_hops = tk.IntVar(value=30)
        self.var_tr_wait_ms = tk.IntVar(value=4000)
        ttk.Checkbutton(
            tr_row,
            text="路由追踪 (tracert)",
            variable=self.var_traceroute,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(tr_row, text="最大跳数", bootstyle=SECONDARY).pack(side=tk.LEFT)
        ttk.Spinbox(tr_row, from_=2, to=64, textvariable=self.var_tr_hops, width=5).pack(
            side=tk.LEFT, padx=(4, 12)
        )
        ttk.Label(tr_row, text="每跳超时 (ms)", bootstyle=SECONDARY).pack(side=tk.LEFT)
        ttk.Spinbox(
            tr_row,
            from_=500,
            to=30000,
            increment=100,
            textvariable=self.var_tr_wait_ms,
            width=7,
        ).pack(side=tk.LEFT, padx=(4, 0))

        lf_bw = ttk.Labelframe(ctrl_panel, text="带宽/吞吐（可选，二选一）", padding=(12, 10, 12, 10))
        lf_bw.pack(fill=tk.X, pady=(0, 8))
        bw_top = ttk.Frame(lf_bw)
        bw_top.pack(fill=tk.X)
        self.var_bw_mode = tk.StringVar(value="off")
        ttk.Radiobutton(bw_top, text="不进行测速", variable=self.var_bw_mode, value="off").pack(
            side=tk.LEFT, padx=(0, 10)
        )
        ttk.Radiobutton(bw_top, text="HTTP 抽样下载", variable=self.var_bw_mode, value="http").pack(
            side=tk.LEFT, padx=(0, 10)
        )
        ttk.Radiobutton(bw_top, text="iperf3", variable=self.var_bw_mode, value="iperf3").pack(side=tk.LEFT)

        self.var_bw_http_url = tk.StringVar(
            value="https://speed.cloudflare.com/__down?bytes=25000000"
        )
        self.var_bw_http_parallel = tk.IntVar(value=4)
        self.var_bw_http_seconds = tk.IntVar(value=15)

        self._frm_bw_http = ttk.Frame(lf_bw)
        http_row1 = ttk.Frame(self._frm_bw_http)
        http_row1.pack(fill=tk.X)
        http_row1.columnconfigure(1, weight=1)
        ttk.Label(http_row1, text="HTTP URL", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 8))
        self.ent_bw_http_url = ttk.Entry(http_row1, textvariable=self.var_bw_http_url, bootstyle=PRIMARY)
        self.ent_bw_http_url.grid(row=0, column=1, sticky=EW)

        http_row2 = ttk.Frame(self._frm_bw_http)
        http_row2.pack(fill=tk.X, pady=(6, 0))
        ttk.Label(http_row2, text="并发连接", bootstyle=SECONDARY).pack(side=tk.LEFT)
        self.sb_bw_http_parallel = ttk.Spinbox(
            http_row2, from_=1, to=16, textvariable=self.var_bw_http_parallel, width=6
        )
        self.sb_bw_http_parallel.pack(side=tk.LEFT, padx=(6, 16))
        ttk.Label(http_row2, text="持续时间 (秒)", bootstyle=SECONDARY).pack(side=tk.LEFT)
        self.sb_bw_http_seconds = ttk.Spinbox(
            http_row2, from_=3, to=300, textvariable=self.var_bw_http_seconds, width=6
        )
        self.sb_bw_http_seconds.pack(side=tk.LEFT, padx=(6, 0))

        self.var_bw_iperf_host = tk.StringVar(value="")
        self.var_bw_iperf_port = tk.IntVar(value=5201)
        self.var_bw_iperf_seconds = tk.IntVar(value=10)

        self._frm_bw_iperf = ttk.Frame(lf_bw)
        ip_row = ttk.Frame(self._frm_bw_iperf)
        ip_row.pack(fill=tk.X)
        ip_row.columnconfigure(1, weight=1)
        ttk.Label(ip_row, text="iperf 服务器", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 8))
        self.ent_bw_iperf_host = ttk.Entry(ip_row, textvariable=self.var_bw_iperf_host, bootstyle=PRIMARY)
        self.ent_bw_iperf_host.grid(row=0, column=1, sticky=EW)
        ttk.Label(ip_row, text="端口", bootstyle=SECONDARY).grid(row=0, column=2, sticky=W, padx=(12, 6))
        self.sb_bw_iperf_port = ttk.Spinbox(
            ip_row, from_=1, to=65535, textvariable=self.var_bw_iperf_port, width=7
        )
        self.sb_bw_iperf_port.grid(row=0, column=3, sticky=W)
        ttk.Label(ip_row, text="时长 (秒)", bootstyle=SECONDARY).grid(
            row=1, column=0, sticky=W, padx=(0, 8), pady=(6, 0)
        )
        self.sb_bw_iperf_seconds = ttk.Spinbox(
            ip_row, from_=2, to=600, textvariable=self.var_bw_iperf_seconds, width=6
        )
        self.sb_bw_iperf_seconds.grid(row=1, column=1, sticky=W, pady=(6, 0))

        self.var_bw_mode.trace_add("write", lambda *_: self._sync_bw_panels())
        self._sync_bw_panels()

        lf_adv = ttk.Labelframe(ctrl_panel, text="进阶探测（可选，可能较慢）", padding=(12, 10, 12, 10))
        lf_adv.pack(fill=tk.X, pady=(0, 8))
        lf_adv.columnconfigure(1, weight=1)
        self.var_optional_dns = tk.StringVar(value="223.5.5.5")
        ttk.Label(lf_adv, text="指定 DNS（与系统解析对比）", bootstyle=SECONDARY).grid(
            row=0, column=0, sticky=W, padx=(0, 8), pady=(0, 6)
        )
        ttk.Entry(lf_adv, textvariable=self.var_optional_dns, bootstyle=PRIMARY).grid(
            row=0, column=1, sticky=EW, pady=(0, 6)
        )
        ttk.Label(
            lf_adv,
            text="例：8.8.8.8；留空则仅使用系统解析器",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 10),
        ).grid(row=1, column=1, sticky=W)

        self.var_adv_pathping = tk.BooleanVar(value=False)
        self.var_adv_tcp_trace = tk.BooleanVar(value=False)
        self.var_adv_tcp_hops = tk.IntVar(value=30)
        self.var_adv_http_tls = tk.BooleanVar(value=False)
        self.var_adv_egress = tk.BooleanVar(value=False)
        self.var_adv_mtu = tk.BooleanVar(value=False)
        self.var_adv_history = tk.BooleanVar(value=True)

        adv_chk = ttk.Frame(lf_adv)
        adv_chk.grid(row=2, column=0, columnspan=2, sticky=W, pady=(10, 4))
        ttk.Checkbutton(
            adv_chk, text="PathPing / mtr", variable=self.var_adv_pathping, bootstyle="round-toggle"
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            adv_chk, text="TCP 路径", variable=self.var_adv_tcp_trace, bootstyle="round-toggle"
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(adv_chk, text="TCP 最大跳数", bootstyle=SECONDARY).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Spinbox(adv_chk, from_=2, to=64, textvariable=self.var_adv_tcp_hops, width=5).pack(
            side=tk.LEFT, padx=(0, 12)
        )

        adv_chk2 = ttk.Frame(lf_adv)
        adv_chk2.grid(row=3, column=0, columnspan=2, sticky=W, pady=(4, 0))
        ttk.Checkbutton(
            adv_chk2, text="HTTPS/TLS", variable=self.var_adv_http_tls, bootstyle="round-toggle"
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            adv_chk2, text="出口 / 代理", variable=self.var_adv_egress, bootstyle="round-toggle"
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            adv_chk2, text="IPv4 MTU", variable=self.var_adv_mtu, bootstyle="round-toggle"
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            adv_chk2,
            text="历史记录对比",
            variable=self.var_adv_history,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(0, 0))

        ttk.Separator(ctrl_panel, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(4, 10))

        actions = ttk.Frame(ctrl_panel)
        actions.pack(fill=tk.X, pady=(0, 6))
        for c in (0, 1, 2, 3):
            actions.columnconfigure(c, weight=1)

        big_btn_kwargs = {"width": 12}

        ttk.Button(
            actions,
            text="安装 Wireshark",
            command=self._open_wireshark_installer,
            bootstyle=INFO,
            **big_btn_kwargs,
        ).grid(row=0, column=0, sticky=EW, padx=(0, 3), pady=(0, 8))
        ttk.Button(
            actions,
            text="检测 Tcping",
            command=self._probe_tcping,
            bootstyle=SECONDARY,
            **big_btn_kwargs,
        ).grid(row=0, column=1, sticky=EW, padx=(3, 3), pady=(0, 8))
        ttk.Button(
            actions,
            text="检测 Tshark",
            command=self._probe_tshark,
            bootstyle=SECONDARY,
            **big_btn_kwargs,
        ).grid(row=0, column=2, sticky=EW, padx=(3, 3), pady=(0, 8))
        ttk.Button(
            actions,
            text="检测 Iperf3",
            command=self._probe_iperf3,
            bootstyle=SECONDARY,
            **big_btn_kwargs,
        ).grid(row=0, column=3, sticky=EW, padx=(3, 0), pady=(0, 8))

        self.btn_run = ttk.Button(
            actions,
            text="开始诊断",
            command=self._on_run,
            bootstyle=SUCCESS,
            width=14,
        )
        self.btn_run.grid(row=1, column=0, columnspan=4, sticky=EW, pady=(0, 0))

        status_shell = ttk.Labelframe(ctrl_panel, text="任务状态", padding=(12, 10, 12, 10), bootstyle=SECONDARY)
        self._status_shell = status_shell
        status_shell.pack(fill=tk.X, pady=(8, 0))
        status_bar = ttk.Frame(status_shell)
        status_bar.pack(fill=tk.X)
        self.lbl_status = ttk.Label(
            status_bar,
            text="就绪",
            bootstyle=SECONDARY,
            anchor=W,
            font=self._status_font_normal,
            wraplength=520,
            justify=tk.LEFT,
        )
        self.lbl_status.pack(fill=tk.X)
        self._run_progress = ttk.Progressbar(
            status_shell,
            mode="indeterminate",
            bootstyle=WARNING,
            length=400,
        )

        btn2 = ttk.Frame(left)
        btn2.grid(row=1, column=0, sticky=EW, pady=(8, 0))
        self.btn_open_md = ttk.Button(
            btn2,
            text="打开技术报告 (Markdown)",
            command=self._open_last_md,
            state=tk.DISABLED,
            bootstyle=PRIMARY,
        )
        self.btn_open_md.pack(side=tk.LEFT)
        self.btn_open_dir = ttk.Button(
            btn2,
            text="打开报告文件夹",
            command=self._open_last_dir,
            state=tk.DISABLED,
            bootstyle=OUTLINE,
        )
        self.btn_open_dir.pack(side=tk.LEFT, padx=(10, 0))

        # —— 右侧：诊断结果 + 进度详情 ——
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        lf_summary = ttk.Labelframe(right, text="诊断结果", padding=(10, 8, 10, 10))
        lf_summary.grid(row=0, column=0, sticky=NSEW, pady=(0, 8))
        lf_summary.rowconfigure(0, weight=1)
        lf_summary.columnconfigure(0, weight=1)

        self.txt_summary = ScrolledText(
            lf_summary,
            height=12,
            wrap=tk.WORD,
            font=("Microsoft YaHei UI", 12),
            relief=tk.FLAT,
            padx=8,
            pady=8,
        )
        self.txt_summary.grid(row=0, column=0, sticky=NSEW)
        self._setup_summary_text_tags()

        lf_log = ttk.Labelframe(right, text="进度详情", padding=(10, 8, 10, 10))
        lf_log.grid(row=1, column=0, sticky=NSEW)
        lf_log.rowconfigure(0, weight=1)
        lf_log.columnconfigure(0, weight=1)

        self.txt_log = ScrolledText(
            lf_log,
            height=8,
            wrap=tk.WORD,
            font=("Consolas", 11),
            relief=tk.FLAT,
            padx=8,
            pady=8,
        )
        self.txt_log.grid(row=0, column=0, sticky=NSEW)

        self._last_md: str | None = None
        self._last_dir: str | None = None

        self.after(200, self._poll_queue)
        self.after_idle(self._init_main_sash)

    def _sync_bw_panels(self) -> None:
        m = self.var_bw_mode.get()
        self._frm_bw_http.pack_forget()
        self._frm_bw_iperf.pack_forget()
        if m == "http":
            self._frm_bw_http.pack(fill=tk.X, pady=(8, 0))
        elif m == "iperf3":
            self._frm_bw_iperf.pack(fill=tk.X, pady=(8, 0))

    def _setup_summary_text_tags(self) -> None:
        st = self.txt_summary
        st.tag_configure("sec_title", font=("Microsoft YaHei UI", 12, "bold"))
        st.tag_configure("headline", font=("Microsoft YaHei UI", 13, "bold"))
        st.tag_configure("body", font=("Microsoft YaHei UI", 12))
        st.tag_configure(
            "quality_grade_exc",
            font=("Microsoft YaHei UI", 13, "bold"),
            background="#d4edda",
            foreground="#155724",
        )
        st.tag_configure(
            "quality_grade_ok",
            font=("Microsoft YaHei UI", 13, "bold"),
            background="#d1ecf1",
            foreground="#0c5460",
        )
        st.tag_configure(
            "quality_grade_poor",
            font=("Microsoft YaHei UI", 13, "bold"),
            background="#fff3cd",
            foreground="#856404",
        )
        st.tag_configure(
            "quality_grade_bad",
            font=("Microsoft YaHei UI", 13, "bold"),
            background="#f8d7da",
            foreground="#721c24",
        )
        st.tag_configure(
            "overall_label",
            font=("Microsoft YaHei UI", 12, "bold"),
            foreground="#2c3e50",
        )

    def _centered_geometry(self, width: int, height: int) -> str:
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w = min(width, sw)
        h = min(height, sh)
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        return f"{w}x{h}+{x}+{y}"

    def _init_main_sash(self) -> None:
        """初次分配左右两栏为 1:1（按 Panedwindow 实际宽度）。"""
        self._init_main_sash_attempt(0)

    def _init_main_sash_attempt(self, attempt: int) -> None:
        if attempt > 10:
            return
        try:
            self.update_idletasks()
            pw = self._pw_main
            w = pw.winfo_width()
            if w <= 10:
                self.after(60, lambda: self._init_main_sash_attempt(attempt + 1))
                return
            pw.sashpos(0, w // 2)
        except tk.TclError:
            pass

    def _start_running_ui(self) -> None:
        self._status_shell.configure(bootstyle=WARNING)
        self.lbl_status.configure(
            text="正在运行诊断\n请留意右侧「进度详情」中的实时输出。",
            bootstyle=WARNING,
            font=self._status_font_running,
        )
        self._run_progress.pack(fill=tk.X, pady=(10, 0))
        self._run_progress.start(14)

    def _stop_running_ui(self) -> None:
        try:
            self._run_progress.stop()
        except tk.TclError:
            pass
        self._run_progress.pack_forget()
        self._status_shell.configure(bootstyle=SECONDARY)
        self.lbl_status.configure(font=self._status_font_normal)

    def _append_log(self, text: str) -> None:
        self.txt_log.insert(END, text + "\n")
        self.txt_log.see(END)

    def _probe_tcping(self) -> None:
        p = resolve_tcping_exe()
        if p:
            messagebox.showinfo("Tcping", f"已找到:\n{p}")
        else:
            messagebox.showwarning(
                "Tcping",
                "未找到 tcping.exe。\n请将可执行文件置于 ThirdParty/tcping/tcping.exe。点击下方链接下载：\nhttps://www.elifulkerson.com/projects/tcping.php#google_vignette",
            )

    def _probe_tshark(self) -> None:
        p = find_tshark()
        if p:
            messagebox.showinfo("tshark", f"已找到:\n{p}")
        else:
            messagebox.showwarning(
                "tshark",
                "未找到 tshark。请先安装 Wireshark（含 Npcap），"
                "或使用「打开 Wireshark 安装包」。",
            )

    def _probe_iperf3(self) -> None:
        p = resolve_iperf3_exe()
        if p:
            messagebox.showinfo("Iperf3", f"已找到:\n{p}")
        else:
            messagebox.showwarning(
                "Iperf3",
                "未找到 iperf3。\n请将 iperf3.exe 置于 ThirdParty/iperf3/，"
                "或从系统 PATH 中安装 iperf3。官方参考：https://iperf.fr/",
            )

    def _open_wireshark_installer(self) -> None:
        cands = iter_wireshark_installers()
        if not cands:
            messagebox.showwarning(
                "Wireshark",
                "未在 ThirdParty/Wireshark/ 下找到 .exe 安装包。\n请将官方安装程序放入该目录。点击下方链接下载：\nhttps://www.wireshark.org/",
            )
            return
        path = str(cands[0])
        try:
            if sys.platform == "win32":
                os.startfile(path)  # noqa: S606
            else:
                subprocess.Popen(["xdg-open", path])  # noqa: S603, S607
        except OSError as e:
            messagebox.showerror("Wireshark", f"无法打开安装包: {e}")

    def _open_last_md(self) -> None:
        if not self._last_md:
            return
        self._startfile(self._last_md)

    def _open_last_dir(self) -> None:
        if not self._last_dir:
            return
        self._startfile(self._last_dir)

    @staticmethod
    def _startfile(path: str) -> None:
        try:
            if sys.platform == "win32":
                os.startfile(path)  # noqa: S606
            else:
                subprocess.Popen(["xdg-open", path])  # noqa: S603, S607
        except OSError as e:
            messagebox.showerror("打开失败", str(e))

    def _on_run(self) -> None:
        if self._worker and self._worker.is_alive():
            messagebox.showinfo("请稍候", "诊断任务仍在运行。")
            return
        host = self.var_host.get().strip()
        if not host:
            messagebox.showwarning("校验", "请填写目标主机。")
            return
        try:
            ports = _parse_ports(self.var_ports.get())
        except ValueError:
            messagebox.showwarning("校验", "端口列表格式不正确。")
            return

        bw_mode = self.var_bw_mode.get()
        if bw_mode == "http":
            u = self.var_bw_http_url.get().strip()
            if not u:
                messagebox.showwarning("校验", "已选择 HTTP 抽样，请填写下载 URL。")
                return
            pr = urlparse(u)
            if pr.scheme not in ("http", "https"):
                messagebox.showwarning("校验", "HTTP URL 须以 http:// 或 https:// 开头。")
                return
        elif bw_mode == "iperf3":
            if not self.var_bw_iperf_host.get().strip():
                messagebox.showwarning("校验", "已选择 iperf3，请填写服务器主机名或 IP。")
                return

        opts = RunOptions(
            target_host=host,
            ports=ports,
            samples_per_port=int(self.var_samples.get()),
            tcp_timeout_ms=int(self.var_timeout.get()),
            enable_ping=bool(self.var_ping.get()),
            enable_capture=bool(self.var_capture.get()),
            prefer_ipv6=bool(self.var_ipv6.get()),
            ping_count=int(self.var_ping_count.get()),
            ping_packet_timeout_ms=int(self.var_ping_wait_ms.get()),
            ping_long=bool(self.var_ping_long.get()),
            long_ping_seconds=int(self.var_long_ping_sec.get()),
            enable_traceroute=bool(self.var_traceroute.get()),
            traceroute_max_hops=int(self.var_tr_hops.get()),
            traceroute_hop_timeout_ms=int(self.var_tr_wait_ms.get()),
            bandwidth_mode=bw_mode,
            bandwidth_http_url=self.var_bw_http_url.get().strip(),
            bandwidth_http_parallel=int(self.var_bw_http_parallel.get()),
            bandwidth_http_seconds=int(self.var_bw_http_seconds.get()),
            bandwidth_iperf_host=self.var_bw_iperf_host.get().strip(),
            bandwidth_iperf_port=int(self.var_bw_iperf_port.get()),
            bandwidth_iperf_seconds=int(self.var_bw_iperf_seconds.get()),
            optional_dns_server=self.var_optional_dns.get().strip(),
            enable_pathping=bool(self.var_adv_pathping.get()),
            enable_tcp_traceroute=bool(self.var_adv_tcp_trace.get()),
            tcp_traceroute_max_hops=int(self.var_adv_tcp_hops.get()),
            enable_http_tls_probe=bool(self.var_adv_http_tls.get()),
            enable_egress_probe=bool(self.var_adv_egress.get()),
            enable_mtu_probe=bool(self.var_adv_mtu.get()),
            enable_history_compare=bool(self.var_adv_history.get()),
        )

        self.txt_log.delete("1.0", END)
        self.txt_summary.delete("1.0", END)
        self._status_shell.configure(text="任务状态")
        self.btn_run.configure(state=tk.DISABLED)
        self._start_running_ui()

        def work() -> None:
            try:

                def prog(msg: str) -> None:
                    self._queue.put(("log", msg))

                rep = run_diagnostic(opts, prog)
                self._queue.put(("done", rep))
            except BaseException as e:
                if isinstance(e, (KeyboardInterrupt, SystemExit)):
                    raise
                self._queue.put(("error", str(e)))

        self._worker = threading.Thread(target=work, daemon=True)
        self._worker.start()

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "error":
                    messagebox.showerror("诊断失败", str(payload))
                    self._stop_running_ui()
                    self.btn_run.configure(state=tk.NORMAL)
                    self.lbl_status.configure(text="失败", bootstyle=DANGER)
                    self._status_shell.configure(text="任务状态")
                elif kind == "done":
                    rep: DiagnosticReport = payload  # type: ignore[assignment]
                    self._render_report(rep)
                    self.btn_run.configure(state=tk.NORMAL)
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)

    def _render_report(self, rep: DiagnosticReport) -> None:
        assert isinstance(rep, DiagnosticReport)
        self._stop_running_ui()
        g = rep.gui
        t = self.txt_summary

        def sec(title: str) -> None:
            t.insert(END, title + "\n", ("sec_title",))

        def body_lines(lines: list[str]) -> None:
            for line in lines:
                t.insert(END, line + "\n", ("body",))
            t.insert(END, "\n")

        def insert_overall_block() -> None:
            qg = rep.network_quality.grade
            qtag = _quality_tag_for_grade(qg)
            t.insert(END, g.headline + "\n\n", ("headline",))

            t.insert(END, "· 网络质量 ", ("overall_label",))
            t.insert(END, "评判：", ("body",))
            t.insert(END, qg, (qtag,))
            t.insert(END, "  " + _gui_oneline_network_quality(rep) + "\n\n", ("body",))

            t.insert(END, "· 域名解析 ", ("overall_label",))
            t.insert(END, _gui_oneline_dns(rep) + "\n\n", ("body",))

            t.insert(END, "· Ping 结果 ", ("overall_label",))
            t.insert(END, _gui_oneline_ping(rep) + "\n\n", ("body",))

            t.insert(END, "· 路由追踪 ", ("overall_label",))
            t.insert(END, _gui_oneline_traceroute(rep) + "\n\n", ("body",))

            t.insert(END, "· 端口连接 ", ("overall_label",))
            t.insert(END, _gui_oneline_ports(rep) + "\n\n", ("body",))

            if _any_advanced(rep):
                t.insert(END, "· 进阶探测 ", ("overall_label",))
                t.insert(END, _gui_oneline_advanced(rep) + "\n\n", ("body",))

        insert_overall_block()

        sec("网络质量与指标")
        body_lines(_gui_lines_network_quality(rep))

        sec("DNS 解析结果")
        body_lines(_gui_lines_dns(rep))

        sec("Ping 结果")
        body_lines(_gui_lines_ping(rep))

        sec("路由追踪")
        body_lines(_gui_lines_traceroute(rep))

        sec("端口测试结果")
        body_lines(_gui_lines_ports(rep))

        sec("抓包结果")
        body_lines(_gui_lines_capture(rep))

        sec("带宽/吞吐抽样")
        body_lines(_gui_lines_bandwidth(rep))

        if _any_advanced(rep):
            sec("进阶探测")
            body_lines(_gui_lines_advanced(rep))

        t.insert(
            END,
            "若需技术人员排查，请使用下方按钮打开 Markdown 报告（含完整路径与原始日志索引）。\n",
            ("body",),
        )

        md = str(g.markdown_path.resolve())
        self._last_md = md
        self._last_dir = str(rep.meta.report_dir.resolve())
        self.btn_open_md.configure(state=tk.NORMAL)
        self.btn_open_dir.configure(state=tk.NORMAL)

        q = rep.network_quality.grade
        self._status_shell.configure(text=f"任务状态（网络质量：{q}）")

        if g.overall.value == "ok":
            self.lbl_status.configure(
                text=f"完成（网络质量：{q}）",
                bootstyle=SUCCESS,
            )
        elif g.overall.value == "degraded":
            self.lbl_status.configure(
                text=f"完成（部分异常或已降级）（网络质量：{q}）",
                bootstyle=WARNING,
            )
        else:
            self.lbl_status.configure(
                text=f"完成（存在明显问题）（网络质量：{q}）",
                bootstyle=DANGER,
            )

        self._append_log(f"报告: {md}")


def main_gui() -> None:
    app = NetworkDiagnosisApp()
    app.mainloop()
