"""ttkbootstrap 主界面：工作线程 + 队列回灌。"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
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
from network_diagnosis.paths import find_tshark, iter_wireshark_installers, resolve_tcping_exe
from network_diagnosis.probes.dns_probe import pick_tcp_target
from network_diagnosis.runner import RunOptions, run_diagnostic


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
    if dns.error:
        lines.append(f"解析失败：{dns.error}")
        return lines
    if not dns.addresses:
        lines.append("未得到任何解析地址。")
        return lines
    lines.append("解析到的地址：" + "、".join(dns.addresses))
    tcp_t = pick_tcp_target(dns, prefer_ipv6=ui.prefer_ipv6)
    if tcp_t:
        lines.append(f"本次 TCP / 抓包使用的 IP：{tcp_t}")
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


class NetworkDiagnosisApp(ttk.Window):
    """网络诊断工具主界面"""
    def __init__(self) -> None:
        # 主题
        super().__init__(themename="flatly")
        # 窗口标题
        self.title("网络诊断工具")
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
        mid = ttk.Frame(pw_main, padding=(8, 0, 8, 0))
        right = ttk.Frame(pw_main, padding=(8, 0, 0, 0))
        pw_main.add(left, weight=1)
        pw_main.add(mid, weight=1)
        pw_main.add(right, weight=1)
        self._pw_main = pw_main

        # —— 左侧：表单 + 状态 + 报告按钮 ——
        lf_target = ttk.Labelframe(left, text="探测目标", padding=(12, 10, 12, 10))
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
        self.var_ports = tk.StringVar(value="")
        ttk.Entry(lf_target, textvariable=self.var_ports, bootstyle=PRIMARY).grid(
            row=1, column=1, sticky=EW, pady=(0, 2)
        )
        ttk.Label(
            lf_target,
            text="留空则不测端口；填写时用英文逗号分隔，例如 80,443",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 10),
        ).grid(row=2, column=1, sticky=W)

        lf_opts = ttk.Labelframe(left, text="探测选项", padding=(12, 10, 12, 12))
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

        long_ping_row = ttk.Frame(lf_opts)
        long_ping_row.grid(row=2, column=0, columnspan=4, sticky=W, pady=(6, 0))
        ttk.Checkbutton(
            long_ping_row,
            text="长 Ping",
            variable=self.var_ping_long,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Spinbox(
            long_ping_row, from_=5, to=600, textvariable=self.var_long_ping_sec, width=5
        ).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(long_ping_row, text="秒（覆盖上方「Ping 次数」）").pack(side=tk.LEFT)

        chk_row = ttk.Frame(lf_opts)
        chk_row.grid(row=3, column=0, columnspan=4, sticky=EW, pady=(10, 0))
        chk_row.columnconfigure(0, weight=1)
        ttk.Checkbutton(
            chk_row,
            text="ICMP Ping",
            variable=self.var_ping,
            bootstyle="round-toggle",
        ).grid(row=0, column=0, sticky=W, padx=(0, 20))
        ttk.Checkbutton(
            chk_row,
            text="抓包",
            variable=self.var_capture,
            bootstyle="round-toggle",
        ).grid(row=0, column=1, sticky=W, padx=(0, 20))
        ttk.Checkbutton(
            chk_row,
            text="优先 IPv6",
            variable=self.var_ipv6,
            bootstyle="round-toggle",
        ).grid(row=0, column=2, sticky=W)

        ttk.Separator(left, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(4, 10))

        actions = ttk.Frame(left)
        actions.pack(fill=tk.X, pady=(0, 6))
        actions.columnconfigure(0, weight=1)
        actions.columnconfigure(1, weight=1)

        big_btn_kwargs = {"width": 18}

        self.btn_run = ttk.Button(
            actions,
            text="开始诊断",
            command=self._on_run,
            bootstyle=SUCCESS,
            **big_btn_kwargs,
        )
        self.btn_run.grid(row=0, column=0, sticky=EW, padx=(0, 6), pady=(0, 8))
        ttk.Button(
            actions,
            text="安装 Wireshark",
            command=self._open_wireshark_installer,
            bootstyle=INFO,
            **big_btn_kwargs,
        ).grid(row=0, column=1, sticky=EW, padx=(6, 0), pady=(0, 8))

        ttk.Button(
            actions,
            text="检测 Tcping",
            command=self._probe_tcping,
            bootstyle=SECONDARY,
            **big_btn_kwargs,
        ).grid(row=1, column=0, sticky=EW, padx=(0, 6))
        ttk.Button(
            actions,
            text="检测 Tshark",
            command=self._probe_tshark,
            bootstyle=SECONDARY,
            **big_btn_kwargs,
        ).grid(row=1, column=1, sticky=EW, padx=(6, 0))

        status_shell = ttk.Labelframe(left, text="任务状态", padding=(12, 10, 12, 10), bootstyle=SECONDARY)
        self._status_shell = status_shell
        status_shell.pack(fill=BOTH, expand=True, pady=(8, 8))
        status_bar = ttk.Frame(status_shell)
        status_bar.pack(fill=tk.X)
        self.lbl_status = ttk.Label(
            status_bar,
            text="就绪",
            bootstyle=SECONDARY,
            anchor=W,
            font=self._status_font_normal,
            wraplength=320,
            justify=tk.LEFT,
        )
        self.lbl_status.pack(fill=tk.X)
        self._run_progress = ttk.Progressbar(
            status_shell,
            mode="indeterminate",
            bootstyle=WARNING,
            length=320,
        )

        btn2 = ttk.Frame(left)
        btn2.pack(fill=tk.X, pady=(0, 0))
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

        # —— 中列：结论 ——
        mid.rowconfigure(0, weight=1)
        mid.columnconfigure(0, weight=1)

        lf_summary = ttk.Labelframe(mid, text="诊断结果", padding=(10, 8, 10, 10))
        lf_summary.grid(row=0, column=0, sticky=NSEW)
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

        # —— 右列：进度详情 ——
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)

        lf_log = ttk.Labelframe(right, text="进度详情", padding=(10, 8, 10, 10))
        lf_log.grid(row=0, column=0, sticky=NSEW)
        lf_log.rowconfigure(0, weight=1)
        lf_log.columnconfigure(0, weight=1)

        self.txt_log = ScrolledText(
            lf_log,
            height=22,
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

    def _setup_summary_text_tags(self) -> None:
        st = self.txt_summary
        st.tag_configure("sec_title", font=("Microsoft YaHei UI", 12, "bold"))
        st.tag_configure("headline", font=("Microsoft YaHei UI", 13, "bold"))
        st.tag_configure("body", font=("Microsoft YaHei UI", 12))

    def _centered_geometry(self, width: int, height: int) -> str:
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w = min(width, sw)
        h = min(height, sh)
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        return f"{w}x{h}+{x}+{y}"

    def _init_main_sash(self) -> None:
        """初次分配三列宽度为 1:1:1（按 Panedwindow 实际宽度，而非整窗宽度）。"""
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
            a = w // 3
            b = (2 * w) // 3
            pw.sashpos(0, a)
            pw.sashpos(1, b)
        except tk.TclError:
            pass

    def _start_running_ui(self) -> None:
        self._status_shell.configure(bootstyle=WARNING)
        self.lbl_status.configure(
            text="正在运行诊断\n请留意最右侧「进度详情」中的实时输出。",
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
        )

        self.txt_log.delete("1.0", END)
        self.txt_summary.delete("1.0", END)
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

        sec("整体结论")
        t.insert(END, g.headline + "\n", ("headline",))
        for b in g.bullets:
            t.insert(END, "• " + b + "\n", ("body",))
        t.insert(END, "\n")

        sec("DNS 解析结果")
        body_lines(_gui_lines_dns(rep))

        sec("Ping 结果")
        body_lines(_gui_lines_ping(rep))

        sec("端口测试结果")
        body_lines(_gui_lines_ports(rep))

        sec("抓包结果")
        body_lines(_gui_lines_capture(rep))

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

        if g.overall.value == "ok":
            self.lbl_status.configure(text="完成（整体正常）", bootstyle=SUCCESS)
        elif g.overall.value == "degraded":
            self.lbl_status.configure(text="完成（部分异常或已降级）", bootstyle=WARNING)
        else:
            self.lbl_status.configure(text="完成（存在明显问题）", bootstyle=DANGER)

        self._append_log(f"报告: {md}")


def main_gui() -> None:
    app = NetworkDiagnosisApp()
    app.mainloop()
