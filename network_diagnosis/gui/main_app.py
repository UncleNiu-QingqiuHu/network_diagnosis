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
from urllib.parse import urlparse

import ttkbootstrap as ttk
from ttkbootstrap.constants import (
    BOTH,
    DANGER,
    DARK,
    END,
    INVERSE,
    NSEW,
    SECONDARY,
    SUCCESS,
    WARNING,
    W,
)

from network_diagnosis.gui.db_diagnosis_frame import DbDiagnosisFrame
from network_diagnosis.gui.main_app_common import parse_ports, try_set_window_icon
from network_diagnosis.gui.main_app_network_views import NetworkViewsMixin
from network_diagnosis.gui.main_app_report_text import (
    _any_advanced,
    _blend_hex,
    _gui_lines_advanced,
    _gui_lines_bandwidth,
    _gui_lines_capture,
    _gui_lines_dns,
    _gui_lines_network_quality,
    _gui_lines_ping,
    _gui_lines_ports,
    _gui_lines_traceroute,
    _gui_oneline_advanced,
    _gui_oneline_dns,
    _gui_oneline_network_quality,
    _gui_oneline_ping,
    _gui_oneline_ports,
    _gui_oneline_traceroute,
    _quality_tag_for_grade,
)
from network_diagnosis.gui.main_app_static_views import StaticViewsMixin
from network_diagnosis.gui.main_app_subnet_views import SubnetViewsMixin
from network_diagnosis.gui.security_diagnosis_frame import SecurityDiagnosisFrame
from network_diagnosis.gui.switch_console_frame import SwitchConsoleFrame
from network_diagnosis.model.report import DiagnosticReport
from network_diagnosis.paths import (
    find_tshark,
    iter_wireshark_installers,
    resolve_iperf3_exe,
    resolve_tcping_exe,
)
from network_diagnosis.runner import RunOptions, run_diagnostic
from network_diagnosis.runtime_log import get_logger, setup_runtime_logging
from network_diagnosis.version import APP_DISPLAY_NAME, APP_VERSION, AUTHOR_SUMMARY

_log = get_logger(__name__)


class NetworkDiagnosisApp(NetworkViewsMixin, SubnetViewsMixin, StaticViewsMixin, ttk.Window):
    """网络与运维相关工具（左侧导航 + 右侧内容区）。"""
    def __init__(self) -> None:
        # 主题
        super().__init__(themename="solar")
        # 初始化完成前先隐藏根窗口，避免短暂出现空白主窗口（易被误认为「多了一个 GUI 窗口」）
        try:
            self.withdraw()
        except tk.TclError:
            pass
        try_set_window_icon(self)
        # 窗口标题
        self.title(f"{APP_DISPLAY_NAME} v{APP_VERSION}（{AUTHOR_SUMMARY}）")
        # 最小窗口大小
        self.minsize(1260, 720)
        # 默认窗口大小：每次启动在主屏居中（大于屏幕时先缩放到可放入再居中）
        self.geometry(self._centered_geometry(1600, 1080))

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

        root_layout = ttk.Frame(self)
        root_layout.pack(fill=BOTH, expand=True)
        root_layout.rowconfigure(0, weight=1)
        root_layout.columnconfigure(0, weight=0, minsize=212)
        root_layout.columnconfigure(1, weight=1)

        # 左侧整列深色底（DARK）；导航项同色系深色自定义样式，避免 LIGHT 白块与默认焦点虚线框
        sidebar = ttk.Frame(root_layout, bootstyle=DARK, padding=(12, 16, 12, 16))
        sidebar.grid(row=0, column=0, sticky=NSEW)

        ttk.Label(
            sidebar,
            text="功能导航",
            font=("Microsoft YaHei UI", 12, "bold"),
            bootstyle=(INVERSE, DARK),
        ).pack(anchor=W, pady=(0, 14))

        action_frame = ttk.Frame(sidebar, bootstyle=DARK)
        action_frame.pack(fill=BOTH, expand=True)

        self._configure_sidebar_nav_styles()

        self._sidebar_btn_by_module: dict[str, ttk.Button] = {}
        nav_items: list[tuple[str, str]] = [
            ("network", "网络诊断"),
            ("subnet", "子网计算"),
            ("switch", "交换机配置"),
            ("database", "数据库诊断"),
            ("security", "安全诊断"),
            ("guide", "使用帮助"),
            ("about", "关于"),
            ("license", "许可"),
        ]
        for mod_key, nav_label in nav_items:
            btn = ttk.Button(
                action_frame,
                text=nav_label,
                command=lambda k=mod_key: self._select_module(k),
                style="SidebarNav.TButton",
                takefocus=False,
                cursor="hand2",
            )
            btn.pack(side=tk.TOP, fill=tk.X, pady=(0, 4))
            self._sidebar_btn_by_module[mod_key] = btn

        content_outer = ttk.Frame(root_layout, padding=(16, 14, 16, 12))
        content_outer.grid(row=0, column=1, sticky=NSEW)
        content_outer.rowconfigure(0, weight=1)
        content_outer.columnconfigure(0, weight=1)

        self._content_host = ttk.Frame(content_outer)
        self._content_host.grid(row=0, column=0, sticky=NSEW)
        self._content_host.rowconfigure(0, weight=1)
        self._content_host.columnconfigure(0, weight=1)

        self._view_frames: dict[str, ttk.Frame] = {}

        self._build_network_diagnosis_view()

        self.after(200, self._poll_queue)

        self._build_subnet_view()
        self._switch_console = SwitchConsoleFrame(self._content_host)
        self._view_frames["switch"] = self._switch_console
        self._db_diagnosis = DbDiagnosisFrame(self._content_host)
        self._view_frames["database"] = self._db_diagnosis
        self._security_diagnosis = SecurityDiagnosisFrame(self._content_host)
        self._view_frames["security"] = self._security_diagnosis

        self._active_module: str | None = None
        self._select_module("network")
        self.after_idle(self._finish_startup_display)

    def _finish_startup_display(self) -> None:
        """布局就绪后再显示主窗口，并初始化分割条（withdraw 期间 winfo_width 不可靠）。"""
        try:
            self.update_idletasks()
            self.deiconify()
        except tk.TclError:
            pass
        self.after_idle(self._init_main_sash)

    def _select_module(self, module_key: str) -> None:
        if self._active_module == module_key:
            return
        prev = self._active_module
        if prev is not None and prev != module_key:
            fr = self._view_frames.get(prev)
            if fr is not None:
                leave = getattr(fr, "on_leave", None)
                if callable(leave):
                    leave()
        self._active_module = module_key
        for k, btn in self._sidebar_btn_by_module.items():
            btn.configure(
                style="SidebarNavActive.TButton" if k == module_key else "SidebarNav.TButton"
            )
        self._ensure_static_module_built(module_key)
        if prev is not None:
            fr_prev = self._view_frames.get(prev)
            if fr_prev is not None:
                try:
                    fr_prev.grid_remove()
                except tk.TclError:
                    pass
        fr_new = self._view_frames.get(module_key)
        if fr_new is not None:
            fr_new.grid(row=0, column=0, sticky=NSEW)
        _log.info("切换导航模块 %s -> %s", prev, module_key)

    def _configure_sidebar_nav_styles(self) -> None:
        c = self.style.colors
        dark_bg = getattr(c, "dark", "#073642")
        if not isinstance(dark_bg, str) or len(dark_bg.strip().lstrip("#")) != 6:
            dark_bg = "#073642"
        dark_bg = dark_bg if dark_bg.startswith("#") else f"#{dark_bg}"
        idle_fg = c.get_foreground(dark_bg)
        if not isinstance(idle_fg, str):
            idle_fg = "#ffffff"
        hover = _blend_hex(dark_bg, "#ffffff", 0.12)
        pressed = _blend_hex(dark_bg, "#000000", 0.15)
        active_bg = _blend_hex(dark_bg, "#ffffff", 0.22)
        disabled_fg = _blend_hex(idle_fg, dark_bg, 0.45)
        disabled_fg_active = _blend_hex(idle_fg, dark_bg, 0.35)

        for name in ("SidebarNav.TButton", "SidebarNavActive.TButton"):
            self.style.configure(
                name,
                font=("Microsoft YaHei UI", 11),
                anchor="w",
                borderwidth=0,
                relief="flat",
                padding=(14, 11),
                background=dark_bg,
                foreground=idle_fg,
                focuscolor=dark_bg,
            )
            self.style.map(
                name,
                background=[("active", hover), ("pressed", pressed)],
                foreground=[("disabled", disabled_fg)],
            )
        self.style.configure(
            "SidebarNavActive.TButton",
            font=("Microsoft YaHei UI", 11, "bold"),
            background=active_bg,
            foreground=idle_fg,
            focuscolor=active_bg,
        )
        self.style.map(
            "SidebarNavActive.TButton",
            background=[("active", hover), ("pressed", pressed)],
            foreground=[("disabled", disabled_fg_active)],
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
        self.lbl_status.configure(font=self._status_font_normal, bootstyle=SECONDARY)

    def _append_log(self, text: str) -> None:
        self.txt_log.insert(END, text + "\n")
        self.txt_log.see(END)

    def _probe_tcping(self) -> None:
        p = resolve_tcping_exe()
        if p:
            _log.info("依赖探测 tcping：已找到 path=%s", p)
            messagebox.showinfo("Tcping", f"已找到:\n{p}")
        else:
            _log.warning("依赖探测 tcping：未找到")
            messagebox.showwarning(
                "Tcping",
                "未找到 tcping.exe。\n请将可执行文件置于 ThirdParty/tcping/tcping.exe。点击下方链接下载：\nhttps://www.elifulkerson.com/projects/tcping.php#google_vignette",
            )

    def _probe_tshark(self) -> None:
        p = find_tshark()
        if p:
            _log.info("依赖探测 tshark：已找到 path=%s", p)
            messagebox.showinfo("tshark", f"已找到:\n{p}")
        else:
            _log.warning("依赖探测 tshark：未找到")
            messagebox.showwarning(
                "tshark",
                "未找到 tshark。请先安装 Wireshark（含 Npcap），"
                "或使用「打开 Wireshark 安装包」。",
            )

    def _probe_iperf3(self) -> None:
        p = resolve_iperf3_exe()
        if p:
            _log.info("依赖探测 iperf3：已找到 path=%s", p)
            messagebox.showinfo("Iperf3", f"已找到:\n{p}")
        else:
            _log.warning("依赖探测 iperf3：未找到")
            messagebox.showwarning(
                "Iperf3",
                "未找到 iperf3。\n请将 iperf3.exe 置于 ThirdParty/iperf3/，"
                "或从系统 PATH 中安装 iperf3。官方参考：https://iperf.fr/",
            )

    def _open_wireshark_installer(self) -> None:
        cands = iter_wireshark_installers()
        if not cands:
            _log.warning("打开 Wireshark 安装包：目录内未找到安装程序")
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
            _log.exception("打开 Wireshark 安装包失败 path=%s", path)
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
            _log.exception("打开路径失败 path=%s", path)
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
            ports = parse_ports(self.var_ports.get())
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
            try:
                bw_iperf_parallel = int(self.var_bw_iperf_parallel.get())
            except tk.TclError:
                messagebox.showwarning("校验", "iperf3 并发流数须为整数。")
                return
            if not (1 <= bw_iperf_parallel <= 64):
                messagebox.showwarning("校验", "iperf3 并发流数须在 1–64 之间。")
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
            bandwidth_iperf_parallel=int(self.var_bw_iperf_parallel.get()),
            optional_dns_server=self.var_optional_dns.get().strip(),
            enable_pathping=bool(self.var_adv_pathping.get()),
            enable_tcp_traceroute=bool(self.var_adv_tcp_trace.get()),
            tcp_traceroute_max_hops=int(self.var_adv_tcp_hops.get()),
            enable_http_tls_probe=bool(self.var_adv_http_tls.get()),
            enable_egress_probe=bool(self.var_adv_egress.get()),
            enable_mtu_probe=bool(self.var_adv_mtu.get()),
            enable_history_compare=bool(self.var_adv_history.get()),
        )

        _log.info(
            "发起网络诊断 host=%s ports=%s ping=%s capture=%s traceroute=%s bw=%s "
            "adv(pathping=%s tcp_trace=%s http_tls=%s egress=%s mtu=%s history=%s)",
            host,
            ports,
            opts.enable_ping,
            opts.enable_capture,
            opts.enable_traceroute,
            bw_mode,
            opts.enable_pathping,
            opts.enable_tcp_traceroute,
            opts.enable_http_tls_probe,
            opts.enable_egress_probe,
            opts.enable_mtu_probe,
            opts.enable_history_compare,
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
                _log.exception(
                    "诊断工作线程异常 host=%s ports=%s",
                    opts.target_host,
                    opts.ports,
                )
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
                    _log.error("诊断失败（已向用户提示）: %s", payload)
                    messagebox.showerror("诊断失败", str(payload))
                    self._stop_running_ui()
                    self.btn_run.configure(state=tk.NORMAL)
                    self.lbl_status.configure(text="失败", bootstyle=(INVERSE, DANGER))
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

        _log.info(
            "网络诊断界面汇总完成 task_id=%s overall=%s grade=%s markdown=%s",
            rep.meta.task_id,
            g.overall.value,
            q,
            md,
        )

        if g.overall.value == "ok":
            self.lbl_status.configure(
                text=f"完成（网络质量：{q}）",
                bootstyle=(INVERSE, SUCCESS),
            )
        elif g.overall.value == "degraded":
            self.lbl_status.configure(
                text=f"完成（部分异常或已降级）（网络质量：{q}）",
                bootstyle=(INVERSE, WARNING),
            )
        else:
            self.lbl_status.configure(
                text=f"完成（存在明显问题）（网络质量：{q}）",
                bootstyle=(INVERSE, DANGER),
            )

        self._append_log(f"报告: {md}")


def main_gui() -> None:
    log_dir = setup_runtime_logging()
    log = get_logger("main")
    log.info(
        "启动 %s v%s pid=%s argv=%s log_dir=%s",
        APP_DISPLAY_NAME,
        APP_VERSION,
        os.getpid(),
        sys.argv,
        str(log_dir) if log_dir else "(文件日志未启用)",
    )
    try:
        app = NetworkDiagnosisApp()
        app.mainloop()
    finally:
        log.info("主循环结束")
