"""ttkbootstrap 主界面：工作线程 + 队列回灌。"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
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

from network_diagnosis.paths import find_tshark, iter_wireshark_installers
from network_diagnosis.runner import RunOptions, run_diagnostic


def _parse_ports(text: str) -> list[int]:
    out: list[int] = []
    for part in text.replace(";", ",").split(","):
        p = part.strip()
        if not p:
            continue
        out.append(int(p))
    return sorted(set(out))


class NetworkDiagnosisApp(ttk.Window):
    def __init__(self) -> None:
        super().__init__(themename="flatly")
        self.title("网络诊断工具")
        self.minsize(960, 680)
        self.geometry("1180x800")

        self._queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._status_font_normal = ("Microsoft YaHei UI", 10)
        self._status_font_running = ("Microsoft YaHei UI", 14, "bold")

        outer = ttk.Frame(self, padding=(16, 14, 16, 12))
        outer.pack(fill=BOTH, expand=True)
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)

        pw_main = ttk.Panedwindow(outer, orient=tk.HORIZONTAL)
        pw_main.grid(row=0, column=0, sticky=NSEW)

        left = ttk.Frame(pw_main, padding=(0, 0, 10, 0))
        right = ttk.Frame(pw_main, padding=(10, 0, 0, 0))
        pw_main.add(left, weight=1)
        pw_main.add(right, weight=3)
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

        ttk.Label(lf_target, text="TCP 端口", bootstyle=SECONDARY).grid(
            row=1, column=0, sticky=W, padx=(0, 12), pady=(0, 2)
        )
        self.var_ports = tk.StringVar(value="80,443")
        ttk.Entry(lf_target, textvariable=self.var_ports, bootstyle=PRIMARY).grid(
            row=1, column=1, sticky=EW, pady=(0, 2)
        )
        ttk.Label(
            lf_target,
            text="多个端口请用英文逗号分隔，例如 80,443,8080",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 8),
        ).grid(row=2, column=1, sticky=W)

        lf_opts = ttk.Labelframe(left, text="探测选项", padding=(12, 10, 12, 12))
        lf_opts.pack(fill=tk.X, pady=(0, 8))
        for c in (1, 3):
            lf_opts.columnconfigure(c, weight=1)

        self.var_samples = tk.IntVar(value=4)
        self.var_timeout = tk.IntVar(value=1000)
        self.var_ping = tk.BooleanVar(value=True)
        self.var_capture = tk.BooleanVar(value=False)
        self.var_ipv6 = tk.BooleanVar(value=False)

        ttk.Label(lf_opts, text="每端口采样次数").grid(row=0, column=0, sticky=W, padx=(0, 8), pady=4)
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

        chk_row = ttk.Frame(lf_opts)
        chk_row.grid(row=1, column=0, columnspan=4, sticky=EW, pady=(10, 0))
        chk_col = ttk.Frame(chk_row)
        chk_col.pack(anchor=W)
        ttk.Checkbutton(
            chk_col,
            text="ICMP ping",
            variable=self.var_ping,
            bootstyle="round-toggle",
        ).pack(anchor=W, pady=(0, 4))
        ttk.Checkbutton(
            chk_col,
            text="抓包（需 tshark + Npcap）",
            variable=self.var_capture,
            bootstyle="round-toggle",
        ).pack(anchor=W, pady=(0, 4))
        ttk.Checkbutton(
            chk_col,
            text="优先 IPv6",
            variable=self.var_ipv6,
            bootstyle="round-toggle",
        ).pack(anchor=W)

        ttk.Separator(left, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(4, 10))

        actions = ttk.Frame(left)
        actions.pack(fill=tk.X, pady=(0, 6))
        actions.columnconfigure(1, weight=1)

        self.btn_run = ttk.Button(
            actions,
            text="开始诊断",
            command=self._on_run,
            bootstyle=SUCCESS,
            width=14,
        )
        self.btn_run.grid(row=0, column=0, sticky=W)

        tools = ttk.Frame(actions)
        tools.grid(row=1, column=0, columnspan=2, sticky=W, pady=(8, 0))
        ttk.Button(
            tools,
            text="Wireshark 安装包",
            command=self._open_wireshark_installer,
            bootstyle=INFO,
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(
            tools,
            text="检测 tshark",
            command=self._probe_tshark,
            bootstyle=SECONDARY,
        ).pack(side=tk.LEFT)

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
            wraplength=280,
            justify=tk.LEFT,
        )
        self.lbl_status.pack(fill=tk.X)
        self._run_progress = ttk.Progressbar(
            status_shell,
            mode="indeterminate",
            bootstyle=WARNING,
            length=280,
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

        # —— 右侧：结论（上）+ 进度与详情（下，占更大垂直空间）——
        right.rowconfigure(0, weight=1)
        right.rowconfigure(1, weight=4)
        right.columnconfigure(0, weight=1)

        lf_summary = ttk.Labelframe(right, text="结论（非技术摘要）", padding=(10, 8, 10, 10))
        lf_summary.grid(row=0, column=0, sticky=NSEW, pady=(0, 8))
        lf_summary.rowconfigure(0, weight=1)
        lf_summary.columnconfigure(0, weight=1)

        self.txt_summary = ScrolledText(
            lf_summary,
            height=5,
            wrap=tk.WORD,
            font=("Microsoft YaHei UI", 10),
            relief=tk.FLAT,
            padx=6,
            pady=6,
        )
        self.txt_summary.grid(row=0, column=0, sticky=NSEW)

        lf_log = ttk.Labelframe(right, text="进度与详情", padding=(10, 8, 10, 10))
        lf_log.grid(row=1, column=0, sticky=NSEW)
        lf_log.rowconfigure(0, weight=1)
        lf_log.columnconfigure(0, weight=1)

        self.txt_log = ScrolledText(
            lf_log,
            height=22,
            wrap=tk.WORD,
            font=("Consolas", 9),
            relief=tk.FLAT,
            padx=6,
            pady=6,
        )
        self.txt_log.grid(row=0, column=0, sticky=NSEW)

        self._last_md: str | None = None
        self._last_dir: str | None = None

        self.after(200, self._poll_queue)
        self.after_idle(self._init_main_sash)

    def _init_main_sash(self) -> None:
        """初次分配左右栏宽度（左侧约 34%）。"""
        try:
            w = max(self.winfo_width(), 700)
            self._pw_main.sashpos(0, int(w * 0.34))
        except tk.TclError:
            pass

    def _start_running_ui(self) -> None:
        self._status_shell.configure(bootstyle=WARNING)
        self.lbl_status.configure(
            text="正在运行诊断\n请留意右侧「进度与详情」中的实时输出。",
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
                "未在 ThirdParty/Wireshark/ 下找到 .exe 安装包。\n请将官方安装程序放入该目录。",
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
        if not ports:
            messagebox.showwarning("校验", "请至少填写一个端口。")
            return

        opts = RunOptions(
            target_host=host,
            ports=ports,
            samples_per_port=int(self.var_samples.get()),
            tcp_timeout_ms=int(self.var_timeout.get()),
            enable_ping=bool(self.var_ping.get()),
            enable_capture=bool(self.var_capture.get()),
            prefer_ipv6=bool(self.var_ipv6.get()),
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
                    from network_diagnosis.model.report import DiagnosticReport

                    rep: DiagnosticReport = payload  # type: ignore[assignment]
                    self._render_report(rep)
                    self.btn_run.configure(state=tk.NORMAL)
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)

    def _render_report(self, rep) -> None:
        from network_diagnosis.model.report import DiagnosticReport

        assert isinstance(rep, DiagnosticReport)
        self._stop_running_ui()
        g = rep.gui
        self.txt_summary.insert(END, g.headline + "\n\n", ("head",))
        self.txt_summary.tag_configure("head", font=("Microsoft YaHei UI", 11, "bold"))
        for b in g.bullets:
            self.txt_summary.insert(END, "• " + b + "\n")
        self.txt_summary.insert(
            END,
            "\n若需技术人员排查，请使用下方按钮打开 Markdown 报告（含完整路径与原始日志索引）。\n",
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
