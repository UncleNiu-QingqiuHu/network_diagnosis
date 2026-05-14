"""网络安全诊断页（企业网管向基线检查）。"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox
from urllib.parse import urlparse

import ttkbootstrap as ttk
from ttkbootstrap.constants import END, EW, INFO, NSEW, PRIMARY, SECONDARY, SUCCESS, WARNING, W

from network_diagnosis.gui.main_app_common import bind_label_wraplength
from network_diagnosis.gui.simple_markdown_text import append_simple_markdown, configure_simple_markdown_tags
from network_diagnosis.paths import iter_nmap_installers, report_root, resolve_nmap_exe_path
from network_diagnosis.security_diag.collect import (
    check_https_target_markdown,
    collect_firewall_summary_markdown,
    collect_tcp_listeners_markdown,
    compare_dns_markdown,
    full_report_preamble,
)
from network_diagnosis.security_diag.local_machine import (
    collect_cpu_gpu_markdown,
    collect_memory_markdown,
    collect_users_policies_markdown,
    junk_cleanup_execute_markdown,
    junk_cleanup_preview_markdown,
)
from network_diagnosis.security_diag.port_scan import (
    TCP_SCAN_PRESET_ITEMS,
    authorized_tcp_port_scan_markdown,
)


class SecurityDiagnosisFrame(ttk.Frame):
    def __init__(self, master: tk.Misc, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self._q: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._sections: list[str] = []
        self._build_ui()
        self.after(200, self._poll_queue)

    def on_leave(self) -> None:
        """切换模块时无独占资源。"""

    def _build_ui(self) -> None:
        """左右两列：左列为全部操作；右列仅放置 Markdown 输出与导出按钮。"""
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=0, minsize=360)
        self.columnconfigure(1, weight=1)

        frm_ops = ttk.Frame(self, padding=(14, 12, 8, 12))
        frm_ops.grid(row=0, column=0, sticky=NSEW)

        frm_out = ttk.Frame(self, padding=(8, 12, 14, 12))
        frm_out.grid(row=0, column=1, sticky=NSEW)

        self._build_operation_column(frm_ops)
        self._build_output_column(frm_out)

    def _build_operation_column(self, parent: tk.Misc) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)

        hint = ttk.Labelframe(parent, text="警告", bootstyle=WARNING, padding=(10, 10, 10, 8))
        hint.grid(row=0, column=0, sticky=EW)
        hint.columnconfigure(0, weight=1)

        _hint_md = (
            "本模块用于授权范围内的基线检查：**左侧列为操作区**，**右侧列为输出区**。"
            "本机可刷新监听端口、防火墙、CPU/GPU/内存；本地用户与密码策略与临时清理在同一行，"
            "临时文件清理请先预览再谨慎执行。\n\n"
            "远程 HTTPS / DNS / TCP 端口扫描须在勾选授权后执行；**扫描可能被对端安全设备记录**。"
        )
        txt_hint = tk.Text(
            hint,
            wrap=tk.WORD,
            height=5,
            relief=tk.FLAT,
            padx=4,
            pady=4,
            font=("Microsoft YaHei UI", 10),
            cursor="arrow",
            highlightthickness=0,
            borderwidth=0,
            takefocus=False,
        )
        txt_hint.grid(row=0, column=0, sticky=EW)
        configure_simple_markdown_tags(
            txt_hint,
            base_font=("Microsoft YaHei UI", 10),
            theme_colors=ttk.Style().colors,
        )
        txt_hint.configure(state=tk.NORMAL)
        append_simple_markdown(txt_hint, _hint_md.rstrip() + "\n")
        txt_hint.configure(state=tk.DISABLED)

        lf_local = ttk.Labelframe(parent, text="本机", padding=(12, 10, 12, 10))
        lf_local.grid(row=1, column=0, sticky=EW, pady=(10, 0))
        lf_local.columnconfigure(0, weight=1)

        row_main = ttk.Frame(lf_local)
        row_main.pack(fill=tk.X)
        ttk.Button(row_main, text="刷新 TCP 监听端口", command=self._on_listeners, bootstyle=PRIMARY).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(row_main, text="刷新防火墙摘要", command=self._on_firewall, bootstyle=PRIMARY).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(row_main, text="刷新 CPU / GPU", command=self._on_cpu_gpu, bootstyle=PRIMARY).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(row_main, text="刷新内存", command=self._on_memory, bootstyle=PRIMARY).pack(
            side=tk.LEFT, padx=(0, 8)
        )

        row_clean = ttk.Frame(lf_local)
        row_clean.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(
            row_clean,
            text="刷新本地用户与密码策略",
            command=self._on_users_policies,
            bootstyle=PRIMARY,
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(
            row_clean,
            text="临时文件：预览可清理空间",
            command=self._on_junk_preview,
            bootstyle=SECONDARY,
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(
            row_clean,
            text="临时文件：执行清理（用户 TEMP）",
            command=self._on_junk_execute,
            bootstyle=WARNING,
        ).pack(side=tk.LEFT, padx=(0, 8))

        lf_remote = ttk.Labelframe(parent, text="授权目标", padding=(12, 10, 12, 10))
        lf_remote.grid(row=2, column=0, sticky=NSEW, pady=(10, 0))
        lf_remote.columnconfigure(1, weight=1)

        ttk.Label(lf_remote, text="HTTPS URL", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 8))
        self.var_url = tk.StringVar(value="https://www.baidu.com")
        ttk.Entry(lf_remote, textvariable=self.var_url).grid(row=0, column=1, sticky=EW)

        ttk.Label(lf_remote, text="对比 DNS", bootstyle=SECONDARY).grid(
            row=1, column=0, sticky=W, padx=(0, 8), pady=(8, 0)
        )
        self.var_dns = tk.StringVar(value="223.5.5.5")
        ttk.Entry(lf_remote, textvariable=self.var_dns).grid(row=1, column=1, sticky=EW, pady=(8, 0))

        self.var_auth = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            lf_remote,
            text="我已确认对目标的测试已获得有效授权",
            variable=self.var_auth,
            bootstyle="round-toggle",
        ).grid(row=2, column=0, columnspan=2, sticky=W, pady=(10, 0))

        btn_r = ttk.Frame(lf_remote)
        btn_r.grid(row=3, column=0, columnspan=2, sticky=W, pady=(10, 0))
        ttk.Button(btn_r, text="检查 TLS 与安全响应头", command=self._on_https, bootstyle=SUCCESS).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(btn_r, text="DNS 对比（系统 vs 上栏 DNS）", command=self._on_dns, bootstyle=SUCCESS).pack(
            side=tk.LEFT, padx=(0, 8)
        )

        lf_scan = ttk.Labelframe(lf_remote, text="TCP 端口扫描（单主机 · 仅 IPv4 · 需勾选授权）", padding=(8, 6))
        lf_scan.grid(row=4, column=0, columnspan=2, sticky=EW, pady=(12, 0))
        lf_remote.rowconfigure(4, weight=0)
        lf_remote.rowconfigure(5, weight=1)
        lf_scan.columnconfigure(1, weight=1)

        self._scan_preset_label_to_key = {label: key for key, label in TCP_SCAN_PRESET_ITEMS}
        scan_preset_labels = [label for key, label in TCP_SCAN_PRESET_ITEMS]

        ttk.Label(lf_scan, text="扫描目标", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 8))
        self.var_scan_host = tk.StringVar(value="127.0.0.1")
        ttk.Entry(lf_scan, textvariable=self.var_scan_host).grid(row=0, column=1, sticky=EW)

        ttk.Label(lf_scan, text="端口预设", bootstyle=SECONDARY).grid(
            row=1, column=0, sticky=W, padx=(0, 8), pady=(6, 0)
        )
        self.var_scan_preset_label = tk.StringVar(value=scan_preset_labels[0])
        ttk.Combobox(
            lf_scan,
            textvariable=self.var_scan_preset_label,
            values=scan_preset_labels,
            state="readonly",
            width=28,
        ).grid(row=1, column=1, sticky=EW, pady=(6, 0))

        ttk.Label(lf_scan, text="自定义端口", bootstyle=SECONDARY).grid(
            row=2, column=0, sticky=W, padx=(0, 8), pady=(4, 0)
        )
        self.var_scan_ports = tk.StringVar(value="80,443,8080")
        ttk.Entry(lf_scan, textvariable=self.var_scan_ports).grid(row=2, column=1, sticky=EW, pady=(4, 0))

        opts = ttk.Frame(lf_scan)
        opts.grid(row=3, column=0, columnspan=2, sticky=EW, pady=(6, 0))
        ttk.Label(opts, text="并发", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 4))
        self.var_scan_workers = tk.IntVar(value=50)
        tk.Spinbox(opts, from_=5, to=200, width=5, textvariable=self.var_scan_workers).grid(
            row=0, column=1, sticky=W, padx=(0, 8)
        )
        ttk.Label(opts, text="超时(s)", bootstyle=SECONDARY).grid(row=0, column=2, sticky=W, padx=(0, 4))
        self.var_scan_timeout = tk.StringVar(value="2.0")
        ttk.Entry(opts, textvariable=self.var_scan_timeout, width=6).grid(row=0, column=3, sticky=W, padx=(0, 8))
        self.var_scan_banner = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="抓取 Banner", variable=self.var_scan_banner, bootstyle="round-toggle").grid(
            row=0, column=4, sticky=W, padx=(0, 6)
        )
        self.var_scan_nmap = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="使用 nmap（-sT）", variable=self.var_scan_nmap, bootstyle="round-toggle").grid(
            row=0, column=5, sticky=W
        )

        row_nmap = ttk.Frame(lf_scan)
        row_nmap.grid(row=4, column=0, columnspan=2, sticky=EW, pady=(4, 0))
        row_nmap.columnconfigure(1, weight=1)
        ttk.Label(row_nmap, text="nmap 路径", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 8))
        _nmap_default = resolve_nmap_exe_path() or ""
        self.var_nmap_path = tk.StringVar(value=_nmap_default)
        ttk.Entry(row_nmap, textvariable=self.var_nmap_path).grid(row=0, column=1, sticky=EW)
        row_nmap_btns = ttk.Frame(row_nmap)
        row_nmap_btns.grid(row=1, column=0, columnspan=2, sticky=W, pady=(6, 0))
        ttk.Button(row_nmap_btns, text="检测 Nmap", command=self._on_detect_nmap, bootstyle=SECONDARY).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(row_nmap_btns, text="安装 Nmap", command=self._on_install_nmap, bootstyle=INFO).pack(side=tk.LEFT)
        ttk.Button(row_nmap_btns, text="执行 TCP 端口扫描", command=self._on_tcp_scan, bootstyle=WARNING).pack(
            side=tk.LEFT, padx=(8, 0)
        )

        self.lf_status = ttk.Labelframe(lf_remote, text="任务状态", padding=(12, 14), bootstyle=SECONDARY)
        self.lf_status.grid(row=5, column=0, columnspan=2, sticky=NSEW, pady=(10, 0))
        self.lf_status.columnconfigure(0, weight=1)
        self.lf_status.rowconfigure(0, weight=1)
        self.var_task_status = tk.StringVar(value="就绪")
        self.lbl_task_status = ttk.Label(
            self.lf_status, textvariable=self.var_task_status, bootstyle=SECONDARY, anchor=tk.NW
        )
        self.lbl_task_status.grid(row=0, column=0, sticky=NSEW)
        bind_label_wraplength(self.lbl_task_status, inset=24)
        self._task_progress = ttk.Progressbar(
            self.lf_status,
            mode="indeterminate",
            bootstyle=WARNING,
            length=400,
        )

    def _build_output_column(self, parent: tk.Misc) -> None:
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        lf_out = ttk.Labelframe(parent, text="输出结果", padding=(10, 10, 10, 12))
        lf_out.grid(row=0, column=0, sticky=NSEW)
        lf_out.columnconfigure(0, weight=1)

        btn_save = ttk.Frame(lf_out)
        btn_save.grid(row=0, column=0, sticky=EW, pady=(0, 8))
        ttk.Button(btn_save, text="导出当前结果为 Markdown…", command=self._save_md, bootstyle=INFO).pack(side=tk.LEFT)
        ttk.Button(btn_save, text="清空输出", command=self._clear_out, bootstyle=SECONDARY).pack(
            side=tk.LEFT, padx=(8, 0)
        )

        text_wrap = ttk.Frame(lf_out)
        text_wrap.grid(row=1, column=0, sticky=NSEW)
        lf_out.rowconfigure(1, weight=1)
        text_wrap.rowconfigure(0, weight=1)
        text_wrap.columnconfigure(0, weight=1)

        self.txt = tk.Text(
            text_wrap,
            height=18,
            wrap=tk.WORD,
            font=("Microsoft YaHei UI", 10),
            relief=tk.FLAT,
            padx=8,
            pady=8,
        )
        vsb = ttk.Scrollbar(text_wrap, orient=tk.VERTICAL, command=self.txt.yview)
        self.txt.configure(yscrollcommand=vsb.set)
        self.txt.grid(row=0, column=0, sticky=NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        configure_simple_markdown_tags(
            self.txt,
            base_font=("Microsoft YaHei UI", 10),
            theme_colors=ttk.Style().colors,
        )

    def _on_detect_nmap(self) -> None:
        p = resolve_nmap_exe_path()
        if p:
            self.var_nmap_path.set(p)
            messagebox.showinfo("Nmap", f"已找到并填入路径：\n{p}")
            return
        messagebox.showwarning(
            "Nmap",
            "未找到 nmap。\n"
            "请安装至默认目录或加入系统 PATH，或将 nmap.exe 置于 ThirdParty/Nmap/；"
            "也可将官方 Windows 安装包放入 ThirdParty/Nmap/ 后点击「安装 Nmap」。\n"
            "下载：https://nmap.org/download.html",
        )

    def _on_install_nmap(self) -> None:
        cands = iter_nmap_installers()
        if not cands:
            messagebox.showwarning(
                "Nmap",
                "未在 ThirdParty/Nmap/ 下找到 .exe 安装包。\n"
                "请将官方 Windows 安装程序放入该目录。\n"
                "下载：https://nmap.org/download.html",
            )
            return
        path = str(cands[0])
        try:
            if sys.platform == "win32":
                os.startfile(path)  # noqa: S606
            else:
                subprocess.Popen(["xdg-open", path])  # noqa: S603, S607
        except OSError as e:
            messagebox.showerror("Nmap", f"无法打开安装包：{e}")

    def _clear_out(self) -> None:
        self._sections.clear()
        self.txt.configure(state=tk.NORMAL)
        self.txt.delete("1.0", END)
        self.txt.configure(state=tk.DISABLED)

    def _append_md(self, chunk: str) -> None:
        self._sections.append(chunk.strip())
        self.txt.configure(state=tk.NORMAL)
        md = chunk if chunk.endswith("\n") else chunk + "\n"
        append_simple_markdown(self.txt, md)
        self.txt.insert(END, "\n")
        self.txt.see(END)
        self.txt.configure(state=tk.DISABLED)

    def _set_task_status(self, text: str, *, running: bool = False) -> None:
        try:
            self.var_task_status.set(text)
            self.lbl_task_status.configure(bootstyle=WARNING if running else SECONDARY)
            if running:
                self.lf_status.configure(bootstyle=WARNING)
                self._task_progress.grid(row=1, column=0, sticky=EW, pady=(10, 0))
                self._task_progress.start(14)
            else:
                try:
                    self._task_progress.stop()
                except tk.TclError:
                    pass
                self._task_progress.grid_remove()
                self.lf_status.configure(bootstyle=SECONDARY)
        except tk.TclError:
            pass

    def _run_bg(self, title: str, fn) -> None:
        if self._busy:
            messagebox.showinfo("安全诊断", "上一项任务仍在运行，请稍候。")
            return

        def work() -> None:
            try:
                out = fn()
                self._q.put(("ok", (title, out)))
            except Exception as e:  # noqa: BLE001 — 将采集异常展示到输出区
                self._q.put(("err", str(e)))
            finally:
                self._q.put(("done", None))

        self._busy = True
        self._set_task_status(f"运行中：{title}", running=True)
        threading.Thread(target=work, daemon=True).start()

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "ok":
                    title, text = payload
                    self._append_md(f"## 〉{title}\n\n{text}\n")
                elif kind == "err":
                    self._append_md(f"## 〉错误\n\n```\n{payload}\n```\n")
                elif kind == "done":
                    self._busy = False
                    self._set_task_status("就绪", running=False)
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)

    def _on_listeners(self) -> None:
        self._run_bg("TCP 监听端口", collect_tcp_listeners_markdown)

    def _on_firewall(self) -> None:
        self._run_bg("防火墙摘要", collect_firewall_summary_markdown)

    def _on_cpu_gpu(self) -> None:
        self._run_bg("CPU / GPU", collect_cpu_gpu_markdown)

    def _on_memory(self) -> None:
        self._run_bg("内存", collect_memory_markdown)

    def _on_users_policies(self) -> None:
        self._run_bg("本地用户与密码策略", collect_users_policies_markdown)

    def _on_junk_preview(self) -> None:
        self._run_bg("临时文件清理（预览）", junk_cleanup_preview_markdown)

    def _on_junk_execute(self) -> None:
        if self._busy:
            messagebox.showinfo("安全诊断", "上一项任务仍在运行，请稍候。")
            return
        if sys.platform != "win32":
            messagebox.showwarning("安全诊断", "临时文件清理当前仅支持 Windows。")
            return
        if not messagebox.askyesno(
            "确认清理",
            "将尝试删除当前用户 TEMP、LOCALAPPDATA\\Temp 目录下的文件。\n"
            "已锁定或无权删除的文件会自动跳过。\n\n"
            "不包含系统目录 Windows\\Temp。\n\n是否继续？",
        ):
            return
        self._run_bg("临时文件清理（已执行）", junk_cleanup_execute_markdown)

    def _on_https(self) -> None:
        if not self.var_auth.get():
            messagebox.showwarning(
                "安全诊断",
                "请先勾选「我已确认对目标的测试已获得有效授权」后再执行远程检查。",
            )
            return
        url = self.var_url.get().strip()
        self._run_bg("HTTPS / 安全响应头", lambda u=url: check_https_target_markdown(u))

    def _on_dns(self) -> None:
        if not self.var_auth.get():
            messagebox.showwarning(
                "安全诊断",
                "请先勾选「我已确认对目标的测试已获得有效授权」后再执行远程检查。",
            )
            return
        url = self.var_url.get().strip()
        u = url
        if not u.lower().startswith(("http://", "https://")):
            u = "https://" + u
        host = urlparse(u).hostname
        if not host:
            messagebox.showwarning("安全诊断", "无法从 URL 解析主机名；请填写有效 HTTPS URL。")
            return
        alt = self.var_dns.get().strip()
        self._run_bg("DNS 对比", lambda h=host, d=alt: compare_dns_markdown(h, d))

    def _on_tcp_scan(self) -> None:
        if not self.var_auth.get():
            messagebox.showwarning(
                "安全诊断",
                "请先勾选「我已确认对目标的测试已获得有效授权」后再执行端口扫描。",
            )
            return
        host = self.var_scan_host.get().strip()
        if not host:
            messagebox.showwarning("安全诊断", "请填写扫描目标（主机名或 IPv4）。")
            return
        label = self.var_scan_preset_label.get()
        preset_key = self._scan_preset_label_to_key.get(label, "web_common")
        custom_spec = self.var_scan_ports.get().strip()
        if preset_key == "custom" and not custom_spec:
            messagebox.showwarning("安全诊断", "预设为「自定义端口列表」时，请在「自定义端口」中填写端口列表。")
            return
        try:
            workers = int(self.var_scan_workers.get())
        except tk.TclError:
            messagebox.showwarning("安全诊断", "并发数无效。")
            return
        try:
            timeout_sec = float(self.var_scan_timeout.get().strip())
        except ValueError:
            messagebox.showwarning("安全诊断", "单端口超时须为数字（秒），例如 2.0。")
            return
        grab_banner = self.var_scan_banner.get()
        use_nmap = self.var_scan_nmap.get()
        nmap_path = self.var_nmap_path.get().strip()

        def run_scan() -> str:
            return authorized_tcp_port_scan_markdown(
                host=host,
                preset_key=preset_key,
                custom_ports_spec=custom_spec,
                max_workers=workers,
                timeout_sec=timeout_sec,
                grab_banner=grab_banner,
                use_nmap=use_nmap,
                nmap_exe_path=nmap_path,
            )

        self._run_bg("TCP 端口扫描", run_scan)

    def _save_md(self) -> None:
        if not self._sections:
            messagebox.showinfo("安全诊断", "暂无输出可导出。")
            return
        body = "\n\n".join(self._sections)
        full = full_report_preamble() + "\n\n" + body
        d = report_root() / "security_diagnosis"
        d.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = d / f"security_diag_{ts}.md"
        path.write_text(full, encoding="utf-8")
        messagebox.showinfo("安全诊断", f"已保存：\n{path}")
        if sys.platform == "win32":
            try:
                os.startfile(str(path))
            except OSError:
                pass
