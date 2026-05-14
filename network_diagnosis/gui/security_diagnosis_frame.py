"""网络安全诊断页（企业网管向基线检查）。"""

from __future__ import annotations

import os
import queue
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
from network_diagnosis.paths import report_root
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
        self.rowconfigure(3, weight=1)
        self.columnconfigure(0, weight=1)

        hint = ttk.Frame(self, padding=(14, 12, 14, 6))
        hint.grid(row=0, column=0, sticky=EW)
        hint.columnconfigure(0, weight=1)
        lbl_hint = ttk.Label(
            hint,
            text=(
                "本模块用于授权范围内的基线检查：本机可刷新监听端口、防火墙、CPU/GPU/内存、"
                "本地用户与密码策略；临时文件清理请先预览再谨慎执行。"
                "远程 HTTPS / DNS 检查前请确认您对目标拥有书面测试授权。"
            ),
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 10),
            justify=tk.LEFT,
        )
        lbl_hint.grid(row=0, column=0, sticky=EW)
        bind_label_wraplength(lbl_hint, inset=8)

        lf_local = ttk.Labelframe(self, text="本机", padding=(12, 10, 12, 10))
        lf_local.grid(row=1, column=0, sticky=EW, padx=(14, 14), pady=(0, 8))

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
        ttk.Button(
            row_main,
            text="刷新本地用户与密码策略",
            command=self._on_users_policies,
            bootstyle=PRIMARY,
        ).pack(side=tk.LEFT, padx=(0, 8))

        row_clean = ttk.Frame(lf_local)
        row_clean.pack(fill=tk.X, pady=(8, 0))
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

        lf_remote = ttk.Labelframe(self, text="授权目标", padding=(12, 10, 12, 10))
        lf_remote.grid(row=2, column=0, sticky=EW, padx=(14, 14), pady=(0, 8))
        lf_remote.columnconfigure(1, weight=1)

        ttk.Label(lf_remote, text="HTTPS URL", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 8))
        self.var_url = tk.StringVar(value="https://www.baidu.com")
        ttk.Entry(lf_remote, textvariable=self.var_url).grid(row=0, column=1, sticky=EW, padx=(0, 16))

        ttk.Label(lf_remote, text="对比 DNS", bootstyle=SECONDARY).grid(row=0, column=2, sticky=W, padx=(0, 8))
        self.var_dns = tk.StringVar(value="223.5.5.5")
        ttk.Entry(lf_remote, textvariable=self.var_dns, width=16).grid(row=0, column=3, sticky=W)

        self.var_auth = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            lf_remote,
            text="我已确认对目标的测试已获得有效授权",
            variable=self.var_auth,
            bootstyle="round-toggle",
        ).grid(row=1, column=0, columnspan=4, sticky=W, pady=(10, 0))

        btn_r = ttk.Frame(lf_remote)
        btn_r.grid(row=2, column=0, columnspan=4, sticky=W, pady=(10, 0))
        ttk.Button(btn_r, text="检查 TLS 与安全响应头", command=self._on_https, bootstyle=SUCCESS).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(btn_r, text="DNS 对比（系统 vs 上栏 DNS）", command=self._on_dns, bootstyle=SUCCESS).pack(
            side=tk.LEFT, padx=(0, 8)
        )

        out_f = ttk.Frame(self, padding=(14, 0, 14, 14))
        out_f.grid(row=3, column=0, sticky=NSEW)
        out_f.rowconfigure(1, weight=1)
        out_f.columnconfigure(0, weight=1)
        btn_save = ttk.Frame(out_f)
        btn_save.grid(row=0, column=0, sticky=EW, pady=(0, 8))
        ttk.Button(btn_save, text="导出当前结果为 Markdown…", command=self._save_md, bootstyle=INFO).pack(side=tk.LEFT)
        ttk.Button(btn_save, text="清空输出", command=self._clear_out, bootstyle=SECONDARY).pack(
            side=tk.LEFT, padx=(8, 0)
        )

        text_wrap = ttk.Frame(out_f)
        text_wrap.grid(row=1, column=0, sticky=NSEW)
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
        configure_simple_markdown_tags(self.txt, base_font=("Microsoft YaHei UI", 10))

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
