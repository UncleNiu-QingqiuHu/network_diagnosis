"""DHCP 诊断页：本机客户端 + 多 DHCP 服务器（污染）探测。"""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox

import ttkbootstrap as ttk
from ttkbootstrap.constants import END, EW, INFO, LEFT, NSEW, PRIMARY, SECONDARY, VERTICAL, WARNING, W

from network_diagnosis.dhcp.client import format_address_source
from network_diagnosis.dhcp.config import (
    DhcpDiagnosisSettings,
    load_dhcp_diagnosis_settings,
    save_dhcp_diagnosis_settings,
)
from network_diagnosis.dhcp.engine import run_dhcp_diagnosis
from network_diagnosis.dhcp.models import DhcpDiagnosisResult, DhcpProbeRound
from network_diagnosis.dhcp.report_md import render_dhcp_diagnosis_markdown
from network_diagnosis.gui.simple_markdown_text import append_simple_markdown, configure_simple_markdown_tags
from network_diagnosis.host_l3_info import list_local_ipv4_adapters
from network_diagnosis.paths import dhcp_diagnosis_report_dir, resolve_nmap_exe_path
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)

_SEV_BOOT = {"info": INFO, "medium": WARNING, "high": "danger"}


class DhcpDiagnosisFrame(ttk.Frame):
    def __init__(self, master: tk.Misc, app: tk.Misc | None = None, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self._app = app
        self._q: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._worker: threading.Thread | None = None
        self._cancel_event = threading.Event()
        self._last_result: DhcpDiagnosisResult | None = None
        self._last_report_dir: Path | None = None
        self._build_ui()
        self._load_settings_to_form()
        self.after(180, self._poll_queue)

    def on_leave(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            self._cancel_event.set()

    def on_show(self) -> None:
        self._refresh_interface_choices()

    def _build_ui(self) -> None:
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        pw = ttk.Panedwindow(self, orient=tk.VERTICAL)
        pw.grid(row=0, column=0, sticky=NSEW)

        frm_ops = ttk.Frame(pw, padding=(14, 12, 14, 8))
        frm_out = ttk.Frame(pw, padding=(14, 8, 14, 14))
        pw.add(frm_ops, weight=0)
        pw.add(frm_out, weight=1)

        frm_ops.columnconfigure(0, weight=1)
        frm_out.rowconfigure(0, weight=1)
        frm_out.columnconfigure(0, weight=1)

        hint = ttk.Labelframe(frm_ops, text="合规提示", bootstyle=WARNING, padding=(10, 10, 10, 8))
        hint.grid(row=0, column=0, sticky=EW)
        hint.columnconfigure(0, weight=1)
        hint_msg = (
            "本模块会读取本机 **ipconfig /all** 与 DHCP 客户端事件日志；在勾选授权后将通过 **Nmap** "
            "发送 **DHCP DISCOVER**，用于检测 **多 DHCP 服务器（DHCP 污染）**。\n"
            "探测可能被安全设备记录；仅用于 **已获得授权** 的内网。"
        )
        txt_hint = tk.Text(
            hint,
            wrap=tk.WORD,
            height=4,
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
        configure_simple_markdown_tags(txt_hint, base_font=("Microsoft YaHei UI", 10), theme_colors=ttk.Style().colors)
        txt_hint.configure(state=tk.NORMAL)
        append_simple_markdown(txt_hint, hint_msg.rstrip() + "\n")
        txt_hint.configure(state=tk.DISABLED)

        lf = ttk.Labelframe(frm_ops, text="诊断参数", padding=(12, 10, 12, 10))
        lf.grid(row=1, column=0, sticky=EW, pady=(10, 0))
        lf.columnconfigure(1, weight=1)

        ttk.Label(lf, text="绑定接口").grid(row=0, column=0, sticky=W, pady=(0, 6))
        self.var_interface = tk.StringVar(value="")
        self.cmb_interface = ttk.Combobox(lf, textvariable=self.var_interface, state="readonly")
        self.cmb_interface.grid(row=0, column=1, sticky=EW, pady=(0, 6), padx=(8, 0))

        ttk.Label(lf, text="合法 DHCP").grid(row=1, column=0, sticky=W)
        self.var_whitelist = tk.StringVar(value="")
        ttk.Entry(lf, textvariable=self.var_whitelist).grid(row=1, column=1, sticky=EW, padx=(8, 0))
        ttk.Label(lf, text="逗号分隔，用于识别非法 DHCP", bootstyle=SECONDARY).grid(
            row=2, column=1, sticky=W, padx=(8, 0), pady=(2, 6)
        )

        ttk.Label(lf, text="作用域 CIDR").grid(row=3, column=0, sticky=W)
        self.var_scope = tk.StringVar(value="")
        ttk.Entry(lf, textvariable=self.var_scope).grid(row=3, column=1, sticky=EW, padx=(8, 0))
        ttk.Label(lf, text="可选；用于检测静态 IP 是否落在 DHCP 池", bootstyle=SECONDARY).grid(
            row=4, column=1, sticky=W, padx=(8, 0), pady=(2, 6)
        )

        row_probe = ttk.Frame(lf)
        row_probe.grid(row=5, column=0, columnspan=2, sticky=EW)
        ttk.Label(row_probe, text="探测轮次").pack(side=LEFT)
        self.var_rounds = tk.IntVar(value=3)
        ttk.Spinbox(row_probe, from_=1, to=5, textvariable=self.var_rounds, width=5).pack(side=LEFT, padx=(6, 16))
        ttk.Label(row_probe, text="Nmap 路径").pack(side=LEFT)
        self.var_nmap = tk.StringVar(value=resolve_nmap_exe_path() or "")
        ttk.Entry(row_probe, textvariable=self.var_nmap, width=36).pack(side=LEFT, padx=(6, 6))
        ttk.Button(row_probe, text="检测", command=self._on_detect_nmap, bootstyle=SECONDARY).pack(side=LEFT)

        self.var_authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            lf,
            text="我已确认对目标网段已获得有效授权（含 DHCP DISCOVER 探测）",
            variable=self.var_authorized,
            bootstyle="round-toggle",
        ).grid(row=6, column=0, columnspan=2, sticky=W, pady=(10, 0))

        actions = ttk.Frame(frm_ops)
        actions.grid(row=2, column=0, sticky=EW, pady=(10, 0))
        actions.columnconfigure(5, weight=1)

        self.btn_start = ttk.Button(actions, text="开始诊断", command=self._on_start, bootstyle=PRIMARY)
        self.btn_start.grid(row=0, column=0, padx=(0, 8))
        self.btn_stop = ttk.Button(
            actions, text="停止", command=self._on_stop, bootstyle=SECONDARY, state=tk.DISABLED
        )
        self.btn_stop.grid(row=0, column=1, padx=(0, 8))
        ttk.Button(actions, text="导出 Markdown…", command=self._on_export, bootstyle=SECONDARY).grid(
            row=0, column=2, padx=(0, 8)
        )
        ttk.Button(actions, text="打开报告目录", command=self._on_open_report_dir, bootstyle=SECONDARY).grid(
            row=0, column=3, padx=(0, 8)
        )
        ttk.Button(actions, text="→ MAC 扫描", command=self._go_mac_scan, bootstyle=INFO).grid(
            row=0, column=4, padx=(0, 8)
        )
        self.lbl_status = ttk.Label(actions, text="就绪。", bootstyle=INFO)
        self.lbl_status.grid(row=0, column=5, sticky=EW)

        nb = ttk.Notebook(frm_out)
        nb.grid(row=0, column=0, sticky=NSEW)

        tab_client = ttk.Frame(nb, padding=(8, 8))
        tab_probe = ttk.Frame(nb, padding=(8, 8))
        tab_verdict = ttk.Frame(nb, padding=(8, 8))
        tab_raw = ttk.Frame(nb, padding=(8, 8))
        nb.add(tab_client, text="  本机摘要  ")
        nb.add(tab_probe, text="  DHCP 探测  ")
        nb.add(tab_verdict, text="  结论建议  ")
        nb.add(tab_raw, text="  原始证据  ")

        for tab in (tab_client, tab_probe):
            tab.rowconfigure(0, weight=1)
            tab.columnconfigure(0, weight=1)

        cols_client = ("iface", "source", "ip", "dhcp_srv", "lease", "flags")
        self.tree_client = ttk.Treeview(tab_client, columns=cols_client, show="headings", height=12)
        for c, h, w in (
            ("iface", "接口", 160),
            ("source", "地址来源", 72),
            ("ip", "IPv4", 120),
            ("dhcp_srv", "DHCP 服务器", 120),
            ("lease", "租约到期", 140),
            ("flags", "健康标记", 180),
        ):
            self.tree_client.heading(c, text=h)
            self.tree_client.column(c, width=w, anchor=tk.W)
        sy1 = ttk.Scrollbar(tab_client, orient=VERTICAL, command=self.tree_client.yview)
        self.tree_client.configure(yscrollcommand=sy1.set)
        self.tree_client.grid(row=0, column=0, sticky=NSEW)
        sy1.grid(row=0, column=1, sticky="ns")

        cols_probe = ("round", "server", "yiaddr", "router", "dns", "whitelist")
        self.tree_probe = ttk.Treeview(tab_probe, columns=cols_probe, show="headings", height=12)
        for c, h, w in (
            ("round", "轮次", 48),
            ("server", "Server ID", 120),
            ("yiaddr", "建议 IP", 120),
            ("router", "网关", 120),
            ("dns", "DNS", 160),
            ("whitelist", "白名单", 64),
        ):
            self.tree_probe.heading(c, text=h)
            self.tree_probe.column(c, width=w, anchor=tk.W)
        sy2 = ttk.Scrollbar(tab_probe, orient=VERTICAL, command=self.tree_probe.yview)
        self.tree_probe.configure(yscrollcommand=sy2.set)
        self.tree_probe.grid(row=0, column=0, sticky=NSEW)
        sy2.grid(row=0, column=1, sticky="ns")

        tab_verdict.rowconfigure(0, weight=1)
        tab_verdict.columnconfigure(0, weight=1)
        self.txt_verdict = tk.Text(
            tab_verdict,
            wrap=tk.WORD,
            font=("Microsoft YaHei UI", 11),
            relief=tk.FLAT,
            padx=8,
            pady=8,
        )
        self.txt_verdict.grid(row=0, column=0, sticky=NSEW)

        tab_raw.rowconfigure(0, weight=1)
        tab_raw.columnconfigure(0, weight=1)
        self.txt_raw = tk.Text(
            tab_raw,
            wrap=tk.NONE,
            font=("Consolas", 10),
            relief=tk.FLAT,
            padx=6,
            pady=6,
        )
        sx = ttk.Scrollbar(tab_raw, orient=tk.HORIZONTAL, command=self.txt_raw.xview)
        sy3 = ttk.Scrollbar(tab_raw, orient=VERTICAL, command=self.txt_raw.yview)
        self.txt_raw.configure(xscrollcommand=sx.set, yscrollcommand=sy3.set)
        self.txt_raw.grid(row=0, column=0, sticky=NSEW)
        sy3.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky=EW)

        self.lbl_verdict_banner = ttk.Label(frm_out, text="", bootstyle=INFO)
        self.lbl_verdict_banner.grid(row=1, column=0, sticky=EW, pady=(8, 0))

        self._apply_busy(False)
        self.after_idle(self._refresh_interface_choices)

    def _load_settings_to_form(self) -> None:
        s = load_dhcp_diagnosis_settings()
        if s.authorized_dhcp_servers:
            self.var_whitelist.set(", ".join(s.authorized_dhcp_servers))
        self.var_scope.set(s.dhcp_scope_cidr)

    def _save_settings_from_form(self) -> None:
        raw = self.var_whitelist.get().strip()
        servers = tuple(x.strip() for x in raw.replace(";", ",").split(",") if x.strip())
        save_dhcp_diagnosis_settings(
            DhcpDiagnosisSettings(
                authorized_dhcp_servers=servers,
                dhcp_scope_cidr=self.var_scope.get().strip(),
            )
        )

    def _refresh_interface_choices(self) -> None:
        adapters, note = list_local_ipv4_adapters()
        choices: list[str] = []
        preferred = ""
        for b in adapters:
            label = f"{b.description} — {b.ipv4}/{b.netmask}"
            choices.append(label)
            if b.gateways and not preferred:
                preferred = label
        self.cmb_interface.configure(values=choices)
        if preferred and not self.var_interface.get():
            self.var_interface.set(preferred)
        elif choices and not self.var_interface.get():
            self.var_interface.set(choices[0])
        if note:
            self.lbl_status.configure(text=note)

    def _selected_interface_ipv4(self) -> str | None:
        label = self.var_interface.get().strip()
        if not label:
            return None
        if " — " in label:
            rest = label.split(" — ", 1)[1]
            return rest.split("/", 1)[0].strip()
        return None

    def _apply_busy(self, busy: bool) -> None:
        self._busy = busy
        self.btn_start.configure(state=tk.DISABLED if busy else tk.NORMAL)
        self.btn_stop.configure(state=tk.NORMAL if busy else tk.DISABLED)

    def _on_detect_nmap(self) -> None:
        p = resolve_nmap_exe_path()
        if p:
            self.var_nmap.set(p)
            messagebox.showinfo("DHCP 诊断", f"已找到 Nmap：\n{p}", parent=self)
        else:
            messagebox.showwarning(
                "DHCP 诊断",
                "未找到 nmap。请安装至默认目录、加入 PATH，或置于 ThirdParty/Nmap/。",
                parent=self,
            )

    def _on_stop(self) -> None:
        self._cancel_event.set()
        self.lbl_status.configure(text="正在停止…")

    def _on_start(self) -> None:
        if self._busy:
            return
        if sys.platform != "win32":
            messagebox.showwarning("DHCP 诊断", "当前实现主要针对 Windows。", parent=self)
        if not self.var_authorized.get():
            messagebox.showwarning("DHCP 诊断", "请先勾选授权确认。", parent=self)
            return
        iface_ip = self._selected_interface_ipv4()
        if not iface_ip:
            messagebox.showwarning("DHCP 诊断", "请选择绑定接口。", parent=self)
            return

        self._save_settings_from_form()
        raw_wl = self.var_whitelist.get().strip()
        authorized = tuple(x.strip() for x in raw_wl.replace(";", ",").split(",") if x.strip())
        try:
            rounds = int(self.var_rounds.get())
        except tk.TclError:
            rounds = 3

        self._clear_results_ui()
        self._cancel_event.clear()
        self._apply_busy(True)
        self.lbl_status.configure(text="诊断进行中…")

        def worker() -> None:
            try:

                def on_prog(msg: str) -> None:
                    self._q.put(("prog", msg))

                def on_round(r: DhcpProbeRound) -> None:
                    self._q.put(("round", r))

                result = run_dhcp_diagnosis(
                    interface_ipv4=iface_ip,
                    authorized_servers=authorized,
                    scope_cidr=self.var_scope.get().strip(),
                    probe_enabled=self.var_authorized.get(),
                    probe_rounds=rounds,
                    probe_timeout_sec=10,
                    nmap_exe_path=self.var_nmap.get().strip(),
                    cancel_event=self._cancel_event,
                    on_progress=on_prog,
                    on_round=on_round,
                )
                self._q.put(("done", result))
            except Exception as e:
                _log.exception("DHCP 诊断失败")
                self._q.put(("error", str(e)))

        self._worker = threading.Thread(target=worker, daemon=True)
        self._worker.start()

    def _clear_results_ui(self) -> None:
        for t in (self.tree_client, self.tree_probe):
            for iid in t.get_children():
                t.delete(iid)
        self.txt_verdict.configure(state=tk.NORMAL)
        self.txt_verdict.delete("1.0", tk.END)
        self.txt_verdict.configure(state=tk.DISABLED)
        self.txt_raw.configure(state=tk.NORMAL)
        self.txt_raw.delete("1.0", tk.END)
        self.txt_raw.configure(state=tk.DISABLED)
        self.lbl_verdict_banner.configure(text="")

    def _fill_result(self, result: DhcpDiagnosisResult) -> None:
        self._last_result = result
        self._last_report_dir = dhcp_diagnosis_report_dir(result.task_id)

        for c in result.clients:
            lease = c.lease_expires.strftime("%Y-%m-%d %H:%M") if c.lease_expires else "—"
            flags = "，".join(c.health_flags) if c.health_flags else "—"
            self.tree_client.insert(
                "",
                END,
                values=(
                    c.interface_name,
                    format_address_source(c.address_source),
                    c.ipv4,
                    c.dhcp_server or "—",
                    lease,
                    flags,
                ),
            )

        for r in result.probe_rounds:
            if not r.offers:
                self.tree_probe.insert("", END, values=(r.round_index, "—", "—", "—", "—", "无 OFFER"))
                continue
            for o in r.offers:
                self.tree_probe.insert(
                    "",
                    END,
                    values=(
                        r.round_index,
                        o.server_id,
                        o.yiaddr or "—",
                        o.router or "—",
                        ", ".join(o.dns) if o.dns else "—",
                        "是" if o.in_whitelist else "否",
                    ),
                )

        lines = []
        if result.conclusions:
            lines.append("【结论】")
            lines.extend(f"• {x}" for x in result.conclusions)
        if result.recommendations:
            lines.append("")
            lines.append("【建议】")
            lines.extend(f"• {x}" for x in result.recommendations)
        if result.probe_skipped_reason:
            lines.extend(["", f"（探测说明）{result.probe_skipped_reason}"])

        self.txt_verdict.configure(state=tk.NORMAL)
        self.txt_verdict.delete("1.0", tk.END)
        self.txt_verdict.insert("1.0", "\n".join(lines) if lines else "（无）")
        self.txt_verdict.configure(state=tk.DISABLED)

        raw_parts = []
        if result.event_log_excerpt:
            raw_parts.append("=== DHCP 客户端事件日志 ===\n" + result.event_log_excerpt)
        if result.nmap_combined_output:
            raw_parts.append("=== Nmap ===\n" + result.nmap_combined_output)
        if result.ipconfig_excerpt:
            raw_parts.append("=== ipconfig 节选 ===\n" + result.ipconfig_excerpt[:6000])
        self.txt_raw.configure(state=tk.NORMAL)
        self.txt_raw.delete("1.0", tk.END)
        self.txt_raw.insert("1.0", "\n\n".join(raw_parts) if raw_parts else "（无）")
        self.txt_raw.configure(state=tk.DISABLED)

        boot = _SEV_BOOT.get(result.severity, INFO)
        labels = {
            "MULTIPLE_DHCP_SERVERS": "疑似 DHCP 污染（多 DHCP 服务器）",
            "MULTIPLE_DHCP_SERVERS_HA": "多 DHCP 服务器（可能热备）",
            "UNKNOWN_DHCP_SERVER": "未知 DHCP 服务器",
            "NO_DHCP_OFFERS": "未收到 DHCP OFFER",
            "CLIENT_ISSUES": "本机 DHCP 客户端异常",
            "PROBE_SKIPPED": "未执行主动探测",
            "OK": "未发现明显异常",
        }
        self.lbl_verdict_banner.configure(
            text=f"结论：{labels.get(result.verdict, result.verdict)}（{result.severity}）",
            bootstyle=boot,
        )

    def _on_export(self) -> None:
        if not self._last_result:
            messagebox.showinfo("DHCP 诊断", "请先完成一次诊断。", parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            title="导出 Markdown",
            defaultextension=".md",
            filetypes=[("Markdown", "*.md")],
            initialfile=f"dhcp_diagnosis_{self._last_result.task_id}.md",
        )
        if not path:
            return
        try:
            Path(path).write_text(render_dhcp_diagnosis_markdown(self._last_result), encoding="utf-8")
        except OSError as e:
            messagebox.showerror("DHCP 诊断", f"写入失败：{e}", parent=self)
            return
        messagebox.showinfo("DHCP 诊断", f"已导出：{path}", parent=self)

    def _on_open_report_dir(self) -> None:
        if not self._last_report_dir or not self._last_report_dir.is_dir():
            messagebox.showinfo("DHCP 诊断", "暂无报告目录。", parent=self)
            return
        path = str(self._last_report_dir.resolve())
        if sys.platform == "win32":
            subprocess.Popen(["explorer", path])  # noqa: S603
        else:
            webbrowser.open(path)

    def _go_mac_scan(self) -> None:
        if self._app is not None and hasattr(self._app, "_select_module"):
            self._app._select_module("mac_scan")

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, *rest = self._q.get_nowait()
                if kind == "prog":
                    self.lbl_status.configure(text=str(rest[0]))
                elif kind == "round":
                    r: DhcpProbeRound = rest[0]
                    if not r.offers:
                        self.tree_probe.insert("", END, values=(r.round_index, "—", "—", "—", "—", "无 OFFER"))
                    else:
                        for o in r.offers:
                            self.tree_probe.insert(
                                "",
                                END,
                                values=(
                                    r.round_index,
                                    o.server_id,
                                    o.yiaddr or "—",
                                    o.router or "—",
                                    ", ".join(o.dns) if o.dns else "—",
                                    "是" if o.in_whitelist else "否",
                                ),
                            )
                elif kind == "done":
                    result: DhcpDiagnosisResult = rest[0]
                    self._apply_busy(False)
                    self._worker = None
                    self._fill_result(result)
                    self.lbl_status.configure(text=f"完成。报告：reports/dhcp_diagnosis/{result.task_id}/")
                elif kind == "error":
                    self._apply_busy(False)
                    self._worker = None
                    messagebox.showerror("DHCP 诊断", str(rest[0]), parent=self)
                    self.lbl_status.configure(text="失败。")
        except queue.Empty:
            pass
        self.after(180, self._poll_queue)
