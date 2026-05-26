"""抓包分析页：实时抓包与 pcap 离线分析。"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, END, EW, INFO, LEFT, NSEW, PRIMARY, SECONDARY, VERTICAL, WARNING, W

from network_diagnosis.capture.config import (
    PacketCaptureSettings,
    load_packet_capture_settings,
    save_packet_capture_settings,
)
from network_diagnosis.capture.engine import (
    iter_diagnosis_pcaps,
    prepare_imported_pcap,
    run_live_capture,
    run_pcap_analysis,
)
from network_diagnosis.capture.iface import (
    default_interface_index,
    format_interface_label,
    list_capture_interfaces,
    parse_interface_label,
)
from network_diagnosis.capture.models import CaptureSessionResult, PcapAnalysisResult
from network_diagnosis.gui.simple_markdown_text import append_simple_markdown, configure_simple_markdown_tags
from network_diagnosis.paths import find_tshark, find_wireshark_gui, packet_capture_report_dir
from network_diagnosis.probes.tshark import tshark_version_line
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)

_BPF_TEMPLATES = (
    "not broadcast and not multicast",
    "tcp port 443",
    "tcp port 80",
    "udp port 53",
    "icmp",
    "host ",
)


class CaptureFrame(ttk.Frame):
    def __init__(self, master: tk.Misc, app: tk.Misc | None = None, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self._app = app
        self._q: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._capturing = False
        self._worker: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_session: CaptureSessionResult | None = None
        self._last_analysis: PcapAnalysisResult | None = None
        self._last_report_dir: Path | None = None
        self._current_pcap: Path | None = None
        self._iface_map: dict[str, tuple[str, str]] = {}
        self._settings = load_packet_capture_settings()
        self._build_ui()
        self._apply_form_settings()
        self.after(180, self._poll_queue)

    def is_capturing(self) -> bool:
        return self._capturing

    def confirm_exit(self) -> bool:
        if not self._capturing:
            return True
        if messagebox.askyesno(
            "抓包分析",
            "正在抓包。退出程序将停止抓包并保存当前文件。\n\n是否退出？",
            parent=self.winfo_toplevel(),
        ):
            self._stop_event.set()
            if self._worker and self._worker.is_alive():
                self._worker.join(timeout=50)
            return True
        return False

    def load_pcap(self, path: Path | str, *, source: str = "from_diagnosis") -> None:
        p = Path(path)
        if not p.is_file():
            messagebox.showwarning("抓包分析", f"文件不存在：\n{p}", parent=self)
            return
        self._current_pcap = p
        self._update_pcap_label()
        self.var_source_kind.set(source)
        self._on_analyze(skip_large_confirm=False)

    def on_show(self) -> None:
        self._refresh_tshark_status()
        self._refresh_interfaces()
        self._update_capture_indicator()

    def on_leave(self) -> bool:
        if not self._capturing:
            return True
        choice = messagebox.askyesnocancel(
            "抓包分析",
            "正在抓包。是否离开本页？\n\n"
            "「是」= 继续在后台抓包\n"
            "「否」= 停止并保存\n"
            "「取消」= 留在本页",
            parent=self.winfo_toplevel(),
        )
        if choice is None:
            return False
        if choice is False:
            self._stop_event.set()
        return True

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

        hint = ttk.Labelframe(frm_ops, text="合规与依赖提示", bootstyle=WARNING, padding=(10, 10, 10, 8))
        hint.grid(row=0, column=0, sticky=EW)
        hint.columnconfigure(0, weight=1)
        hint_msg = (
            "本模块依赖本机 **Wireshark**（含 **Npcap**）。部分环境须 **以管理员身份运行** 本程序。\n"
            "抓包可能包含账号、Cookie、内网地址等敏感信息，**仅** 在已获得授权的网络中使用；"
            "长时间或无过滤器抓包可能占用大量磁盘。"
        )
        txt_hint = tk.Text(
            hint,
            wrap=tk.WORD,
            height=3,
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

        dep_row = ttk.Frame(frm_ops)
        dep_row.grid(row=1, column=0, sticky=EW, pady=(8, 0))
        dep_row.columnconfigure(0, weight=1)

        self.lbl_tshark = ttk.Label(dep_row, text="tshark：检测中…", bootstyle=INFO)
        self.lbl_tshark.grid(row=0, column=0, sticky=EW)

        dep_btns = ttk.Frame(dep_row)
        dep_btns.grid(row=0, column=1, sticky=tk.E, padx=(12, 0))
        ttk.Button(
            dep_btns,
            text="检测 Tshark",
            command=self._probe_tshark,
            bootstyle=SECONDARY,
        ).pack(side=LEFT, padx=(0, 6))
        self.btn_install_wireshark = ttk.Button(
            dep_btns,
            text="安装 Wireshark",
            command=self._open_wireshark_installer,
            bootstyle=INFO,
        )
        self.btn_install_wireshark.pack(side=LEFT)

        lf_live = ttk.Labelframe(frm_ops, text="实时抓包", padding=(12, 10, 12, 10))
        lf_live.grid(row=2, column=0, sticky=EW, pady=(10, 0))
        lf_live.columnconfigure(1, weight=1)

        ttk.Label(lf_live, text="网卡").grid(row=0, column=0, sticky=W)
        self.var_iface = tk.StringVar(value="")
        self.cmb_iface = ttk.Combobox(lf_live, textvariable=self.var_iface, state="readonly")
        self.cmb_iface.grid(row=0, column=1, sticky=EW, padx=(8, 0))

        ttk.Label(lf_live, text="BPF").grid(row=1, column=0, sticky=W, pady=(6, 0))
        bpf_row = ttk.Frame(lf_live)
        bpf_row.grid(row=1, column=1, sticky=EW, padx=(8, 0), pady=(6, 0))
        bpf_row.columnconfigure(0, weight=1)
        self.var_bpf = tk.StringVar(value="")
        ttk.Entry(bpf_row, textvariable=self.var_bpf).grid(row=0, column=0, sticky=EW)
        self.cmb_bpf_tpl = ttk.Combobox(bpf_row, values=_BPF_TEMPLATES, width=22, state="readonly")
        self.cmb_bpf_tpl.grid(row=0, column=1, padx=(6, 0))
        self.cmb_bpf_tpl.bind("<<ComboboxSelected>>", self._on_bpf_template)

        row_stop = ttk.Frame(lf_live)
        row_stop.grid(row=2, column=0, columnspan=2, sticky=EW, pady=(8, 0))
        self.var_stop_mode = tk.StringVar(value="manual")
        ttk.Radiobutton(row_stop, text="手动停止", variable=self.var_stop_mode, value="manual").pack(side=LEFT)
        ttk.Radiobutton(row_stop, text="定时", variable=self.var_stop_mode, value="timed").pack(side=LEFT, padx=(12, 0))
        self.var_duration = tk.IntVar(value=60)
        ttk.Spinbox(row_stop, from_=5, to=3600, textvariable=self.var_duration, width=6).pack(side=LEFT, padx=(6, 0))
        ttk.Label(row_stop, text="秒").pack(side=LEFT, padx=(4, 16))
        self.var_filesize_enable = tk.BooleanVar(value=False)
        ttk.Checkbutton(row_stop, text="文件上限", variable=self.var_filesize_enable).pack(side=LEFT)
        self.var_filesize_mb = tk.IntVar(value=100)
        ttk.Spinbox(
            row_stop, from_=10, to=2048, textvariable=self.var_filesize_mb, width=6
        ).pack(side=LEFT, padx=(6, 0))
        ttk.Label(row_stop, text="MB").pack(side=LEFT, padx=(4, 0))

        live_actions = ttk.Frame(lf_live)
        live_actions.grid(row=3, column=0, columnspan=2, sticky=EW, pady=(10, 0))
        self.btn_start_cap = ttk.Button(
            live_actions, text="开始抓包", command=self._on_start_capture, bootstyle=PRIMARY
        )
        self.btn_start_cap.pack(side=LEFT)
        self.btn_stop_cap = ttk.Button(
            live_actions, text="停止抓包", command=self._on_stop_capture, bootstyle=SECONDARY, state=tk.DISABLED
        )
        self.btn_stop_cap.pack(side=LEFT, padx=(8, 0))

        lf_off = ttk.Labelframe(frm_ops, text="离线分析", padding=(12, 10, 12, 10))
        lf_off.grid(row=3, column=0, sticky=EW, pady=(10, 0))
        lf_off.columnconfigure(1, weight=1)

        self.lbl_pcap = ttk.Label(lf_off, text="当前文件：—", bootstyle=SECONDARY)
        self.lbl_pcap.grid(row=0, column=0, columnspan=2, sticky=W)

        ttk.Label(lf_off, text="Display Filter").grid(row=1, column=0, sticky=W, pady=(6, 0))
        self.var_display_filter = tk.StringVar(value="")
        ttk.Entry(lf_off, textvariable=self.var_display_filter).grid(
            row=1, column=1, sticky=EW, padx=(8, 0), pady=(6, 0)
        )

        off_actions = ttk.Frame(lf_off)
        off_actions.grid(row=2, column=0, columnspan=2, sticky=EW, pady=(10, 0))
        ttk.Button(off_actions, text="打开文件…", command=self._on_open_file, bootstyle=SECONDARY).pack(side=LEFT)
        ttk.Button(off_actions, text="从网络诊断载入…", command=self._on_load_diagnosis, bootstyle=SECONDARY).pack(
            side=LEFT, padx=(8, 0)
        )
        self.btn_analyze = ttk.Button(off_actions, text="分析", command=self._on_analyze, bootstyle=PRIMARY)
        self.btn_analyze.pack(side=LEFT, padx=(8, 0))

        self.var_source_kind = tk.StringVar(value="imported")

        status_row = ttk.Frame(frm_ops)
        status_row.grid(row=4, column=0, sticky=EW, pady=(10, 0))
        status_row.columnconfigure(0, weight=1)
        self.lbl_status = ttk.Label(status_row, text="就绪。", bootstyle=INFO)
        self.lbl_status.grid(row=0, column=0, sticky=EW)
        self._progress = ttk.Progressbar(status_row, mode="indeterminate", bootstyle=WARNING, length=200)
        self._progress.grid(row=0, column=1, padx=(8, 0))

        nb = ttk.Notebook(frm_out)
        nb.grid(row=0, column=0, sticky=NSEW)

        tab_summary = ttk.Frame(nb, padding=(8, 8))
        tab_detail = ttk.Frame(nb, padding=(8, 8))
        nb.add(tab_summary, text="  摘要  ")
        nb.add(tab_detail, text="  详情  ")

        tab_summary.rowconfigure(0, weight=1)
        tab_summary.columnconfigure(0, weight=1)
        self.txt_summary = tk.Text(
            tab_summary,
            wrap=tk.WORD,
            font=("Microsoft YaHei UI", 11),
            relief=tk.FLAT,
            padx=8,
            pady=8,
        )
        sy = ttk.Scrollbar(tab_summary, orient=VERTICAL, command=self.txt_summary.yview)
        self.txt_summary.configure(yscrollcommand=sy.set)
        self.txt_summary.grid(row=0, column=0, sticky=NSEW)
        sy.grid(row=0, column=1, sticky="ns")
        configure_simple_markdown_tags(
            self.txt_summary, base_font=("Microsoft YaHei UI", 11), theme_colors=ttk.Style().colors
        )

        tab_detail.rowconfigure(1, weight=1)
        tab_detail.columnconfigure(0, weight=1)

        self.lbl_detail_stats = ttk.Label(tab_detail, text="", bootstyle=SECONDARY, wraplength=900, justify=LEFT)
        self.lbl_detail_stats.grid(row=0, column=0, sticky=EW, pady=(0, 6))

        detail_nb = ttk.Notebook(tab_detail)
        detail_nb.grid(row=1, column=0, sticky=NSEW)

        tab_proto = ttk.Frame(detail_nb, padding=(4, 4))
        tab_preview = ttk.Frame(detail_nb, padding=(4, 4))
        detail_nb.add(tab_proto, text="  协议  ")
        detail_nb.add(tab_preview, text="  报文预览  ")

        cols_p = ("proto", "frames")
        self.tree_proto = ttk.Treeview(tab_proto, columns=cols_p, show="headings", height=10)
        self.tree_proto.heading("proto", text="协议")
        self.tree_proto.heading("frames", text="帧数")
        self.tree_proto.column("proto", width=220, anchor=W)
        self.tree_proto.column("frames", width=80, anchor=W)
        sy_p = ttk.Scrollbar(tab_proto, orient=VERTICAL, command=self.tree_proto.yview)
        self.tree_proto.configure(yscrollcommand=sy_p.set)
        self.tree_proto.pack(side=LEFT, fill=BOTH, expand=True)
        sy_p.pack(side=LEFT, fill=tk.Y)

        cols_v = ("no", "time", "src", "dst", "proto", "len", "info")
        self.tree_preview = ttk.Treeview(tab_preview, columns=cols_v, show="headings", height=14)
        for c, h, w in (
            ("no", "No.", 52),
            ("time", "时间", 72),
            ("src", "源", 140),
            ("dst", "目的", 140),
            ("proto", "协议", 72),
            ("len", "长度", 56),
            ("info", "Info", 320),
        ):
            self.tree_preview.heading(c, text=h)
            self.tree_preview.column(c, width=w, anchor=W)
        sy_v = ttk.Scrollbar(tab_preview, orient=VERTICAL, command=self.tree_preview.yview)
        self.tree_preview.configure(yscrollcommand=sy_v.set)
        self.tree_preview.pack(side=LEFT, fill=BOTH, expand=True)
        sy_v.pack(side=LEFT, fill=tk.Y)

        btn_row = ttk.Frame(frm_out)
        btn_row.grid(row=1, column=0, sticky=EW, pady=(10, 0))
        ttk.Button(btn_row, text="导出报告", command=self._on_export_report, bootstyle=SECONDARY).pack(side=LEFT)
        ttk.Button(btn_row, text="打开报告目录", command=self._on_open_report_dir, bootstyle=SECONDARY).pack(
            side=LEFT, padx=(8, 0)
        )
        ttk.Button(btn_row, text="用 Wireshark 打开", command=self._on_open_wireshark, bootstyle=SECONDARY).pack(
            side=LEFT, padx=(8, 0)
        )
        ttk.Button(btn_row, text="复制摘要", command=self._on_copy_summary, bootstyle=SECONDARY).pack(
            side=LEFT, padx=(8, 0)
        )

    def _apply_form_settings(self) -> None:
        s = self._settings
        self.var_bpf.set(s.default_bpf)
        self.var_duration.set(s.default_duration_sec)
        if s.default_filesize_limit_mb > 0:
            self.var_filesize_enable.set(True)
            self.var_filesize_mb.set(s.default_filesize_limit_mb)

    def _save_form_settings(self) -> None:
        idx, _ = self._selected_iface()
        save_packet_capture_settings(
            PacketCaptureSettings(
                default_interface_index=idx,
                default_bpf=self.var_bpf.get().strip(),
                default_duration_sec=int(self.var_duration.get()),
                default_filesize_limit_mb=int(self.var_filesize_mb.get()) if self.var_filesize_enable.get() else 0,
                preview_limit=self._settings.preview_limit,
                max_analyze_bytes=self._settings.max_analyze_bytes,
                confirm_empty_bpf=self._settings.confirm_empty_bpf,
            )
        )

    def _open_wireshark_installer(self) -> None:
        app = self._app
        if app is not None and hasattr(app, "_open_wireshark_installer"):
            app._open_wireshark_installer()
            self.after(800, self._refresh_tshark_status)
            self.after(800, self._refresh_interfaces)
            return
        messagebox.showinfo("抓包分析", "请将 Wireshark 安装包放入 ThirdParty/Wireshark/。", parent=self)

    def _probe_tshark(self) -> None:
        app = self._app
        if app is not None and hasattr(app, "_probe_tshark"):
            app._probe_tshark()
        else:
            p = find_tshark()
            if p:
                messagebox.showinfo("Tshark", f"已找到:\n{p}", parent=self)
            else:
                messagebox.showwarning(
                    "Tshark",
                    "未找到 tshark。请先安装 Wireshark（含 Npcap），或将安装包放入 ThirdParty/Wireshark/。",
                    parent=self,
                )
        self._refresh_tshark_status()
        self._refresh_interfaces()

    def _refresh_tshark_status(self) -> None:
        p = find_tshark()
        if p is None:
            self.lbl_tshark.configure(text="tshark：未找到（请安装 Wireshark / Npcap）", bootstyle=WARNING)
            try:
                self.btn_install_wireshark.configure(bootstyle=WARNING)
            except tk.TclError:
                pass
            return
        ver = ""
        try:
            tmp = packet_capture_report_dir("_probe")
            line = tshark_version_line(p, tmp)
            if line:
                ver = f" · {line[:80]}"
        except OSError:
            pass
        self.lbl_tshark.configure(text=f"tshark：{p}{ver}", bootstyle=INFO)
        try:
            self.btn_install_wireshark.configure(bootstyle=INFO)
        except tk.TclError:
            pass

    def _refresh_interfaces(self) -> None:
        tshark = find_tshark()
        if tshark is None:
            self.cmb_iface.configure(values=[])
            return
        log_dir = packet_capture_report_dir("_iface_list")
        try:
            ifaces = list_capture_interfaces(tshark, log_dir)
        except OSError as e:
            self.lbl_status.configure(text=f"无法列出网卡：{e}")
            return
        labels: list[str] = []
        self._iface_map.clear()
        default_idx = self._settings.default_interface_index.strip()
        pick = ""
        for idx, desc in ifaces:
            label = format_interface_label(idx, desc)
            labels.append(label)
            self._iface_map[label] = (idx, desc)
            if default_idx and idx == default_idx:
                pick = label
        if not pick and labels:
            try:
                rec = default_interface_index(tshark, log_dir)
                for label, (idx, _) in self._iface_map.items():
                    if idx == rec:
                        pick = label
                        break
            except OSError:
                pick = labels[0]
        self.cmb_iface.configure(values=labels)
        if pick:
            self.var_iface.set(pick)
        elif labels and not self.var_iface.get():
            self.var_iface.set(labels[0])

    def _selected_iface(self) -> tuple[str, str]:
        label = self.var_iface.get().strip()
        if label in self._iface_map:
            return self._iface_map[label]
        return parse_interface_label(label)

    def _on_bpf_template(self, _event=None) -> None:
        tpl = self.cmb_bpf_tpl.get().strip()
        if tpl:
            self.var_bpf.set(tpl)

    def _update_pcap_label(self) -> None:
        p = self._current_pcap
        if p is None or not p.is_file():
            self.lbl_pcap.configure(text="当前文件：—")
            return
        mb = p.stat().st_size / (1024 * 1024)
        self.lbl_pcap.configure(text=f"当前文件：{p.name}（{mb:.2f} MB）")

    def _apply_busy(self, busy: bool, *, capturing: bool = False) -> None:
        self._busy = busy
        self._capturing = capturing
        self.btn_start_cap.configure(state=tk.DISABLED if busy else tk.NORMAL)
        self.btn_stop_cap.configure(state=tk.NORMAL if capturing else tk.DISABLED)
        self.btn_analyze.configure(state=tk.DISABLED if busy else tk.NORMAL)
        if busy:
            self._progress.start(10)
        else:
            self._progress.stop()
        self._update_capture_indicator()

    def _update_capture_indicator(self) -> None:
        app = self._app
        if app is None:
            return
        base = getattr(app, "title", lambda: "")()
        if self._capturing and "● 抓包中" not in base:
            if "（" in base:
                app.title(base.replace("（", " ● 抓包中（", 1))
            else:
                app.title(base + " ● 抓包中")
        elif not self._capturing and "● 抓包中" in base:
            app.title(base.replace(" ● 抓包中", ""))

    def _on_start_capture(self) -> None:
        if self._busy:
            return
        tshark = find_tshark()
        if tshark is None:
            messagebox.showwarning("抓包分析", "未找到 tshark。请先安装 Wireshark（含 Npcap）。", parent=self)
            return
        bpf = self.var_bpf.get().strip()
        if not bpf and self._settings.confirm_empty_bpf:
            if not messagebox.askyesno(
                "抓包分析",
                "未设置捕获过滤器将抓取网卡上的大量流量，可能包含敏感信息并占用大量磁盘。\n\n是否继续？",
                parent=self,
            ):
                return
        idx, desc = self._selected_iface()
        if not idx:
            messagebox.showwarning("抓包分析", "请选择网卡。", parent=self)
            return
        self._save_form_settings()
        timed = self.var_stop_mode.get() == "timed"
        try:
            duration = int(self.var_duration.get())
        except tk.TclError:
            duration = 60
        filesize_mb = int(self.var_filesize_mb.get()) if self.var_filesize_enable.get() else 0

        self._stop_event.clear()
        self._apply_busy(True, capturing=True)
        self.lbl_status.configure(text="抓包进行中…")

        def work() -> None:
            try:
                session = run_live_capture(
                    tshark,
                    interface_index=idx,
                    interface_desc=desc,
                    bpf_filter=bpf,
                    timed=timed,
                    duration_sec=duration,
                    filesize_limit_mb=filesize_mb,
                    stop_event=self._stop_event,
                    progress=lambda m: self._q.put(("progress", m)),
                )
                self._q.put(("capture_done", session))
            except BaseException as e:
                if isinstance(e, (KeyboardInterrupt, SystemExit)):
                    raise
                _log.exception("抓包线程异常")
                self._q.put(("error", str(e)))

        self._worker = threading.Thread(target=work, daemon=True)
        self._worker.start()

    def _on_stop_capture(self) -> None:
        self._stop_event.set()
        self.lbl_status.configure(text="正在停止抓包…")

    def _on_open_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="选择 pcap/pcapng",
            filetypes=[
                ("抓包文件", "*.pcapng;*.pcap;*.cap"),
                ("所有文件", "*.*"),
            ],
        )
        if not path:
            return
        self._current_pcap = Path(path)
        self.var_source_kind.set("imported")
        self._update_pcap_label()

    def _on_load_diagnosis(self) -> None:
        pcaps = iter_diagnosis_pcaps()
        if not pcaps:
            messagebox.showinfo("抓包分析", "未在 reports/ 下找到网络诊断抓包文件。", parent=self)
            return
        labels = [f"{p.parent.name} / {p.name}" for p in pcaps]
        choice = simpledialog.askstring(
            "从网络诊断载入",
            "输入序号（1 为最新）：\n" + "\n".join(f"{i+1}. {lb}" for i, lb in enumerate(labels[:15])),
            parent=self,
        )
        if not choice:
            return
        try:
            n = int(choice.strip())
            p = pcaps[n - 1]
        except (ValueError, IndexError):
            messagebox.showwarning("抓包分析", "序号无效。", parent=self)
            return
        self._current_pcap = p
        self.var_source_kind.set("from_diagnosis")
        self._update_pcap_label()

    def _confirm_large_file(self, size: int) -> bool:
        if size <= self._settings.max_analyze_bytes:
            return True
        mb = size / (1024 * 1024)
        return messagebox.askyesno(
            "抓包分析",
            f"文件约 {mb:.0f} MB，分析可能较慢。\n\n是否继续？",
            parent=self,
        )

    def _on_analyze(self, *, skip_large_confirm: bool = False) -> None:
        if self._busy:
            return
        tshark = find_tshark()
        if tshark is None:
            messagebox.showwarning("抓包分析", "未找到 tshark。", parent=self)
            return
        pcap = self._current_pcap
        if pcap is None or not pcap.is_file():
            messagebox.showwarning("抓包分析", "请先选择或完成一次抓包。", parent=self)
            return
        if pcap.stat().st_size == 0:
            messagebox.showwarning("抓包分析", "抓包文件为空。", parent=self)
            return
        if not skip_large_confirm and not self._confirm_large_file(pcap.stat().st_size):
            return

        display = self.var_display_filter.get().strip() or None
        source = self.var_source_kind.get() or "imported"
        session = self._last_session if source == "live" else None

        self._apply_busy(True)
        self.lbl_status.configure(text="分析中…")

        def work() -> None:
            try:
                if session is not None and session.pcap_path.resolve() == pcap.resolve():
                    tid = session.task_id
                    report_dir = packet_capture_report_dir(tid)
                    dest = session.pcap_path
                else:
                    tid, report_dir, dest = prepare_imported_pcap(pcap, source_kind=source)
                analysis = run_pcap_analysis(
                    tshark,
                    dest,
                    report_dir,
                    task_id=tid,
                    source=source,
                    display_filter=display,
                    preview_limit=self._settings.preview_limit,
                    session=session if session and session.task_id == tid else None,
                    progress=lambda m: self._q.put(("progress", m)),
                )
                self._q.put(("analysis_done", (session, analysis)))
            except BaseException as e:
                if isinstance(e, (KeyboardInterrupt, SystemExit)):
                    raise
                _log.exception("分析线程异常")
                self._q.put(("error", str(e)))

        self._worker = threading.Thread(target=work, daemon=True)
        self._worker.start()

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "progress":
                    self.lbl_status.configure(text=str(payload))
                elif kind == "error":
                    messagebox.showerror("抓包分析", str(payload), parent=self)
                    self._apply_busy(False)
                    self.lbl_status.configure(text="失败。")
                elif kind == "capture_done":
                    session: CaptureSessionResult = payload  # type: ignore[assignment]
                    self._last_session = session
                    self._last_report_dir = session.pcap_path.parent
                    self._current_pcap = session.pcap_path
                    self._update_pcap_label()
                    self.var_source_kind.set("live")
                    if session.status == "failed":
                        self._apply_busy(False)
                        msg = session.error_message or "抓包失败。"
                        self.lbl_status.configure(text=msg[:200])
                        messagebox.showwarning("抓包分析", msg[:1200], parent=self)
                    else:
                        self._apply_busy(False, capturing=False)
                        self.lbl_status.configure(text="抓包完成，正在分析…")
                        self._on_analyze(skip_large_confirm=True)
                elif kind == "analysis_done":
                    session, analysis = payload  # type: ignore[misc]
                    self._last_session = session
                    self._last_analysis = analysis
                    self._last_report_dir = analysis.report_dir
                    self._current_pcap = analysis.pcap_path
                    self._render_analysis(analysis)
                    self._apply_busy(False)
                    self.lbl_status.configure(text="分析完成。")
        except queue.Empty:
            pass
        self.after(180, self._poll_queue)

    def _render_analysis(self, analysis: PcapAnalysisResult) -> None:
        self.txt_summary.configure(state=tk.NORMAL)
        self.txt_summary.delete("1.0", END)
        header = (
            f"帧数：{analysis.frame_count}  ·  大小：{analysis.file_size_bytes // 1024} KB"
        )
        if analysis.duration_sec is not None:
            header += f"  ·  时长约 {analysis.duration_sec:.1f}s"
        append_simple_markdown(self.txt_summary, header + "\n\n")
        append_simple_markdown(self.txt_summary, analysis.summary_plain + "\n")
        self.txt_summary.configure(state=tk.DISABLED)

        stats_parts: list[str] = []
        if analysis.retransmission_count is not None:
            stats_parts.append(f"TCP 重传：{analysis.retransmission_count}")
        if analysis.rst_count is not None:
            stats_parts.append(f"TCP RST：{analysis.rst_count}")
        if analysis.dns_queries:
            stats_parts.append(f"DNS 查询：{len(analysis.dns_queries)} 条（抽样）")
        if analysis.tls_sni_list:
            stats_parts.append(f"TLS SNI：{len(analysis.tls_sni_list)} 条（抽样）")
        if analysis.http_status_summary:
            stats_parts.append(analysis.http_status_summary)
        for w in analysis.expert_warnings:
            stats_parts.append(f"⚠ {w.summary}（{w.count}）")
        self.lbl_detail_stats.configure(text="  ·  ".join(stats_parts) if stats_parts else "—")

        for tree in (self.tree_proto, self.tree_preview):
            for iid in tree.get_children():
                tree.delete(iid)

        for name, fr in sorted(analysis.protocol_hierarchy.items(), key=lambda x: -x[1])[:40]:
            self.tree_proto.insert("", END, values=(name, fr))

        for row in analysis.packet_preview:
            self.tree_preview.insert(
                "",
                END,
                values=(row.no, row.time_relative, row.src, row.dst, row.protocol, row.length, row.info),
            )

    def _on_export_report(self) -> None:
        if self._last_analysis and self._last_analysis.markdown_path:
            messagebox.showinfo(
                "抓包分析",
                f"报告已保存：\n{self._last_analysis.markdown_path}",
                parent=self,
            )
            return
        messagebox.showinfo("抓包分析", "请先完成一次分析。", parent=self)

    def _on_open_report_dir(self) -> None:
        d = self._last_report_dir
        if d is None or not d.is_dir():
            messagebox.showinfo("抓包分析", "尚无报告目录。", parent=self)
            return
        try:
            if sys.platform == "win32":
                os.startfile(str(d))  # noqa: S606
            else:
                subprocess.Popen(["xdg-open", str(d)])  # noqa: S603
        except OSError as e:
            messagebox.showerror("抓包分析", str(e), parent=self)

    def _on_open_wireshark(self) -> None:
        pcap = self._current_pcap
        if pcap is None or not pcap.is_file():
            messagebox.showinfo("抓包分析", "请先选择 pcap 文件。", parent=self)
            return
        exe = find_wireshark_gui()
        if exe is None:
            messagebox.showwarning("抓包分析", "未找到 Wireshark.exe。", parent=self)
            return
        try:
            subprocess.Popen([str(exe), str(pcap.resolve())])  # noqa: S603
        except OSError as e:
            messagebox.showerror("抓包分析", str(e), parent=self)

    def _on_copy_summary(self) -> None:
        if self._last_analysis is None:
            messagebox.showinfo("抓包分析", "尚无摘要。", parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(self._last_analysis.summary_plain)
        self.lbl_status.configure(text="摘要已复制到剪贴板。")
