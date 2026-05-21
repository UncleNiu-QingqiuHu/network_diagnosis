"""MAC 扫描页：同网段 ICMP + ARP + 可选计算机名解析。"""

from __future__ import annotations

import csv
import ipaddress
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

import ttkbootstrap as ttk
from ttkbootstrap.constants import END, EW, INFO, LEFT, NSEW, PRIMARY, SECONDARY, VERTICAL, WARNING, W, X

from network_diagnosis.gui.simple_markdown_text import append_simple_markdown, configure_simple_markdown_tags
from network_diagnosis.host_l3_info import list_local_ipv4_adapters
from network_diagnosis.ip_scan import MAX_SCAN_HOSTS_HARD_LIMIT, parse_scan_targets
from network_diagnosis.mac_scan import (
    MacScanRow,
    merge_scan_rows,
    resolve_scan_interface,
    run_host_label_scan,
    run_mac_scan,
)
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)

_SEARCH_PLACEHOLDER = "输入 IP、MAC、厂商或备注过滤"

_STATUS_ONLINE_DISP = "\u25cf 在线"
_STATUS_OFFLINE_DISP = "\u25cb 离线"

# 列宽：IP/MAC/状态等关键列固定且设 minwidth；备注固定不拉伸；厂商/计算机名均分剩余宽度
_COL_IP_W = 142
_COL_ALIVE_W = 108
_COL_MAC_W = 192
_COL_TYPE_W = 76
_COL_RTT_W = 92
_COL_VENDOR_W = 108
_COL_VENDOR_MIN = 88
_COL_REMARK_W = 100
_COL_HOST_W = 148
_COL_HOST_MIN = 120
_TREE_COL_GUTTER = 28

_BASE_COLS = ("ip", "alive", "mac", "arp_type", "rtt", "vendor", "remark")
_NAME_COLS = ("hostname",)


class MacScanFrame(ttk.Frame):
    def __init__(self, master: tk.Misc, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self._q: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._worker: threading.Thread | None = None
        self._cancel_event = threading.Event()
        self._scan_data: dict[str, MacScanRow] = {}
        self._tree_refresh_after_id: str | None = None
        self._show_name_cols = False
        self._build_ui()
        self.after(180, self._poll_queue)

    def on_leave(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            self._cancel_event.set()

    def on_show(self) -> None:
        self.update_idletasks()
        self.after_idle(lambda: self._init_mac_scan_sash(0))
        self.after(120, lambda: self._init_mac_scan_sash(0))
        self.after(160, self._sync_scan_tree_columns)

    def _build_ui(self) -> None:
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        # 上下分栏：上方参数区、下方结果表占满宽度（多列不易挤）
        pw = ttk.Panedwindow(self, orient=tk.VERTICAL)
        pw.grid(row=0, column=0, sticky=NSEW)
        self._pw_mac_scan = pw

        frm_ops = ttk.Frame(pw, padding=(14, 12, 14, 8))
        frm_out = ttk.Frame(pw, padding=(14, 8, 14, 14))
        pw.add(frm_ops, weight=0)
        pw.add(frm_out, weight=1)
        try:
            pw.pane(frm_ops, weight=0)
            pw.pane(frm_out, weight=1)
        except tk.TclError:
            pass

        frm_ops.columnconfigure(0, weight=2)
        frm_ops.columnconfigure(1, weight=3)
        frm_ops.rowconfigure(0, weight=1)
        frm_out.rowconfigure(0, weight=1)
        frm_out.columnconfigure(0, weight=1)

        hint = ttk.Labelframe(frm_ops, text="合规提示", bootstyle=WARNING, padding=(10, 10, 10, 8))
        hint.grid(row=0, column=0, sticky=NSEW, padx=(0, 10))
        hint.columnconfigure(0, weight=1)
        hint.rowconfigure(0, weight=1)
        hint_msg = (
            "批量 ICMP 与读取本机 **ARP 表** 可能被安全设备记录；请在 **已获得授权** 的内网或测试环境中使用。\n"
            "**仅支持本机已连接网段**（不支持跨网段）；MAC 与计算机名不保证 100% 完整。"
        )
        self._txt_hint = tk.Text(
            hint,
            wrap=tk.WORD,
            width=28,
            height=2,
            relief=tk.FLAT,
            padx=4,
            pady=4,
            font=("Microsoft YaHei UI", 10),
            cursor="arrow",
            highlightthickness=0,
            borderwidth=0,
            takefocus=False,
        )
        self._txt_hint.grid(row=0, column=0, sticky=NSEW)
        configure_simple_markdown_tags(
            self._txt_hint,
            base_font=("Microsoft YaHei UI", 10),
            theme_colors=ttk.Style().colors,
        )
        self._txt_hint.configure(state=tk.NORMAL)
        append_simple_markdown(self._txt_hint, hint_msg.rstrip() + "\n")
        self._fit_readonly_text_height(self._txt_hint)
        self._txt_hint.configure(state=tk.DISABLED)
        self._hint_labelframe = hint
        hint.bind("<Configure>", self._sync_hint_text_layout)
        self.after_idle(self._sync_hint_text_layout)

        lf = ttk.Labelframe(frm_ops, text="扫描参数", padding=(12, 10, 12, 10))
        lf.grid(row=0, column=1, sticky=NSEW)
        lf.columnconfigure(1, weight=1)

        ttk.Label(lf, text="范围").grid(row=0, column=0, sticky=W, pady=(0, 6))
        self.var_range = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(lf, textvariable=self.var_range).grid(
            row=0, column=1, columnspan=5, sticky=EW, pady=(0, 6), padx=(8, 0)
        )

        opts = ttk.Frame(lf)
        opts.grid(row=1, column=0, columnspan=6, sticky=W, pady=(0, 8))
        self.var_resolve_name = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            opts,
            text="解析计算机名",
            variable=self.var_resolve_name,
            command=self._on_resolve_name_toggle,
            bootstyle="round-toggle",
        ).pack(side=LEFT, padx=(0, 14))
        self.var_dns = tk.BooleanVar(value=False)
        self.chk_dns = ttk.Checkbutton(
            opts,
            text="DNS 反向补充计算机名",
            variable=self.var_dns,
            bootstyle="round-toggle",
            state=tk.DISABLED,
        )
        self.chk_dns.pack(side=LEFT, padx=(0, 14))
        self.var_netbios = tk.BooleanVar(value=False)
        self.chk_netbios = ttk.Checkbutton(
            opts,
            text="含 NetBIOS",
            variable=self.var_netbios,
            bootstyle="round-toggle",
            state=tk.DISABLED,
        )
        self.chk_netbios.pack(side=LEFT)

        ttk.Label(lf, text="单次上限").grid(row=2, column=0, sticky=W)
        self.var_max_hosts = tk.IntVar(value=512)
        ttk.Spinbox(
            lf,
            from_=16,
            to=MAX_SCAN_HOSTS_HARD_LIMIT,
            textvariable=self.var_max_hosts,
            width=7,
        ).grid(row=2, column=1, sticky=W, padx=(6, 0))

        ttk.Label(lf, text="并发数").grid(row=2, column=2, sticky=W, padx=(14, 0))
        self.var_workers = tk.IntVar(value=48)
        ttk.Spinbox(lf, from_=1, to=256, textvariable=self.var_workers, width=7).grid(
            row=2, column=3, sticky=W, padx=(6, 0)
        )

        ttk.Label(lf, text="ICMP 等待(ms)").grid(row=2, column=4, sticky=W, padx=(14, 0))
        self.var_timeout_ms = tk.IntVar(value=800)
        ttk.Spinbox(
            lf,
            from_=100,
            to=5000,
            increment=50,
            textvariable=self.var_timeout_ms,
            width=7,
        ).grid(row=2, column=5, sticky=W, padx=(6, 0))

        self.var_authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            lf,
            text="我已确认对扫描对象已获得有效授权",
            variable=self.var_authorized,
            bootstyle="round-toggle",
        ).grid(row=3, column=0, columnspan=6, sticky=W, pady=(10, 0))

        actions = ttk.Frame(frm_ops)
        actions.grid(row=1, column=0, columnspan=2, sticky=EW, pady=(10, 0))
        actions.columnconfigure(6, weight=1)

        self.btn_start = ttk.Button(actions, text="开始扫描", command=self._on_start, bootstyle=PRIMARY)
        self.btn_start.grid(row=0, column=0, padx=(0, 8))
        self.btn_stop = ttk.Button(
            actions, text="停止", command=self._on_stop, bootstyle=SECONDARY, state=tk.DISABLED
        )
        self.btn_stop.grid(row=0, column=1, padx=(0, 8))
        ttk.Button(actions, text="清空表格", command=self._clear_grid, bootstyle=SECONDARY).grid(
            row=0, column=2, padx=(0, 8)
        )
        ttk.Button(actions, text="导出 CSV…", command=self._export_csv, bootstyle=SECONDARY).grid(
            row=0, column=3, padx=(0, 8)
        )
        ttk.Button(actions, text="复制 IP+MAC", command=self._copy_ip_mac, bootstyle=SECONDARY).grid(
            row=0, column=4, padx=(0, 8)
        )
        ttk.Button(actions, text="复制在线列表", command=self._copy_alive, bootstyle=SECONDARY).grid(
            row=0, column=5, padx=(0, 12)
        )
        self.lbl_status = ttk.Label(actions, text="就绪。", bootstyle=INFO)
        self.lbl_status.grid(row=0, column=6, sticky=EW)

        lf_out = ttk.Labelframe(frm_out, text="扫描结果", padding=(12, 10, 12, 10))
        lf_out.grid(row=0, column=0, sticky=NSEW)
        lf_out.rowconfigure(1, weight=1)
        lf_out.columnconfigure(0, weight=1)

        search_row = ttk.Frame(lf_out)
        search_row.grid(row=0, column=0, sticky=EW, pady=(0, 8))
        search_row.columnconfigure(0, weight=1)
        self._search_is_placeholder = True
        self.var_search = tk.StringVar(value=_SEARCH_PLACEHOLDER)
        self.ent_search = ttk.Entry(search_row, textvariable=self.var_search)
        self.ent_search.grid(row=0, column=0, sticky=EW, padx=(0, 8))
        self.ent_search.bind("<FocusIn>", self._on_search_focus_in)
        self.ent_search.bind("<FocusOut>", self._on_search_focus_out)
        self.ent_search.bind("<KeyRelease>", self._on_search_changed)
        ttk.Button(search_row, text="清空", command=self._clear_search, bootstyle=SECONDARY).grid(
            row=0, column=1, sticky=W
        )

        wrap = ttk.Frame(lf_out)
        wrap.grid(row=1, column=0, sticky=NSEW)
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        self._scan_wrap = wrap

        self._tree_holder = ttk.Frame(wrap)
        self._tree_holder.grid(row=0, column=0, sticky=NSEW)
        self._tree_holder.rowconfigure(0, weight=1)
        self._tree_holder.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(self._tree_holder, show="headings", height=22, selectmode=tk.BROWSE)

        scroll_y = ttk.Scrollbar(wrap, orient=VERTICAL, command=self.tree.yview)
        scroll_x = ttk.Scrollbar(wrap, orient=tk.HORIZONTAL, command=self.tree.xview)
        self._scan_scroll_y = scroll_y
        self._scan_scroll_x = scroll_x
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self._rebuild_tree_columns(False)
        self.tree.grid(row=0, column=0, sticky=NSEW)
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky=EW)
        wrap.bind("<Configure>", self._sync_scan_tree_columns)

        try:
            style = ttk.Style()
            tc = style.colors
            ok_col = getattr(tc, "success", "#2aa198")
            bad_col = getattr(tc, "danger", "#cb4b16")
            self.tree.tag_configure("alive", foreground=ok_col)
            self.tree.tag_configure("dead", foreground=bad_col)
        except tk.TclError:
            self.tree.tag_configure("alive", foreground="#2aa198")
            self.tree.tag_configure("dead", foreground="#dc322f")

        self.lbl_summary = ttk.Label(lf_out, text="", bootstyle=SECONDARY)
        self.lbl_summary.grid(row=2, column=0, sticky=EW, pady=(10, 0))

        self.after(180, self._init_mac_scan_sash)
        self.after_idle(self._sync_scan_tree_columns)
        self._apply_busy(False)

    def _fit_readonly_text_height(self, txt: tk.Text) -> None:
        """只读提示文本按实际行数设定高度，避免固定行数裁切内容。"""
        try:
            txt.update_idletasks()
            line_count = int(float(txt.index("end-1c")))
            txt.configure(height=max(line_count, 2))
        except tk.TclError:
            pass

    def _sync_hint_text_layout(self, event: tk.Event | None = None) -> None:
        """左侧合规提示区随宽度换行并重算高度，不改变左右分栏布局。"""
        if event is not None and event.widget is not self._hint_labelframe:
            return
        try:
            w_px = self._hint_labelframe.winfo_width() - 28
        except tk.TclError:
            return
        if w_px <= 48:
            return
        try:
            chars = max(22, w_px // 11)
            self._txt_hint.configure(width=chars)
            self._fit_readonly_text_height(self._txt_hint)
        except tk.TclError:
            pass

    def _on_resolve_name_toggle(self) -> None:
        on = self.var_resolve_name.get()
        st = tk.NORMAL if on else tk.DISABLED
        self.chk_dns.configure(state=st)
        self.chk_netbios.configure(state=st)
        if not on:
            self.var_dns.set(False)
            self.var_netbios.set(False)

    def _fixed_tree_columns(self) -> tuple[str, ...]:
        return ("ip", "alive", "mac", "arp_type", "rtt", "remark")

    def _flex_tree_columns(self) -> tuple[str, ...]:
        cols: list[str] = ["vendor"]
        if self._show_name_cols:
            cols.append("hostname")
        return tuple(cols)

    def _tree_column_base_width(self, col: str) -> int:
        return {
            "ip": _COL_IP_W,
            "alive": _COL_ALIVE_W,
            "mac": _COL_MAC_W,
            "arp_type": _COL_TYPE_W,
            "rtt": _COL_RTT_W,
            "vendor": _COL_VENDOR_W,
            "remark": _COL_REMARK_W,
            "hostname": _COL_HOST_W,
        }[col]

    def _tree_column_min_width(self, col: str) -> int:
        if col == "vendor":
            return _COL_VENDOR_MIN
        if col == "hostname":
            return _COL_HOST_MIN
        return self._tree_column_base_width(col)

    def _apply_tree_column_layout(self) -> None:
        """固定列保证完整显示；备注不拉伸；厂商/计算机名均分剩余宽度。"""
        if not hasattr(self, "tree"):
            return
        try:
            cols = [str(c) for c in self.tree["columns"]]
        except tk.TclError:
            return
        if not cols:
            return

        fixed_cols = [c for c in self._fixed_tree_columns() if c in cols]
        flex_cols = [c for c in self._flex_tree_columns() if c in cols]

        fixed_sum = sum(self._tree_column_base_width(c) for c in fixed_cols)
        flex_base = sum(self._tree_column_base_width(c) for c in flex_cols) or 1
        flex_min = sum(self._tree_column_min_width(c) for c in flex_cols)

        try:
            ww = self._scan_wrap.winfo_width()
            sb = getattr(self, "_scan_scroll_y", None)
            sb_y = max(int(sb.winfo_width()), 16) if sb is not None else 18
        except tk.TclError:
            ww, sb_y = 0, 18
        inner = max(ww - sb_y - _TREE_COL_GUTTER, fixed_sum + flex_min)

        flex_budget = max(inner - fixed_sum, flex_min)
        flex_extra = max(0, flex_budget - sum(self._tree_column_base_width(c) for c in flex_cols))

        for c in fixed_cols:
            w = self._tree_column_base_width(c)
            anchor = tk.W if c in ("ip", "mac", "remark") else tk.CENTER
            self.tree.column(c, width=w, minwidth=w, anchor=anchor, stretch=False)

        assigned = 0
        for idx, c in enumerate(flex_cols):
            base = self._tree_column_base_width(c)
            if idx == len(flex_cols) - 1:
                w = max(self._tree_column_min_width(c), flex_budget - assigned)
            else:
                share = base + int(flex_extra * base / flex_base)
                w = max(self._tree_column_min_width(c), share)
                assigned += w
            anchor = tk.W
            self.tree.column(c, width=w, minwidth=self._tree_column_min_width(c), anchor=anchor, stretch=False)

    def _sync_scan_tree_columns(self, event: tk.Event | None = None) -> None:
        if event is not None and event.widget is not self._scan_wrap:
            return
        self._apply_tree_column_layout()

    def _rebuild_tree_columns(self, show_names: bool) -> None:
        self._show_name_cols = show_names
        cols = list(_BASE_COLS)
        if show_names:
            cols.extend(_NAME_COLS)
        self.tree.configure(columns=cols)
        headings = {
            "ip": "IPv4 地址",
            "alive": "状态",
            "mac": "MAC 地址",
            "arp_type": "类型",
            "rtt": "RTT (ms)",
            "vendor": "厂商",
            "remark": "备注",
            "hostname": "计算机名",
        }
        for c in cols:
            self.tree.heading(c, text=headings[c])
        self._apply_tree_column_layout()
        self.after_idle(self._sync_scan_tree_columns)

    def _init_mac_scan_sash(self, attempt: int = 0) -> None:
        """上方面板约占 32% 高度，下方留给多列表格。"""
        if attempt > 40:
            return
        try:
            self.update_idletasks()
            pw = self._pw_mac_scan
            h = pw.winfo_height()
            if h <= 120:
                self.after(80, lambda a=attempt + 1: self._init_mac_scan_sash(a))
                return
            top_h = max(min(int(h * 0.36), 320), 232)
            top_h = min(top_h, h - 160)
            pw.sashpos(0, top_h)
        except tk.TclError:
            pass
        self.after_idle(self._sync_scan_tree_columns)

    def _apply_busy(self, busy: bool) -> None:
        self._busy = busy
        self.btn_start.configure(state=tk.DISABLED if busy else tk.NORMAL)
        self.btn_stop.configure(state=tk.NORMAL if busy else tk.DISABLED)

    def _ip_sort_key(self, ip: str) -> int:
        return int(ipaddress.ip_address(ip))

    def _row_values(self, row: MacScanRow) -> tuple[str, ...]:
        st = _STATUS_ONLINE_DISP if row.alive else _STATUS_OFFLINE_DISP
        mac_s = row.mac if row.mac else "—"
        rtt_s = "" if row.rtt_ms is None else f"{row.rtt_ms:.0f}"
        base = (row.ip, st, mac_s, row.arp_type, rtt_s, row.vendor, row.remark)
        if self._show_name_cols:
            return base + (row.computer_name,)
        return base

    def _row_matches_search(self, row: MacScanRow, needle: str) -> bool:
        if not needle:
            return True
        parts = [
            row.ip,
            row.mac or "",
            row.arp_type,
            row.vendor,
            row.remark,
            row.computer_name,
        ]
        return any(needle in str(p).lower() for p in parts)

    def _cancel_tree_refresh(self) -> None:
        if self._tree_refresh_after_id is not None:
            try:
                self.after_cancel(self._tree_refresh_after_id)
            except tk.TclError:
                pass
            self._tree_refresh_after_id = None

    def _schedule_tree_refresh(self, *, immediate: bool = False) -> None:
        if immediate:
            self._cancel_tree_refresh()
            self._refresh_scan_tree()
            return
        if self._tree_refresh_after_id is not None:
            return
        self._tree_refresh_after_id = self.after(120, self._run_scheduled_tree_refresh)

    def _run_scheduled_tree_refresh(self) -> None:
        self._tree_refresh_after_id = None
        self._refresh_scan_tree()

    def _summary_without_filter_hint(self) -> str:
        text = self.lbl_summary.cget("text")
        marker = "　显示 "
        if marker in text:
            return text.rsplit(marker, 1)[0]
        return text

    def _search_needle(self) -> str:
        if self._search_is_placeholder:
            return ""
        return self.var_search.get().strip().lower()

    def _on_search_focus_in(self, _event: tk.Event | None = None) -> None:
        if self._search_is_placeholder:
            self._search_is_placeholder = False
            self.var_search.set("")

    def _on_search_focus_out(self, _event: tk.Event | None = None) -> None:
        if not self.var_search.get().strip():
            self._search_is_placeholder = True
            self.var_search.set(_SEARCH_PLACEHOLDER)

    def _refresh_scan_tree(self) -> None:
        needle = self._search_needle()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        shown = 0
        for ip in sorted(self._scan_data.keys(), key=self._ip_sort_key):
            row = self._scan_data[ip]
            if not self._row_matches_search(row, needle):
                continue
            tag = "alive" if row.alive else "dead"
            self.tree.insert("", END, values=self._row_values(row), tags=(tag,))
            shown += 1
        total = len(self._scan_data)
        core = self._summary_without_filter_hint()
        if needle and total:
            self.lbl_summary.configure(text=f"{core}　显示 {shown}/{total}")
        elif "　显示 " in self.lbl_summary.cget("text"):
            self.lbl_summary.configure(text=core)

    def _on_search_changed(self, _event: tk.Event | None = None) -> None:
        if self._scan_data:
            self._schedule_tree_refresh(immediate=True)

    def _clear_search(self) -> None:
        self._search_is_placeholder = True
        self.var_search.set(_SEARCH_PLACEHOLDER)
        if self._scan_data:
            self._schedule_tree_refresh(immediate=True)

    def _clear_grid(self) -> None:
        if self._busy:
            messagebox.showinfo("MAC 扫描", "扫描进行中，请稍候或先停止。", parent=self)
            return
        self._cancel_tree_refresh()
        self._scan_data.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.lbl_summary.configure(text="")

    def _copy_alive(self) -> None:
        lines = [ip for ip in sorted(self._scan_data.keys(), key=self._ip_sort_key) if self._scan_data[ip].alive]
        if not lines:
            messagebox.showinfo("MAC 扫描", "当前没有在线地址可复制。", parent=self)
            return
        text = "\n".join(lines) + "\n"
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
        except tk.TclError as e:
            messagebox.showwarning("MAC 扫描", f"复制失败：{e}", parent=self)
            return
        messagebox.showinfo("MAC 扫描", f"已复制 {len(lines)} 条在线地址。", parent=self)

    def _copy_ip_mac(self) -> None:
        lines: list[str] = []
        for ip in sorted(self._scan_data.keys(), key=self._ip_sort_key):
            row = self._scan_data[ip]
            if row.alive and row.mac:
                lines.append(f"{ip}\t{row.mac}")
        if not lines:
            messagebox.showinfo("MAC 扫描", "当前没有「在线且已有 MAC」的记录可复制。", parent=self)
            return
        text = "\n".join(lines) + "\n"
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
        except tk.TclError as e:
            messagebox.showwarning("MAC 扫描", f"复制失败：{e}", parent=self)
            return
        messagebox.showinfo("MAC 扫描", f"已复制 {len(lines)} 条 IP+MAC。", parent=self)

    def _export_csv(self) -> None:
        if not self._scan_data:
            messagebox.showinfo("MAC 扫描", "表格为空。", parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            title="导出 CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("文本", "*.txt")],
        )
        if not path:
            return
        header = ["IPv4", "状态", "MAC", "类型", "RTT_ms", "厂商", "备注"]
        if self._show_name_cols:
            header.append("计算机名")
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(header)
                for ip in sorted(self._scan_data.keys(), key=self._ip_sort_key):
                    row = self._scan_data[ip]
                    st = "在线" if row.alive else "离线"
                    rtt_s = "" if row.rtt_ms is None else f"{row.rtt_ms:.0f}"
                    cells = [
                        ip,
                        st,
                        row.mac or "",
                        row.arp_type,
                        rtt_s,
                        row.vendor,
                        row.remark,
                    ]
                    if self._show_name_cols:
                        cells.append(row.computer_name)
                    w.writerow(cells)
        except OSError as e:
            messagebox.showerror("MAC 扫描", f"写入失败：{e}", parent=self)
            return
        messagebox.showinfo("MAC 扫描", f"已导出：{path}", parent=self)

    def _on_stop(self) -> None:
        self._cancel_event.set()
        self.lbl_status.configure(text="正在停止…（等待已发起的探测结束）")

    def _on_start(self) -> None:
        if self._busy:
            return
        if not self.var_authorized.get():
            messagebox.showwarning(
                "MAC 扫描",
                "请先勾选「我已确认对扫描对象已获得有效授权」。",
                parent=self,
            )
            return

        try:
            mh = int(self.var_max_hosts.get())
            workers = int(self.var_workers.get())
            timeout_ms = int(self.var_timeout_ms.get())
        except tk.TclError:
            messagebox.showwarning("MAC 扫描", "参数须为整数。", parent=self)
            return

        if not (1 <= mh <= MAX_SCAN_HOSTS_HARD_LIMIT):
            messagebox.showwarning("MAC 扫描", f"单次上限须在 1–{MAX_SCAN_HOSTS_HARD_LIMIT}。", parent=self)
            return
        if not (1 <= workers <= 256):
            messagebox.showwarning("MAC 扫描", "并发数须在 1–256。", parent=self)
            return
        if not (100 <= timeout_ms <= 5000):
            messagebox.showwarning("MAC 扫描", "ICMP 等待须在 100–5000 ms。", parent=self)
            return

        spec = self.var_range.get().strip()
        try:
            ips, summary_text = parse_scan_targets(spec, max_hosts=mh)
        except ValueError as e:
            messagebox.showwarning("MAC 扫描", str(e), parent=self)
            return

        adapters, adapter_note = list_local_ipv4_adapters()
        if adapter_note and not adapters:
            messagebox.showwarning("MAC 扫描", adapter_note, parent=self)
            return
        try:
            iface = resolve_scan_interface(ips, adapters)
        except ValueError as e:
            messagebox.showwarning("MAC 扫描", str(e), parent=self)
            return

        resolve_name = self.var_resolve_name.get()
        use_dns = resolve_name and self.var_dns.get()
        use_netbios = resolve_name and self.var_netbios.get()
        self._rebuild_tree_columns(resolve_name)

        self._cancel_tree_refresh()
        self._scan_data.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)

        self._cancel_event.clear()
        self._busy = True
        self._apply_busy(True)
        self.lbl_summary.configure(
            text=f"范围摘要：{summary_text}　{iface.interface_summary}　网段 {iface.network.with_prefixlen}"
        )
        self.lbl_status.configure(text=f"扫描中… 共 {len(ips)} 个地址（ICMP）")

        def worker() -> None:
            try:
                ping_map, arp_all, cancelled = run_mac_scan(
                    ips,
                    iface,
                    timeout_ms=timeout_ms,
                    max_workers=workers,
                    cancel_event=self._cancel_event,
                    on_ping=lambda ip, alive, rtt: self._q.put(("ping", ip, alive, rtt)),
                    on_progress=lambda done, total: self._q.put(("prog", done, total, "icmp")),
                )
                merged: dict[str, MacScanRow] = {}
                if not self._cancel_event.is_set():
                    merged = merge_scan_rows(ips, ping_map, arp_all, iface)
                    self._q.put(("arp", merged))
                if (
                    not cancelled
                    and not self._cancel_event.is_set()
                    and resolve_name
                ):
                    self._q.put(("name_phase", len(ips)))

                    def on_name(ip: str, cn: str | None, dns: str | None) -> None:
                        self._q.put(("name", ip, cn, dns))

                    run_host_label_scan(
                        ips,
                        timeout_ms=timeout_ms,
                        use_dns=use_dns,
                        use_netbios=use_netbios,
                        max_workers=workers,
                        cancel_event=self._cancel_event,
                        on_each=on_name,
                    )
                alive_total = sum(1 for a, _ in ping_map.values() if a)
                mac_total = sum(1 for ip in ips if merged.get(ip) and merged[ip].mac)
                self._q.put(
                    (
                        "done",
                        alive_total,
                        mac_total,
                        len(ips),
                        cancelled,
                        summary_text,
                        iface.interface_summary,
                    )
                )
            except Exception as e:
                _log.exception("MAC 扫描线程异常")
                self._q.put(("error", str(e)))

        self._worker = threading.Thread(target=worker, daemon=True)
        self._worker.start()

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, *rest = self._q.get_nowait()
                if kind == "ping":
                    ip, alive, rtt = str(rest[0]), bool(rest[1]), rest[2]
                    row = self._scan_data.get(ip) or MacScanRow(ip=ip)
                    row.alive = alive
                    row.rtt_ms = float(rtt) if rtt is not None else None
                    self._scan_data[ip] = row
                    self._schedule_tree_refresh()
                elif kind == "arp":
                    rows: dict[str, MacScanRow] = rest[0]
                    self._scan_data.update(rows)
                    self._schedule_tree_refresh(immediate=True)
                    self.lbl_status.configure(text="扫描中… ARP 已合并，可选解析计算机名…")
                elif kind == "name_phase":
                    total = int(rest[0])
                    self.lbl_status.configure(text=f"扫描中… 解析计算机名 0/{total}")
                elif kind == "name":
                    ip = str(rest[0])
                    cn = rest[1]
                    if ip in self._scan_data and cn:
                        self._scan_data[ip].computer_name = str(cn)
                        self._schedule_tree_refresh()
                elif kind == "prog":
                    done, total, phase = int(rest[0]), int(rest[1]), str(rest[2])
                    if phase == "icmp":
                        self.lbl_status.configure(text=f"扫描中… ICMP {done}/{total}")
                elif kind == "done":
                    alive_total, mac_total, total, cancelled = (
                        int(rest[0]),
                        int(rest[1]),
                        int(rest[2]),
                        bool(rest[3]),
                    )
                    summary_text = str(rest[4])
                    iface_sum = str(rest[5])
                    self._busy = False
                    self._apply_busy(False)
                    self._worker = None
                    if cancelled:
                        n_done = len(self._scan_data)
                        self.lbl_status.configure(
                            text=f"已中止：已记录 {n_done} 条（在线 {alive_total}，有 MAC {mac_total}）。"
                        )
                    else:
                        self.lbl_status.configure(
                            text=f"完成。在线 {alive_total}/{total}，已解析 MAC {mac_total}/{total}"
                        )
                    self.lbl_summary.configure(
                        text=(
                            f"范围摘要：{summary_text}　{iface_sum}　"
                            f"在线 {alive_total}/{total}　MAC {mac_total}/{total}"
                        )
                    )
                    self._schedule_tree_refresh(immediate=True)
                    _log.info(
                        "MAC 扫描结束 alive=%s mac=%s total=%s cancelled=%s",
                        alive_total,
                        mac_total,
                        total,
                        cancelled,
                    )
                elif kind == "error":
                    self._busy = False
                    self._apply_busy(False)
                    self._worker = None
                    messagebox.showerror("MAC 扫描", str(rest[0]), parent=self)
                    self.lbl_status.configure(text="失败。")
        except queue.Empty:
            pass
        self.after(180, self._poll_queue)
