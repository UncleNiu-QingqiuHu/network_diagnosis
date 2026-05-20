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

_STATUS_ONLINE_DISP = "\u25cf 在线"
_STATUS_OFFLINE_DISP = "\u25cb 离线"

_COL_ALIVE_W = 100
_COL_MAC_W = 148
_COL_TYPE_W = 72
_COL_RTT_W = 72
_COL_VENDOR_W = 100
_COL_REMARK_W = 120
_COL_HOST_W = 120
_COL_DNS_W = 140

_BASE_COLS = ("ip", "alive", "mac", "arp_type", "rtt", "vendor", "remark")
_NAME_COLS = ("hostname", "dns_name")


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

    def _build_ui(self) -> None:
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        pw = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        pw.grid(row=0, column=0, sticky=NSEW)
        self._pw_mac_scan = pw

        frm_ops = ttk.Frame(pw, padding=(14, 14, 8, 14))
        frm_out = ttk.Frame(pw, padding=(8, 14, 14, 14))
        pw.add(frm_ops, weight=1)
        pw.add(frm_out, weight=1)
        try:
            pw.pane(frm_ops, weight=1)
            pw.pane(frm_out, weight=1)
        except tk.TclError:
            pass

        frm_ops.columnconfigure(0, weight=1)
        frm_out.rowconfigure(2, weight=1)
        frm_out.columnconfigure(0, weight=1)

        hint = ttk.Labelframe(frm_ops, text="合规提示", bootstyle=WARNING, padding=(10, 10, 10, 8))
        hint.grid(row=0, column=0, sticky=EW)
        hint.columnconfigure(0, weight=1)
        hint_msg = (
            "批量 ICMP 与读取本机 **ARP 表** 可能被安全设备记录；请在 **已获得授权** 的内网或测试环境中使用。\n"
            "**仅支持本机已连接网段**（不支持跨网段）；MAC 与计算机名不保证 100% 完整。"
        )
        txt_hint = tk.Text(
            hint,
            wrap=tk.WORD,
            width=36,
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
        append_simple_markdown(txt_hint, hint_msg.rstrip() + "\n")
        txt_hint.configure(state=tk.DISABLED)

        lf = ttk.Labelframe(frm_ops, text="扫描参数", padding=(12, 10, 12, 10))
        lf.grid(row=1, column=0, sticky=EW, pady=(12, 0))
        lf.columnconfigure(1, weight=1)

        ttk.Label(lf, text="范围").grid(row=0, column=0, sticky=W, pady=(0, 6))
        self.var_range = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(lf, textvariable=self.var_range).grid(row=0, column=1, sticky=EW, pady=(0, 6), padx=(8, 0))

        tip = (
            "① IPv4 CIDR，例如 192.168.1.0/24\n"
            "② 起止地址：192.168.1.1-192.168.1.254\n"
            "③ 单个地址：10.0.0.5"
        )
        ttk.Label(lf, text=tip, bootstyle=SECONDARY, justify=tk.LEFT).grid(
            row=1, column=0, columnspan=2, sticky=W, pady=(0, 10)
        )

        ttk.Label(lf, text="单次上限").grid(row=2, column=0, sticky=W)
        self.var_max_hosts = tk.IntVar(value=512)
        ttk.Spinbox(
            lf,
            from_=16,
            to=MAX_SCAN_HOSTS_HARD_LIMIT,
            textvariable=self.var_max_hosts,
            width=8,
        ).grid(row=2, column=1, sticky=W, padx=(8, 0))

        ttk.Label(lf, text="并发数").grid(row=3, column=0, sticky=W, pady=(8, 0))
        self.var_workers = tk.IntVar(value=48)
        ttk.Spinbox(lf, from_=1, to=256, textvariable=self.var_workers, width=8).grid(
            row=3, column=1, sticky=W, padx=(8, 0), pady=(8, 0)
        )

        ttk.Label(lf, text="ICMP 等待(ms)").grid(row=4, column=0, sticky=W, pady=(8, 0))
        self.var_timeout_ms = tk.IntVar(value=800)
        ttk.Spinbox(
            lf,
            from_=100,
            to=5000,
            increment=50,
            textvariable=self.var_timeout_ms,
            width=8,
        ).grid(row=4, column=1, sticky=W, padx=(8, 0), pady=(8, 0))

        self.var_authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            lf,
            text="我已确认对扫描对象已获得有效授权",
            variable=self.var_authorized,
            bootstyle="round-toggle",
        ).grid(row=5, column=0, columnspan=2, sticky=W, pady=(14, 0))

        self.var_resolve_name = tk.BooleanVar(value=False)
        chk_name = ttk.Checkbutton(
            lf,
            text="解析计算机名",
            variable=self.var_resolve_name,
            command=self._on_resolve_name_toggle,
            bootstyle="round-toggle",
        )
        chk_name.grid(row=6, column=0, columnspan=2, sticky=W, pady=(10, 0))

        self.var_dns = tk.BooleanVar(value=False)
        self.chk_dns = ttk.Checkbutton(
            lf,
            text="　含 DNS 反向查询",
            variable=self.var_dns,
            bootstyle="round-toggle",
            state=tk.DISABLED,
        )
        self.chk_dns.grid(row=7, column=0, columnspan=2, sticky=W)

        self.var_netbios = tk.BooleanVar(value=False)
        self.chk_netbios = ttk.Checkbutton(
            lf,
            text="　含 NetBIOS（较慢）",
            variable=self.var_netbios,
            bootstyle="round-toggle",
            state=tk.DISABLED,
        )
        self.chk_netbios.grid(row=8, column=0, columnspan=2, sticky=W)

        btn_row = ttk.Frame(frm_ops)
        btn_row.grid(row=2, column=0, sticky=EW, pady=(14, 0))
        self.btn_start = ttk.Button(btn_row, text="开始扫描", command=self._on_start, bootstyle=PRIMARY)
        self.btn_start.pack(fill=X, pady=(0, 6))
        self.btn_stop = ttk.Button(
            btn_row, text="停止", command=self._on_stop, bootstyle=SECONDARY, state=tk.DISABLED
        )
        self.btn_stop.pack(fill=X, pady=(0, 6))

        btn_row2 = ttk.Frame(frm_ops)
        btn_row2.grid(row=3, column=0, sticky=EW)
        ttk.Button(btn_row2, text="清空表格", command=self._clear_grid, bootstyle=SECONDARY).pack(
            side=LEFT, padx=(0, 8)
        )
        ttk.Button(btn_row2, text="导出 CSV…", command=self._export_csv, bootstyle=SECONDARY).pack(
            side=LEFT, padx=(0, 8)
        )
        ttk.Button(btn_row2, text="复制 IP+MAC", command=self._copy_ip_mac, bootstyle=SECONDARY).pack(
            side=LEFT, padx=(0, 8)
        )
        ttk.Button(btn_row2, text="复制在线列表", command=self._copy_alive, bootstyle=SECONDARY).pack(side=LEFT)

        self.lbl_status = ttk.Label(frm_ops, text="就绪。", bootstyle=INFO)
        self.lbl_status.grid(row=4, column=0, sticky=EW, pady=(14, 0))

        ttk.Label(frm_out, text="扫描结果", font=("Microsoft YaHei UI", 12, "bold")).grid(
            row=0, column=0, sticky=W, pady=(0, 8)
        )

        search_row = ttk.Frame(frm_out)
        search_row.grid(row=1, column=0, sticky=EW, pady=(0, 8))
        search_row.columnconfigure(1, weight=1)
        ttk.Label(search_row, text="搜索").grid(row=0, column=0, sticky=W)
        self.var_search = tk.StringVar()
        ent_search = ttk.Entry(search_row, textvariable=self.var_search)
        ent_search.grid(row=0, column=1, sticky=EW, padx=(8, 8))
        ent_search.bind("<KeyRelease>", self._on_search_changed)
        ttk.Button(search_row, text="清空", command=self._clear_search, bootstyle=SECONDARY).grid(
            row=0, column=2, sticky=W
        )

        wrap = ttk.Frame(frm_out)
        wrap.grid(row=2, column=0, sticky=NSEW)
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        self._scan_wrap = wrap

        self._tree_holder = ttk.Frame(wrap)
        self._tree_holder.grid(row=0, column=0, sticky=NSEW)
        self._tree_holder.rowconfigure(0, weight=1)
        self._tree_holder.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(self._tree_holder, show="headings", height=22, selectmode=tk.BROWSE)
        self._rebuild_tree_columns(False)

        scroll_y = ttk.Scrollbar(wrap, orient=VERTICAL, command=self.tree.yview)
        scroll_x = ttk.Scrollbar(wrap, orient=tk.HORIZONTAL, command=self.tree.xview)
        self._scan_scroll_y = scroll_y
        self._scan_scroll_x = scroll_x
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.tree.grid(row=0, column=0, sticky=NSEW)
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky=EW)

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

        self.lbl_summary = ttk.Label(frm_out, text="", bootstyle=SECONDARY, wraplength=520)
        self.lbl_summary.grid(row=3, column=0, sticky=W, pady=(10, 0))

        self.after(180, self._init_mac_scan_sash)
        self._apply_busy(False)

    def _on_resolve_name_toggle(self) -> None:
        on = self.var_resolve_name.get()
        st = tk.NORMAL if on else tk.DISABLED
        self.chk_dns.configure(state=st)
        self.chk_netbios.configure(state=st)
        if not on:
            self.var_dns.set(False)
            self.var_netbios.set(False)

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
            "dns_name": "DNS 名称",
        }
        widths = {
            "ip": 120,
            "alive": _COL_ALIVE_W,
            "mac": _COL_MAC_W,
            "arp_type": _COL_TYPE_W,
            "rtt": _COL_RTT_W,
            "vendor": _COL_VENDOR_W,
            "remark": _COL_REMARK_W,
            "hostname": _COL_HOST_W,
            "dns_name": _COL_DNS_W,
        }
        for c in cols:
            self.tree.heading(c, text=headings[c])
            anchor = tk.W if c in ("ip", "mac", "vendor", "remark", "hostname", "dns_name") else tk.CENTER
            self.tree.column(c, width=widths[c], anchor=anchor, stretch=False)

    def _init_mac_scan_sash(self, attempt: int = 0) -> None:
        if attempt > 40:
            return
        try:
            self.update_idletasks()
            pw = self._pw_mac_scan
            w = pw.winfo_width()
            if w <= 80:
                self.after(80, lambda a=attempt + 1: self._init_mac_scan_sash(a))
                return
            pw.sashpos(0, max(w // 2, 120))
        except tk.TclError:
            pass

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
            return base + (row.computer_name, row.dns_name)
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
            row.dns_name,
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

    def _refresh_scan_tree(self) -> None:
        needle = self.var_search.get().strip().lower()
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
        self.var_search.set("")
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
            header.extend(["计算机名", "DNS名称"])
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
                        cells.extend([row.computer_name, row.dns_name])
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
                    cn, dns = rest[1], rest[2]
                    if ip in self._scan_data:
                        if cn:
                            self._scan_data[ip].computer_name = str(cn)
                        if dns:
                            self._scan_data[ip].dns_name = str(dns)
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
