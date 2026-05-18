"""IP 扫描页：IPv4 ICMP 存活探测（授权确认后执行）。"""

from __future__ import annotations

import csv
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

import ttkbootstrap as ttk
from ttkbootstrap.constants import END, EW, INFO, LEFT, NSEW, PRIMARY, SECONDARY, VERTICAL, WARNING, W, X

from network_diagnosis.gui.simple_markdown_text import append_simple_markdown, configure_simple_markdown_tags
from network_diagnosis.ip_scan import MAX_SCAN_HOSTS_HARD_LIMIT, parse_scan_targets, run_ping_scan
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)

# 状态列：实心圆 ● / 空心圆 ○（字形易区分）；行前景色再用主题绿/红强化在线/离线
_STATUS_ONLINE_DISP = "\u25cf 在线"
_STATUS_OFFLINE_DISP = "\u25cb 离线"

# 扫描表格固定列宽（像素）；IPv4 列随容器宽度在 _sync_scan_tree_columns 中计算
_TREE_COL_ALIVE_W = 132
_TREE_COL_RTT_W = 120


class IpScanFrame(ttk.Frame):
    def __init__(self, master: tk.Misc, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self._q: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._worker: threading.Thread | None = None
        self._cancel_event = threading.Event()
        self._build_ui()
        self.after(180, self._poll_queue)

    def on_leave(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            self._cancel_event.set()

    def on_show(self) -> None:
        """首次显示前 Panedwindow 宽度常为 0，延迟执行的 sash 易失效；切换回本页时再居中一次。"""
        self.update_idletasks()
        self.after_idle(lambda: self._init_ip_scan_sash(0))
        self.after(120, lambda: self._init_ip_scan_sash(0))

    def _build_ui(self) -> None:
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        pw = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        pw.grid(row=0, column=0, sticky=NSEW)
        self._pw_ip_scan = pw

        frm_ops = ttk.Frame(pw, padding=(14, 14, 8, 14))
        frm_out = ttk.Frame(pw, padding=(8, 14, 14, 14))
        self._frm_ops_pane = frm_ops
        self._frm_out_pane = frm_out
        pw.add(frm_ops, weight=1)
        pw.add(frm_out, weight=1)
        try:
            pw.pane(frm_ops, weight=1)
            pw.pane(frm_out, weight=1)
        except tk.TclError:
            pass

        frm_ops.columnconfigure(0, weight=1)

        frm_out.rowconfigure(1, weight=1)
        frm_out.columnconfigure(0, weight=1)

        hint = ttk.Labelframe(frm_ops, text="合规提示", bootstyle=WARNING, padding=(10, 10, 10, 8))
        hint.grid(row=0, column=0, sticky=EW)
        hint.columnconfigure(0, weight=1)
        hint_msg = (
            "向一段 IPv4 地址发送 ICMP 可能被安全设备记录；请在 **已获得授权** 的内网或测试环境中使用。\n"
            "本页默认排除典型以太网前缀下的网络地址与广播地址（与子网计算的可用主机语义一致）；"
            "`/32` 仅探测该主机。"
        )
        txt_hint = tk.Text(
            hint,
            wrap=tk.WORD,
            width=36,
            height=6,
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
        ent_range = ttk.Entry(lf, textvariable=self.var_range)
        ent_range.grid(row=0, column=1, sticky=EW, pady=(0, 6), padx=(8, 0))

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
        sp_max = ttk.Spinbox(
            lf,
            from_=16,
            to=MAX_SCAN_HOSTS_HARD_LIMIT,
            textvariable=self.var_max_hosts,
            width=8,
        )
        sp_max.grid(row=2, column=1, sticky=W, padx=(8, 0))

        ttk.Label(lf, text="并发数").grid(row=3, column=0, sticky=W, pady=(8, 0))
        self.var_workers = tk.IntVar(value=48)
        sp_workers = ttk.Spinbox(lf, from_=1, to=256, textvariable=self.var_workers, width=8)
        sp_workers.grid(row=3, column=1, sticky=W, padx=(8, 0), pady=(8, 0))

        ttk.Label(lf, text="ICMP 等待(ms)").grid(row=4, column=0, sticky=W, pady=(8, 0))
        self.var_timeout_ms = tk.IntVar(value=800)
        sp_to = ttk.Spinbox(lf, from_=100, to=5000, increment=50, textvariable=self.var_timeout_ms, width=8)
        sp_to.grid(row=4, column=1, sticky=W, padx=(8, 0), pady=(8, 0))

        self.var_authorized = tk.BooleanVar(value=False)
        chk_auth = ttk.Checkbutton(
            lf,
            text="我已确认对扫描对象已获得有效授权",
            variable=self.var_authorized,
            bootstyle="round-toggle",
        )
        chk_auth.grid(row=5, column=0, columnspan=2, sticky=W, pady=(14, 0))

        btn_row = ttk.Frame(frm_ops)
        btn_row.grid(row=2, column=0, sticky=EW, pady=(14, 0))
        btn_row.columnconfigure(0, weight=1)

        self.btn_start = ttk.Button(btn_row, text="开始扫描", command=self._on_start, bootstyle=PRIMARY)
        self.btn_start.pack(fill=X, pady=(0, 6))
        self.btn_stop = ttk.Button(btn_row, text="停止", command=self._on_stop, bootstyle=SECONDARY, state=tk.DISABLED)
        self.btn_stop.pack(fill=X, pady=(0, 6))

        btn_row2 = ttk.Frame(frm_ops)
        btn_row2.grid(row=3, column=0, sticky=EW)
        ttk.Button(btn_row2, text="清空表格", command=self._clear_grid, bootstyle=SECONDARY).pack(
            side=LEFT, padx=(0, 8)
        )
        ttk.Button(btn_row2, text="导出 CSV…", command=self._export_csv, bootstyle=SECONDARY).pack(
            side=LEFT, padx=(0, 8)
        )
        ttk.Button(btn_row2, text="复制在线列表", command=self._copy_alive, bootstyle=SECONDARY).pack(side=LEFT)

        self.lbl_status = ttk.Label(frm_ops, text="就绪。", bootstyle=INFO)
        self.lbl_status.grid(row=4, column=0, sticky=EW, pady=(14, 0))

        hdr = ttk.Label(frm_out, text="扫描结果", font=("Microsoft YaHei UI", 12, "bold"))
        hdr.grid(row=0, column=0, sticky=W, pady=(0, 8))

        wrap = ttk.Frame(frm_out)
        wrap.grid(row=1, column=0, sticky=NSEW)
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        self._scan_wrap = wrap

        cols = ("ip", "alive", "rtt")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", height=22, selectmode=tk.BROWSE)
        self.tree.heading("ip", text="IPv4 地址")
        self.tree.heading("alive", text="状态")
        self.tree.heading("rtt", text="RTT (ms)")
        # 初始宽度占位；真实宽度在 _sync_scan_tree_columns 中按容器裁定（避免列宽总和超出可视区域）
        self.tree.column("ip", width=260, anchor=tk.W, stretch=False)
        self.tree.column("alive", width=_TREE_COL_ALIVE_W, anchor=tk.CENTER, stretch=False)
        self.tree.column("rtt", width=_TREE_COL_RTT_W, anchor=tk.CENTER, stretch=False)

        scroll_y = ttk.Scrollbar(wrap, orient=VERTICAL, command=self.tree.yview)
        self._scan_scroll_y = scroll_y
        self.tree.configure(yscrollcommand=scroll_y.set)
        self.tree.grid(row=0, column=0, sticky=NSEW)
        scroll_y.grid(row=0, column=1, sticky="ns")

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

        self.lbl_summary = ttk.Label(frm_out, text="", bootstyle=SECONDARY)
        self.lbl_summary.grid(row=2, column=0, sticky=W, pady=(10, 0))

        self.after_idle(self._sync_scan_tree_columns)
        self.after(180, self._init_ip_scan_sash)

        self._apply_busy(False)

    def _init_ip_scan_sash(self, attempt: int = 0) -> None:
        """左右约 1:1；与子网计算页 Panedwindow 行为一致。"""
        if attempt > 40:
            return
        try:
            self.update_idletasks()
            pw = self._pw_ip_scan
            w = pw.winfo_width()
            if w <= 80:
                self.after(80, lambda a=attempt + 1: self._init_ip_scan_sash(a))
                return
            half = max(w // 2, 120)
            pw.sashpos(0, half)
        except tk.TclError:
            pass
        self.after_idle(self._sync_scan_tree_columns)

    def _sync_scan_tree_columns(self, event: tk.Event | None = None) -> None:
        """按右侧容器宽度裁定 IPv4 列宽，避免 Treeview 列总宽超出可视区域导致显示错乱。"""
        if event is not None and event.widget is not self._scan_wrap:
            return
        try:
            ww = self._scan_wrap.winfo_width()
        except tk.TclError:
            return
        if ww <= 48:
            return
        try:
            sb_w = max(int(self._scan_scroll_y.winfo_width()), 16)
        except tk.TclError:
            sb_w = 18
        inner = max(ww - sb_w - 12, 160)
        sep_gutter = 28
        ip_w = max(140, inner - _TREE_COL_ALIVE_W - _TREE_COL_RTT_W - sep_gutter)
        try:
            self.tree.column("alive", width=_TREE_COL_ALIVE_W)
            self.tree.column("rtt", width=_TREE_COL_RTT_W)
            self.tree.column("ip", width=int(ip_w))
        except tk.TclError:
            pass

    def _apply_busy(self, busy: bool) -> None:
        self._busy = busy
        if busy:
            self.btn_start.configure(state=tk.DISABLED)
            self.btn_stop.configure(state=tk.NORMAL)
        else:
            self.btn_start.configure(state=tk.NORMAL)
            self.btn_stop.configure(state=tk.DISABLED)

    def _clear_grid(self) -> None:
        if self._busy:
            messagebox.showinfo("IP 扫描", "扫描进行中，请稍候或先停止。", parent=self)
            return
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.lbl_summary.configure(text="")

    def _copy_alive(self) -> None:
        lines: list[str] = []
        for iid in self.tree.get_children():
            ip, alive, _rtt = self.tree.item(iid, "values")
            if str(alive).endswith("在线"):
                lines.append(str(ip))
        if not lines:
            messagebox.showinfo("IP 扫描", "当前没有「在线」地址可复制。", parent=self)
            return
        text = "\n".join(lines) + "\n"
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
        except tk.TclError as e:
            messagebox.showwarning("IP 扫描", f"复制失败：{e}", parent=self)
            return
        messagebox.showinfo("IP 扫描", f"已复制 {len(lines)} 条在线地址到剪贴板。", parent=self)

    def _export_csv(self) -> None:
        rows = [self.tree.item(iid, "values") for iid in self.tree.get_children()]
        if not rows:
            messagebox.showinfo("IP 扫描", "表格为空。", parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            title="导出 CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("文本", "*.txt")],
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["IPv4", "状态", "RTT_ms"])
                for ip, alive, rtt in rows:
                    plain = "离线" if str(alive).endswith("离线") else "在线"
                    w.writerow([ip, plain, rtt])
        except OSError as e:
            messagebox.showerror("IP 扫描", f"写入失败：{e}", parent=self)
            return
        messagebox.showinfo("IP 扫描", f"已导出：{path}", parent=self)

    def _on_stop(self) -> None:
        self._cancel_event.set()
        self.lbl_status.configure(text="正在停止…（等待已发起的 ping 结束）")

    def _on_start(self) -> None:
        if self._busy:
            return
        if not self.var_authorized.get():
            messagebox.showwarning(
                "IP 扫描",
                "请先勾选「我已确认对扫描对象已获得有效授权」。",
                parent=self,
            )
            return

        try:
            mh = int(self.var_max_hosts.get())
        except tk.TclError:
            messagebox.showwarning("IP 扫描", "单次上限须为整数。", parent=self)
            return
        try:
            workers = int(self.var_workers.get())
        except tk.TclError:
            messagebox.showwarning("IP 扫描", "并发数须为整数。", parent=self)
            return
        try:
            timeout_ms = int(self.var_timeout_ms.get())
        except tk.TclError:
            messagebox.showwarning("IP 扫描", "ICMP 等待须为整数。", parent=self)
            return

        if not (1 <= mh <= MAX_SCAN_HOSTS_HARD_LIMIT):
            messagebox.showwarning("IP 扫描", f"单次上限须在 1–{MAX_SCAN_HOSTS_HARD_LIMIT}。", parent=self)
            return
        if not (1 <= workers <= 256):
            messagebox.showwarning("IP 扫描", "并发数须在 1–256。", parent=self)
            return
        if not (100 <= timeout_ms <= 5000):
            messagebox.showwarning("IP 扫描", "ICMP 等待须在 100–5000 ms。", parent=self)
            return

        spec = self.var_range.get().strip()
        try:
            ips, summary_text = parse_scan_targets(spec, max_hosts=mh)
        except ValueError as e:
            messagebox.showwarning("IP 扫描", str(e), parent=self)
            return

        for iid in self.tree.get_children():
            self.tree.delete(iid)

        self._cancel_event.clear()
        self._busy = True
        self._apply_busy(True)
        self.lbl_summary.configure(text=f"范围摘要：{summary_text}")
        self.lbl_status.configure(text=f"扫描中… 共 {len(ips)} 个地址")

        def worker() -> None:
            try:
                alive_total, cancelled = run_ping_scan(
                    ips,
                    timeout_ms=timeout_ms,
                    max_workers=workers,
                    cancel_event=self._cancel_event,
                    on_each=lambda ip, alive, rtt: self._q.put(("row", ip, alive, rtt)),
                    on_progress=lambda done, total: self._q.put(("prog", done, total)),
                )
                self._q.put(("done", alive_total, len(ips), cancelled, summary_text))
            except Exception as e:
                _log.exception("IP 扫描线程异常")
                self._q.put(("error", str(e)))

        self._worker = threading.Thread(target=worker, daemon=True)
        self._worker.start()

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, *rest = self._q.get_nowait()
                if kind == "row":
                    ip, alive, rtt = rest[0], rest[1], rest[2]
                    tag = "alive" if alive else "dead"
                    st = _STATUS_ONLINE_DISP if alive else _STATUS_OFFLINE_DISP
                    rtt_s = "" if rtt is None else f"{rtt:.0f}"
                    self.tree.insert("", END, values=(ip, st, rtt_s), tags=(tag,))
                elif kind == "prog":
                    done, total = int(rest[0]), int(rest[1])
                    self.lbl_status.configure(text=f"扫描中… {done}/{total}")
                elif kind == "done":
                    alive_total, total, cancelled, summary_text = (
                        int(rest[0]),
                        int(rest[1]),
                        bool(rest[2]),
                        str(rest[3]),
                    )
                    self._busy = False
                    self._apply_busy(False)
                    self._worker = None
                    if cancelled:
                        n_done = len(self.tree.get_children())
                        self.lbl_status.configure(
                            text=f"已中止：已记录 {n_done} 条结果（其中在线 {alive_total}）。"
                        )
                    else:
                        self.lbl_status.configure(text=f"完成。在线 {alive_total} / {total}")
                    self.lbl_summary.configure(text=f"范围摘要：{summary_text}　在线 {alive_total}/{total}")
                    _log.info("IP 扫描结束 alive=%s total=%s cancelled=%s", alive_total, total, cancelled)
                elif kind == "error":
                    self._busy = False
                    self._apply_busy(False)
                    self._worker = None
                    messagebox.showerror("IP 扫描", str(rest[0]), parent=self)
                    self.lbl_status.configure(text="失败。")
        except queue.Empty:
            pass
        self.after(180, self._poll_queue)
