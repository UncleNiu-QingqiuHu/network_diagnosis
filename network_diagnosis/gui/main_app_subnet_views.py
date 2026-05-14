"""子网计算视图：界面搭建与主机信息异步刷新。"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText

import ttkbootstrap as ttk
from ttkbootstrap.constants import END, EW, NSEW, PRIMARY, SECONDARY, SUCCESS, W

from network_diagnosis.gui.main_app_common import bind_label_wraplength
from network_diagnosis.host_l3_info import (
    AdapterIPv4Block,
    list_local_ipv4_adapters,
    local_hostname,
)
from network_diagnosis.model.report import EgressProbeResult
from network_diagnosis.probes.egress_probe import run_egress
from network_diagnosis.runtime_log import get_logger
from network_diagnosis.subnet_calc import (
    SubnetCalcResult,
    calc_from_cidr_combo,
    calc_subnet,
    subdivide_ipv4_equal_children,
)

_log = get_logger(__name__)


class SubnetViewsMixin:
    def _build_subnet_view(self) -> None:
        self._subnet_refresh_busy = False
        frm = ttk.Frame(self._content_host)
        self._view_frames["subnet"] = frm
        frm.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)

        pw = ttk.Panedwindow(frm, orient=tk.HORIZONTAL)
        pw.grid(row=0, column=0, sticky=NSEW)
        self._pw_subnet = pw

        left = ttk.Frame(pw, padding=(14, 14, 8, 14))
        right = ttk.Frame(pw, padding=(8, 14, 14, 14))
        pw.add(left, weight=1)
        pw.add(right, weight=1)

        left.columnconfigure(0, weight=1)

        lf_cidr = ttk.Labelframe(left, text="方式一(推荐)", padding=(12, 10, 12, 10))
        lf_cidr.grid(row=0, column=0, sticky=EW, pady=(0, 10))
        lf_cidr.columnconfigure(0, weight=1)
        self.var_subnet_combo = tk.StringVar(value="192.168.1.10/24")
        lbl_cidr_hint = ttk.Label(
            lf_cidr,
            text="支持 IP/前缀（如 192.168.1.10/24）或 IP/掩码（如 192.168.1.10/255.255.255.0）",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 10),
            justify=tk.LEFT,
        )
        lbl_cidr_hint.grid(row=0, column=0, sticky=EW)
        bind_label_wraplength(lbl_cidr_hint, inset=6)
        ttk.Entry(lf_cidr, textvariable=self.var_subnet_combo).grid(
            row=1, column=0, sticky=EW, pady=(8, 0)
        )

        lf_split = ttk.Labelframe(left, text="方式二(仅当方式一不含「/」时使用)", padding=(12, 10, 12, 10))
        lf_split.grid(row=1, column=0, sticky=EW, pady=(0, 10))
        lf_split.columnconfigure(1, weight=1)
        self.var_subnet_ip = tk.StringVar(value="192.168.1.10")
        self.var_subnet_prefix = tk.IntVar(value=24)
        self.var_subnet_mask = tk.StringVar(value="")

        ttk.Label(lf_split, text="IPv4 地址", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 10))
        ttk.Entry(lf_split, textvariable=self.var_subnet_ip).grid(
            row=0, column=1, sticky=EW
        )
        row1 = ttk.Frame(lf_split)
        row1.grid(row=1, column=0, columnspan=2, sticky=W, pady=(10, 0))
        ttk.Label(row1, text="前缀长度", bootstyle=SECONDARY).pack(side=tk.LEFT)
        ttk.Spinbox(row1, from_=0, to=32, textvariable=self.var_subnet_prefix, width=5).pack(
            side=tk.LEFT, padx=(6, 16)
        )
        ttk.Label(row1, text="或掩码", bootstyle=SECONDARY).pack(side=tk.LEFT)
        ttk.Entry(row1, textvariable=self.var_subnet_mask, width=18).pack(
            side=tk.LEFT, padx=(6, 0)
        )
        lbl_split_hint = ttk.Label(
            lf_split,
            text="须填 IPv4; 掩码非空时只按掩码计算（前缀 Spinbox 不参与）；掩码留空时才按前缀。方式一含「/」时本组会被忽略。",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 10),
            justify=tk.LEFT,
        )
        lbl_split_hint.grid(row=2, column=0, columnspan=2, sticky=EW, pady=(10, 0))
        bind_label_wraplength(lbl_split_hint, inset=6)

        btn_row = ttk.Frame(left)
        btn_row.grid(row=2, column=0, sticky=EW, pady=(0, 10))
        ttk.Button(btn_row, text="计算子网", command=self._subnet_on_compute, bootstyle=SUCCESS).pack(
            side=tk.LEFT
        )
        ttk.Button(btn_row, text="复制结果", command=self._subnet_copy_result, bootstyle=SECONDARY).pack(
            side=tk.LEFT, padx=(8, 0)
        )

        lf_div = ttk.Labelframe(left, text="可选：等长子网划分", padding=(12, 10, 12, 10))
        lf_div.grid(row=3, column=0, sticky=EW, pady=(0, 10))
        lbl_div_hint = ttk.Label(
            lf_div,
            text="将父网均匀划分成更小前缀的子网；下列最多列出 64 条，可与上方「计算子网」结果同时保留在结果框内。",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 10),
            justify=tk.LEFT,
        )
        lbl_div_hint.pack(fill=tk.X)
        bind_label_wraplength(lbl_div_hint, inset=6)
        row_pa = ttk.Frame(lf_div)
        row_pa.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(row_pa, text="父网 CIDR", bootstyle=SECONDARY).pack(side=tk.LEFT)
        self.var_subnet_parent = tk.StringVar(value="192.168.0.0/16")
        ttk.Entry(row_pa, textvariable=self.var_subnet_parent).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))
        row_pb = ttk.Frame(lf_div)
        row_pb.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(row_pb, text="划至前缀 /", bootstyle=SECONDARY).pack(side=tk.LEFT)
        self.var_subnet_child_prefix = tk.IntVar(value=24)
        ttk.Spinbox(row_pb, from_=1, to=32, textvariable=self.var_subnet_child_prefix, width=5).pack(
            side=tk.LEFT, padx=(6, 12)
        )
        ttk.Button(row_pb, text="生成子网列表", command=self._subnet_on_subdivide, bootstyle=SECONDARY).pack(
            side=tk.LEFT
        )

        lf_out = ttk.Labelframe(left, text="计算结果", padding=(10, 8, 10, 10))
        lf_out.grid(row=4, column=0, sticky=NSEW)
        lf_out.rowconfigure(0, weight=1)
        lf_out.columnconfigure(0, weight=1)
        self.txt_subnet_result = ScrolledText(
            lf_out,
            height=14,
            wrap=tk.WORD,
            font=("Consolas", 11),
            relief=tk.FLAT,
            padx=8,
            pady=8,
        )
        self.txt_subnet_result.grid(row=0, column=0, sticky=NSEW)

        left.rowconfigure(4, weight=1)

        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        head_r = ttk.Frame(right)
        head_r.grid(row=0, column=0, sticky=EW, pady=(0, 10))
        ttk.Label(head_r, text="本机 IPv4、网关、DNS 与公网地址（点击刷新）", bootstyle=SECONDARY).pack(
            side=tk.LEFT, anchor=W, fill=tk.X, expand=True
        )
        self.btn_subnet_refresh = ttk.Button(
            head_r,
            text="刷新",
            command=self._subnet_refresh_host_info,
            bootstyle=PRIMARY,
            width=8,
        )
        self.btn_subnet_refresh.pack(side=tk.RIGHT)

        lf_host = ttk.Labelframe(right, text="当前主机与出口", padding=(10, 8, 10, 10))
        lf_host.grid(row=1, column=0, sticky=NSEW)
        lf_host.rowconfigure(0, weight=1)
        lf_host.columnconfigure(0, weight=1)
        self.txt_subnet_host = ScrolledText(
            lf_host,
            height=18,
            wrap=tk.WORD,
            font=("Microsoft YaHei UI", 11),
            relief=tk.FLAT,
            padx=8,
            pady=8,
        )
        self.txt_subnet_host.grid(row=0, column=0, sticky=NSEW)

        self.after(180, self._init_subnet_sash)

    def _init_subnet_sash(self, attempt: int = 0) -> None:
        if attempt > 12:
            return
        try:
            self.update_idletasks()
            pw = self._pw_subnet
            w = pw.winfo_width()
            if w <= 10:
                self.after(80, lambda: self._init_subnet_sash(attempt + 1))
                return
            pw.sashpos(0, w // 2)
        except tk.TclError:
            pass

    @staticmethod
    def _format_subnet_calc(r: SubnetCalcResult) -> str:
        return "\n".join(
            [
                f"输入：{r.input_interface}",
                f"地址空间归类：{r.scope_note}",
                f"输入 IP 角色：{r.host_role_note}",
                f"所属网络（CIDR）：{r.network_cidr}",
                f"网络地址：{r.network_address}",
                f"广播地址：{r.broadcast_address}",
                f"子网掩码：{r.netmask}",
                f"通配符掩码（ACL）：{r.wildcard_mask}",
                f"前缀长度：/{r.prefix_len}",
                f"总地址数：{r.total_addresses}",
                f"可用主机数：{r.usable_hosts}",
                f"第一个可用主机：{r.first_host}",
                f"最后一个可用主机：{r.last_host}",
            ]
        )

    def _subnet_on_compute(self) -> None:
        combo = self.var_subnet_combo.get().strip()
        try:
            if "/" in combo:
                r = calc_from_cidr_combo(combo)
            else:
                ip = self.var_subnet_ip.get().strip()
                if not ip:
                    messagebox.showwarning("子网计算", "请填写 CIDR 栏（含 /）或 IPv4 地址。")
                    return
                mask = self.var_subnet_mask.get().strip()
                if mask:
                    r = calc_subnet(ip, netmask_dotted=mask)
                else:
                    r = calc_subnet(ip, prefix_len=int(self.var_subnet_prefix.get()))
        except ValueError as e:
            messagebox.showwarning("子网计算", str(e))
            return

        txt = self._format_subnet_calc(r)
        _log.info(
            "子网计算完成 network_cidr=%s prefix=%s",
            r.network_cidr,
            r.prefix_len,
        )
        st = self.txt_subnet_result
        st.configure(state=tk.NORMAL)
        st.delete("1.0", END)
        st.insert(END, txt)
        st.configure(state=tk.DISABLED)

    def _subnet_copy_result(self) -> None:
        st = self.txt_subnet_result
        st.configure(state=tk.NORMAL)
        txt = st.get("1.0", END).strip()
        st.configure(state=tk.DISABLED)
        if not txt:
            messagebox.showinfo("子网计算", "暂无结果可复制。")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(txt)
            self.update()
        except tk.TclError as e:
            messagebox.showwarning("子网计算", f"复制失败：{e}")

    def _subnet_on_subdivide(self) -> None:
        parent = self.var_subnet_parent.get().strip()
        try:
            child_pf = int(self.var_subnet_child_prefix.get())
        except (tk.TclError, ValueError):
            messagebox.showwarning("子网划分", "划至前缀无效。")
            return
        try:
            block = subdivide_ipv4_equal_children(parent, child_pf)
        except ValueError as e:
            messagebox.showwarning("子网划分", str(e))
            return
        _log.info("子网划分 parent=%s child_prefix=%s", parent, child_pf)
        st = self.txt_subnet_result
        st.configure(state=tk.NORMAL)
        cur = st.get("1.0", END).strip()
        if cur:
            st.insert(END, "\n\n")
        st.insert(END, block)
        st.see(END)
        st.configure(state=tk.DISABLED)

    def _subnet_refresh_host_info(self) -> None:
        if self._subnet_refresh_busy:
            return
        self._subnet_refresh_busy = True
        self.btn_subnet_refresh.configure(state=tk.DISABLED)
        self.txt_subnet_host.configure(state=tk.NORMAL)
        self.txt_subnet_host.delete("1.0", END)
        self.txt_subnet_host.insert(END, "正在读取本机配置与公网地址，请稍候…")
        self.txt_subnet_host.configure(state=tk.DISABLED)

        _log.info("子网页刷新本机与出口信息（后台线程）")

        def work() -> None:
            adapters, warn = list_local_ipv4_adapters()
            try:
                egress = run_egress()
            except Exception as e:
                err_s = str(e)
                _log.warning("出口探测 run_egress 异常", exc_info=True)
                self.after(
                    0,
                    lambda ad=adapters, w=warn, err=err_s: self._subnet_apply_host_info(
                        ad, w, None, err
                    ),
                )
                return
            self.after(
                0,
                lambda ad=adapters, w=warn, eg=egress: self._subnet_apply_host_info(ad, w, eg, None),
            )
            _log.info(
                "子网页本机适配器与出口探测完成 adapter_blocks=%s warn=%s",
                len(adapters),
                bool(warn),
            )

        threading.Thread(target=work, daemon=True).start()

    def _subnet_apply_host_info(
        self,
        adapters: list[AdapterIPv4Block],
        warn: str | None,
        egress: EgressProbeResult | None,
        egress_exc: str | None,
    ) -> None:
        self._subnet_refresh_busy = False
        try:
            self.btn_subnet_refresh.configure(state=tk.NORMAL)
        except tk.TclError:
            return

        lines: list[str] = [f"主机名：{local_hostname()}", ""]

        if warn:
            lines.append(f"提示：{warn}")
            lines.append("")

        lines.append("【本机 IPv4 接口（Windows：WMI；每条为地址+掩码）】")
        if adapters:
            for i, b in enumerate(adapters, 1):
                lines.append(f"{i}. {b.description}")
                if b.mac:
                    lines.append(f"   MAC：{b.mac}")
                lines.append(f"   IPv4 / 掩码：{b.ipv4} / {b.netmask}")
                lines.append(
                    f"   默认网关：{'；'.join(b.gateways) if b.gateways else '—'}"
                )
                lines.append(
                    f"   DNS 服务器：{'；'.join(b.dns_servers) if b.dns_servers else '—'}"
                )
                lines.append("")
        else:
            lines.append("（未列出任何 IPv4 地址，可能查询失败或当前无活动网卡）")
            lines.append("")

        lines.append("【公网 IPv4（国内多源查询，仅供参考）】")
        if egress_exc:
            lines.append(f"查询过程异常：{egress_exc}")
        elif egress is not None:
            if egress.public_ip:
                lines.append(f"地址：{egress.public_ip}")
            else:
                lines.append("地址：（未获取）")
            if egress.ipify_error:
                lines.append(f"详细信息：{egress.ipify_error}")
        else:
            lines.append("—")
        lines.append("")

        lines.append("【代理摘要（环境变量 / WinHTTP）】")
        if egress is not None:
            if egress.http_proxy:
                lines.append(f"HTTP_PROXY：{egress.http_proxy}")
            if egress.https_proxy:
                lines.append(f"HTTPS_PROXY：{egress.https_proxy}")
            if egress.all_proxy:
                lines.append(f"ALL_PROXY：{egress.all_proxy}")
            if egress.no_proxy:
                lines.append(f"NO_PROXY：{egress.no_proxy}")
            if egress.winhttp_note:
                snippet = egress.winhttp_note.replace("\n", " ").strip()
                if len(snippet) > 400:
                    snippet = snippet[:397] + "…"
                lines.append(f"netsh winhttp（节选）：{snippet}")
        lines.append("")
        lines.append("说明：同一物理网卡多块 IPv4 时，网关与 DNS 可能在每条记录中重复列出（来自 WMI）。")

        body = "\n".join(lines)
        st = self.txt_subnet_host
        st.configure(state=tk.NORMAL)
        st.delete("1.0", END)
        st.insert(END, body)
        st.configure(state=tk.DISABLED)
