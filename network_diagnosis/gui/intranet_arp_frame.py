"""ARP 安全监控页：网关 MAC 基线对比、`arp -a` 轮询。"""

from __future__ import annotations

import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox

import ttkbootstrap as ttk

from network_diagnosis.arp_monitor import ArpGatewaySnapshot, build_snapshot, normalize_mac, run_arp_a_text
from network_diagnosis.host_l3_info import list_local_ipv4_adapters

_BG = "#0a0a0a"
_CARD = "#12121a"
_FG = "#e8eaed"
_FG_DIM = "#9aa0a6"
_GREEN = "#3dff7a"
_RED = "#ff5c5c"
_ORANGE = "#ffb020"
_LOG_BG = "#0d0d12"
_LOG_FG = "#b8f5c6"


class IntranetArpMonitorFrame(ttk.Frame):
    """ARP 网关 MAC 一致性监视：启动后以 `arp -a` 轮询，MAC 相对基线变化则提示疑似欺骗。"""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self._poll_after_id: str | None = None
        self._monitoring = False
        self._baseline_mac: str | None = None
        self._last_snap: ArpGatewaySnapshot | None = None
        self._adapter_warn: str | None = None

        shell = tk.Frame(self, bg=_BG)
        shell.grid(row=0, column=0, sticky=tk.NSEW)
        shell.rowconfigure(1, weight=1)
        shell.columnconfigure(0, weight=1)

        _theme = ttk.Style().colors
        self._theme_colors = _theme

        fr_top = tk.Frame(
            shell,
            bg=_CARD,
            highlightbackground=_theme.primary,
            highlightthickness=2,
            highlightcolor=_theme.primary,
        )
        fr_top.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 8))

        inner = tk.Frame(fr_top, bg=_CARD)
        inner.pack(fill=tk.X, padx=10, pady=(8, 10))

        self._var_local_ip = tk.StringVar(value="—")
        self._var_gateway = tk.StringVar(value="—")
        self._var_net = tk.StringVar(value="—")
        self._var_dev_cnt = tk.StringVar(value="—")
        self._var_abn_cnt = tk.StringVar(value="0")

        def _pair(base_col: int, title: str, var: tk.StringVar, *, first: bool = False) -> None:
            tk.Label(inner, text=title + "：", bg=_CARD, fg=_FG_DIM, font=("Microsoft YaHei UI", 10)).grid(
                row=0,
                column=base_col,
                sticky=tk.W,
                padx=(2 if first else 12, 4),
            )
            tk.Label(
                inner,
                textvariable=var,
                bg=_CARD,
                fg=_GREEN,
                font=("Consolas", 11, "bold"),
            ).grid(row=0, column=base_col + 1, sticky=tk.W, padx=(0, 18))

        _pair(0, "本机 IP", self._var_local_ip, first=True)
        _pair(2, "网关", self._var_gateway)
        _pair(4, "网段", self._var_net)
        _pair(6, "设备数", self._var_dev_cnt)
        tk.Label(inner, text="异常 IP 数：", bg=_CARD, fg=_FG_DIM, font=("Microsoft YaHei UI", 10)).grid(
            row=0, column=8, sticky=tk.W, padx=(12, 4)
        )
        self._lbl_abn_val = tk.Label(
            inner,
            textvariable=self._var_abn_cnt,
            bg=_CARD,
            fg=_GREEN,
            font=("Consolas", 11, "bold"),
        )
        self._lbl_abn_val.grid(row=0, column=9, sticky=tk.W, padx=(0, 8))

        mid = tk.Frame(shell, bg=_BG)
        mid.grid(row=1, column=0, sticky=tk.NSEW, padx=10, pady=(0, 8))
        mid.rowconfigure(0, weight=1)
        mid.columnconfigure(0, weight=1, uniform="arp_mid")
        mid.columnconfigure(1, weight=1, uniform="arp_mid")
        mid.columnconfigure(2, weight=1, uniform="arp_mid")

        lf_log = tk.LabelFrame(
            mid,
            text=" 实时日志 ",
            bg=_CARD,
            fg=_FG,
            font=("Microsoft YaHei UI", 11, "bold"),
            labelanchor="nw",
            bd=1,
            relief=tk.GROOVE,
            padx=6,
            pady=6,
        )
        lf_log.grid(row=0, column=0, sticky=tk.NSEW, padx=(0, 4))
        lf_log.rowconfigure(0, weight=1)
        lf_log.columnconfigure(0, weight=1)
        self.txt_log = tk.Text(
            lf_log,
            height=16,
            wrap=tk.WORD,
            bg=_LOG_BG,
            fg=_LOG_FG,
            insertbackground=_LOG_FG,
            relief=tk.FLAT,
            font=("Consolas", 10),
            padx=8,
            pady=8,
        )
        self.txt_log.grid(row=0, column=0, sticky=tk.NSEW)

        lf_bad = tk.LabelFrame(
            mid,
            text=" 异常设备详情 ",
            bg=_CARD,
            fg=_RED,
            font=("Microsoft YaHei UI", 11, "bold"),
            labelanchor="nw",
            bd=1,
            relief=tk.GROOVE,
            padx=6,
            pady=6,
        )
        lf_bad.grid(row=0, column=1, sticky=tk.NSEW, padx=(4, 4))
        lf_bad.rowconfigure(0, weight=1)
        lf_bad.columnconfigure(0, weight=1)

        self._var_anom_type = tk.StringVar(value="—")
        self._var_anom_ip = tk.StringVar(value="—")
        self._var_real_mac = tk.StringVar(value="—")
        self._var_att_mac = tk.StringVar(value="—")
        self._var_first_seen = tk.StringVar(value="—")
        self._var_risk = tk.StringVar(value="—")
        self._bad_banner_text = ""
        self._bad_banner_kind: str = "none"

        self.txt_bad = tk.Text(
            lf_bad,
            height=16,
            wrap=tk.WORD,
            bg=_LOG_BG,
            fg=_FG,
            insertbackground=_FG,
            relief=tk.FLAT,
            highlightthickness=0,
            font=("Microsoft YaHei UI", 10),
            padx=8,
            pady=8,
        )
        self.txt_bad.grid(row=0, column=0, sticky=tk.NSEW)
        tc = self._theme_colors
        self.txt_bad.tag_configure("key", foreground=_FG_DIM, font=("Microsoft YaHei UI", 10))
        self.txt_bad.tag_configure("v", foreground=_FG, font=("Consolas", 10))
        self.txt_bad.tag_configure("vd", foreground=_RED, font=("Consolas", 10))
        self.txt_bad.tag_configure(
            "banner_ok",
            foreground=tc.get_foreground(tc.success),
            background=tc.success,
            font=("Microsoft YaHei UI", 10),
            spacing1=4,
            spacing3=4,
            lmargin1=8,
            rmargin=8,
        )
        self.txt_bad.tag_configure(
            "banner_alert",
            foreground=tc.get_foreground(tc.danger),
            background=tc.danger,
            font=("Microsoft YaHei UI", 10),
            spacing1=4,
            spacing3=4,
            lmargin1=8,
            rmargin=8,
        )
        self.txt_bad.configure(state=tk.DISABLED)
        self._sync_bad_detail_view()

        lf_tip = tk.LabelFrame(
            mid,
            text=" 设备定位建议 ",
            bg=_CARD,
            fg=_FG,
            font=("Microsoft YaHei UI", 11, "bold"),
            labelanchor="nw",
            bd=1,
            relief=tk.GROOVE,
            padx=6,
            pady=6,
        )
        lf_tip.grid(row=0, column=2, sticky=tk.NSEW, padx=(4, 0))
        lf_tip.rowconfigure(0, weight=1)
        lf_tip.columnconfigure(0, weight=1)
        self.txt_tip = tk.Text(
            lf_tip,
            height=16,
            wrap=tk.WORD,
            bg=_LOG_BG,
            fg=_FG,
            relief=tk.FLAT,
            font=("Microsoft YaHei UI", 10),
            padx=8,
            pady=8,
        )
        self.txt_tip.grid(row=0, column=0, sticky=tk.NSEW)
        self._default_tip_text = (
            "1）查 ARP 表（交换机）\n"
            "   display arp | include <网关IP>\n\n"
            "2）查 MAC 地址表\n"
            "   display mac-address | include <MAC>\n\n"
            "3）定位到交换机端口后，核对 DHCP 绑定、终端准入与接入交换机端口。\n\n"
            "4）疑似冒充网关时，优先在接入侧将该 MAC 所在端口隔离或 shutdown，"
            "并向上追溯上联。\n\n"
            "（监视启动后，此处自动填入当前网关 IP / 异常 MAC 占位命令。）"
        )
        self.txt_tip.insert("1.0", self._default_tip_text)
        self.txt_tip.configure(state=tk.DISABLED)

        foot = tk.Frame(shell, bg=_BG)
        foot.grid(row=2, column=0, sticky="ew", padx=12, pady=(6, 12))
        foot.columnconfigure(0, weight=1)

        self._lbl_status_title = tk.Label(
            foot,
            text="状态：未监视",
            bg=_BG,
            fg=_FG_DIM,
            font=("Microsoft YaHei UI", 11, "bold"),
        )
        self._lbl_status_title.grid(row=0, column=0, sticky="w")

        btn_fr = tk.Frame(foot, bg=_BG)
        btn_fr.grid(row=0, column=1, sticky="e")

        self._btn_monitor = tk.Button(
            btn_fr,
            text="● 开始",
            bg="#15351f",
            fg=_GREEN,
            activeforeground=_GREEN,
            activebackground="#1f4d2e",
            font=("Microsoft YaHei UI", 11, "bold"),
            padx=18,
            pady=8,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._on_toggle_monitor,
        )
        self._btn_monitor.pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            btn_fr,
            text="↻ 重启",
            bg="#352815",
            fg=_ORANGE,
            activeforeground=_ORANGE,
            activebackground="#4d3a1f",
            font=("Microsoft YaHei UI", 11, "bold"),
            padx=18,
            pady=8,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._on_restart,
        ).pack(side=tk.LEFT, padx=(0, 0))

        self._sync_monitor_button()

        self._first_anomaly_ts: str | None = None

    def _sync_bad_detail_view(self) -> None:
        self.txt_bad.configure(state=tk.NORMAL)
        self.txt_bad.delete("1.0", tk.END)

        def add_field(title: str, var: tk.StringVar, *, danger: bool = False) -> None:
            self.txt_bad.insert(tk.END, title + "\n", ("key",))
            tag = "vd" if danger else "v"
            self.txt_bad.insert(tk.END, var.get() + "\n\n", (tag,))

        add_field("异常类型", self._var_anom_type, danger=self._var_anom_type.get() not in ("未发现异常", "—"))
        add_field("异常 IP", self._var_anom_ip, danger=self._var_anom_ip.get() != "—")
        add_field("真实网关 MAC（基线）", self._var_real_mac)
        add_field("攻击者 MAC（当前观测）", self._var_att_mac, danger=self._var_att_mac.get() != "—")
        add_field("首次发现", self._var_first_seen)
        add_field("风险等级", self._var_risk, danger=self._var_risk.get() not in ("低", "—"))

        if self._bad_banner_kind == "ok" and self._bad_banner_text:
            self.txt_bad.insert(tk.END, "\n")
            self.txt_bad.insert(tk.END, self._bad_banner_text, ("banner_ok",))
        elif self._bad_banner_kind == "alert" and self._bad_banner_text:
            self.txt_bad.insert(tk.END, "\n")
            self.txt_bad.insert(tk.END, self._bad_banner_text, ("banner_alert",))

        self.txt_bad.configure(state=tk.DISABLED)

    def _sync_monitor_button(self) -> None:
        if self._monitoring:
            self._btn_monitor.configure(
                text="■ 停止",
                bg="#351518",
                fg=_RED,
                activeforeground=_RED,
                activebackground="#4d2025",
            )
        else:
            self._btn_monitor.configure(
                text="● 开始",
                bg="#15351f",
                fg=_GREEN,
                activeforeground=_GREEN,
                activebackground="#1f4d2e",
            )

    def _on_toggle_monitor(self) -> None:
        if self._monitoring:
            self._on_stop()
        else:
            self._on_start()

    def on_leave(self) -> None:
        self._on_stop()

    def _log(self, line: str, *, alert: bool = False) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        prefix = "🚨 " if alert else ""
        self.txt_log.configure(state=tk.NORMAL)
        self.txt_log.insert(tk.END, f"[{ts}] {prefix}{line}\n")
        self.txt_log.see(tk.END)
        n = int(self.txt_log.index("end-1c").split(".")[0])
        if n > 800:
            self.txt_log.delete("1.0", "100.0")
        self.txt_log.configure(state=tk.DISABLED)

    def _pick_primary_adapter(self) -> tuple[str, str, str] | None:
        adapters, warn = list_local_ipv4_adapters()
        self._adapter_warn = warn
        for b in adapters:
            if b.gateways:
                return b.ipv4, b.netmask, b.gateways[0]
        return None

    def _refresh_tip_commands(self, gw: str, mac: str) -> None:
        mac_cmd = mac.lower() if mac != "—" else "<mac>"
        body = (
            "1）查 ARP 表（交换机）\n"
            f"   display arp | include {gw}\n\n"
            "2）查 MAC 地址表\n"
            f"   display mac-address | include {mac_cmd}\n\n"
            "3）定位到交换机端口\n"
            "   → 在上游三层/二层设备上沿 MAC 表逐级追溯到接入端口。\n\n"
            "4）扩展排查\n"
            "   • 核对 DHCP 绑定与终端名称\n"
            "   • 检查接入交换机端口安全 / 静态绑定\n\n"
            "结论：若当前 MAC 非运维登记的网关设备，应在接入侧先行隔离，避免流量被劫持。\n"
        )
        self.txt_tip.configure(state=tk.NORMAL)
        self.txt_tip.delete("1.0", tk.END)
        self.txt_tip.insert("1.0", body)
        self.txt_tip.configure(state=tk.DISABLED)

    def _clear_anomaly_ui(self, *, ok_hint: bool = False) -> None:
        self._var_abn_cnt.set("0")
        self._lbl_abn_val.configure(fg=_GREEN)
        if ok_hint:
            self._lbl_status_title.configure(text="状态：监视中（正常）", fg=_GREEN)
            self._var_anom_type.set("未发现异常")
            self._var_anom_ip.set("—")
            self._var_real_mac.set(self._baseline_mac or "—")
            self._var_att_mac.set("—")
            self._var_first_seen.set("—")
            self._var_risk.set("低")
            self._bad_banner_text = "当前网关 MAC 与基线一致。"
            self._bad_banner_kind = "ok"
        else:
            self._var_anom_type.set("—")
            self._var_anom_ip.set("—")
            self._var_real_mac.set("—")
            self._var_att_mac.set("—")
            self._var_first_seen.set("—")
            self._var_risk.set("—")
            self._bad_banner_text = ""
            self._bad_banner_kind = "none"

        self._sync_bad_detail_view()

        self.txt_tip.configure(state=tk.NORMAL)
        self.txt_tip.delete("1.0", tk.END)
        self.txt_tip.insert("1.0", self._default_tip_text)
        self.txt_tip.configure(state=tk.DISABLED)

    def _set_anomaly(self, snap: ArpGatewaySnapshot, observed: str) -> None:
        self._var_abn_cnt.set("1")
        self._lbl_abn_val.configure(fg=_RED)
        self._lbl_status_title.configure(text="状态：存在 ARP 异常", fg=_RED)
        self._var_anom_type.set("网关 ARP 欺骗（疑似）")
        self._var_anom_ip.set(snap.gateway_ip)
        self._var_real_mac.set(self._baseline_mac or "—")
        self._var_att_mac.set(observed)
        if self._first_anomaly_ts is None:
            self._first_anomaly_ts = datetime.now().strftime("%H:%M:%S")
        self._var_first_seen.set(self._first_anomaly_ts)
        self._var_risk.set("高危")
        self._bad_banner_text = (
            "该地址映射到的 MAC 与监视启动后记录的基线不一致，可能存在冒充网关或 ARP 缓存污染。"
            "请立即在交换机侧核对并隔离可疑端口。"
        )
        self._bad_banner_kind = "alert"
        self._sync_bad_detail_view()
        self._refresh_tip_commands(snap.gateway_ip, observed)

    def _poll_tick(self) -> None:
        if not self._monitoring:
            return

        def work() -> None:
            picked = self._pick_primary_adapter()
            arp_txt, arp_err = run_arp_a_text()
            self.after(0, lambda: self._apply_poll_result(picked, arp_txt, arp_err))

        threading.Thread(target=work, daemon=True).start()

    def _apply_poll_result(
        self,
        picked: tuple[str, str, str] | None,
        arp_txt: str,
        arp_err: str | None,
    ) -> None:
        if not self._monitoring:
            return

        if picked is None:
            self._var_local_ip.set("—")
            self._var_gateway.set("—")
            self._var_net.set("—")
            self._var_dev_cnt.set("—")
            self._log("未能从本机读取带默认网关的 IPv4 配置（请检查网络适配器）。")
            if self._adapter_warn:
                self._log(self._adapter_warn)
            self._schedule_next()
            return

        lip, mask, gw = picked
        self._var_local_ip.set(lip)
        self._var_gateway.set(gw)
        snap = build_snapshot(
            arp_txt,
            local_ip=lip,
            netmask=mask,
            gateway_ip=gw,
            arp_command_error=arp_err,
        )
        self._last_snap = snap
        self._var_net.set(snap.network_cidr or "—")
        self._var_dev_cnt.set(str(snap.subnet_entry_count))

        if arp_err:
            self._log(f"arp -a 警告：{arp_err}")

        gw_mac = snap.gateway_mac
        if gw_mac is None:
            self._log(f"在 ARP 表中未找到网关 {gw} 的 MAC（可能尚未通信）。")
            self._schedule_next()
            return

        if self._baseline_mac is None:
            self._baseline_mac = gw_mac
            self._log(f"已记录网关 {gw} 基线 MAC：{gw_mac}")
            self._clear_anomaly_ui(ok_hint=True)
            self._var_real_mac.set(self._baseline_mac)
            self._schedule_next()
            return

        if normalize_mac(gw_mac) != normalize_mac(self._baseline_mac):
            self._log(
                f"ARP 异常：网关 {gw} MAC 变化 {self._baseline_mac} -> {gw_mac}",
                alert=True,
            )
            self._set_anomaly(snap, gw_mac)
        else:
            self._first_anomaly_ts = None
            self._clear_anomaly_ui(ok_hint=True)
            self._var_real_mac.set(self._baseline_mac)

        self._schedule_next()

    def _schedule_next(self) -> None:
        if self._monitoring:
            self._poll_after_id = self.after(2500, self._poll_tick)

    def _on_start(self) -> None:
        if sys.platform != "win32":
            messagebox.showwarning(
                "ARP安全",
                "当前实现主要针对 Windows（arp -a + WMI）。在非 Windows 系统上结果可能不可用。",
            )
        if self._monitoring:
            return
        self._monitoring = True
        self._baseline_mac = None
        self._first_anomaly_ts = None
        self.txt_log.configure(state=tk.NORMAL)
        self.txt_log.delete("1.0", tk.END)
        self.txt_log.configure(state=tk.DISABLED)
        self._clear_anomaly_ui(ok_hint=False)
        self._lbl_status_title.configure(text="状态：监视中…", fg=_ORANGE)
        self._sync_monitor_button()
        self._log("监视开始：正在读取本机网关与 ARP 表…")
        self._poll_tick()

    def _on_stop(self) -> None:
        self._monitoring = False
        if self._poll_after_id is not None:
            try:
                self.after_cancel(self._poll_after_id)
            except tk.TclError:
                pass
            self._poll_after_id = None
        self._lbl_status_title.configure(text="状态：已停止", fg=_FG_DIM)
        self._sync_monitor_button()

    def _on_restart(self) -> None:
        self._on_stop()
        self._baseline_mac = None
        self._first_anomaly_ts = None
        self._on_start()
