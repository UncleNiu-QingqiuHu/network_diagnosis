"""Network diagnosis tab UI; user-visible zh_CN strings use Unicode escapes (ASCII-only source)."""

from __future__ import annotations

import tkinter as tk
from tkinter.scrolledtext import ScrolledText

import ttkbootstrap as ttk
from ttkbootstrap.constants import EW, INFO, NSEW, OUTLINE, PRIMARY, SECONDARY, SUCCESS, WARNING, W

from network_diagnosis.gui.main_app_common import bind_label_wraplength


class NetworkViewsMixin:
    def _build_network_diagnosis_view(self) -> None:
        frm_network = ttk.Frame(self._content_host)
        frm_network.rowconfigure(0, weight=1)
        frm_network.columnconfigure(0, weight=1)
        self._view_frames["network"] = frm_network

        pw_main = ttk.Panedwindow(frm_network, orient=tk.HORIZONTAL)
        pw_main.grid(row=0, column=0, sticky=NSEW)

        left = ttk.Frame(pw_main, padding=(0, 0, 8, 0))
        right = ttk.Frame(pw_main, padding=(8, 0, 0, 0))
        pw_main.add(left, weight=1)
        pw_main.add(right, weight=1)
        self._pw_main = pw_main

        # \u2014\u2014\u0020\u5de6\u4fa7\uff1a\u8868\u5355\u4e0e\u63a7\u5236\u0020\u2014\u2014
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)

        ctrl_panel = ttk.Frame(left)
        ctrl_panel.grid(row=0, column=0, sticky=tk.N + tk.E + tk.W)

        lf_target = ttk.Labelframe(
            ctrl_panel,
            text="\u63a2\u6d4b\u76ee\u6807",
            padding=(12, 10, 12, 10),
        )
        lf_target.pack(fill=tk.X, pady=(0, 8))
        lf_target.columnconfigure(1, weight=1)

        ttk.Label(lf_target, text="\u4e3b\u673a\u540d\u6216 IP", bootstyle=SECONDARY).grid(
            row=0, column=0, sticky=W, padx=(0, 12), pady=(0, 6)
        )
        self.var_host = tk.StringVar(value="www.baidu.com")
        ttk.Entry(lf_target, textvariable=self.var_host, bootstyle=PRIMARY).grid(
            row=0, column=1, sticky=EW, pady=(0, 6)
        )

        ttk.Label(lf_target, text="TCP \u7aef\u53e3\uff08\u53ef\u9009\uff09", bootstyle=SECONDARY).grid(
            row=1, column=0, sticky=W, padx=(0, 12), pady=(0, 2)
        )
        self.var_ports = tk.StringVar(value="80,443")
        ttk.Entry(lf_target, textvariable=self.var_ports, bootstyle=PRIMARY).grid(
            row=1, column=1, sticky=EW, pady=(0, 2)
        )
        ttk.Label(
            lf_target,
            text=(
                "\u9ed8\u8ba4 80,443\uff1b\u7559\u7a7a\u5219\u4e0d\u6d4b\u7aef\u53e3\uff1b"
                "\u591a\u4e2a\u7aef\u53e3\u7528\u82f1\u6587\u9017\u53f7\u5206\u9694"
            ),
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 10),
        ).grid(row=2, column=1, sticky=W)

        lf_opts = ttk.Labelframe(ctrl_panel, text="\u63a2\u6d4b\u9009\u9879", padding=(12, 10, 12, 12))
        lf_opts.pack(fill=tk.X, pady=(0, 8))
        for c in (1, 3):
            lf_opts.columnconfigure(c, weight=1)

        self.var_samples = tk.IntVar(value=10)
        self.var_timeout = tk.IntVar(value=1000)
        self.var_ping_count = tk.IntVar(value=10)
        self.var_ping_long = tk.BooleanVar(value=False)
        self.var_long_ping_sec = tk.IntVar(value=30)
        self.var_ping_wait_ms = tk.IntVar(value=2000)
        self.var_ping = tk.BooleanVar(value=True)
        self.var_capture = tk.BooleanVar(value=False)
        self.var_ipv6 = tk.BooleanVar(value=False)

        ttk.Label(lf_opts, text="\u7aef\u53e3\u91c7\u6837\u6b21\u6570").grid(
            row=0, column=0, sticky=W, padx=(0, 8), pady=4
        )
        sb_samples = ttk.Spinbox(lf_opts, from_=1, to=50, textvariable=self.var_samples, width=8)
        sb_samples.grid(row=0, column=1, sticky=W, pady=4)

        ttk.Label(lf_opts, text="TCP \u8d85\u65f6 (ms)", bootstyle=SECONDARY).grid(
            row=0, column=2, sticky=W, padx=(16, 8), pady=4
        )
        ttk.Spinbox(
            lf_opts,
            from_=200,
            to=60000,
            increment=100,
            textvariable=self.var_timeout,
            width=10,
        ).grid(row=0, column=3, sticky=W, pady=4)

        ping_row = ttk.Frame(lf_opts)
        ping_row.grid(row=1, column=0, columnspan=4, sticky=W, pady=(8, 0))
        ttk.Label(ping_row, text="Ping \u6b21\u6570").pack(side=tk.LEFT)
        ttk.Spinbox(ping_row, from_=1, to=300, textvariable=self.var_ping_count, width=6).pack(
            side=tk.LEFT, padx=(4, 14)
        )
        ttk.Label(ping_row, text="ICMP \u7b49\u5f85 (ms)").pack(side=tk.LEFT)
        ttk.Spinbox(
            ping_row,
            from_=500,
            to=20000,
            increment=100,
            textvariable=self.var_ping_wait_ms,
            width=7,
        ).pack(side=tk.LEFT, padx=(4, 14))
        ttk.Checkbutton(
            ping_row,
            text="ICMP Ping",
            variable=self.var_ping,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(4, 0))

        chk_row = ttk.Frame(lf_opts)
        chk_row.grid(row=2, column=0, columnspan=4, sticky=EW, pady=(10, 0))
        ttk.Checkbutton(
            chk_row,
            text="\u957f Ping",
            variable=self.var_ping_long,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Spinbox(
            chk_row, from_=5, to=600, textvariable=self.var_long_ping_sec, width=5
        ).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(
            chk_row,
            text="\u79d2\uff08\u8986\u76d6\u300cPing \u6b21\u6570\u300d\uff09",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 10),
        ).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(
            chk_row,
            text="\u6293\u5305",
            variable=self.var_capture,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(
            chk_row,
            text="\u4f18\u5148 IPv6",
            variable=self.var_ipv6,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(0, 14))

        tr_row = ttk.Frame(lf_opts)
        tr_row.grid(row=3, column=0, columnspan=4, sticky=W, pady=(8, 0))
        self.var_traceroute = tk.BooleanVar(value=False)
        self.var_tr_hops = tk.IntVar(value=30)
        self.var_tr_wait_ms = tk.IntVar(value=4000)
        ttk.Checkbutton(
            tr_row,
            text="\u8def\u7531\u8ffd\u8e2a (tracert)",
            variable=self.var_traceroute,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(tr_row, text="\u6700\u5927\u8df3\u6570", bootstyle=SECONDARY).pack(side=tk.LEFT)
        ttk.Spinbox(tr_row, from_=2, to=64, textvariable=self.var_tr_hops, width=5).pack(
            side=tk.LEFT, padx=(4, 12)
        )
        ttk.Label(tr_row, text="\u6bcf\u8df3\u8d85\u65f6 (ms)", bootstyle=SECONDARY).pack(side=tk.LEFT)
        ttk.Spinbox(
            tr_row,
            from_=500,
            to=30000,
            increment=100,
            textvariable=self.var_tr_wait_ms,
            width=7,
        ).pack(side=tk.LEFT, padx=(4, 0))

        lf_bw = ttk.Labelframe(
            ctrl_panel,
            text="\u5e26\u5bbd / \u541e\u5410\uff08\u53ef\u9009\uff0c\u4e8c\u9009\u4e00\uff09",
            padding=(12, 10, 12, 10),
        )
        lf_bw.pack(fill=tk.X, pady=(0, 8))
        bw_top = ttk.Frame(lf_bw)
        bw_top.pack(fill=tk.X)
        self.var_bw_mode = tk.StringVar(value="off")
        ttk.Radiobutton(bw_top, text="\u4e0d\u8fdb\u884c\u6d4b\u901f", variable=self.var_bw_mode, value="off").pack(
            side=tk.LEFT, padx=(0, 10)
        )
        ttk.Radiobutton(bw_top, text="HTTP \u62bd\u6837\u4e0b\u8f7d", variable=self.var_bw_mode, value="http").pack(
            side=tk.LEFT, padx=(0, 10)
        )
        ttk.Radiobutton(bw_top, text="iperf3", variable=self.var_bw_mode, value="iperf3").pack(side=tk.LEFT)

        self.var_bw_http_url = tk.StringVar(
            value="https://speed.cloudflare.com/__down?bytes=25000000"
        )
        self.var_bw_http_parallel = tk.IntVar(value=4)
        self.var_bw_http_seconds = tk.IntVar(value=15)

        self._frm_bw_http = ttk.Frame(lf_bw)
        http_row1 = ttk.Frame(self._frm_bw_http)
        http_row1.pack(fill=tk.X)
        http_row1.columnconfigure(1, weight=1)
        ttk.Label(http_row1, text="HTTP URL", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 8))
        self.ent_bw_http_url = ttk.Entry(http_row1, textvariable=self.var_bw_http_url, bootstyle=PRIMARY)
        self.ent_bw_http_url.grid(row=0, column=1, sticky=EW)

        http_row2 = ttk.Frame(self._frm_bw_http)
        http_row2.pack(fill=tk.X, pady=(6, 0))
        ttk.Label(http_row2, text="\u5e76\u53d1\u8fde\u63a5", bootstyle=SECONDARY).pack(side=tk.LEFT)
        self.sb_bw_http_parallel = ttk.Spinbox(
            http_row2, from_=1, to=16, textvariable=self.var_bw_http_parallel, width=6
        )
        self.sb_bw_http_parallel.pack(side=tk.LEFT, padx=(6, 16))
        ttk.Label(http_row2, text="\u6301\u7eed\u65f6\u95f4 (\u79d2)", bootstyle=SECONDARY).pack(side=tk.LEFT)
        self.sb_bw_http_seconds = ttk.Spinbox(
            http_row2, from_=3, to=300, textvariable=self.var_bw_http_seconds, width=6
        )
        self.sb_bw_http_seconds.pack(side=tk.LEFT, padx=(6, 0))

        self.var_bw_iperf_host = tk.StringVar(value="")
        self.var_bw_iperf_port = tk.IntVar(value=5201)
        self.var_bw_iperf_seconds = tk.IntVar(value=30)
        self.var_bw_iperf_parallel = tk.IntVar(value=4)
        self.var_bw_iperf_for_quality = tk.BooleanVar(value=True)
        self.var_bw_iperf_udp_mbps = tk.IntVar(value=1000)

        self._frm_bw_iperf = ttk.Frame(lf_bw)
        ip_row = ttk.Frame(self._frm_bw_iperf)
        ip_row.pack(fill=tk.X)
        ip_row.columnconfigure(1, weight=1)
        ttk.Label(ip_row, text="iperf \u670d\u52a1\u5668", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 8))
        self.ent_bw_iperf_host = ttk.Entry(ip_row, textvariable=self.var_bw_iperf_host, bootstyle=PRIMARY)
        self.ent_bw_iperf_host.grid(row=0, column=1, sticky=EW)
        ttk.Label(ip_row, text="\u7aef\u53e3", bootstyle=SECONDARY).grid(row=0, column=2, sticky=W, padx=(12, 6))
        self.sb_bw_iperf_port = ttk.Spinbox(
            ip_row, from_=1, to=65535, textvariable=self.var_bw_iperf_port, width=7
        )
        self.sb_bw_iperf_port.grid(row=0, column=3, sticky=W)
        ttk.Label(ip_row, text="\u65f6\u957f (\u79d2)", bootstyle=SECONDARY).grid(
            row=1, column=0, sticky=W, padx=(0, 8), pady=(6, 0)
        )
        self.sb_bw_iperf_seconds = ttk.Spinbox(
            ip_row, from_=2, to=600, textvariable=self.var_bw_iperf_seconds, width=6
        )
        self.sb_bw_iperf_seconds.grid(row=1, column=1, sticky=W, pady=(6, 0))
        ttk.Label(ip_row, text="\u5e76\u53d1\u6d41 (-P)", bootstyle=SECONDARY).grid(
            row=1, column=2, sticky=W, padx=(12, 6), pady=(6, 0)
        )
        self.sb_bw_iperf_parallel = ttk.Spinbox(
            ip_row, from_=1, to=64, textvariable=self.var_bw_iperf_parallel, width=6
        )
        self.sb_bw_iperf_parallel.grid(row=1, column=3, sticky=W, pady=(6, 0))

        iperf_qual_row = ttk.Frame(self._frm_bw_iperf)
        iperf_qual_row.pack(fill=tk.X, pady=(8, 0))
        ttk.Checkbutton(
            iperf_qual_row,
            text="\u5c06 iperf3 UDP \u7eb3\u5165\u7f51\u7edc\u8d28\u91cf\u7efc\u5408\u5224\u5b9a\uff08\u989d\u5916\u8dd1\u4e00\u6b21 UDP\uff09",
            variable=self.var_bw_iperf_for_quality,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT)
        ttk.Label(iperf_qual_row, text="UDP -b", bootstyle=SECONDARY).pack(side=tk.LEFT, padx=(12, 4))
        self.sb_bw_iperf_udp_mbps = ttk.Spinbox(
            iperf_qual_row,
            from_=1,
            to=1_000_000,
            textvariable=self.var_bw_iperf_udp_mbps,
            width=8,
        )
        self.sb_bw_iperf_udp_mbps.pack(side=tk.LEFT)
        ttk.Label(
            iperf_qual_row,
            text=" M\uff08Mbps\uff0ciperf3 \u5355\u4f4d\uff09",
            bootstyle=SECONDARY,
        ).pack(side=tk.LEFT, padx=(2, 0))

        self.var_bw_mode.trace_add("write", lambda *_: self._sync_bw_panels())
        self._sync_bw_panels()

        lf_adv = ttk.Labelframe(
            ctrl_panel,
            text="\u8fdb\u9636\u63a2\u6d4b\uff08\u53ef\u9009\uff0c\u53ef\u80fd\u8f83\u6162\uff09",
            padding=(12, 10, 12, 10),
        )
        lf_adv.pack(fill=tk.X, pady=(0, 8))
        lf_adv.columnconfigure(1, weight=1)
        self.var_optional_dns = tk.StringVar(value="223.5.5.5")
        ttk.Label(lf_adv, text="\u6307\u5b9a DNS\uff08\u4e0e\u7cfb\u7edf\u89e3\u6790\u5bf9\u6bd4\uff09", bootstyle=SECONDARY).grid(
            row=0, column=0, sticky=W, padx=(0, 8), pady=(0, 6)
        )
        ttk.Entry(lf_adv, textvariable=self.var_optional_dns, bootstyle=PRIMARY).grid(
            row=0, column=1, sticky=EW, pady=(0, 6)
        )
        ttk.Label(
            lf_adv,
            text="\u4f8b\uff1a8.8.8.8\uff1b\u7559\u7a7a\u5219\u4ec5\u4f7f\u7528\u7cfb\u7edf\u89e3\u6790\u5668",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 10),
        ).grid(row=1, column=1, sticky=W)

        self.var_adv_pathping = tk.BooleanVar(value=False)
        self.var_adv_tcp_trace = tk.BooleanVar(value=False)
        self.var_adv_tcp_hops = tk.IntVar(value=30)
        self.var_adv_http_tls = tk.BooleanVar(value=False)
        self.var_adv_egress = tk.BooleanVar(value=False)
        self.var_adv_mtu = tk.BooleanVar(value=False)
        self.var_adv_history = tk.BooleanVar(value=True)

        adv_chk = ttk.Frame(lf_adv)
        adv_chk.grid(row=2, column=0, columnspan=2, sticky=W, pady=(10, 4))
        ttk.Checkbutton(
            adv_chk, text="PathPing / mtr", variable=self.var_adv_pathping, bootstyle="round-toggle"
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            adv_chk, text="TCP \u8def\u5f84", variable=self.var_adv_tcp_trace, bootstyle="round-toggle"
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(adv_chk, text="TCP \u6700\u5927\u8df3\u6570", bootstyle=SECONDARY).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Spinbox(adv_chk, from_=2, to=64, textvariable=self.var_adv_tcp_hops, width=5).pack(
            side=tk.LEFT, padx=(0, 12)
        )

        adv_chk2 = ttk.Frame(lf_adv)
        adv_chk2.grid(row=3, column=0, columnspan=2, sticky=W, pady=(4, 0))
        ttk.Checkbutton(
            adv_chk2, text="HTTPS/TLS", variable=self.var_adv_http_tls, bootstyle="round-toggle"
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            adv_chk2,
            text="\u51fa\u53e3 / \u4ee3\u7406",
            variable=self.var_adv_egress,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            adv_chk2, text="IPv4 MTU", variable=self.var_adv_mtu, bootstyle="round-toggle"
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            adv_chk2,
            text="\u5386\u53f2\u8bb0\u5f55\u5bf9\u6bd4",
            variable=self.var_adv_history,
            bootstyle="round-toggle",
        ).pack(side=tk.LEFT, padx=(0, 0))

        ttk.Separator(ctrl_panel, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(4, 10))

        actions = ttk.Frame(ctrl_panel)
        actions.pack(fill=tk.X, pady=(0, 6))
        for c in (0, 1, 2, 3):
            actions.columnconfigure(c, weight=1)

        big_btn_kwargs = {"width": 12}

        ttk.Button(
            actions,
            text="\u5b89\u88c5 Wireshark",
            command=self._open_wireshark_installer,
            bootstyle=INFO,
            **big_btn_kwargs,
        ).grid(row=0, column=0, sticky=EW, padx=(0, 3), pady=(0, 8))
        ttk.Button(
            actions,
            text="\u68c0\u6d4b Tcping",
            command=self._probe_tcping,
            bootstyle=SECONDARY,
            **big_btn_kwargs,
        ).grid(row=0, column=1, sticky=EW, padx=(3, 3), pady=(0, 8))
        ttk.Button(
            actions,
            text="\u68c0\u6d4b Tshark",
            command=self._probe_tshark,
            bootstyle=SECONDARY,
            **big_btn_kwargs,
        ).grid(row=0, column=2, sticky=EW, padx=(3, 3), pady=(0, 8))
        ttk.Button(
            actions,
            text="\u68c0\u6d4b Iperf3",
            command=self._probe_iperf3,
            bootstyle=SECONDARY,
            **big_btn_kwargs,
        ).grid(row=0, column=3, sticky=EW, padx=(3, 0), pady=(0, 8))

        self.btn_run = ttk.Button(
            actions,
            text="\u5f00\u59cb\u8bca\u65ad",
            command=self._on_run,
            bootstyle=SUCCESS,
            width=14,
        )
        self.btn_run.grid(row=1, column=0, columnspan=4, sticky=EW, pady=(0, 0))

        status_shell = ttk.Labelframe(
            ctrl_panel,
            text="\u4efb\u52a1\u72b6\u6001",
            padding=(12, 10, 12, 10),
            bootstyle=SECONDARY,
        )
        self._status_shell = status_shell
        status_shell.pack(fill=tk.X, pady=(8, 0))
        status_bar = ttk.Frame(status_shell)
        status_bar.pack(fill=tk.X)
        self.lbl_status = ttk.Label(
            status_bar,
            text="\u5c31\u7eea",
            bootstyle=SECONDARY,
            anchor=W,
            font=self._status_font_normal,
            justify=tk.LEFT,
        )
        self.lbl_status.pack(fill=tk.X)
        bind_label_wraplength(self.lbl_status, inset=4)
        self._run_progress = ttk.Progressbar(
            status_shell,
            mode="indeterminate",
            bootstyle=WARNING,
            length=400,
        )

        btn2 = ttk.Frame(left)
        btn2.grid(row=1, column=0, sticky=EW, pady=(8, 0))
        self.btn_open_md = ttk.Button(
            btn2,
            text="\u6253\u5f00\u6280\u672f\u62a5\u544a (Markdown)",
            command=self._open_last_md,
            state=tk.DISABLED,
            bootstyle=PRIMARY,
        )
        self.btn_open_md.pack(side=tk.LEFT)
        self.btn_open_dir = ttk.Button(
            btn2,
            text="\u6253\u5f00\u62a5\u544a\u6587\u4ef6\u5939",
            command=self._open_last_dir,
            state=tk.DISABLED,
            bootstyle=OUTLINE,
        )
        self.btn_open_dir.pack(side=tk.LEFT, padx=(10, 0))

        # \u2014\u2014\u0020\u53f3\u4fa7\uff1a\u8bca\u65ad\u7ed3\u679c + \u8fdb\u5ea6\u8be6\u60c5 \u2014\u2014
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        lf_summary = ttk.Labelframe(right, text="\u8bca\u65ad\u7ed3\u679c", padding=(10, 8, 10, 10))
        lf_summary.grid(row=0, column=0, sticky=NSEW, pady=(0, 8))
        lf_summary.rowconfigure(0, weight=1)
        lf_summary.columnconfigure(0, weight=1)

        self.txt_summary = ScrolledText(
            lf_summary,
            height=12,
            wrap=tk.WORD,
            font=("Microsoft YaHei UI", 12),
            relief=tk.FLAT,
            padx=8,
            pady=8,
        )
        self.txt_summary.grid(row=0, column=0, sticky=NSEW)
        self._setup_summary_text_tags()

        lf_log = ttk.Labelframe(right, text="\u8fdb\u5ea6\u8be6\u60c5", padding=(10, 8, 10, 10))
        lf_log.grid(row=1, column=0, sticky=NSEW)
        lf_log.rowconfigure(0, weight=1)
        lf_log.columnconfigure(0, weight=1)

        self.txt_log = ScrolledText(
            lf_log,
            height=8,
            wrap=tk.WORD,
            font=("Consolas", 11),
            relief=tk.FLAT,
            padx=8,
            pady=8,
        )
        self.txt_log.grid(row=0, column=0, sticky=NSEW)

        self._last_md: str | None = None
        self._last_dir: str | None = None

    def _sync_bw_panels(self) -> None:
        m = self.var_bw_mode.get()
        self._frm_bw_http.pack_forget()
        self._frm_bw_iperf.pack_forget()
        if m == "http":
            self._frm_bw_http.pack(fill=tk.X, pady=(8, 0))
        elif m == "iperf3":
            self._frm_bw_iperf.pack(fill=tk.X, pady=(8, 0))

    def _setup_summary_text_tags(self) -> None:
        st = self.txt_summary
        tc = self.style.colors
        ff = "Microsoft YaHei UI"

        def pick(attr: str, fb: str) -> str:
            v = getattr(tc, attr, fb)
            return v if isinstance(v, str) and v else fb

        bg = getattr(tc, "inputbg", None) or "#ffffff"
        fg = getattr(tc, "inputfg", None) or "#2b2b2b"
        sel_bg = getattr(tc, "selectbg", None) or "#347083"
        sel_fg = getattr(tc, "selectfg", None) or "#ffffff"
        st.configure(
            background=bg,
            foreground=fg,
            insertbackground=fg,
            selectbackground=sel_bg,
            selectforeground=sel_fg,
        )

        lum = 1.0
        gl = getattr(tc, "get_luminance", None)
        if callable(gl):
            try:
                lum = float(gl(bg))
            except (TypeError, ValueError):
                lum = 1.0
        dark_ui = lum < 0.45

        def contrast_fg(hex_bg: str, fb: str) -> str:
            gf = getattr(tc, "get_foreground", None)
            if callable(gf):
                try:
                    out = gf(hex_bg)
                    if isinstance(out, str) and out:
                        return out
                except (TypeError, ValueError):
                    pass
            return fb

        if dark_ui:
            hi = pick("light", "#fdf6e3")
            accent = pick("primary", pick("info", "#268bd2"))
            st.tag_configure("sec_title", font=(ff, 12, "bold"), foreground=pick("success", "#44aca4"))
            st.tag_configure("headline", font=(ff, 13, "bold"), foreground=hi)
            st.tag_configure("body", font=(ff, 12), foreground=fg)
            st.tag_configure("overall_label", font=(ff, 12, "bold"), foreground=accent)

            pairs = [
                ("quality_grade_exc", "success", "#28a745", "#fdf6e3"),
                ("quality_grade_ok", "info", "#17a2b8", "#fdf6e3"),
                ("quality_grade_poor", "warning", "#ffc107", "#1a1a1a"),
                ("quality_grade_bad", "danger", "#dc3545", "#fdf6e3"),
            ]
            for tag_name, col_attr, fb_bg, fb_fg in pairs:
                bgb = pick(col_attr, fb_bg)
                st.tag_configure(
                    tag_name,
                    font=(ff, 13, "bold"),
                    background=bgb,
                    foreground=contrast_fg(bgb, fb_fg),
                )
            return

        # 浅色主题：保留原有柔和底色，略加深标题与档位字色
        st.tag_configure("sec_title", font=(ff, 12, "bold"), foreground=pick("success", "#146c43"))
        st.tag_configure("headline", font=(ff, 13, "bold"), foreground=pick("dark", "#1a252f"))
        st.tag_configure("body", font=(ff, 12))
        st.tag_configure(
            "quality_grade_exc",
            font=(ff, 13, "bold"),
            background="#c3e6cb",
            foreground="#0d462c",
        )
        st.tag_configure(
            "quality_grade_ok",
            font=(ff, 13, "bold"),
            background="#bee5eb",
            foreground="#055160",
        )
        st.tag_configure(
            "quality_grade_poor",
            font=(ff, 13, "bold"),
            background="#ffe69c",
            foreground="#664d03",
        )
        st.tag_configure(
            "quality_grade_bad",
            font=(ff, 13, "bold"),
            background="#f5c2c7",
            foreground="#58151c",
        )
        st.tag_configure(
            "overall_label",
            font=(ff, 12, "bold"),
            foreground=pick("info", "#087990"),
        )
