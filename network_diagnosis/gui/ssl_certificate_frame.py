"""SSL 证书页：Let's Encrypt（DNS-01，阿里云 / 腾讯云）与私有 CA（cryptography）。"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext

import ttkbootstrap as ttk
from ttkbootstrap.constants import EW, NSEW, W

from network_diagnosis.ssl_tools import dns_common, letsencrypt_dns, private_ca

_PRIV_HINT = """【有效期】根 CA 与站点证书均为 10 年（3650 天），由程序固定。

【各文件做什么】
• private-ca.key.pem — 根 CA 私钥：仅本机妥善保管，勿上传 Web、勿发给他人；日后若要再签发站点证书时才需要（一般不必拷到对外服务器）。
• private-ca.crt.pem — 根 CA 公钥（证书）：给「客户端」安装信任用（见下文）；不要与私钥一起打包分发。
• private-site.key.pem — 站点 TLS 私钥：只放在 HTTPS 服务器上，与下面任一证书文件配对使用；文件权限收紧，勿泄露。
• private-site.crt.pem — 站点「叶子」证书（仅本站域名/IP）：可与私钥一起交给服务端软件；若软件要求「完整链」，改用 fullchain。
• private-site.fullchain.pem — 叶子证书 + 根 CA（PEM 首尾相接）：最常作为「服务端呈现的证书链」；例如 Nginx 的 ssl_certificate 常指向此文件。
• private-site.pfx — 仅在填写了 PFX 导出密码时生成：内含站点私钥与证书链，便于在 IIS「导入证书」后在站点 HTTPS 绑定中选择。

【服务端怎么用（典型）】
• Nginx：ssl_certificate 填 private-site.fullchain.pem；ssl_certificate_key 填 private-site.key.pem。（reload 配置后生效。）
• IIS：使用生成的 .pfx 导入到「本地计算机 → 个人」，再在站点绑定中选择对应证书。
• 其它（Apache、反向代理等）：原则是「对外发送的证书链」用 fullchain（或 crt + 手动配置链），「私钥」单独指向 private-site.key.pem。

【客户端如何信任】在每台需要访问 HTTPS 的机器上，将 private-ca.crt.pem 导入「受信任的根证书颁发机构」（或通过 AD/GPO 统一下发）。仅信任根即可，无需把站点叶子证书装进客户端。

"""

_PRIVATE_CERT_VALIDITY_DAYS = 365 * 10


class SslCertificateFrame(ttk.Frame):
    """TLS 服务端证书：公有 DV（Let's Encrypt）与内网自建 CA。"""

    def __init__(self, master: tk.Misc, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        nb = ttk.Notebook(self, bootstyle="primary")
        nb.grid(row=0, column=0, sticky=NSEW, padx=14, pady=(12, 8))

        self._build_tab_private(nb)
        self._build_tab_le(nb)

    def on_leave(self) -> None:
        """切换模块时无独占资源。"""
        return

    def _append_le_log(self, msg: str) -> None:
        self._txt_le_log.configure(state=tk.NORMAL)
        self._txt_le_log.insert(tk.END, msg + "\n")
        self._txt_le_log.see(tk.END)
        self._txt_le_log.configure(state=tk.DISABLED)

    def _append_priv_log(self, msg: str) -> None:
        self._txt_priv_log.configure(state=tk.NORMAL)
        self._txt_priv_log.insert(tk.END, msg + "\n")
        self._txt_priv_log.see(tk.END)
        self._txt_priv_log.configure(state=tk.DISABLED)

    def _sync_dns_frames(self) -> None:
        row = self._le_dns_grid_row
        prov = self._var_le_dns.get()

        def _rm(w: tk.Misc) -> None:
            try:
                if w.winfo_manager() == "grid":
                    w.grid_remove()
            except tk.TclError:
                pass

        if prov == "aliyun":
            _rm(self._lf_tc)
            self._lf_ali.grid(row=row, column=0, columnspan=2, sticky=EW, pady=6)
        else:
            _rm(self._lf_ali)
            self._lf_tc.grid(row=row, column=0, columnspan=2, sticky=EW, pady=6)

    def _build_tab_le(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=(12, 12, 12, 10))
        nb.add(tab, text="Let's Encrypt（免费）")
        tab.columnconfigure(1, weight=1)

        r = 0
        ttk.Label(tab, text="证书域名（逗号或空格分隔，可多个；泛域名 *.example.com 需 DNS-01，本页已使用 DNS-01）：").grid(
            row=r, column=0, sticky=W, padx=(0, 8), pady=4
        )
        self._var_le_domains = tk.StringVar(value="")
        ttk.Entry(tab, textvariable=self._var_le_domains).grid(row=r, column=1, sticky=EW, pady=4)
        r += 1

        ttk.Label(tab, text="DNS 根域名（须与云解析主域名一致；留空则按末两段猜测）：").grid(
            row=r, column=0, sticky=W, padx=(0, 8), pady=4
        )
        self._var_le_apex = tk.StringVar(value="")
        ttk.Entry(tab, textvariable=self._var_le_apex).grid(row=r, column=1, sticky=EW, pady=4)
        r += 1

        ttk.Label(tab, text="联系邮箱（选填）：").grid(row=r, column=0, sticky=W, padx=(0, 8), pady=4)
        self._var_le_mail = tk.StringVar(value="")
        ttk.Entry(tab, textvariable=self._var_le_mail).grid(row=r, column=1, sticky=EW, pady=4)
        r += 1

        self._var_le_staging = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            tab,
            text="使用 Let's Encrypt Staging（测试用，浏览器不信任）",
            variable=self._var_le_staging,
        ).grid(row=r, column=0, columnspan=2, sticky=W, pady=4)
        r += 1

        ttk.Label(tab, text="DNS 服务商：").grid(row=r, column=0, sticky=W, padx=(0, 8), pady=4)
        dns_fr = ttk.Frame(tab)
        dns_fr.grid(row=r, column=1, sticky=W, pady=4)
        self._var_le_dns = tk.StringVar(value="aliyun")
        ttk.Radiobutton(
            dns_fr, text="阿里云 DNS", variable=self._var_le_dns, value="aliyun", command=self._sync_dns_frames
        ).pack(side=tk.LEFT, padx=(0, 16))
        ttk.Radiobutton(
            dns_fr, text="腾讯云 DNSPod", variable=self._var_le_dns, value="tencent", command=self._sync_dns_frames
        ).pack(side=tk.LEFT)
        r += 1

        self._lf_ali = ttk.Labelframe(tab, text="阿里云 AccessKey", padding=(10, 8))
        self._lf_ali.columnconfigure(1, weight=1)
        ttk.Label(self._lf_ali, text="AccessKey ID").grid(row=0, column=0, sticky=W, padx=(0, 8))
        self._var_ali_ak = tk.StringVar(value="")
        ttk.Entry(self._lf_ali, textvariable=self._var_ali_ak).grid(row=0, column=1, sticky=EW)
        ttk.Label(self._lf_ali, text="AccessKey Secret").grid(row=1, column=0, sticky=W, padx=(0, 8), pady=(6, 0))
        self._var_ali_sk = tk.StringVar(value="")
        ttk.Entry(self._lf_ali, textvariable=self._var_ali_sk, show="*").grid(row=1, column=1, sticky=EW, pady=(6, 0))

        self._lf_tc = ttk.Labelframe(tab, text="腾讯云 API 密钥", padding=(10, 8))
        self._lf_tc.columnconfigure(1, weight=1)
        ttk.Label(self._lf_tc, text="SecretId").grid(row=0, column=0, sticky=W, padx=(0, 8))
        self._var_tc_sid = tk.StringVar(value="")
        ttk.Entry(self._lf_tc, textvariable=self._var_tc_sid).grid(row=0, column=1, sticky=EW)
        ttk.Label(self._lf_tc, text="SecretKey").grid(row=1, column=0, sticky=W, padx=(0, 8), pady=(6, 0))
        self._var_tc_sk = tk.StringVar(value="")
        ttk.Entry(self._lf_tc, textvariable=self._var_tc_sk, show="*").grid(row=1, column=1, sticky=EW, pady=(6, 0))
        ttk.Label(self._lf_tc, text="解析线路").grid(row=2, column=0, sticky=W, padx=(0, 8), pady=(6, 0))
        self._var_tc_line = tk.StringVar(value="默认")
        ttk.Entry(self._lf_tc, textvariable=self._var_tc_line).grid(row=2, column=1, sticky=EW, pady=(6, 0))

        self._le_dns_grid_row = r
        self._sync_dns_frames()
        r += 1

        ttk.Label(tab, text="输出目录：").grid(row=r, column=0, sticky=W, padx=(0, 8), pady=4)
        out_fr = ttk.Frame(tab)
        out_fr.grid(row=r, column=1, sticky=EW, pady=4)
        out_fr.columnconfigure(0, weight=1)
        self._var_le_out = tk.StringVar(value=str(Path.home() / "qqhu-letsencrypt"))
        ttk.Entry(out_fr, textvariable=self._var_le_out).grid(row=0, column=0, sticky=EW, padx=(0, 8))
        ttk.Button(out_fr, text="浏览…", command=self._browse_le_out, width=8).grid(row=0, column=1, sticky=W)
        r += 1

        ttk.Label(tab, text="ACME 账户密钥 PEM（可选；留空则用输出目录下 letsencrypt-account.pem）：").grid(
            row=r, column=0, sticky=W, padx=(0, 8), pady=4
        )
        acc_fr = ttk.Frame(tab)
        acc_fr.grid(row=r, column=1, sticky=EW, pady=4)
        acc_fr.columnconfigure(0, weight=1)
        self._var_le_acc = tk.StringVar(value="")
        ttk.Entry(acc_fr, textvariable=self._var_le_acc).grid(row=0, column=0, sticky=EW, padx=(0, 8))
        ttk.Button(acc_fr, text="浏览…", command=self._browse_le_acc, width=8).grid(row=0, column=1, sticky=W)
        r += 1

        ttk.Label(tab, text="DNS 传播等待（秒）：").grid(row=r, column=0, sticky=W, padx=(0, 8), pady=4)
        self._var_le_wait = tk.StringVar(value="25")
        ttk.Entry(tab, textvariable=self._var_le_wait, width=12).grid(row=r, column=1, sticky=W, pady=4)
        r += 1

        btn_fr = ttk.Frame(tab)
        btn_fr.grid(row=r, column=0, columnspan=2, sticky=W, pady=(10, 6))
        ttk.Button(btn_fr, text="申请 / 续期证书", command=self._on_le_issue, width=18).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(
            btn_fr,
            text="续期：保持同一账户密钥与域名重新执行即可。",
            bootstyle="secondary",
        ).pack(side=tk.LEFT)
        r += 1

        log_lf = ttk.Labelframe(tab, text="运行日志", padding=(8, 6))
        log_lf.grid(row=r, column=0, columnspan=2, sticky=NSEW, pady=(8, 0))
        log_lf.columnconfigure(0, weight=1)
        log_lf.rowconfigure(0, weight=1)
        tab.rowconfigure(r, weight=1)
        self._txt_le_log = scrolledtext.ScrolledText(
            log_lf, height=14, wrap=tk.WORD, font=("Consolas", 10), state=tk.DISABLED
        )
        self._txt_le_log.grid(row=0, column=0, sticky=NSEW)

    def _browse_le_out(self) -> None:
        p = filedialog.askdirectory(title="选择证书输出目录")
        if p:
            self._var_le_out.set(p)

    def _browse_le_acc(self) -> None:
        p = filedialog.askopenfilename(title="选择已有账户密钥 PEM", filetypes=[("PEM", "*.pem"), ("所有文件", "*.*")])
        if p:
            self._var_le_acc.set(p)

    def _parse_domains(self, raw: str) -> list[str]:
        parts: list[str] = []
        for chunk in raw.replace(",", " ").split():
            chunk = chunk.strip()
            if chunk:
                parts.append(chunk)
        return dns_common.normalize_domains(parts)

    def _on_le_issue(self) -> None:
        try:
            doms = self._parse_domains(self._var_le_domains.get())
            if not doms:
                messagebox.showwarning("Let's Encrypt", "请填写至少一个域名。", parent=self.winfo_toplevel())
                return
            out_dir = Path(self._var_le_out.get().strip()).expanduser()
            mail_v = self._var_le_mail.get().strip() or None
            try:
                wait_s = float(self._var_le_wait.get().strip())
            except ValueError:
                messagebox.showwarning("Let's Encrypt", "DNS 等待秒数无效。", parent=self.winfo_toplevel())
                return
            acc_path_str = self._var_le_acc.get().strip()
            acc_path = Path(acc_path_str).expanduser() if acc_path_str else None
            prov = self._var_le_dns.get()
            staging = bool(self._var_le_staging.get())
            apex = self._var_le_apex.get().strip() or None

            ak, sk = self._var_ali_ak.get().strip(), self._var_ali_sk.get().strip()
            sid, tsk = self._var_tc_sid.get().strip(), self._var_tc_sk.get().strip()
            tc_line = self._var_tc_line.get().strip()

            self._txt_le_log.configure(state=tk.NORMAL)
            self._txt_le_log.delete("1.0", tk.END)
            self._txt_le_log.configure(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Let's Encrypt", str(e), parent=self.winfo_toplevel())
            return

        def log_fn(m: str) -> None:
            self.after(0, lambda s=m: self._append_le_log(s))

        def work() -> None:
            try:
                paths = letsencrypt_dns.issue_via_dns01(
                    domains=doms,
                    staging=staging,
                    mailto=mail_v,
                    dns_provider="tencent" if prov == "tencent" else "aliyun",
                    aliyun_access_key_id=ak or None,
                    aliyun_access_key_secret=sk or None,
                    tencent_secret_id=sid or None,
                    tencent_secret_key=tsk or None,
                    tencent_record_line=tc_line,
                    apex_domain=apex,
                    output_dir=out_dir,
                    account_key_file=acc_path,
                    propagation_seconds=max(0.0, wait_s),
                    log=log_fn,
                )
                msg = "\n".join(f"{k}: {v}" for k, v in paths.items())
                self.after(
                    0,
                    lambda m=msg: messagebox.showinfo("Let's Encrypt", f"完成。\n{m}", parent=self.winfo_toplevel()),
                )
            except Exception as ex:
                err_s = str(ex)
                self.after(0, lambda: self._append_le_log(f"[错误] {err_s}"))
                self.after(
                    0,
                    lambda err=err_s: messagebox.showerror("Let's Encrypt", err, parent=self.winfo_toplevel()),
                )

        threading.Thread(target=work, daemon=True).start()

    def _build_tab_private(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=(12, 12, 12, 10))
        nb.add(tab, text="私有证书")
        tab.columnconfigure(1, weight=1)

        r = 0
        ttk.Label(tab, text="站点 Common Name：").grid(row=r, column=0, sticky=W, padx=(0, 8), pady=4)
        self._var_priv_cn = tk.StringVar(value="dev.server.local")
        ttk.Entry(tab, textvariable=self._var_priv_cn).grid(row=r, column=1, sticky=EW, pady=4)
        r += 1

        ttk.Label(tab, text="SAN（逗号分隔，域名或 IP）：").grid(row=r, column=0, sticky=W, padx=(0, 8), pady=4)
        self._var_priv_san = tk.StringVar(value="dev.server.local,127.0.0.1")
        ttk.Entry(tab, textvariable=self._var_priv_san).grid(row=r, column=1, sticky=EW, pady=4)
        r += 1

        ttk.Label(tab, text="输出目录：").grid(row=r, column=0, sticky=W, padx=(0, 8), pady=4)
        out_fr = ttk.Frame(tab)
        out_fr.grid(row=r, column=1, sticky=EW, pady=4)
        out_fr.columnconfigure(0, weight=1)
        self._var_priv_out = tk.StringVar(value=str(Path.home() / "qqhu-private-ca"))
        ttk.Entry(out_fr, textvariable=self._var_priv_out).grid(row=0, column=0, sticky=EW, padx=(0, 8))
        ttk.Button(out_fr, text="浏览…", command=self._browse_priv_out, width=8).grid(row=0, column=1, sticky=W)
        r += 1

        ttk.Label(tab, text="导出 PFX 密码（留空则不生成 .pfx）：").grid(row=r, column=0, sticky=W, padx=(0, 8), pady=4)
        self._var_priv_pfx = tk.StringVar(value="")
        ttk.Entry(tab, textvariable=self._var_priv_pfx, show="*").grid(row=r, column=1, sticky=EW, pady=4)
        r += 1

        btn_fr = ttk.Frame(tab)
        btn_fr.grid(row=r, column=0, columnspan=2, sticky=W, pady=(10, 6))
        ttk.Button(btn_fr, text="生成根 CA 与站点证书", command=self._on_priv_generate, width=20).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        ttk.Button(btn_fr, text="打开证书目录", command=self._on_open_priv_out_dir, width=14).pack(side=tk.LEFT)
        r += 1

        log_lf = ttk.Labelframe(tab, text="说明与日志", padding=(8, 6))
        log_lf.grid(row=r, column=0, columnspan=2, sticky=NSEW, pady=(8, 0))
        log_lf.columnconfigure(0, weight=1)
        log_lf.rowconfigure(0, weight=1)
        tab.rowconfigure(r, weight=1)
        self._txt_priv_log = scrolledtext.ScrolledText(
            log_lf, height=18, wrap=tk.WORD, font=("Microsoft YaHei UI", 10), state=tk.DISABLED
        )
        self._txt_priv_log.grid(row=0, column=0, sticky=NSEW)
        self._txt_priv_log.configure(state=tk.NORMAL)
        self._txt_priv_log.insert(tk.END, _PRIV_HINT)
        self._txt_priv_log.configure(state=tk.DISABLED)

    def _browse_priv_out(self) -> None:
        p = filedialog.askdirectory(title="选择输出目录")
        if p:
            self._var_priv_out.set(p)

    def _on_open_priv_out_dir(self) -> None:
        out_s = self._var_priv_out.get().strip()
        if not out_s:
            messagebox.showwarning("私有证书", "请先填写输出目录。", parent=self.winfo_toplevel())
            return
        p = Path(out_s).expanduser().resolve()
        if not p.is_dir():
            messagebox.showwarning(
                "私有证书",
                f"目录不存在：\n{p}\n\n请先生成证书，或核对路径是否正确。",
                parent=self.winfo_toplevel(),
            )
            return
        try:
            if sys.platform == "win32":
                os.startfile(str(p))
            elif sys.platform == "darwin":
                subprocess.run(["open", str(p)], check=False)
            else:
                subprocess.run(["xdg-open", str(p)], check=False)
        except OSError as e:
            messagebox.showerror("私有证书", f"无法打开目录：{e}", parent=self.winfo_toplevel())

    def _on_priv_generate(self) -> None:
        cn = self._var_priv_cn.get().strip()
        if not cn:
            messagebox.showwarning("私有证书", "请填写 Common Name。", parent=self.winfo_toplevel())
            return
        san_tokens = [x.strip() for x in self._var_priv_san.get().replace(",", " ").split() if x.strip()]
        out_s = self._var_priv_out.get().strip()
        if not out_s:
            messagebox.showwarning("私有证书", "请填写输出目录。", parent=self.winfo_toplevel())
            return
        out = Path(out_s).expanduser()
        pfx_pw = self._var_priv_pfx.get().strip() or None
        days = _PRIVATE_CERT_VALIDITY_DAYS

        def log_fn(m: str) -> None:
            self.after(0, lambda s=m: self._append_priv_log(s))

        def work() -> None:
            try:
                ca_key, ca_cert = private_ca.generate_ca(common_name=f"{cn} Root CA", days_valid=days)
                site_key, site_cert = private_ca.generate_site_signed_by_ca(
                    ca_key,
                    ca_cert,
                    common_name=cn,
                    san_tokens=san_tokens,
                    days_valid=days,
                )
                paths = private_ca.write_private_bundle(
                    out,
                    ca_key=ca_key,
                    ca_cert=ca_cert,
                    site_key=site_key,
                    site_cert=site_cert,
                    pfx_password=pfx_pw,
                )
                for k, p in paths.items():
                    log_fn(f"{k}: {p}")
                log_fn("")
                log_fn("下一步：服务端绑定证书请参考上文「服务端怎么用」；客户端请按「客户端如何信任」安装根证书。")
                msg = "\n".join(f"{k}: {v}" for k, v in paths.items())
                self.after(
                    0,
                    lambda m=msg: messagebox.showinfo("私有证书", f"已生成。\n{m}", parent=self.winfo_toplevel()),
                )
            except Exception as ex:
                err_s = str(ex)
                log_fn(f"[错误] {err_s}")
                self.after(
                    0,
                    lambda err=err_s: messagebox.showerror("私有证书", err, parent=self.winfo_toplevel()),
                )

        self._txt_priv_log.configure(state=tk.NORMAL)
        self._txt_priv_log.delete("1.0", tk.END)
        self._txt_priv_log.insert(tk.END, _PRIV_HINT)
        self._txt_priv_log.configure(state=tk.DISABLED)
        threading.Thread(target=work, daemon=True).start()
