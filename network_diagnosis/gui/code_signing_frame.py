"""数字签名页：PFX（CA 或自签名）对 exe/dll 执行 Authenticode 签名，一键生成自签名证书。"""

from __future__ import annotations

import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

import ttkbootstrap as ttk
from ttkbootstrap.constants import (
    DANGER,
    EW,
    INFO,
    NSEW,
    PRIMARY,
    SECONDARY,
    SUCCESS,
    WARNING,
    E,
    W,
)

from network_diagnosis.code_sign_windows import (
    find_signtool_exe,
    generate_self_signed_code_signing_pfx,
    sign_pe,
    verify_pe,
)


class CodeSigningFrame(ttk.Frame):
    """Windows Authenticode：signtool + PFX；支持 CA 证书与自签名一键生成。"""

    #: 「待签名文件」分组宽度小于该像素时使用多行布局（标签一行、路径一行、按钮一行）。
    _TGT_INLINE_MIN_WIDTH = 720

    def __init__(self, master: tk.Misc, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        if sys.platform != "win32":
            ttk.Label(
                self,
                text="数字签名功能依赖 Windows 上的 signtool.exe，当前环境不可用。",
                bootstyle=WARNING,
                font=("Microsoft YaHei UI", 12),
                wraplength=560,
            ).grid(row=0, column=0, sticky=W, padx=16, pady=24)
            return

        self._var_pfx = tk.StringVar(value="")
        self._var_pfx_pw = tk.StringVar(value="")
        self._var_exe = tk.StringVar(value="")
        self._var_timestamp = tk.BooleanVar(value=True)
        self._var_ts_url = tk.StringVar(value="http://timestamp.digicert.com")
        self._lf_tgt: tk.Misc | None = None
        self._tgt_compact: bool | None = None

        self._build_ui()

    def on_leave(self) -> None:
        """切换模块时无独占资源。"""

    @staticmethod
    def _center_toplevel(win: tk.Toplevel, *, width: int, height: int) -> None:
        """将顶层窗口置于**主屏**近似居中（固定像素宽高）。"""
        win.geometry(f"{width}x{height}")
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = max(0, (sw - width) // 2)
        y = max(0, (sh - height) // 2)
        win.geometry(f"{width}x{height}+{x}+{y}")

    def _apply_tgt_layout(self, compact: bool) -> None:
        """宽屏：路径与按钮同一行；窄屏：路径独占一行，按钮下一行左对齐。"""
        for w in (
            self._lbl_tgt_pe,
            self._ent_tgt_exe,
            self._btn_tgt_browse,
            self._btn_tgt_verify,
            self._btn_tgt_sign,
        ):
            w.grid_forget()

        if compact:
            self._lf_tgt.columnconfigure(1, weight=0)
            self._lf_tgt.columnconfigure(0, weight=1)
            self._lbl_tgt_pe.grid(row=0, column=0, sticky=W, padx=(0, 8))
            self._ent_tgt_exe.grid(row=1, column=0, columnspan=5, sticky=EW, pady=(4, 0))
            self._btn_tgt_browse.grid(row=2, column=0, sticky=W, pady=(8, 0))
            self._btn_tgt_verify.grid(row=2, column=1, sticky=W, padx=(8, 0), pady=(8, 0))
            self._btn_tgt_sign.grid(row=2, column=2, sticky=W, padx=(8, 0), pady=(8, 0))
        else:
            self._lf_tgt.columnconfigure(0, weight=0)
            self._lf_tgt.columnconfigure(1, weight=1)
            self._lbl_tgt_pe.grid(row=0, column=0, sticky=W, padx=(0, 8))
            self._ent_tgt_exe.grid(row=0, column=1, sticky=EW)
            self._btn_tgt_browse.grid(row=0, column=2, padx=(8, 8))
            self._btn_tgt_verify.grid(row=0, column=3, sticky=W, padx=(0, 8))
            self._btn_tgt_sign.grid(row=0, column=4, sticky=W)

    def _on_lf_tgt_configure(self, event: tk.Event) -> None:
        if getattr(self, "_lf_tgt", None) is None or event.widget is not self._lf_tgt:
            return
        w = event.width
        if w < 80:
            return
        compact = w < self._TGT_INLINE_MIN_WIDTH
        if self._tgt_compact is not None and compact == self._tgt_compact:
            return
        self._tgt_compact = compact
        self._apply_tgt_layout(compact)

    def _build_ui(self) -> None:
        lf_top = ttk.Labelframe(self, text="环境", bootstyle=SUCCESS, padding=(12, 10, 12, 10))
        lf_top.grid(row=0, column=0, sticky=EW, padx=(14, 14), pady=(12, 8))
        lf_top.columnconfigure(1, weight=1)

        st = find_signtool_exe()
        sig_txt = str(st) if st else "未检测到 signtool.exe（请安装 Windows SDK）"
        ttk.Label(lf_top, text="当前 Signtool 路径:", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 10))
        ttk.Label(lf_top, text=sig_txt, wraplength=900).grid(row=0, column=1, sticky=W)

        hint = ttk.Labelframe(self, text="说明", bootstyle=INFO, padding=(12, 10, 12, 10))
        hint.grid(row=1, column=0, sticky=EW, padx=(14, 14), pady=(0, 8))
        hint.columnconfigure(0, weight=1)
        # ttk.Label 不支持 Markdown；用语义化标点表述强调，避免 raw ``**``。
        ttk.Label(
            hint,
            text=(
                "• CA / 商业证书：使用厂商下发的「PFX」及密码签名（可被公开信任链验证）。\n"
                "• 自签名：点击下方「一键生成自签名证书」导出「PFX」与「CER」；\n"
                "• 以下所有路径建议不要使用中文或空格，以免 signtool 兼容性问题（尤其是时间戳 URL）。\n"
            ),
            bootstyle=SECONDARY,
            wraplength=920,
            justify=tk.LEFT,
        ).grid(row=0, column=0, sticky=W)

        grid = ttk.Frame(self, padding=(14, 0, 14, 12))
        grid.grid(row=2, column=0, sticky=NSEW)
        grid.columnconfigure(0, weight=1)
        grid.rowconfigure(3, weight=1)

        lf_cert = ttk.Labelframe(grid, text="证书（PFX）", bootstyle=SECONDARY, padding=(12, 10, 12, 10))
        lf_cert.grid(row=0, column=0, sticky=EW, pady=(0, 8))
        lf_cert.columnconfigure(1, weight=1)

        ttk.Button(
            lf_cert,
            text="一键生成自签名证书…",
            bootstyle=SUCCESS,
            command=self._on_generate_self_signed,
        ).grid(row=0, column=0, columnspan=3, sticky=W, pady=(0, 8))

        ttk.Label(lf_cert, text="PFX 路径").grid(row=1, column=0, sticky=W, padx=(0, 8), pady=(0, 6))
        ttk.Entry(lf_cert, textvariable=self._var_pfx).grid(row=1, column=1, sticky=EW, pady=(0, 6))
        ttk.Button(lf_cert, text="浏览…", width=8, command=self._browse_pfx).grid(row=1, column=2, sticky=E, padx=(8, 0))

        ttk.Label(lf_cert, text="PFX 密码").grid(row=2, column=0, sticky=W, padx=(0, 8))
        ttk.Entry(lf_cert, textvariable=self._var_pfx_pw, show="•").grid(row=2, column=1, sticky=EW, pady=(4, 0))

        lf_opt = ttk.Labelframe(grid, text="签名选项", bootstyle=SECONDARY, padding=(12, 10, 12, 10))
        lf_opt.grid(row=1, column=0, sticky=EW, pady=(0, 8))
        lf_opt.columnconfigure(1, weight=1)

        ttk.Checkbutton(
            lf_opt,
            text="附加 RFC3161 时间戳（需能访问时间戳服务器）",
            variable=self._var_timestamp,
            bootstyle="round-toggle",
        ).grid(row=0, column=0, columnspan=2, sticky=W)
        ttk.Label(lf_opt, text="时间戳 URL").grid(row=1, column=0, sticky=W, padx=(0, 8), pady=(8, 0))
        ttk.Entry(lf_opt, textvariable=self._var_ts_url).grid(row=1, column=1, sticky=EW, pady=(8, 0))

        lf_tgt = ttk.Labelframe(grid, text="待签名文件", bootstyle=SECONDARY, padding=(12, 10, 12, 10))
        lf_tgt.grid(row=2, column=0, sticky=EW, pady=(0, 8))
        self._lf_tgt = lf_tgt

        self._lbl_tgt_pe = ttk.Label(lf_tgt, text="PE 文件")
        self._ent_tgt_exe = ttk.Entry(lf_tgt, textvariable=self._var_exe)
        self._btn_tgt_browse = ttk.Button(lf_tgt, text="浏览…", width=8, command=self._browse_exe)
        self._btn_tgt_verify = ttk.Button(lf_tgt, text="验证签名", bootstyle=SECONDARY, command=self._on_verify)
        self._btn_tgt_sign = ttk.Button(lf_tgt, text="执行签名", bootstyle=PRIMARY, command=self._on_sign)

        self._tgt_compact = False
        self._apply_tgt_layout(False)
        lf_tgt.bind("<Configure>", self._on_lf_tgt_configure)
        lf_log = ttk.Labelframe(grid, text="输出", bootstyle=SECONDARY, padding=(8, 8, 8, 8))
        lf_log.grid(row=3, column=0, sticky=NSEW)
        lf_log.rowconfigure(0, weight=1)
        lf_log.columnconfigure(0, weight=1)
        self._txt = tk.Text(lf_log, height=14, wrap=tk.WORD, font=("Consolas", 10), relief=tk.FLAT)
        self._txt.grid(row=0, column=0, sticky=NSEW)

    def _append_log(self, text: str) -> None:
        self._txt.configure(state=tk.NORMAL)
        self._txt.insert(tk.END, text.rstrip() + "\n")
        self._txt.see(tk.END)
        self._txt.configure(state=tk.DISABLED)

    def _browse_pfx(self) -> None:
        p = filedialog.askopenfilename(
            title="选择 PFX 证书",
            filetypes=[("PFX/P12", "*.pfx *.p12"), ("所有文件", "*.*")],
        )
        if p:
            self._var_pfx.set(p)

    def _browse_exe(self) -> None:
        p = filedialog.askopenfilename(
            title="选择可执行文件或 DLL",
            filetypes=[
                ("PE 文件", "*.exe *.dll *.sys"),
                ("可执行文件", "*.exe"),
                ("所有文件", "*.*"),
            ],
        )
        if p:
            self._var_exe.set(p)

    def _on_generate_self_signed(self) -> None:
        dlg = tk.Toplevel(self)
        dlg.title("一键生成自签名代码签名证书")
        dlg.transient(self.winfo_toplevel())
        dlg.grab_set()
        dlg.withdraw()
        dlg.columnconfigure(1, weight=1)
        dlg.rowconfigure(0, weight=0)

        home_docs = Path.home() / "Documents"
        var_dir = tk.StringVar(value=str(home_docs if home_docs.is_dir() else Path.home()))
        var_pw = tk.StringVar()
        var_pw2 = tk.StringVar()
        var_sub = tk.StringVar(value="CN=Qingqiuhu Self-Signed Code Signing")

        pad = {"padx": 16, "pady": 10}
        ttk.Label(dlg, text="保存目录").grid(row=0, column=0, sticky=W, **pad)

        def browse_dir() -> None:
            d = filedialog.askdirectory(title="选择保存目录", initialdir=var_dir.get())
            if d:
                var_dir.set(d)

        row0 = ttk.Frame(dlg)
        row0.grid(row=0, column=1, sticky=EW, **pad)
        row0.columnconfigure(0, weight=1)
        ttk.Entry(row0, textvariable=var_dir).grid(row=0, column=0, sticky=EW)
        ttk.Button(row0, text="浏览…", command=browse_dir, width=8).grid(row=0, column=1, padx=(8, 0))

        ttk.Label(dlg, text="证书主题 (Subject)").grid(row=1, column=0, sticky=W, **pad)
        ttk.Entry(dlg, textvariable=var_sub).grid(row=1, column=1, sticky=EW, **pad)

        ttk.Label(dlg, text="PFX 密码").grid(row=2, column=0, sticky=W, **pad)
        ttk.Entry(dlg, textvariable=var_pw, show="•").grid(row=2, column=1, sticky=EW, **pad)

        ttk.Label(dlg, text="确认密码").grid(row=3, column=0, sticky=W, **pad)
        ttk.Entry(dlg, textvariable=var_pw2, show="•").grid(row=3, column=1, sticky=EW, **pad)

        err_lbl = ttk.Label(dlg, text="", bootstyle=DANGER, wraplength=640)
        err_lbl.grid(row=4, column=0, columnspan=2, sticky=W, padx=10)

        def ok() -> None:
            err_lbl.configure(text="")
            if var_pw.get() != var_pw2.get():
                err_lbl.configure(text="两次密码不一致。")
                return
            out = Path(var_dir.get().strip())
            sub = var_sub.get().strip()
            if not sub:
                err_lbl.configure(text="请填写证书主题。")
                return
            dlg.configure(cursor="watch")
            dlg.update_idletasks()

            def work() -> None:
                ok_b, msg, pfx_p, cer_p = generate_self_signed_code_signing_pfx(out, var_pw.get(), sub)

                def finish() -> None:
                    dlg.configure(cursor="")
                    if ok_b and pfx_p and cer_p:
                        self._var_pfx.set(str(pfx_p))
                        self._var_pfx_pw.set(var_pw.get())
                        self._append_log(
                            f"[生成成功]\nPFX: {pfx_p}\nCER (用于下发信任): {cer_p}\n"
                            "请将 CER 导入客户端「受信任的根证书颁发机构」，详见文档第 8 节。"
                        )
                        messagebox.showinfo("数字签名", f"已生成：\n{pfx_p}\n{cer_p}", parent=dlg)
                        dlg.destroy()
                    else:
                        err_lbl.configure(text=msg[:500] if msg else "生成失败。")
                        self._append_log(f"[生成失败]\n{msg}")

                self.after(0, finish)

            threading.Thread(target=work, daemon=True).start()

        def cancel() -> None:
            dlg.destroy()

        bf = ttk.Frame(dlg)
        bf.grid(row=5, column=0, columnspan=2, pady=(20, 16))
        ttk.Button(bf, text="生成", bootstyle=SUCCESS, command=ok).pack(side=tk.LEFT, padx=6)
        ttk.Button(bf, text="取消", bootstyle=SECONDARY, command=cancel).pack(side=tk.LEFT)

        self._center_toplevel(dlg, width=720, height=420)
        dlg.resizable(True, True)
        dlg.minsize(620, 360)
        dlg.deiconify()
    def _on_sign(self) -> None:
        exe = Path(self._var_exe.get().strip())
        pfx = Path(self._var_pfx.get().strip())
        pw = self._var_pfx_pw.get()
        if not exe.is_file():
            messagebox.showwarning("数字签名", "请选择有效的待签名文件。", parent=self.winfo_toplevel())
            return
        if not pfx.is_file():
            messagebox.showwarning("数字签名", "请选择有效的 PFX 文件。", parent=self.winfo_toplevel())
            return

        exe_resolved = exe.resolve()

        ts = self._var_ts_url.get().strip() if self._var_timestamp.get() else None

        def work() -> None:
            try:
                proc = sign_pe(exe_resolved, pfx, pw, timestamp_url=ts)
                out = ""
                if proc.stdout:
                    out += proc.stdout
                if proc.stderr:
                    out += "\n" + proc.stderr
                summary = f"[签名] exit={proc.returncode}\n{out.strip()}"

                def done() -> None:
                    self._append_log(summary)
                    if proc.returncode == 0:
                        messagebox.showinfo("数字签名", "签名完成。", parent=self.winfo_toplevel())
                    else:
                        messagebox.showerror("数字签名", "签名失败，请查看输出日志。", parent=self.winfo_toplevel())

                self.after(0, done)
            except FileNotFoundError as e:
                self.after(0, lambda: messagebox.showerror("数字签名", str(e), parent=self.winfo_toplevel()))
            except OSError as e:
                self.after(0, lambda: messagebox.showerror("数字签名", str(e), parent=self.winfo_toplevel()))

        self._append_log(f"[签名开始] {exe_resolved}")
        threading.Thread(target=work, daemon=True).start()

    def _on_verify(self) -> None:
        exe = Path(self._var_exe.get().strip())
        if not exe.is_file():
            messagebox.showwarning("数字签名", "请选择有效的文件。", parent=self.winfo_toplevel())
            return

        def work() -> None:
            try:
                proc = verify_pe(exe)
                out = ""
                if proc.stdout:
                    out += proc.stdout
                if proc.stderr:
                    out += "\n" + proc.stderr
                summary = f"[验证] exit={proc.returncode}\n{out.strip()}"

                def done() -> None:
                    self._append_log(summary)
                    if proc.returncode != 0:
                        messagebox.showwarning("数字签名", "验证未通过或文件未签名，详见输出。", parent=self.winfo_toplevel())

                self.after(0, done)
            except FileNotFoundError as e:
                self.after(0, lambda: messagebox.showerror("数字签名", str(e), parent=self.winfo_toplevel()))

        threading.Thread(target=work, daemon=True).start()
