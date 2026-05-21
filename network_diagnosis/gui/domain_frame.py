"""域与组策略页：诊断、策略查看/刷新、信任修复、改名、加域、退域。"""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import messagebox

import ttkbootstrap as ttk
from ttkbootstrap.constants import DANGER, END, EW, INFO, NSEW, PRIMARY, ROUND, SECONDARY, SUCCESS, WARNING, W

from network_diagnosis.domain.collect import fetch_domain_identity, run_domain_diagnosis, run_gpresult
from network_diagnosis.domain.config import DomainOpsSettings, load_domain_ops_settings, save_domain_ops_settings
from network_diagnosis.domain.elevation import cancel_scheduled_reboot, is_admin, is_windows, schedule_reboot
from network_diagnosis.domain.models import DomainDiagnosisResult, DomainOperationResult, GpResultReport
from network_diagnosis.domain.operations import (
    run_gpupdate,
    run_join_domain,
    run_rename_computer,
    run_repair_trust,
    run_unjoin_domain,
)
from network_diagnosis.domain.report_md import render_diagnosis_markdown, render_gpresult_markdown
from network_diagnosis.gui.simple_markdown_text import append_simple_markdown, configure_simple_markdown_tags
from network_diagnosis.paths import domain_ops_report_dir
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)

OperationMode = str  # diagnose | view_policy | gpupdate | repair | rename | join | unjoin


class _CredentialDialog(tk.Toplevel):
    def __init__(self, master: tk.Misc, *, title: str, default_user: str = "") -> None:
        super().__init__(master)
        self.title(title)
        self.resizable(False, False)
        self.transient(master.winfo_toplevel())
        self.grab_set()
        self.result: tuple[str, str] | None = None

        frm = ttk.Frame(self, padding=16)
        frm.grid(row=0, column=0, sticky=NSEW)
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text="用户名（域\\用户）").grid(row=0, column=0, sticky=W, pady=4)
        self.var_user = tk.StringVar(value=default_user)
        ttk.Entry(frm, textvariable=self.var_user, width=36).grid(row=0, column=1, sticky=EW, padx=(8, 0), pady=4)

        ttk.Label(frm, text="密码").grid(row=1, column=0, sticky=W, pady=4)
        self.var_pass = tk.StringVar()
        ent_pass = ttk.Entry(frm, textvariable=self.var_pass, show="*", width=36)
        ent_pass.grid(row=1, column=1, sticky=EW, padx=(8, 0), pady=4)

        row_btn = ttk.Frame(frm)
        row_btn.grid(row=2, column=0, columnspan=2, sticky=EW, pady=(12, 0))
        ttk.Button(row_btn, text="确定", command=self._ok, bootstyle=PRIMARY).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(row_btn, text="取消", command=self._cancel, bootstyle=SECONDARY).pack(side=tk.LEFT)

        ent_pass.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.after(50, ent_pass.focus_set)

    def _ok(self) -> None:
        u = self.var_user.get().strip()
        p = self.var_pass.get()
        if not u:
            messagebox.showwarning("凭据", "请填写用户名。", parent=self)
            return
        self.result = (u, p)
        self.var_pass.set("")
        self.grab_release()
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.var_pass.set("")
        self.grab_release()
        self.destroy()


class DomainFrame(ttk.Frame):
    def __init__(self, master: tk.Misc, app: tk.Misc | None = None, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self._app = app
        self._q: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._worker: threading.Thread | None = None
        self._mode: OperationMode = "diagnose"
        self._last_report_dir: Path | None = None
        self._last_gp_html: str = ""
        self._settings = load_domain_ops_settings()
        self._build_ui()
        self._apply_mode("diagnose")
        self.after(180, self._poll_queue)

    def on_show(self) -> None:
        self._refresh_status()

    def on_leave(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            pass

    def _build_ui(self) -> None:
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=0, minsize=380)
        self.columnconfigure(1, weight=1)

        frm_ops = ttk.Frame(self, padding=(14, 12, 8, 12))
        frm_ops.grid(row=0, column=0, sticky=NSEW)
        frm_out = ttk.Frame(self, padding=(8, 12, 14, 12))
        frm_out.grid(row=0, column=1, sticky=NSEW)

        frm_ops.columnconfigure(0, weight=1)
        frm_out.rowconfigure(1, weight=1)
        frm_out.columnconfigure(0, weight=1)

        self._build_ops_column(frm_ops)
        self._build_out_column(frm_out)

    def _build_ops_column(self, parent: tk.Misc) -> None:
        parent.columnconfigure(0, weight=1)

        hint = ttk.Labelframe(parent, text="合规提示", bootstyle=WARNING, padding=(10, 10, 10, 8))
        hint.grid(row=0, column=0, sticky=EW)
        hint.columnconfigure(0, weight=1)
        hint_msg = (
            "写操作（加域/退域/改名/修复信任/刷新策略）需 **管理员** 权限与 **明确授权**。\n"
            "加域后指定用户加入本地 **Power Users**（非 Administrators）。\n"
            "**退域** 风险最高，请确认本地管理员可登录。"
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
        append_simple_markdown(txt_hint, hint_msg + "\n")
        txt_hint.configure(state=tk.DISABLED)

        status = ttk.Labelframe(parent, text="当前状态", padding=(10, 8, 10, 8))
        status.grid(row=1, column=0, sticky=EW, pady=(10, 0))
        status.columnconfigure(0, weight=1)
        self.lbl_status = ttk.Label(status, text="加载中…", wraplength=320, justify=tk.LEFT)
        self.lbl_status.grid(row=0, column=0, sticky=W)
        ttk.Button(status, text="刷新", command=self._refresh_status, bootstyle=SECONDARY).grid(
            row=1, column=0, sticky=W, pady=(6, 0)
        )

        actions = ttk.Labelframe(parent, text="操作", padding=(10, 8, 10, 8))
        actions.grid(row=2, column=0, sticky=EW, pady=(10, 0))
        for i in range(2):
            actions.columnconfigure(i, weight=1)

        btns = [
            ("diagnose", "域诊断", INFO),
            ("view_policy", "查看域策略", INFO),
            ("gpupdate", "更新域策略", WARNING),
            ("repair", "修复域信任", WARNING),
            ("rename", "计算机重命名", WARNING),
            ("join", "加入域", WARNING),
            ("unjoin", "退出域", DANGER),
        ]
        for idx, (mode, label, style) in enumerate(btns):
            ttk.Button(
                actions,
                text=label,
                command=lambda m=mode: self._apply_mode(m),
                bootstyle=style,
            ).grid(row=idx // 2, column=idx % 2, sticky=EW, padx=(0 if idx % 2 == 0 else 4, 0), pady=2)

        self.frm_form = ttk.Labelframe(parent, text="参数", padding=(10, 8, 10, 8))
        self.frm_form.grid(row=3, column=0, sticky=EW, pady=(10, 0))
        self.frm_form.columnconfigure(1, weight=1)

        self.var_probe_domain = tk.StringVar(value=self._settings.default_domain_dns)
        self.var_gp_scope = tk.StringVar(value="both")
        self.var_new_name = tk.StringVar()
        self.var_domain_dns = tk.StringVar(value=self._settings.default_domain_dns)
        self.var_ou_path = tk.StringVar()
        self.var_post_join_user = tk.StringVar()
        self.var_workgroup = tk.StringVar(value=self._settings.default_workgroup)
        self.var_unjoin_confirm = tk.BooleanVar(value=False)

        self._form_widgets: list[tk.Widget] = []

        row_exec = ttk.Frame(parent)
        row_exec.grid(row=4, column=0, sticky=EW, pady=(10, 0))
        self.btn_exec = ttk.Button(row_exec, text="执行", command=self._on_execute, bootstyle=PRIMARY)
        self.btn_exec.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(
            row_exec,
            text="取消重启计划",
            command=self._on_cancel_reboot,
            bootstyle=SECONDARY,
        ).pack(side=tk.LEFT)

        self.lbl_admin = ttk.Label(parent, text="", bootstyle=SECONDARY)
        self.lbl_admin.grid(row=5, column=0, sticky=W, pady=(8, 0))
        self._update_admin_label()

        self.prog = ttk.Progressbar(parent, mode="indeterminate", bootstyle=INFO)
        self.prog.grid(row=6, column=0, sticky=EW, pady=(8, 0))
        self.lbl_task = ttk.Label(parent, text="", bootstyle=SECONDARY)
        self.lbl_task.grid(row=7, column=0, sticky=W, pady=(4, 0))

    def _build_out_column(self, parent: tk.Misc) -> None:
        row_btns = ttk.Frame(parent)
        row_btns.grid(row=0, column=0, sticky=EW, pady=(0, 8))
        ttk.Button(row_btns, text="打开报告目录", command=self._on_open_report_dir, bootstyle=SECONDARY).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(row_btns, text="打开 gpresult.html", command=self._on_open_gp_html, bootstyle=SECONDARY).pack(
            side=tk.LEFT
        )

        self.txt = tk.Text(
            parent,
            wrap=tk.WORD,
            relief=tk.FLAT,
            padx=8,
            pady=8,
            font=("Microsoft YaHei UI", 10),
            state=tk.DISABLED,
        )
        self.txt.grid(row=1, column=0, sticky=NSEW)
        sb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.txt.yview, bootstyle=ROUND)
        sb.grid(row=1, column=1, sticky=NSEW)
        self.txt.configure(yscrollcommand=sb.set)
        configure_simple_markdown_tags(self.txt, base_font=("Microsoft YaHei UI", 10), theme_colors=ttk.Style().colors)

    def _update_admin_label(self) -> None:
        if not is_windows():
            self.lbl_admin.configure(text="当前平台非 Windows，域模块不可用。", bootstyle=DANGER)
        elif is_admin():
            self.lbl_admin.configure(text="已检测到管理员权限。", bootstyle=SUCCESS)
        else:
            self.lbl_admin.configure(text="未以管理员运行；写操作将不可用。", bootstyle=WARNING)

    def _refresh_status(self) -> None:
        if not is_windows():
            self.lbl_status.configure(text="非 Windows 环境")
            return

        def worker() -> None:
            try:
                idn = fetch_domain_identity()
                sc = "—"
                if idn.part_of_domain:
                    from network_diagnosis.domain.ps_win import parse_ps_json, run_powershell

                    _, out, _ = run_powershell(
                        "Test-ComputerSecureChannel | ConvertTo-Json -Compress",
                        timeout=30,
                    )
                    try:
                        data = parse_ps_json(out)
                        if isinstance(data, bool):
                            sc = "正常" if data else "异常"
                    except Exception:
                        sc = "—"
                if idn.part_of_domain:
                    text = (
                        f"计算机：{idn.computer_name}\n"
                        f"域：{idn.domain}\n"
                        f"已入域 | 安全通道：{sc}"
                    )
                else:
                    text = f"计算机：{idn.computer_name}\n工作组：{idn.workgroup}\n未加入域"
                self._q.put(("status", text))
            except Exception as e:
                self._q.put(("status", f"状态读取失败：{e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _clear_form(self) -> None:
        for w in self._form_widgets:
            w.destroy()
        self._form_widgets.clear()

    def _form_label(self, row: int, text: str) -> None:
        lbl = ttk.Label(self.frm_form, text=text)
        lbl.grid(row=row, column=0, sticky=W, pady=3)
        self._form_widgets.append(lbl)

    def _form_entry(self, row: int, var: tk.StringVar, *, show: str | None = None) -> None:
        kw: dict = dict(textvariable=var)
        if show:
            kw["show"] = show
        ent = ttk.Entry(self.frm_form, **kw)
        ent.grid(row=row, column=1, sticky=EW, padx=(8, 0), pady=3)
        self._form_widgets.append(ent)

    def _apply_mode(self, mode: OperationMode) -> None:
        self._mode = mode
        self._clear_form()
        titles = {
            "diagnose": "域诊断",
            "view_policy": "查看域策略（本机）",
            "gpupdate": "更新域策略",
            "repair": "修复域信任",
            "rename": "计算机重命名",
            "join": "加入域",
            "unjoin": "退出域",
        }
        self.frm_form.configure(text=titles.get(mode, "参数"))
        row = 0

        if mode == "diagnose":
            self._form_label(row, "探测域 DNS（可选）")
            self._form_entry(row, self.var_probe_domain)
            row += 1
            hint_lbl = ttk.Label(
                self.frm_form,
                text="未入域时可填目标域；已入域留空则用当前域",
                bootstyle=SECONDARY,
            )
            hint_lbl.grid(row=row, column=1, sticky=W, padx=(8, 0))
            self._form_widgets.append(hint_lbl)

        elif mode == "view_policy":
            self._form_label(row, "范围")
            frm = ttk.Frame(self.frm_form)
            frm.grid(row=row, column=1, sticky=W, padx=(8, 0))
            for val, lbl in (("both", "用户+计算机"), ("user", "用户"), ("computer", "计算机")):
                ttk.Radiobutton(frm, text=lbl, variable=self.var_gp_scope, value=val).pack(side=tk.LEFT, padx=(0, 8))
            self._form_widgets.append(frm)

        elif mode == "gpupdate":
            lbl = ttk.Label(
                self.frm_form,
                text="将刷新本机计算机策略与当前登录用户策略，无需额外参数。",
                bootstyle=SECONDARY,
                wraplength=300,
                justify=tk.LEFT,
            )
            lbl.grid(row=row, column=0, columnspan=2, sticky=W, pady=3)
            self._form_widgets.append(lbl)

        elif mode == "rename":
            idn = fetch_domain_identity()
            self._form_label(row, "当前名称")
            lbl_cur = ttk.Label(self.frm_form, text=idn.computer_name or "—")
            lbl_cur.grid(row=row, column=1, sticky=W, padx=(8, 0))
            self._form_widgets.append(lbl_cur)
            row += 1
            self._form_label(row, "新计算机名")
            self._form_entry(row, self.var_new_name)
            row += 1
            ttk.Label(self.frm_form, text="1–15 位字母/数字/连字符；完成后需重启", bootstyle=SECONDARY).grid(
                row=row, column=1, sticky=W, padx=(8, 0)
            )

        elif mode == "join":
            self._form_label(row, "域 DNS 名")
            self._form_entry(row, self.var_domain_dns)
            row += 1
            self._form_label(row, "OU 路径（可选）")
            self._form_entry(row, self.var_ou_path)
            row += 1
            self._form_label(row, "加域后 Power Users 用户")
            self._form_entry(row, self.var_post_join_user)
            row += 1
            ttk.Label(
                self.frm_form,
                text="如 CORP\\zhangsan；Domain Admins 组不会被移除",
                bootstyle=SECONDARY,
            ).grid(row=row, column=1, sticky=W, padx=(8, 0))

        elif mode == "unjoin":
            self._form_label(row, "目标工作组")
            self._form_entry(row, self.var_workgroup)
            row += 1
            chk = ttk.Checkbutton(
                self.frm_form,
                text="已确认存在可用本地 Administrator 或已知本地管理员密码",
                variable=self.var_unjoin_confirm,
                bootstyle="round-toggle",
            )
            chk.grid(row=row, column=0, columnspan=2, sticky=W, pady=6)
            self._form_widgets.append(chk)

    def _append_md(self, chunk: str) -> None:
        self.txt.configure(state=tk.NORMAL)
        self.txt.delete("1.0", END)
        append_simple_markdown(self.txt, chunk if chunk.endswith("\n") else chunk + "\n")
        self.txt.configure(state=tk.DISABLED)

    def _set_busy(self, busy: bool, msg: str = "") -> None:
        self._busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        self.btn_exec.configure(state=state)
        if busy:
            self.prog.start(10)
        else:
            self.prog.stop()
        self.lbl_task.configure(text=msg)

    def _ask_credentials(self, title: str, default_user: str = "") -> tuple[str, str] | None:
        dlg = _CredentialDialog(self, title=title, default_user=default_user)
        self.wait_window(dlg)
        return dlg.result

    def _confirm_write(self, message: str) -> bool:
        return messagebox.askyesno("确认", message, parent=self.winfo_toplevel())

    def _offer_reboot(self) -> None:
        if not messagebox.askyesno(
            "重启计算机",
            "操作已成功，需要重启计算机后完全生效。\n\n是否现在重启？\n（60 秒倒计时，可取消）",
            parent=self.winfo_toplevel(),
        ):
            return
        ok, msg = schedule_reboot(delay_sec=60)
        if ok:
            messagebox.showinfo(
                "重启",
                f"{msg}\n\n若要取消，请点击左侧「取消重启计划」或在 CMD 运行：shutdown /a",
                parent=self.winfo_toplevel(),
            )
        else:
            messagebox.showerror("重启", msg, parent=self.winfo_toplevel())

    def _on_cancel_reboot(self) -> None:
        ok, msg = cancel_scheduled_reboot()
        if ok:
            messagebox.showinfo("重启", msg, parent=self.winfo_toplevel())
        else:
            messagebox.showwarning("重启", msg, parent=self.winfo_toplevel())

    def _persist_settings(self) -> None:
        self._settings = DomainOpsSettings(
            default_domain_dns=self.var_domain_dns.get().strip() or self.var_probe_domain.get().strip(),
            default_workgroup=self.var_workgroup.get().strip() or "WORKGROUP",
        )
        save_domain_ops_settings(self._settings)

    def _on_execute(self) -> None:
        if self._busy:
            return
        if not is_windows():
            messagebox.showwarning("域与策略", "本模块仅支持 Windows。", parent=self.winfo_toplevel())
            return

        mode = self._mode
        if mode in ("gpupdate", "repair", "rename", "join", "unjoin") and not is_admin():
            messagebox.showwarning("域与策略", "请以管理员身份运行本程序。", parent=self.winfo_toplevel())
            return

        if mode == "diagnose":
            self._start_worker("diagnose", probe=self.var_probe_domain.get().strip())
            return

        if mode == "view_policy":
            scope = self.var_gp_scope.get()
            if scope not in ("both", "user", "computer"):
                scope = "both"
            self._start_worker("view_policy", scope=scope)
            return

        if mode == "gpupdate":
            if not self._confirm_write(
                "将强制刷新 **本机计算机策略** 与 **当前登录用户** 的组策略（gpupdate /force）。是否继续？"
            ):
                return
            self._start_worker("gpupdate")
            return

        if mode == "repair":
            if not self._confirm_write("将尝试修复域安全通道。是否继续？"):
                return
            cred = self._ask_credentials("域凭据（修复信任）")
            if not cred:
                return
            self._start_worker("repair", username=cred[0], password=cred[1])
            return

        if mode == "rename":
            new_name = self.var_new_name.get().strip()
            if not new_name:
                messagebox.showwarning("重命名", "请填写新计算机名。", parent=self.winfo_toplevel())
                return
            if not self._confirm_write(f"计算机将重命名为「{new_name}」，完成后必须重启。是否继续？"):
                return
            cred = None
            idn = fetch_domain_identity()
            if idn.part_of_domain:
                cred = self._ask_credentials("域凭据（重命名已入域计算机）")
                if not cred:
                    return
            self._start_worker(
                "rename",
                new_name=new_name,
                domain_username=cred[0] if cred else "",
                domain_password=cred[1] if cred else "",
            )
            return

        if mode == "join":
            domain = self.var_domain_dns.get().strip()
            post_user = self.var_post_join_user.get().strip()
            if not domain or not post_user:
                messagebox.showwarning("加域", "请填写域 DNS 名与 Power Users 用户。", parent=self.winfo_toplevel())
                return
            if not self._confirm_write(
                f"将加入域「{domain}」，并将 {post_user} 加入本地 Power Users。\n完成后必须重启。是否继续？"
            ):
                return
            cred = self._ask_credentials("域凭据（加域）")
            if not cred:
                return
            self._persist_settings()
            self._start_worker(
                "join",
                domain_dns=domain,
                join_username=cred[0],
                join_password=cred[1],
                post_join_user=post_user,
                ou_path=self.var_ou_path.get().strip(),
            )
            return

        if mode == "unjoin":
            if not self.var_unjoin_confirm.get():
                messagebox.showwarning(
                    "退域",
                    "请勾选「已确认本地管理员可用」后再执行。",
                    parent=self.winfo_toplevel(),
                )
                return
            if not self._confirm_write("退域后域账户将无法登录本机，且必须重启。此操作风险极高。是否继续？"):
                return
            cred = self._ask_credentials("域凭据（退域）")
            if not cred:
                return
            self._persist_settings()
            self._start_worker(
                "unjoin",
                unjoin_username=cred[0],
                unjoin_password=cred[1],
                workgroup=self.var_workgroup.get().strip() or "WORKGROUP",
            )

    def _start_worker(self, kind: str, **kwargs: object) -> None:
        self._set_busy(True, "执行中…")
        self._append_md(f"## 正在执行\n\n`{kind}` …\n")

        def worker() -> None:
            try:
                if kind == "diagnose":
                    result = run_domain_diagnosis(probe_domain_dns=str(kwargs.get("probe") or ""))
                    self._q.put(("diagnose_done", result))
                elif kind == "view_policy":
                    scope = str(kwargs.get("scope") or "both")
                    rep = run_gpresult(scope=scope)  # type: ignore[arg-type]
                    self._q.put(("gpresult_done", rep))
                elif kind == "gpupdate":
                    res = run_gpupdate()
                    self._q.put(("op_done", res))
                elif kind == "repair":
                    res = run_repair_trust(
                        username=str(kwargs["username"]),
                        password=str(kwargs["password"]),
                    )
                    self._q.put(("op_done", res))
                elif kind == "rename":
                    res = run_rename_computer(
                        new_name=str(kwargs["new_name"]),
                        domain_username=str(kwargs.get("domain_username") or ""),
                        domain_password=str(kwargs.get("domain_password") or ""),
                    )
                    self._q.put(("op_done", res))
                elif kind == "join":
                    res = run_join_domain(
                        domain_dns=str(kwargs["domain_dns"]),
                        join_username=str(kwargs["join_username"]),
                        join_password=str(kwargs["join_password"]),
                        post_join_user=str(kwargs["post_join_user"]),
                        ou_path=str(kwargs.get("ou_path") or ""),
                        local_group=self._settings.post_join_local_group,
                    )
                    self._q.put(("op_done", res))
                elif kind == "unjoin":
                    res = run_unjoin_domain(
                        unjoin_username=str(kwargs["unjoin_username"]),
                        unjoin_password=str(kwargs["unjoin_password"]),
                        workgroup=str(kwargs.get("workgroup") or "WORKGROUP"),
                    )
                    self._q.put(("op_done", res))
                else:
                    self._q.put(("error", f"未知操作：{kind}"))
            except Exception as e:
                _log.exception("域模块任务失败")
                self._q.put(("error", str(e)))

        self._worker = threading.Thread(target=worker, daemon=True)
        self._worker.start()

    def _handle_diagnose(self, result: DomainDiagnosisResult) -> None:
        self._last_report_dir = domain_ops_report_dir(result.task_id)
        self._last_gp_html = ""
        md = render_diagnosis_markdown(result)
        self._append_md(md)
        self._refresh_status()

    def _handle_gpresult(self, rep: GpResultReport) -> None:
        self._last_report_dir = domain_ops_report_dir(rep.task_id)
        self._last_gp_html = rep.html_path
        self._append_md(render_gpresult_markdown(rep))

    def _handle_operation(self, res: DomainOperationResult) -> None:
        self._last_report_dir = domain_ops_report_dir(res.task_id)
        from network_diagnosis.domain.report_md import render_operation_markdown

        self._append_md(render_operation_markdown(res))
        if res.success:
            if res.needs_reboot:
                self._offer_reboot()
            self._refresh_status()

    def _on_open_report_dir(self) -> None:
        if not self._last_report_dir or not self._last_report_dir.is_dir():
            messagebox.showinfo("域与策略", "暂无报告目录。", parent=self.winfo_toplevel())
            return
        path = str(self._last_report_dir.resolve())
        if sys.platform == "win32":
            subprocess.Popen(["explorer", path])  # noqa: S603
        else:
            webbrowser.open(path)

    def _on_open_gp_html(self) -> None:
        if not self._last_gp_html or not Path(self._last_gp_html).is_file():
            messagebox.showinfo("域与策略", "暂无 gpresult.html。", parent=self.winfo_toplevel())
            return
        webbrowser.open(Path(self._last_gp_html).resolve().as_uri())

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, *rest = self._q.get_nowait()
                if kind == "status":
                    self.lbl_status.configure(text=str(rest[0]))
                elif kind == "diagnose_done":
                    self._set_busy(False, f"完成。reports/domain_ops/{rest[0].task_id}/")
                    self._worker = None
                    self._handle_diagnose(rest[0])
                elif kind == "gpresult_done":
                    self._set_busy(False, f"完成。reports/domain_ops/{rest[0].task_id}/")
                    self._worker = None
                    self._handle_gpresult(rest[0])
                elif kind == "op_done":
                    self._set_busy(False, f"完成。reports/domain_ops/{rest[0].task_id}/")
                    self._worker = None
                    self._handle_operation(rest[0])
                elif kind == "error":
                    self._set_busy(False, "失败。")
                    self._worker = None
                    messagebox.showerror("域与策略", str(rest[0]), parent=self.winfo_toplevel())
        except queue.Empty:
            pass
        self.after(180, self._poll_queue)
