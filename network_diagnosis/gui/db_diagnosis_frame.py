"""数据库诊断页：多引擎连接、完整诊断（Markdown）、实时监控。"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import uuid
from datetime import datetime
from pathlib import Path
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText

import ttkbootstrap as ttk
from ttkbootstrap.constants import DANGER, EW, INFO, NSEW, PRIMARY, SECONDARY, SUCCESS, WARNING, W

from network_diagnosis.db_diagnosis.markdown_report import render_monitor_snapshot_markdown
from network_diagnosis.db_diagnosis.model import DbDiagnosisReport
from network_diagnosis.db_diagnosis.runner import DbConnectConfig, run_full_diagnosis
from network_diagnosis.db_diagnosis.snapshot import collect_monitor_snapshot
from network_diagnosis.gui.main_app_common import fix_primary_notebook_selected_tab_colors
from network_diagnosis.gui.simple_markdown_text import append_simple_markdown, configure_simple_markdown_tags
from network_diagnosis.paths import db_diagnosis_report_dir
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)


class DbDiagnosisFrame(ttk.Frame):
    def __init__(self, master: tk.Misc, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self._q: queue.Queue[tuple[str, object]] = queue.Queue()
        self._diag_worker: threading.Thread | None = None
        self._mon_stop = threading.Event()
        self._mon_worker: threading.Thread | None = None
        self._last_report_dir: str | None = None
        self._last_md_path: str | None = None
        self._monitor_chunks: list[str] = []
        self._mon_started: datetime | None = None
        self._build_ui()
        self.after(200, self._poll_queue)

    def on_leave(self) -> None:
        self._stop_monitor()

    def _build_ui(self) -> None:
        self.rowconfigure(2, weight=1)
        self.columnconfigure(0, weight=1)

        top = ttk.Frame(self, padding=(12, 12, 12, 8))
        top.grid(row=0, column=0, sticky=EW)
        top.columnconfigure(1, weight=0)
        top.columnconfigure(3, weight=1)
        top.columnconfigure(5, weight=1)

        ctl_w = 18

        ttk.Label(top, text="引擎", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 8))
        self.var_engine = tk.StringVar(value="mysql")
        self.cmb_engine = ttk.Combobox(
            top,
            textvariable=self.var_engine,
            values=["sqlite", "mysql", "postgresql", "sqlserver", "oracle"],
            width=ctl_w,
            state="readonly",
        )
        self.cmb_engine.grid(row=0, column=1, sticky=W)
        self.cmb_engine.bind("<<ComboboxSelected>>", lambda _e: self._sync_engine_hints())

        ttk.Label(top, text="主机 / 路径", bootstyle=SECONDARY).grid(row=0, column=2, sticky=W, padx=(16, 6))
        self.var_host = tk.StringVar(value="127.0.0.1")
        ttk.Entry(top, textvariable=self.var_host).grid(row=0, column=3, sticky=EW, padx=(0, 10))
        ttk.Label(top, text="端口", bootstyle=SECONDARY).grid(row=0, column=4, sticky=W, padx=(0, 6))
        self.var_port = tk.IntVar(value=3306)
        self.sp_port = ttk.Spinbox(top, from_=0, to=65535, textvariable=self.var_port, width=8)
        self.sp_port.grid(row=0, column=5, sticky=W)

        ttk.Label(top, text="用户名", bootstyle=SECONDARY).grid(row=1, column=0, sticky=W, pady=(10, 0), padx=(0, 8))
        self.var_user = tk.StringVar(value="root")
        ttk.Entry(top, textvariable=self.var_user, width=ctl_w).grid(
            row=1, column=1, sticky=W, pady=(10, 0), padx=(0, 10)
        )
        ttk.Label(top, text="密码", bootstyle=SECONDARY).grid(row=1, column=2, sticky=W, pady=(10, 0), padx=(16, 6))
        self.var_pass = tk.StringVar(value="asd123")
        ttk.Entry(top, textvariable=self.var_pass, show="*").grid(
            row=1, column=3, sticky=EW, pady=(10, 0), padx=(0, 10)
        )
        ttk.Label(top, text="库名 / Service", bootstyle=SECONDARY).grid(
            row=1, column=4, sticky=W, pady=(10, 0), padx=(0, 6)
        )
        self.var_db = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.var_db).grid(row=1, column=5, sticky=EW, pady=(10, 0))

        self.lbl_db_hint = ttk.Label(
            top,
            text="",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 9),
            wraplength=0,
            justify=tk.LEFT,
        )
        self.lbl_db_hint.grid(row=2, column=0, columnspan=6, sticky=W, pady=(8, 0))

        btnf = ttk.Frame(self, padding=(12, 0, 12, 8))
        btnf.grid(row=1, column=0, sticky=EW)
        self.btn_diag = ttk.Button(btnf, text="运行诊断（生成 Markdown）", command=self._on_diagnose, bootstyle=SUCCESS)
        self.btn_diag.pack(side=tk.LEFT, padx=(0, 8))
        self.btn_toggle_monitor = ttk.Button(
            btnf, text="开始监控", command=self._on_toggle_monitor, bootstyle=PRIMARY
        )
        self.btn_toggle_monitor.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(btnf, text="间隔(秒)", bootstyle=SECONDARY).pack(side=tk.LEFT, padx=(8, 4))
        self.var_interval = tk.IntVar(value=5)
        ttk.Spinbox(btnf, from_=1, to=120, textvariable=self.var_interval, width=5).pack(side=tk.LEFT, padx=(0, 8))
        self.btn_open_dir = ttk.Button(btnf, text="打开报告目录", command=self._open_report_dir, bootstyle=INFO)
        self.btn_open_dir.pack(side=tk.LEFT, padx=(0, 8))
        self.btn_open_md = ttk.Button(
            btnf, text="打开上次报告", command=self._open_last_md, bootstyle=SECONDARY, state=tk.DISABLED
        )
        self.btn_open_md.pack(side=tk.LEFT)

        self.lbl_status = ttk.Label(btnf, text="就绪", bootstyle=SECONDARY)
        self.lbl_status.pack(side=tk.RIGHT, padx=(12, 0))

        nb = ttk.Notebook(self, bootstyle=PRIMARY)
        nb.grid(row=2, column=0, sticky=NSEW, padx=12, pady=(0, 12))
        tab_d = ttk.Frame(nb, padding=6)
        tab_m = ttk.Frame(nb, padding=6)
        nb.add(tab_d, text="诊断输出")
        nb.add(tab_m, text="实时监控")
        tab_d.rowconfigure(0, weight=1)
        tab_d.columnconfigure(0, weight=1)
        tab_m.rowconfigure(0, weight=1)
        tab_m.columnconfigure(0, weight=1)

        self.txt_diag = ScrolledText(tab_d, height=18, wrap=tk.WORD, font=("Microsoft YaHei UI", 10))
        self.txt_diag.grid(row=0, column=0, sticky=NSEW)
        configure_simple_markdown_tags(
            self.txt_diag,
            base_font=("Microsoft YaHei UI", 10),
            theme_colors=ttk.Style().colors,
        )
        self.txt_mon = ScrolledText(tab_m, height=18, wrap=tk.WORD, font=("Consolas", 10))
        self.txt_mon.grid(row=0, column=0, sticky=NSEW)

        self._sync_engine_hints()
        fix_primary_notebook_selected_tab_colors(nb)

    def _render_diag_md(self, md: str) -> None:
        self.txt_diag.configure(state=tk.NORMAL)
        self.txt_diag.delete("1.0", tk.END)
        append_simple_markdown(self.txt_diag, md if md.endswith("\n") else md + "\n")
        self.txt_diag.see(tk.END)

    def _fallback_diag_preview_md(self, rep: DbDiagnosisReport) -> str:
        lines_md: list[str] = [
            f"- **任务 ID**：{rep.task_id}",
            f"- **版本摘要**：{rep.version_line}",
            f"- **Markdown**：{self._last_md_path or '—'}",
            "",
        ]
        if rep.errors:
            lines_md.append("## 告警 / 错误")
            for err in rep.errors:
                lines_md.append(f"- {err}")
            lines_md.append("")
        lines_md.append("## 章节预览")
        lines_md.append("")
        for t, body in rep.sections.items():
            lines_md.append(f"### {t}")
            lines_md.append("")
            snippet = body[:800] + ("…" if len(body) > 800 else "")
            lines_md.append(snippet)
            lines_md.append("")
        return "\n".join(lines_md).rstrip() + "\n"

    def _sync_monitor_toggle_idle(self) -> None:
        self.btn_toggle_monitor.configure(text="开始监控", bootstyle=PRIMARY, state=tk.NORMAL)

    def _sync_engine_hints(self) -> None:
        eng = self.var_engine.get().lower()
        ports = {
            "sqlite": 0,
            "mysql": 3306,
            "postgresql": 5432,
            "sqlserver": 1433,
            "oracle": 1521,
        }
        self.var_port.set(ports.get(eng, 0))
        if eng == "sqlite":
            self.lbl_db_hint.configure(
                text="SQLite：在「主机」或「库名」填写 .db / .sqlite 文件完整路径；用户名密码可留空。"
            )
            self.sp_port.configure(state=tk.DISABLED)
        else:
            self.lbl_db_hint.configure(
                text=(
                    "MySQL/PostgreSQL/SQL Server/Oracle：填写可达主机与库名；"
                    "SQL Server 需本机 ODBC 驱动；Oracle「库名」填 Service Name。"
                )
            )
            self.sp_port.configure(state=tk.NORMAL)

    def _cfg(self) -> DbConnectConfig:
        return DbConnectConfig(
            engine=self.var_engine.get().strip(),
            host=self.var_host.get().strip(),
            port=int(self.var_port.get()),
            user=self.var_user.get(),
            password=self.var_pass.get(),
            database=self.var_db.get().strip(),
        )

    def _on_diagnose(self) -> None:
        if self._diag_worker and self._diag_worker.is_alive():
            messagebox.showinfo("请稍候", "诊断任务仍在运行。")
            return
        try:
            cfg = self._cfg()
            if cfg.engine == "sqlite":
                if not (cfg.host or cfg.database):
                    raise ValueError("SQLite 请填写数据库文件路径。")
            elif not cfg.host:
                raise ValueError("请填写主机。")
            elif cfg.engine in ("postgresql", "sqlserver", "oracle") and not cfg.database:
                raise ValueError("请填写库名 / 服务名。")
        except ValueError as e:
            messagebox.showwarning("校验", str(e))
            return

        _log.info(
            "数据库诊断开始 engine=%s host=%s port=%s database=%s user=%s",
            cfg.engine,
            cfg.host,
            cfg.port,
            cfg.database or "",
            cfg.user or "",
        )

        self.btn_diag.configure(state=tk.DISABLED)
        self.lbl_status.configure(text="正在诊断…", bootstyle=WARNING)
        self._render_diag_md("> 正在连接并执行只读采集…")

        cfg = self._cfg()

        def work() -> None:
            try:
                rep = run_full_diagnosis(cfg)
                self._q.put(("diag_done", rep))
            except Exception as e:
                _log.exception(
                    "数据库诊断失败 engine=%s host=%s",
                    cfg.engine,
                    cfg.host,
                )
                self._q.put(("diag_err", str(e)))

        self._diag_worker = threading.Thread(target=work, daemon=True)
        self._diag_worker.start()

    def _on_toggle_monitor(self) -> None:
        if self._mon_worker and self._mon_worker.is_alive():
            self._stop_monitor()
        else:
            self._on_start_monitor()

    def _on_start_monitor(self) -> None:
        if self._mon_worker and self._mon_worker.is_alive():
            return
        try:
            cfg = self._cfg()
            if cfg.engine == "sqlite":
                if not (cfg.host or cfg.database):
                    raise ValueError("SQLite 请填写路径。")
            elif not cfg.host:
                raise ValueError("请填写主机。")
            if cfg.engine in ("postgresql", "sqlserver", "oracle") and not cfg.database:
                raise ValueError("请填写库名 / 服务名。")
        except ValueError as e:
            messagebox.showwarning("校验", str(e))
            return

        self._mon_stop.clear()
        self._monitor_chunks.clear()
        self._mon_started = datetime.now()
        self.txt_mon.delete("1.0", tk.END)
        self.btn_toggle_monitor.configure(text="停止监控", bootstyle=WARNING, state=tk.NORMAL)
        self.lbl_status.configure(text="监控中…", bootstyle=INFO)

        interval = max(1, int(self.var_interval.get()))
        cfg = self._cfg()

        _log.info(
            "数据库监控开始 engine=%s host=%s port=%s interval_sec=%s",
            cfg.engine,
            cfg.host,
            cfg.port,
            interval,
        )

        def mon_loop() -> None:
            from network_diagnosis.db_diagnosis.connection import open_database_connection

            while not self._mon_stop.is_set():
                conn = None
                try:
                    conn = open_database_connection(
                        cfg.engine,
                        cfg.host,
                        cfg.port,
                        cfg.user,
                        cfg.password,
                        cfg.database,
                        timeout_sec=8,
                    )
                    snap = collect_monitor_snapshot(cfg.engine, conn)
                    self._q.put(("mon_snap", (snap, datetime.now())))
                except Exception as e:
                    _log.warning("数据库监控采样异常", exc_info=True)
                    self._q.put(("mon_err", str(e)))
                finally:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass
                if self._mon_stop.wait(timeout=interval):
                    break
            self._q.put(("mon_end", None))

        self._mon_worker = threading.Thread(target=mon_loop, daemon=True)
        self._mon_worker.start()

    def _stop_monitor(self) -> None:
        self._mon_stop.set()
        self._sync_monitor_toggle_idle()
        if self._mon_worker is not None and self._mon_worker.is_alive():
            self.lbl_status.configure(text="正在停止监控…", bootstyle=WARNING)
        else:
            self.lbl_status.configure(text="就绪", bootstyle=SECONDARY)

    def _write_monitor_session_markdown(self) -> Path | None:
        """将本轮 `_monitor_chunks` 写入 ``reports/db_diagnosis/<任务ID>/``；无成功采样则跳过。"""
        if not self._monitor_chunks:
            return None
        tid = datetime.now().strftime("%Y%m%d-%H%M%S") + "-mon-" + uuid.uuid4().hex[:6]
        d = db_diagnosis_report_dir(tid)
        path = d / f"db-monitor_{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
        cfg = self._cfg()
        body = render_monitor_snapshot_markdown(
            engine=cfg.engine,
            host_hint=cfg.host if cfg.engine != "sqlite" else "",
            db_hint=cfg.database or cfg.host,
            interval_sec=max(1, int(self.var_interval.get())),
            chunks=list(self._monitor_chunks),
            started=self._mon_started or datetime.now(),
            ended=datetime.now(),
        )
        path.write_text(body, encoding="utf-8")
        _log.info("数据库监控已自动生成 Markdown path=%s report_dir=%s", path, d)
        self._last_report_dir = str(d.resolve())
        self._last_md_path = str(path.resolve())
        try:
            self.btn_open_md.configure(state=tk.NORMAL)
        except tk.TclError:
            pass
        return path

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "diag_done":
                    self._apply_diag_done(payload)  # type: ignore[arg-type]
                elif kind == "diag_err":
                    self._apply_diag_err(str(payload))
                elif kind == "mon_snap":
                    snap, _ts = payload  # type: ignore[misc]
                    self._apply_mon_snap(str(snap))
                elif kind == "mon_err":
                    self.txt_mon.insert(tk.END, f"[错误] {payload}\n")
                    self.txt_mon.see(tk.END)
                elif kind == "mon_end":
                    self.txt_mon.insert(tk.END, "\n--- 监控已结束 ---\n")
                    self.txt_mon.see(tk.END)
                    saved = self._write_monitor_session_markdown()
                    if saved is not None:
                        self.txt_mon.insert(tk.END, f"\n（已自动生成 Markdown：`{saved}`）\n")
                        self.txt_mon.see(tk.END)
                        self.lbl_status.configure(text="监控已结束，Markdown 已保存", bootstyle=SUCCESS)
                    else:
                        self.txt_mon.insert(tk.END, "\n（本轮无成功采样，未生成 Markdown。）\n")
                        self.txt_mon.see(tk.END)
                        self.lbl_status.configure(text="监控已结束", bootstyle=SECONDARY)
                    self._sync_monitor_toggle_idle()
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)

    def _apply_diag_done(self, rep: object) -> None:
        assert isinstance(rep, DbDiagnosisReport)
        self.btn_diag.configure(state=tk.NORMAL)
        self.lbl_status.configure(text="诊断完成", bootstyle=SUCCESS)
        p = rep.markdown_path
        self._last_md_path = str(p.resolve()) if p else None
        self._last_report_dir = str(rep.report_dir.resolve()) if rep.report_dir else None
        _log.info(
            "数据库诊断完成 task_id=%s markdown=%s",
            rep.task_id,
            self._last_md_path or "",
        )
        if p:
            self.btn_open_md.configure(state=tk.NORMAL)
        if p and p.is_file():
            try:
                self._render_diag_md(p.read_text(encoding="utf-8"))
            except OSError:
                _log.warning("读取诊断 Markdown 失败 path=%s", p, exc_info=True)
                self._render_diag_md(self._fallback_diag_preview_md(rep))
        else:
            self._render_diag_md(self._fallback_diag_preview_md(rep))

    def _apply_diag_err(self, msg: str) -> None:
        self.btn_diag.configure(state=tk.NORMAL)
        self.lbl_status.configure(text="诊断失败", bootstyle=DANGER)
        _log.error("数据库诊断界面提示失败: %s", msg)
        safe = msg.replace("```", "'''")
        self._render_diag_md(f"## 诊断失败\n\n```\n{safe}\n```\n")

    def _apply_mon_snap(self, snap: str) -> None:
        self._monitor_chunks.append(snap)
        self.txt_mon.insert(tk.END, snap + "\n\n")
        self.txt_mon.see(tk.END)

    def _open_report_dir(self) -> None:
        d = self._last_report_dir
        if not d:
            messagebox.showinfo("打开目录", "尚无报告目录，请先运行诊断或完成一轮监控（结束后会自动生成报告）。")
            return
        self._startfile(d)

    def _open_last_md(self) -> None:
        p = self._last_md_path
        if not p:
            return
        self._startfile(p)

    @staticmethod
    def _startfile(path: str) -> None:
        try:
            if sys.platform == "win32":
                os.startfile(path)  # noqa: S606
            else:
                subprocess.Popen(["xdg-open", path])  # noqa: S603, S607
        except OSError as e:
            messagebox.showerror("打开失败", str(e))
