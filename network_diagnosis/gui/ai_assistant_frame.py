"""AI 助手页：大模型配置 + 对话（流式输出、skills、工具调用）。"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
import tkinter.font as tkfont
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
from typing import TYPE_CHECKING, Any

import ttkbootstrap as ttk
from ttkbootstrap.constants import DANGER, END, EW, INFO, NSEW, PRIMARY, SECONDARY, SUCCESS, W

from network_diagnosis.ai.agent import run_agent_chat
from network_diagnosis.ai.app_actions import AppActions
from network_diagnosis.ai.client import LlmClientError, test_connection
from network_diagnosis.ai.config import LlmConfig, load_llm_config, save_llm_config
from network_diagnosis.gui.simple_markdown_text import append_simple_markdown, configure_simple_markdown_tags
from network_diagnosis.paths import skills_root
from network_diagnosis.runtime_log import get_logger

if TYPE_CHECKING:
    from network_diagnosis.gui.main_app import NetworkDiagnosisApp

_log = get_logger(__name__)


class AiAssistantFrame(ttk.Frame):
    def __init__(self, master: tk.Misc, *, app: NetworkDiagnosisApp, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self._app = app
        self._actions = AppActions(app)
        self._q: queue.Queue[tuple[str, object]] = queue.Queue()
        self._chat_worker: threading.Thread | None = None
        self._messages: list[dict[str, Any]] = []
        self._stream_body_start: str | None = None
        self._stream_buffer: list[str] = []
        self._build_ui()
        self._load_config_into_form()
        self.after(200, self._poll_queue)

    def on_leave(self) -> None:
        pass

    def _build_ui(self) -> None:
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        lf_cfg = ttk.Labelframe(self, text="大模型配置(仅测试了DeepSeek模型，其他模型请自行配置)", padding=(12, 10, 12, 10))
        lf_cfg.grid(row=0, column=0, sticky=EW, padx=12, pady=(12, 8))
        lf_cfg.columnconfigure(1, weight=1)
        lf_cfg.columnconfigure(3, weight=1)

        ttk.Label(lf_cfg, text="API Base", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 8))
        self.var_api_base = tk.StringVar()
        ttk.Entry(lf_cfg, textvariable=self.var_api_base).grid(row=0, column=1, sticky=EW, padx=(0, 12))
        ttk.Label(lf_cfg, text="模型", bootstyle=SECONDARY).grid(row=0, column=2, sticky=W, padx=(0, 8))
        self.var_model = tk.StringVar()
        ttk.Entry(lf_cfg, textvariable=self.var_model, width=28).grid(row=0, column=3, sticky=EW)

        ttk.Label(lf_cfg, text="API Key", bootstyle=SECONDARY).grid(
            row=1, column=0, sticky=W, pady=(10, 0), padx=(0, 8)
        )
        self.var_api_key = tk.StringVar()
        ttk.Entry(lf_cfg, textvariable=self.var_api_key, show="*").grid(
            row=1, column=1, columnspan=3, sticky=EW, pady=(10, 0)
        )

        btn_row = ttk.Frame(lf_cfg)
        btn_row.grid(row=2, column=0, columnspan=4, sticky=W, pady=(12, 0))
        ttk.Button(btn_row, text="保存配置", command=self._on_save_config, bootstyle=PRIMARY).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(btn_row, text="测试连接", command=self._on_test_connection, bootstyle=INFO).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        skills_hint = str(skills_root())
        self.lbl_cfg_hint = ttk.Label(
            btn_row,
            text=f"OpenAI 兼容接口(DeepSeek/Qwen/Gemini/Kimi...) · Skills 目录：{skills_hint}",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 9),
        )
        self.lbl_cfg_hint.pack(side=tk.LEFT, padx=(8, 0))

        chat_outer = ttk.Frame(self, padding=(12, 0, 12, 12))
        chat_outer.grid(row=1, column=0, sticky=NSEW)
        chat_outer.rowconfigure(0, weight=1)
        chat_outer.columnconfigure(0, weight=1)

        lf_chat = ttk.Labelframe(chat_outer, text="与 AI 助手对话", padding=(10, 8, 10, 10))
        lf_chat.grid(row=0, column=0, sticky=NSEW)
        lf_chat.rowconfigure(0, weight=1)
        lf_chat.columnconfigure(0, weight=1)

        self.txt_chat = ScrolledText(
            lf_chat,
            wrap=tk.WORD,
            font=("Microsoft YaHei UI", 11),
            state=tk.DISABLED,
            height=20,
        )
        self.txt_chat.grid(row=0, column=0, sticky=NSEW)
        self.txt_chat.tag_configure("user", foreground="#268bd2")
        self.txt_chat.tag_configure("assistant_label", foreground="#2aa198", font=("Microsoft YaHei UI", 11, "bold"))
        self.txt_chat.tag_configure("system", foreground="#93a1a1", font=("Microsoft YaHei UI", 10, "italic"))
        self.txt_chat.tag_configure("error", foreground="#dc322f")
        self.txt_chat.tag_configure("status", foreground="#657b83", font=("Microsoft YaHei UI", 10))
        configure_simple_markdown_tags(
            self.txt_chat,
            base_font=("Microsoft YaHei UI", 11),
            theme_colors=ttk.Style().colors,
        )

        input_row = ttk.Frame(lf_chat)
        input_row.grid(row=1, column=0, sticky=EW, pady=(10, 0))
        input_row.columnconfigure(0, weight=1)

        input_wrap = ttk.Frame(input_row)
        input_wrap.grid(row=0, column=0, sticky=tk.N + tk.E + tk.W, padx=(0, 8))
        input_wrap.columnconfigure(0, weight=1)

        self.txt_input = ScrolledText(input_wrap, wrap=tk.WORD, height=2, font=("Microsoft YaHei UI", 11))
        self.txt_input.pack(fill=tk.BOTH, expand=False)
        self.txt_input.bind("<Return>", self._on_input_return)
        self.txt_input.bind("<Control-Return>", self._on_input_ctrl_return)

        self._btn_col = ttk.Frame(input_row)
        self._btn_col.grid(row=0, column=1, sticky=tk.N)
        self.btn_send = ttk.Button(
            self._btn_col, text="发送", command=self._on_send, bootstyle=SUCCESS, width=10
        )
        self.btn_send.pack(pady=(0, 6))
        ttk.Button(self._btn_col, text="清空对话", command=self._on_clear_chat, bootstyle=SECONDARY, width=10).pack()

        ttk.Label(
            input_row,
            text="Ctrl+Enter 换行",
            bootstyle=SECONDARY,
            font=("Microsoft YaHei UI", 9),
        ).grid(row=1, column=0, columnspan=2, sticky=W, pady=(4, 0))

        self.after_idle(self._sync_input_height_to_buttons)

        self.lbl_status = ttk.Label(lf_chat, text="请配置 API Key 后开始对话", bootstyle=SECONDARY)
        self.lbl_status.grid(row=2, column=0, sticky=W, pady=(8, 0))

        self._append_chat_line(
            "system",
            "你好！我是青丘狐网络工作台 AI 助手。配置好大模型后，可直接说：\n"
            "• 帮我诊断 www.example.com 的网络\n"
            "• 计算 192.168.1.10/24 的子网信息\n"
            "• 切换到网络诊断页面\n"
            "回复将实时流式显示。可在项目 skills/ 目录添加 SKILL.md，下一条消息起自动生效。",
        )

    def _sync_input_height_to_buttons(self, attempt: int = 0) -> None:
        """使消息输入框像素高度与右侧「发送 + 清空」按钮列一致。"""
        if attempt > 12:
            return
        try:
            self.update_idletasks()
            btn_h = int(self._btn_col.winfo_reqheight())
            if btn_h <= 4:
                self.after(40, lambda: self._sync_input_height_to_buttons(attempt + 1))
                return
            f = tkfont.Font(font=self.txt_input.cget("font"))
            line_h = max(f.metrics("linespace"), 1)
            border = 2 * int(float(self.txt_input.cget("borderwidth") or 0))
            # 纵向滚动条占用少量高度，略减一行避免输入框偏高
            lines = max(2, round((btn_h - border - 4) / line_h))
            self.txt_input.configure(height=lines)
        except tk.TclError:
            pass

    def _on_input_return(self, event: tk.Event) -> str:
        self._on_send()
        return "break"

    def _on_input_ctrl_return(self, event: tk.Event) -> str:
        self.txt_input.insert(tk.INSERT, "\n")
        return "break"

    def _config_from_form(self) -> LlmConfig:
        return LlmConfig(
            api_base=self.var_api_base.get().strip(),
            api_key=self.var_api_key.get().strip(),
            model=self.var_model.get().strip(),
        )

    def _load_config_into_form(self) -> None:
        cfg = load_llm_config()
        self.var_api_base.set(cfg.api_base)
        self.var_api_key.set(cfg.api_key)
        self.var_model.set(cfg.model)

    def _on_save_config(self) -> None:
        cfg = self._config_from_form()
        if not cfg.model.strip():
            messagebox.showwarning("配置", "请填写模型名称。", parent=self.winfo_toplevel())
            return
        save_llm_config(cfg)
        self.lbl_status.configure(text="配置已保存", bootstyle=SUCCESS)
        messagebox.showinfo("配置", "大模型配置已保存到本地。", parent=self.winfo_toplevel())

    def _on_test_connection(self) -> None:
        cfg = self._config_from_form()
        if not cfg.is_ready():
            messagebox.showwarning("测试连接", "请填写 API Key 与模型名称。", parent=self.winfo_toplevel())
            return
        self.lbl_status.configure(text="正在测试连接…", bootstyle=INFO)
        self.btn_send.configure(state=tk.DISABLED)

        def work() -> None:
            try:
                reply = test_connection(cfg)
                self._q.put(("test_ok", reply))
            except LlmClientError as e:
                self._q.put(("test_fail", str(e)))
            except Exception as e:
                _log.exception("测试连接异常")
                self._q.put(("test_fail", str(e)))

        threading.Thread(target=work, daemon=True).start()

    def _append_chat_line(self, role: str, text: str) -> None:
        self.txt_chat.configure(state=tk.NORMAL)
        body = text.rstrip()
        if role == "assistant":
            self.txt_chat.insert(END, "助手：\n", ("assistant_label",))
            if body:
                append_simple_markdown(self.txt_chat, body + "\n")
            self.txt_chat.insert(END, "\n")
        else:
            prefix = {"user": "你：", "system": "", "error": "错误：", "status": ""}.get(role, "")
            tag = role if role in ("user", "system", "error", "status") else "user"
            if prefix:
                self.txt_chat.insert(END, prefix + "\n", (tag,))
            if body:
                self.txt_chat.insert(END, body + "\n\n", (tag,))
            elif prefix:
                self.txt_chat.insert(END, "\n")
        self.txt_chat.see(END)
        self.txt_chat.configure(state=tk.DISABLED)

    def _begin_assistant_stream(self) -> None:
        self._stream_body_start = None
        self._stream_buffer = []
        self.txt_chat.configure(state=tk.NORMAL)
        self.txt_chat.insert(END, "助手：\n", ("assistant_label",))
        self._stream_body_start = self.txt_chat.index(END)
        self.txt_chat.see(END)
        self.txt_chat.configure(state=tk.DISABLED)

    def _append_assistant_stream_delta(self, piece: str) -> None:
        if not piece:
            return
        self._stream_buffer.append(piece)
        # 流式阶段先显示纯文本，结束后统一 Markdown 渲染
        self.txt_chat.configure(state=tk.NORMAL)
        self.txt_chat.insert(END, piece)
        self.txt_chat.see(END)
        self.txt_chat.configure(state=tk.DISABLED)

    def _end_assistant_stream(self) -> None:
        self.txt_chat.configure(state=tk.NORMAL)
        raw = "".join(self._stream_buffer)
        if self._stream_body_start:
            try:
                self.txt_chat.delete(self._stream_body_start, END)
            except tk.TclError:
                pass
            if raw.strip():
                append_simple_markdown(self.txt_chat, raw.rstrip() + "\n")
        self.txt_chat.insert(END, "\n")
        self.txt_chat.see(END)
        self.txt_chat.configure(state=tk.DISABLED)
        self._stream_body_start = None
        self._stream_buffer = []

    def _on_clear_chat(self) -> None:
        if self._chat_worker and self._chat_worker.is_alive():
            messagebox.showinfo("请稍候", "对话进行中，请等待完成。", parent=self.winfo_toplevel())
            return
        self._messages.clear()
        self.txt_chat.configure(state=tk.NORMAL)
        self.txt_chat.delete("1.0", END)
        self.txt_chat.configure(state=tk.DISABLED)
        self._append_chat_line("system", "对话已清空。可继续提问。")

    def _on_send(self) -> None:
        if self._chat_worker and self._chat_worker.is_alive():
            messagebox.showinfo("请稍候", "上一条消息仍在处理中。", parent=self.winfo_toplevel())
            return
        user_text = self.txt_input.get("1.0", END).strip()
        if not user_text:
            return
        cfg = self._config_from_form()
        if not cfg.is_ready():
            messagebox.showwarning("AI 助手", "请先配置并保存 API Key 与模型。", parent=self.winfo_toplevel())
            return

        self.txt_input.delete("1.0", END)
        self._append_chat_line("user", user_text)
        self._messages.append({"role": "user", "content": user_text})
        self.btn_send.configure(state=tk.DISABLED)
        self.lbl_status.configure(text="正在连接大模型…", bootstyle=INFO)

        def work() -> None:
            try:

                def on_status(s: str) -> None:
                    self._q.put(("status", s))

                def on_stream_start() -> None:
                    self._q.put(("stream_start", None))

                def on_delta(piece: str) -> None:
                    self._q.put(("stream_delta", piece))

                reply, updated = run_agent_chat(
                    cfg,
                    self._actions,
                    list(self._messages),
                    on_status=on_status,
                    on_delta=on_delta,
                    on_stream_start=on_stream_start,
                )
                self._q.put(("chat_done", (reply, updated)))
            except LlmClientError as e:
                self._q.put(("chat_fail", str(e)))
            except Exception as e:
                _log.exception("AI 对话异常")
                self._q.put(("chat_fail", str(e)))

        self._chat_worker = threading.Thread(target=work, daemon=True)
        self._chat_worker.start()

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "status":
                    self.lbl_status.configure(text=str(payload), bootstyle=INFO)
                elif kind == "stream_start":
                    self._begin_assistant_stream()
                    self.lbl_status.configure(text="正在接收回复…", bootstyle=INFO)
                elif kind == "stream_delta":
                    self._append_assistant_stream_delta(str(payload))
                elif kind == "test_ok":
                    self.btn_send.configure(state=tk.NORMAL)
                    self.lbl_status.configure(text="连接测试成功", bootstyle=SUCCESS)
                    messagebox.showinfo("测试连接", f"连接成功。\n\n模型回复：\n{payload}", parent=self.winfo_toplevel())
                elif kind == "test_fail":
                    self.btn_send.configure(state=tk.NORMAL)
                    self.lbl_status.configure(text="连接测试失败", bootstyle=DANGER)
                    messagebox.showerror("测试连接", str(payload), parent=self.winfo_toplevel())
                elif kind == "chat_done":
                    reply, updated = payload  # type: ignore[misc]
                    self._messages = list(updated)
                    if self._stream_body_start is not None:
                        self._end_assistant_stream()
                    elif str(reply).strip():
                        self._append_chat_line("assistant", str(reply))
                    self.lbl_status.configure(text="就绪", bootstyle=SECONDARY)
                    self.btn_send.configure(state=tk.NORMAL)
                elif kind == "chat_fail":
                    if self._stream_body_start is not None:
                        self._end_assistant_stream()
                    self._append_chat_line("error", str(payload))
                    self.lbl_status.configure(text="请求失败", bootstyle=DANGER)
                    self.btn_send.configure(state=tk.NORMAL)
        except queue.Empty:
            pass
        self.after(50, self._poll_queue)
