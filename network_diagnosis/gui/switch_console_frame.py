"""交换机配置页：串口 Console 与 SSH PTY。"""

from __future__ import annotations

import queue
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

import ttkbootstrap as ttk
from ttkbootstrap.constants import DANGER, EW, NSEW, SECONDARY, SUCCESS, WARNING, W

from network_diagnosis.switch_console.session import (
    SerialBackend,
    SSHPtyBackend,
    SwitchConsoleSession,
    iter_serial_port_labels,
)


class SwitchConsoleFrame(ttk.Frame):
    """左右可忽略：顶栏表单 + 下方终端区。"""

    def __init__(self, master: tk.Misc, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self._session: SwitchConsoleSession | None = None
        self._backend: object | None = None
        self._out_q: queue.Queue[bytes | None] = queue.Queue()
        self._drain_after: str | None = None
        self._connect_mode = tk.StringVar(value="serial")
        self._build_ui()

    def on_leave(self) -> None:
        """离开本页时断开，避免占用串口或 SSH。"""
        self._disconnect()

    def _build_ui(self) -> None:
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        top = ttk.Frame(self, padding=(12, 12, 12, 10))
        top.grid(row=0, column=0, sticky=EW)
        top.columnconfigure(0, weight=1)

        mode_row = ttk.Frame(top)
        mode_row.grid(row=0, column=0, sticky=EW, pady=(0, 10))
        ttk.Radiobutton(
            mode_row,
            text="串口 (COM)",
            variable=self._connect_mode,
            value="serial",
            command=self._sync_mode_panels,
        ).pack(side=tk.LEFT, padx=(0, 16))
        ttk.Radiobutton(
            mode_row,
            text="SSH (PTY)",
            variable=self._connect_mode,
            value="ssh",
            command=self._sync_mode_panels,
        ).pack(side=tk.LEFT)

        self._frm_serial = ttk.Frame(top)
        self._frm_ssh = ttk.Frame(top)

        self.var_port = tk.StringVar(value="COM1")
        self.var_baud = tk.IntVar(value=9600)
        self.var_bytesize = tk.IntVar(value=8)
        self.var_parity = tk.StringVar(value="N")
        self.var_stopbits = tk.IntVar(value=1)
        self.var_xonxoff = tk.BooleanVar(value=False)
        self.var_rtscts = tk.BooleanVar(value=False)
        self.var_local_echo = tk.BooleanVar(value=False)

        sf = self._frm_serial
        r0 = ttk.Frame(sf)
        r0.grid(row=0, column=0, sticky=EW)
        ttk.Label(r0, text="端口", bootstyle=SECONDARY).pack(side=tk.LEFT)
        self.cmb_port = ttk.Combobox(r0, textvariable=self.var_port, width=18)
        self.cmb_port.pack(side=tk.LEFT, padx=(6, 10))
        ttk.Button(r0, text="刷新端口列表", command=self._refresh_ports, bootstyle=SECONDARY).pack(
            side=tk.LEFT, padx=(0, 16)
        )
        ttk.Label(r0, text="波特率", bootstyle=SECONDARY).pack(side=tk.LEFT)
        ttk.Spinbox(r0, from_=300, to=921600, increment=300, textvariable=self.var_baud, width=10).pack(
            side=tk.LEFT, padx=(4, 12)
        )
        ttk.Label(r0, text="数据位", bootstyle=SECONDARY).pack(side=tk.LEFT)
        ttk.Spinbox(r0, from_=5, to=8, textvariable=self.var_bytesize, width=6).pack(
            side=tk.LEFT, padx=(4, 12)
        )
        ttk.Label(r0, text="校验", bootstyle=SECONDARY).pack(side=tk.LEFT)
        ttk.Combobox(
            r0,
            textvariable=self.var_parity,
            values=["N", "E", "O", "M", "S"],
            width=5,
            state="readonly",
        ).pack(side=tk.LEFT, padx=(4, 12))
        ttk.Label(r0, text="停止位", bootstyle=SECONDARY).pack(side=tk.LEFT)
        ttk.Spinbox(r0, from_=1, to=2, textvariable=self.var_stopbits, width=5).pack(
            side=tk.LEFT, padx=(4, 0)
        )

        row1 = ttk.Frame(sf)
        row1.grid(row=1, column=0, sticky=W, pady=(8, 0))
        ttk.Checkbutton(row1, text="XON/XOFF", variable=self.var_xonxoff, bootstyle="round-toggle").pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Checkbutton(row1, text="RTS/CTS", variable=self.var_rtscts, bootstyle="round-toggle").pack(
            side=tk.LEFT
        )

        self.var_ssh_host = tk.StringVar(value="")
        self.var_ssh_port = tk.IntVar(value=22)
        self.var_ssh_user = tk.StringVar(value="")
        self.var_ssh_pass = tk.StringVar(value="")
        self.var_ssh_key = tk.StringVar(value="")
        self.var_ssh_key_pass = tk.StringVar(value="")
        self.var_ssh_term = tk.StringVar(value="xterm")
        self.var_ssh_cols = tk.IntVar(value=120)
        self.var_ssh_rows = tk.IntVar(value=36)

        z = self._frm_ssh
        z.columnconfigure(0, weight=1)

        ssh_row1 = ttk.Frame(z)
        ssh_row1.grid(row=0, column=0, sticky=EW)
        ssh_row1.columnconfigure(1, weight=2)
        ssh_row1.columnconfigure(5, weight=1)
        ssh_row1.columnconfigure(7, weight=1)
        ttk.Label(ssh_row1, text="主机", bootstyle=SECONDARY).grid(row=0, column=0, sticky=W, padx=(0, 6))
        ttk.Entry(ssh_row1, textvariable=self.var_ssh_host).grid(
            row=0, column=1, sticky=EW, padx=(0, 10)
        )
        ttk.Label(ssh_row1, text="端口", bootstyle=SECONDARY).grid(row=0, column=2, sticky=W, padx=(0, 6))
        ttk.Spinbox(ssh_row1, from_=1, to=65535, textvariable=self.var_ssh_port, width=7).grid(
            row=0, column=3, sticky=W, padx=(0, 14)
        )
        ttk.Label(ssh_row1, text="用户名", bootstyle=SECONDARY).grid(row=0, column=4, sticky=W, padx=(0, 6))
        ttk.Entry(ssh_row1, textvariable=self.var_ssh_user).grid(
            row=0, column=5, sticky=EW, padx=(0, 10)
        )
        ttk.Label(ssh_row1, text="密码", bootstyle=SECONDARY).grid(row=0, column=6, sticky=W, padx=(0, 6))
        ttk.Entry(ssh_row1, textvariable=self.var_ssh_pass, show="*").grid(
            row=0, column=7, sticky=EW
        )

        ssh_row2 = ttk.Frame(z)
        ssh_row2.grid(row=1, column=0, sticky=EW, pady=(8, 0))
        ssh_row2.columnconfigure(1, weight=2)
        ssh_row2.columnconfigure(3, weight=1)
        ttk.Label(ssh_row2, text="私钥路径（可选）", bootstyle=SECONDARY).grid(
            row=0, column=0, sticky=W, padx=(0, 6)
        )
        kf = ttk.Frame(ssh_row2)
        kf.grid(row=0, column=1, sticky=EW, padx=(0, 14))
        kf.columnconfigure(0, weight=1)
        ttk.Entry(kf, textvariable=self.var_ssh_key).grid(row=0, column=0, sticky=EW)
        ttk.Button(kf, text="浏览…", command=self._browse_key, bootstyle=SECONDARY, width=8).grid(
            row=0, column=1, padx=(8, 0)
        )
        ttk.Label(ssh_row2, text="私钥口令", bootstyle=SECONDARY).grid(row=0, column=2, sticky=W, padx=(0, 6))
        ttk.Entry(ssh_row2, textvariable=self.var_ssh_key_pass, show="*").grid(
            row=0, column=3, sticky=EW, padx=(0, 14)
        )
        ttk.Label(ssh_row2, text="TERM", bootstyle=SECONDARY).grid(row=0, column=4, sticky=W, padx=(0, 6))
        ttk.Combobox(
            ssh_row2,
            textvariable=self.var_ssh_term,
            values=["xterm", "xterm-256color", "vt100", "linux"],
            width=18,
        ).grid(row=0, column=5, sticky=W, padx=(0, 10))
        ttk.Label(ssh_row2, text="PTY 列", bootstyle=SECONDARY).grid(row=0, column=6, sticky=W, padx=(0, 6))
        ttk.Spinbox(ssh_row2, from_=40, to=300, textvariable=self.var_ssh_cols, width=6).grid(
            row=0, column=7, sticky=W, padx=(0, 10)
        )
        ttk.Label(ssh_row2, text="行", bootstyle=SECONDARY).grid(row=0, column=8, sticky=W, padx=(0, 6))
        ttk.Spinbox(ssh_row2, from_=10, to=100, textvariable=self.var_ssh_rows, width=6).grid(
            row=0, column=9, sticky=W
        )

        btn_row = ttk.Frame(top)
        btn_row.grid(row=4, column=0, sticky=EW, pady=(12, 0))
        self.btn_connect = ttk.Button(
            btn_row,
            text="连接",
            command=self._connect,
            bootstyle=SUCCESS,
            width=10,
        )
        self.btn_connect.pack(side=tk.LEFT, padx=(0, 10))
        self.btn_disconnect = ttk.Button(
            btn_row,
            text="断开",
            command=self._disconnect,
            bootstyle=WARNING,
            width=10,
            state=tk.DISABLED,
        )
        self.btn_disconnect.pack(side=tk.LEFT, padx=(0, 10))
        self.lbl_switch_status = ttk.Label(btn_row, text="未连接", bootstyle=SECONDARY)
        self.lbl_switch_status.pack(side=tk.LEFT, padx=(8, 0))

        echo_row = ttk.Frame(top)
        echo_row.grid(row=5, column=0, sticky=W, pady=(8, 0))
        self.chk_echo = ttk.Checkbutton(
            echo_row,
            text="串口本地回显（设备不回显输入时勾选；SSH 一般勿用）",
            variable=self.var_local_echo,
            bootstyle="round-toggle",
        )
        self.chk_echo.pack(side=tk.LEFT)

        lf_term = ttk.Labelframe(self, text="终端", padding=(8, 8, 8, 8))
        lf_term.grid(row=1, column=0, sticky=NSEW, padx=12, pady=(0, 12))
        lf_term.rowconfigure(0, weight=1)
        lf_term.columnconfigure(0, weight=1)

        self.txt_term = ScrolledText(
            lf_term,
            height=22,
            wrap=tk.NONE,
            font=("Consolas", 11),
            relief=tk.FLAT,
            padx=8,
            pady=8,
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="#d4d4d4",
        )
        self.txt_term.grid(row=0, column=0, sticky=NSEW)
        hint = (
            "操作说明：连接后在下方黑色区域按键输入；Enter 发送回车。\n"
            "Ctrl+C 发送中断；Ctrl+V / 右键菜单可粘贴（部分终端需用菜单粘贴）。\n"
            "未知 SSH 主机密钥将写入程序目录下 switch_console/ssh_known_hosts。\n"
        )
        self.txt_term.insert(tk.END, hint)
        self.txt_term.see(tk.END)

        self.txt_term.bind("<KeyPress>", self._on_term_key)
        self.txt_term.bind("<<Paste>>", self._on_term_paste)
        self._term_context = tk.Menu(self.txt_term, tearoff=0)
        self._term_context.add_command(label="粘贴", command=self._paste_from_clipboard)
        self.txt_term.bind("<Button-3>", self._term_b3)

        self._refresh_ports()
        self._sync_mode_panels()

    def _term_b3(self, event: tk.Event) -> str | None:
        try:
            self._term_context.tk_popup(event.x_root, event.y_root)
        finally:
            self._term_context.grab_release()
        return "break"

    def _browse_key(self) -> None:
        p = filedialog.askopenfilename(title="选择私钥文件")
        if p:
            self.var_ssh_key.set(p)

    def _sync_mode_panels(self) -> None:
        self._frm_serial.grid_remove()
        self._frm_ssh.grid_remove()
        if self._connect_mode.get() == "serial":
            self._frm_serial.grid(row=3, column=0, sticky=EW, pady=(8, 0))
            self.chk_echo.configure(state=tk.NORMAL)
        else:
            self._frm_ssh.grid(row=3, column=0, sticky=EW, pady=(8, 0))
            self.var_local_echo.set(False)
            self.chk_echo.configure(state=tk.DISABLED)

    def _refresh_ports(self) -> None:
        labels = iter_serial_port_labels()
        if labels:
            self.cmb_port["values"] = [lab for _dev, lab in labels]
            cur = self.var_port.get().strip()
            if " — " in cur:
                cur_dev = cur.split(" — ", 1)[0].strip()
            else:
                cur_dev = cur
            devs = {d for d, _ in labels}
            if cur_dev not in devs:
                self.var_port.set(labels[0][1])
            else:
                for d, lab in labels:
                    if d == cur_dev:
                        self.var_port.set(lab)
                        break
        else:
            self.cmb_port["values"] = []

    def _connect(self) -> None:
        if self._session is not None:
            return
        mode = self._connect_mode.get()
        try:
            if mode == "serial":
                self._connect_serial()
            else:
                self._connect_ssh()
        except Exception as e:
            self._append_notice(f"\r\n[连接失败] {e}\r\n")
            self.lbl_switch_status.configure(text="连接失败", bootstyle=DANGER)
            messagebox.showerror("交换机 Console", str(e))

    def _connect_serial(self) -> None:
        port = self.var_port.get().strip()
        if not port:
            raise ValueError("请选择或填写串口。")
        if " — " in port:
            port = port.split(" — ", 1)[0].strip()
        bs = int(self.var_bytesize.get())
        if bs not in (5, 6, 7, 8):
            raise ValueError("数据位须为 5–8。")
        sb = int(self.var_stopbits.get())
        if sb not in (1, 2):
            raise ValueError("停止位须为 1 或 2。")

        back = SerialBackend(
            port=port,
            baudrate=int(self.var_baud.get()),
            bytesize=bs,
            parity=self.var_parity.get() or "N",
            stopbits=sb,
            xonxoff=bool(self.var_xonxoff.get()),
            rtscts=bool(self.var_rtscts.get()),
        )
        try:
            back.connect()
            self._attach_session(back, f"串口 {port} @ {self.var_baud.get()}")
        except Exception:
            back.close()
            raise

    def _connect_ssh(self) -> None:
        host = self.var_ssh_host.get().strip()
        if not host:
            raise ValueError("请填写 SSH 主机。")
        user = self.var_ssh_user.get().strip()
        if not user:
            raise ValueError("请填写用户名。")
        key_path = self.var_ssh_key.get().strip()
        password = self.var_ssh_pass.get().strip()
        if not key_path and not password:
            raise ValueError("请填写密码或私钥路径。")

        back = SSHPtyBackend(
            hostname=host,
            port=int(self.var_ssh_port.get()),
            username=user,
            password=self.var_ssh_pass.get(),
            key_filename=key_path,
            key_passphrase=self.var_ssh_key_pass.get(),
            term=self.var_ssh_term.get(),
            width=int(self.var_ssh_cols.get()),
            height=int(self.var_ssh_rows.get()),
        )
        try:
            back.connect()
            self._attach_session(back, f"SSH {user}@{host}")
        except Exception:
            back.close()
            raise

    def _attach_session(self, backend: object, status: str) -> None:
        self._disconnect_queue_only()
        self._backend = backend
        self._out_q = queue.Queue()
        self._session = SwitchConsoleSession(backend, self._out_q)
        self._session.start()
        self.btn_connect.configure(state=tk.DISABLED)
        self.btn_disconnect.configure(state=tk.NORMAL)
        self.lbl_switch_status.configure(text=f"已连接 — {status}", bootstyle=SUCCESS)
        self._drain_output_loop()
        self.txt_term.focus_set()

    def _disconnect_queue_only(self) -> None:
        if self._drain_after is not None:
            try:
                self.after_cancel(self._drain_after)
            except tk.TclError:
                pass
            self._drain_after = None
        try:
            while True:
                self._out_q.get_nowait()
        except queue.Empty:
            pass

    def _disconnect(self) -> None:
        self._disconnect_queue_only()
        if self._session is not None:
            self._session.stop()
            self._session = None
        self._backend = None
        self.btn_connect.configure(state=tk.NORMAL)
        self.btn_disconnect.configure(state=tk.DISABLED)
        self.lbl_switch_status.configure(text="未连接", bootstyle=SECONDARY)

    def _drain_output_loop(self) -> None:
        try:
            while True:
                chunk = self._out_q.get_nowait()
                if chunk is None:
                    self._append_notice("\r\n[会话已结束]\r\n")
                    self._disconnect()
                    return
                self._append_bytes(chunk)
        except queue.Empty:
            pass
        self._drain_after = self.after(40, self._drain_output_loop)

    def _append_bytes(self, data: bytes) -> None:
        text = data.decode("utf-8", errors="replace")
        self.txt_term.configure(state=tk.NORMAL)
        self.txt_term.insert(tk.END, text)
        self.txt_term.see(tk.END)
        self.txt_term.configure(state=tk.NORMAL)

    def _append_notice(self, text: str) -> None:
        self.txt_term.configure(state=tk.NORMAL)
        self.txt_term.insert(tk.END, text)
        self.txt_term.see(tk.END)

    def _send(self, data: bytes) -> None:
        if self._session is None:
            return
        self._session.send_bytes(data)

    def _on_term_paste(self, event: tk.Event) -> str:
        self._paste_from_clipboard()
        return "break"

    def _paste_from_clipboard(self) -> None:
        try:
            clip = self.clipboard_get()
        except tk.TclError:
            return
        self._send(clip.encode("utf-8", errors="replace"))
        if self._connect_mode.get() == "serial" and self.var_local_echo.get():
            self._append_bytes(clip.encode("utf-8", errors="replace"))

    def _on_term_key(self, event: tk.Event) -> str | None:
        if self._session is None:
            return None
        keysym = event.keysym
        state = event.state or 0
        ctrl = (state & 0x4) != 0 or (state & 0x20000) != 0

        if ctrl and keysym.lower() == "c":
            self._send(b"\x03")
            return "break"
        if ctrl and keysym.lower() == "v":
            self._paste_from_clipboard()
            return "break"
        if ctrl and keysym.lower() == "d":
            self._send(b"\x04")
            return "break"
        if keysym == "Return":
            self._send(b"\r")
            if self._connect_mode.get() == "serial" and self.var_local_echo.get():
                self._append_notice("\n")
            return "break"
        if keysym == "Tab":
            self._send(b"\t")
            if self._connect_mode.get() == "serial" and self.var_local_echo.get():
                self._append_notice("\t")
            return "break"
        if keysym == "BackSpace":
            self._send(b"\x7f")
            return "break"
        if keysym in ("Left", "Right", "Up", "Down", "Prior", "Next", "Home", "End"):
            # 简单方向键序列（常见终端）
            seq = {
                "Up": b"\x1b[A",
                "Down": b"\x1b[B",
                "Right": b"\x1b[C",
                "Left": b"\x1b[D",
                "Home": b"\x1b[H",
                "End": b"\x1b[F",
                "Prior": b"\x1b[5~",
                "Next": b"\x1b[6~",
            }.get(keysym, b"")
            if seq:
                self._send(seq)
            return "break"
        ch = event.char
        if ch and len(ch) == 1:
            b = ch.encode("utf-8")
            self._send(b)
            if self._connect_mode.get() == "serial" and self.var_local_echo.get():
                self._append_bytes(b)
            return "break"
        return "break"
