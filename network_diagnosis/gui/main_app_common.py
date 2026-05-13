"""主窗口杂项：图标路径、端口列表解析。"""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path

from network_diagnosis.paths import bundle_root


def resolve_window_icon_path() -> Path | None:
    """任务栏/标题栏图标：`network_diagnosis/images/qingqiu.ico`（与 `gui` 包同级目录 `images`）。"""
    pkg_root = Path(__file__).resolve().parent.parent
    candidates: list[Path] = [
        pkg_root / "images" / "qingqiu.ico",
    ]
    root = bundle_root()
    candidates.append(root / "network_diagnosis" / "images" / "qingqiu.ico")
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        candidates.extend(
            [
                exe_dir / "network_diagnosis" / "images" / "qingqiu.ico",
                exe_dir / "qingqiu.ico",
            ]
        )
    candidates.append(root / "qingqiu.ico")
    for p in candidates:
        if p.is_file():
            return p
    return None


def try_set_window_icon(win: tk.Misc) -> None:
    path = resolve_window_icon_path()
    if path is None:
        return
    try:
        win.iconbitmap(str(path))
    except tk.TclError:
        pass


def bind_label_wraplength(label: tk.Misc, *, inset: int = 4) -> None:
    """按标签控件实际宽度设置 ``wraplength``（随布局变化），避免按外层框架算得过宽导致文字被裁切。"""

    def set_wrap(pixels: int) -> None:
        if pixels <= 1:
            return
        try:
            label.configure(wraplength=max(24, pixels - inset))
        except tk.TclError:
            pass

    def on_configure(event: tk.Event) -> None:
        if event.widget is not label:
            return
        set_wrap(int(getattr(event, "width", 0) or 0))

    label.bind("<Configure>", on_configure, add="+")

    def after_idle_sync() -> None:
        try:
            set_wrap(int(label.winfo_width()))
        except tk.TclError:
            pass

    label.after_idle(after_idle_sync)


def parse_ports(text: str) -> list[int]:
    """
    解析端口列表，支持英文逗号分隔。
    例如：80,443,8080
    返回排序后的端口列表。
    """
    out: list[int] = []
    for part in text.replace(";", ",").split(","):
        p = part.strip()
        if not p:
            continue
        out.append(int(p))
    return sorted(set(out))
