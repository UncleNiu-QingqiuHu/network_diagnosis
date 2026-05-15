"""主窗口杂项：图标路径、端口列表解析。"""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path

from network_diagnosis.paths import bundle_root


def resolve_window_icon_path() -> Path | None:
    """任务栏/标题栏图标：`network_diagnosis/images/qqhu_black2.ico`（与 `gui` 包同级目录 `images`）。"""
    pkg_root = Path(__file__).resolve().parent.parent
    candidates: list[Path] = [
        pkg_root / "images" / "qqhu_black2.ico",
    ]
    root = bundle_root()
    candidates.append(root / "network_diagnosis" / "images" / "qqhu_black2.ico")
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        candidates.extend(
            [
                exe_dir / "network_diagnosis" / "images" / "qqhu_black2.ico",
                exe_dir / "qqhu_black2.ico",
            ]
        )
    candidates.append(root / "qqhu_black2.ico")
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


def scaled_photo_from_png(
    master: tk.Misc,
    path: Path,
    *,
    size_px: int,
    trim_alpha_bbox: bool = False,
) -> tk.PhotoImage | None:
    """将 PNG 统一缩放为 ``size_px × size_px`` 像素后再装入 Tk（便于与高 DPI / 任意素材尺寸解耦）。

    ``trim_alpha_bbox=True`` 时先按不透明区域裁剪再缩放，用于画布留白较多的图标（如侧边栏「数字签名」），
    避免与其它满幅图标相比显得过小。

    依赖 Pillow（``ttkbootstrap`` 已间接引入）。若缩放失败则退回原始 ``PhotoImage`` 加载。
    """
    if not path.is_file() or size_px <= 0:
        return None
    try:
        from PIL import Image, ImageTk

        img = Image.open(path).convert("RGBA")
        if trim_alpha_bbox:
            bbox = img.split()[3].getbbox()
            if bbox:
                img = img.crop(bbox)
        try:
            resample = Image.Resampling.LANCZOS
        except AttributeError:
            resample = Image.LANCZOS  # Pillow 旧版
        img = img.resize((size_px, size_px), resample)
        return ImageTk.PhotoImage(img, master=master)
    except Exception:
        try:
            return tk.PhotoImage(master=master, file=str(path))
        except tk.TclError:
            return None


def fix_primary_notebook_selected_tab_colors(nb: tk.Misc) -> None:
    """修正 ``bootstyle=PRIMARY`` 的 Notebook：仅「当前选中」Tab 使用主色底，未选中 Tab 使用输入区底色。

    ttkbootstrap 默认实现与此相反（未选中为主色、选中为窗口底色），与本产品 Tab 交互预期不符。
    """
    try:
        import ttkbootstrap as ttk

        base = str(nb.cget("style"))
    except (tk.TclError, AttributeError):
        return
    if base.lower() != "primary.tnotebook":
        return
    tab_style = f"{base}.Tab"
    try:
        root = nb.winfo_toplevel()
        style = getattr(root, "style", None)
        if style is None:
            style = ttk.Style()
        colors = style.colors
        primary = colors.get("primary")
        bordercolor = colors.border
        fg_sel = colors.get_foreground("primary")
        style.map(
            tab_style,
            background=[
                ("selected", primary),
                ("!selected", colors.inputbg),
            ],
            lightcolor=[
                ("selected", primary),
                ("!selected", colors.inputbg),
            ],
            darkcolor=[
                ("selected", primary),
                ("!selected", colors.inputbg),
            ],
            bordercolor=[
                ("selected", bordercolor),
                ("!selected", bordercolor),
            ],
            foreground=[
                ("selected", fg_sel),
                ("!selected", colors.inputfg),
            ],
            padding=[("selected", (6, 5)), ("!selected", (6, 5))],
        )
    except tk.TclError:
        pass


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
