"""Tk Text / ScrolledText 的轻量 Markdown 子集渲染（无第三方依赖）。"""

from __future__ import annotations

import re
import tkinter as tk
from tkinter import END

# 行内 **粗体** 与 `代码`
_INLINE_TOKEN = re.compile(r"\*\*.+?\*\*|`[^`]+`")


def configure_simple_markdown_tags(widget: tk.Text, *, base_font: tuple[str, int] | None = None) -> None:
    ff, fs = base_font or ("Microsoft YaHei UI", 10)
    widget.tag_configure("md_h2", font=(ff, fs + 4, "bold"), spacing3=6, foreground="#1a5276")
    widget.tag_configure("md_h3", font=(ff, fs + 2, "bold"), spacing3=4, foreground="#2c3e50")
    widget.tag_configure("md_h4", font=(ff, fs + 1, "bold"), spacing3=2)
    widget.tag_configure("md_bold", font=(ff, fs, "bold"))
    widget.tag_configure("md_code", font=(ff, max(fs - 1, 8)), background="#eef2f7", foreground="#a93226")
    widget.tag_configure(
        "md_code_block",
        font=(ff, max(fs - 1, 8)),
        background="#f4f6f9",
        lmargin1=16,
        lmargin2=16,
    )
    widget.tag_configure("md_table", font=(ff, fs), background="#fafafa")
    widget.tag_configure("md_table_sep", font=(ff, max(fs - 1, 9)), foreground="#7f8c8d")
    widget.tag_configure("md_quote", font=(ff, fs), foreground="#566573", lmargin1=12, lmargin2=12)
    widget.tag_configure("md_li", font=(ff, fs))


def _as_tags(base: tuple[str, ...] | None, *more: str) -> tuple[str, ...] | None:
    parts = list(base or ())
    parts.extend(m for m in more if m)
    return tuple(parts) if parts else None


def _insert_mixed(widget: tk.Text, line: str, *extra_tags: str) -> None:
    tags_base = _as_tags(None, *extra_tags)
    pos = 0
    for m in _INLINE_TOKEN.finditer(line):
        if m.start() > pos:
            frag = line[pos : m.start()]
            t = tags_base
            if t:
                widget.insert(END, frag, t)
            else:
                widget.insert(END, frag)
        raw = m.group(0)
        if raw.startswith("**"):
            inner = raw[2:-2]
            t = _as_tags(tags_base, "md_bold")
        else:
            inner = raw[1:-1]
            t = _as_tags(tags_base, "md_code")
        if t:
            widget.insert(END, inner, t)
        else:
            widget.insert(END, inner)
        pos = m.end()
    if pos < len(line):
        frag = line[pos:]
        if tags_base:
            widget.insert(END, frag, tags_base)
        else:
            widget.insert(END, frag)


def _is_table_sep_row(s: str) -> bool:
    s = s.strip()
    if not s.startswith("|"):
        return False
    core = s.replace("|", "").replace(":", "").replace("-", "").strip()
    return len(core) == 0


def append_simple_markdown(widget: tk.Text, md: str) -> None:
    """将 Markdown 子集追加到 Text 末尾（调用前先将 state 设为 NORMAL）。"""
    lines = md.splitlines()
    in_code = False
    code_buf: list[str] = []
    for line in lines:
        if line.strip().startswith("```"):
            if in_code and code_buf:
                widget.insert(END, "\n".join(code_buf) + "\n", "md_code_block")
                code_buf.clear()
            in_code = not in_code
            continue
        if in_code:
            code_buf.append(line)
            continue

        if not line.strip():
            widget.insert(END, "\n")
            continue

        if line.startswith("## "):
            widget.insert(END, line[3:] + "\n", "md_h2")
            continue
        if line.startswith("### "):
            widget.insert(END, line[4:] + "\n", "md_h3")
            continue
        if line.startswith("#### "):
            widget.insert(END, line[5:] + "\n", "md_h4")
            continue
        if line.startswith("> "):
            _insert_mixed(widget, line[2:] + "\n", "md_quote")
            continue

        st = line.strip()
        if st.startswith("|") and "|" in st[1:]:
            if _is_table_sep_row(st):
                widget.insert(END, line + "\n", "md_table_sep")
            else:
                _insert_mixed(widget, line + "\n", "md_table")
            continue

        m_li = re.match(r"^(\s*)[-*]\s+(.*)$", line)
        if m_li:
            pre = m_li.group(1)
            if pre:
                widget.insert(END, pre)
            widget.insert(END, "• ", "md_li")
            _insert_mixed(widget, m_li.group(2) + "\n", "md_li")
            continue

        _insert_mixed(widget, line + "\n")

    if in_code and code_buf:
        widget.insert(END, "\n".join(code_buf) + "\n", "md_code_block")
