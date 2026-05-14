"""Tk Text / ScrolledText 的轻量 Markdown 子集渲染（无第三方依赖）。"""

from __future__ import annotations

import re
import sys
import tkinter as tk
from tkinter import END, ttk
from tkinter import font as tkfont

# 行内 **粗体** 与 `代码`
_INLINE_TOKEN = re.compile(r"\*\*.+?\*\*|`[^`]+`")


def configure_simple_markdown_tags(widget: tk.Text, *, base_font: tuple[str, int] | None = None) -> None:
    ff, fs = base_font or ("Microsoft YaHei UI", 10)
    mono_fn = "Consolas" if sys.platform == "win32" else "Courier New"
    mono_fs = max(fs - 1, 9)
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
    # 孤儿表格行（无法解析为整块 GFM 表时）回退为等宽文本
    widget.tag_configure("md_table", font=(mono_fn, fs), background="#fafafa")
    widget.tag_configure(
        "md_table_sep",
        font=(mono_fn, mono_fs),
        foreground="#7f8c8d",
        background="#fafafa",
    )
    widget.tag_configure("md_table_bold", font=(mono_fn, fs, "bold"), background="#fafafa")
    widget.tag_configure(
        "md_table_code",
        font=(mono_fn, max(fs - 1, 8)),
        background="#eef2f7",
        foreground="#a93226",
    )
    widget.tag_configure("md_quote", font=(ff, fs), foreground="#566573", lmargin1=12, lmargin2=12)
    widget.tag_configure("md_li", font=(ff, fs))


def _as_tags(base: tuple[str, ...] | None, *more: str) -> tuple[str, ...] | None:
    parts = list(base or ())
    parts.extend(m for m in more if m)
    return tuple(parts) if parts else None


def _insert_mixed(widget: tk.Text, line: str, *extra_tags: str) -> None:
    tags_base = _as_tags(None, *extra_tags)
    in_table = "md_table" in extra_tags
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
            span_tag = "md_table_bold" if in_table else "md_bold"
            t = _as_tags(tags_base, span_tag)
        else:
            inner = raw[1:-1]
            span_tag = "md_table_code" if in_table else "md_code"
            t = _as_tags(tags_base, span_tag)
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


def _looks_like_md_table_row(s: str) -> bool:
    st = s.strip()
    return st.startswith("|") and st.count("|") >= 2


def _split_md_table_row(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [p.strip() for p in s.split("|")]


def _strip_inline_md_cell(s: str) -> str:
    t = re.sub(r"\*\*(.+?)\*\*", r"\1", s)
    t = re.sub(r"`([^`]+)`", r"\1", t)
    return t.strip()


def _try_consume_md_table(
    lines: list[str], start: int
) -> tuple[int, list[str], list[list[str]]] | None:
    """若从 start 起为 GFM 表格（表头 + 分隔行 + 数据行），返回 (下一行索引, 表头, 行数据)。"""
    if start + 1 >= len(lines):
        return None
    h_raw = lines[start].strip()
    if not _looks_like_md_table_row(h_raw):
        return None
    sep_raw = lines[start + 1].strip()
    if not _is_table_sep_row(sep_raw):
        return None
    headers = _split_md_table_row(h_raw)
    if not headers:
        return None
    ncols = len(headers)
    rows: list[list[str]] = []
    j = start + 2
    while j < len(lines):
        raw_ln = lines[j]
        if not raw_ln.strip():
            break
        st = raw_ln.strip()
        if not _looks_like_md_table_row(st):
            break
        if _is_table_sep_row(st):
            j += 1
            continue
        cells = _split_md_table_row(raw_ln)
        while len(cells) < ncols:
            cells.append("")
        rows.append(cells[:ncols])
        j += 1
    return j, headers, rows


def _embed_md_table_widget(text_w: tk.Text, headers: list[str], rows: list[list[str]]) -> None:
    """在 Text 内嵌入 Treeview，渲染真实表格（不显示原始 | 语法）。"""
    plain_h = [_strip_inline_md_cell(h) for h in headers]
    plain_r = [[_strip_inline_md_cell(c) for c in row] for row in rows]

    outer = tk.Frame(text_w, highlightthickness=1, highlightbackground="#cfd8dc")
    inner = tk.Frame(outer)
    inner.pack(fill=tk.X, padx=2, pady=(6, 10))

    try:
        fw = tkfont.Font(font=text_w.cget("font"))
    except tk.TclError:
        fw = tkfont.Font(family="Microsoft YaHei UI", size=10)

    n = len(plain_h)
    try:
        tw_px = int(text_w.winfo_width())
    except tk.TclError:
        tw_px = 0
    if tw_px <= 100:
        try:
            tw_px = int(text_w.winfo_reqwidth())
        except tk.TclError:
            tw_px = 0
    if tw_px <= 100:
        try:
            top_w = int(text_w.winfo_toplevel().winfo_width())
            tw_px = max(tw_px, top_w - 280)
        except tk.TclError:
            pass
    # 与输出区 Text 同宽（减去内边距）；未完成布局时用较高默认值，避免表格外观过扁
    budget = max(1280, tw_px - 96) if tw_px > 100 else 1520
    max_each = min(720, max(140, budget // max(n, 1)))
    widths: list[int] = []
    for ci in range(n):
        mx = fw.measure(plain_h[ci])
        for r in plain_r:
            if ci < len(r):
                mx = max(mx, fw.measure(r[ci]))
        widths.append(min(max(mx + 36, 96), max_each))

    col_ids = [f"c{k}" for k in range(n)]
    max_vis = 14
    tree_h = min(max(len(plain_r), 1), max_vis)
    tv = ttk.Treeview(inner, columns=col_ids, show="headings", selectmode="none", height=tree_h)

    for k, cid in enumerate(col_ids):
        tv.heading(cid, text=plain_h[k])
        tv.column(cid, width=widths[k], anchor="w", stretch=(k == n - 1))

    for r in plain_r:
        tv.insert("", tk.END, values=tuple(r))

    tv.grid(row=0, column=0, sticky=tk.NSEW)
    inner.columnconfigure(0, weight=1)
    if len(plain_r) > max_vis:
        vsb = ttk.Scrollbar(inner, orient=tk.VERTICAL, command=tv.yview)
        tv.configure(yscrollcommand=vsb.set)
        vsb.grid(row=0, column=1, sticky=tk.NS)

    text_w.window_create(END, window=outer)
    text_w.insert(END, "\n")


def append_simple_markdown(widget: tk.Text, md: str) -> None:
    """将 Markdown 子集追加到 Text 末尾（调用前先将 state 设为 NORMAL）。"""
    lines = md.splitlines()
    in_code = False
    code_buf: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("```"):
            if in_code and code_buf:
                widget.insert(END, "\n".join(code_buf) + "\n", "md_code_block")
                code_buf.clear()
            in_code = not in_code
            i += 1
            continue
        if in_code:
            code_buf.append(line)
            i += 1
            continue

        if not line.strip():
            widget.insert(END, "\n")
            i += 1
            continue

        if not in_code:
            tbl = _try_consume_md_table(lines, i)
            if tbl is not None:
                j, hdrs, body = tbl
                _embed_md_table_widget(widget, hdrs, body)
                i = j
                continue

        if line.startswith("## "):
            widget.insert(END, line[3:] + "\n", "md_h2")
            i += 1
            continue
        if line.startswith("### "):
            widget.insert(END, line[4:] + "\n", "md_h3")
            i += 1
            continue
        if line.startswith("#### "):
            widget.insert(END, line[5:] + "\n", "md_h4")
            i += 1
            continue
        if line.startswith("> "):
            _insert_mixed(widget, line[2:] + "\n", "md_quote")
            i += 1
            continue

        st = line.strip()
        if st.startswith("|") and "|" in st[1:]:
            if _is_table_sep_row(st):
                widget.insert(END, line + "\n", "md_table_sep")
            else:
                _insert_mixed(widget, line + "\n", "md_table")
            i += 1
            continue

        m_li = re.match(r"^(\s*)[-*]\s+(.*)$", line)
        if m_li:
            pre = m_li.group(1)
            if pre:
                widget.insert(END, pre)
            widget.insert(END, "• ", "md_li")
            _insert_mixed(widget, m_li.group(2) + "\n", "md_li")
            i += 1
            continue

        _insert_mixed(widget, line + "\n")
        i += 1

    if in_code and code_buf:
        widget.insert(END, "\n".join(code_buf) + "\n", "md_code_block")
