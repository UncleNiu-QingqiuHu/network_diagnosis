"""tshark 网卡列表与默认推荐。"""

from __future__ import annotations

import re
from pathlib import Path

from network_diagnosis.probes.subproc_util import read_text_best_effort, run_to_log_files
from network_diagnosis.probes.tshark import _iface_choice_score, _iface_skip_auto_capture, pick_capture_interface_index


def list_capture_interfaces(tshark: Path, log_dir: Path) -> list[tuple[str, str]]:
    """返回 [(接口索引, 描述), ...]（跳过不可自动抓包的 extcap/loopback）。"""
    r = run_to_log_files([str(tshark), "-D"], log_dir, "tshark_list_if", timeout_sec=30)
    text = read_text_best_effort(r.stdout_path)
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        m = re.match(r"^(\d+)\.\s*(.+)$", line.strip())
        if not m:
            continue
        idx, desc = m.group(1), m.group(2)
        if _iface_skip_auto_capture(desc):
            continue
        out.append((idx, desc))
    return out


def default_interface_index(tshark: Path, log_dir: Path) -> str:
    return pick_capture_interface_index(tshark, log_dir)


def format_interface_label(index: str, desc: str) -> str:
    return f"{index}. {desc}"


def parse_interface_label(label: str) -> tuple[str, str]:
    label = label.strip()
    m = re.match(r"^(\d+)\.\s*(.+)$", label)
    if m:
        return m.group(1), m.group(2)
    if label.isdigit():
        return label, label
    return label, label


def score_interface_desc(desc: str) -> int:
    return _iface_choice_score(desc)
