"""可执行文件与资源路径解析（开发目录 / PyInstaller frozen）。"""

from __future__ import annotations

import sys
from pathlib import Path


def bundle_root() -> Path:
    """项目根或 PyInstaller 解包目录。"""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    # network_diagnosis/paths.py -> package -> repo root
    return Path(__file__).resolve().parent.parent


def third_party_tcping() -> Path:
    return bundle_root() / "ThirdParty" / "tcping" / "tcping.exe"


def third_party_wireshark_dir() -> Path:
    return bundle_root() / "ThirdParty" / "Wireshark"


def resolve_tcping_exe() -> Path | None:
    p = third_party_tcping()
    return p if p.is_file() else None


def iter_wireshark_installers() -> list[Path]:
    d = third_party_wireshark_dir()
    if not d.is_dir():
        return []
    exes = sorted(d.glob("*.exe"), key=lambda x: x.stat().st_mtime, reverse=True)
    return [p for p in exes if p.is_file()]


def find_tshark() -> Path | None:
    import os

    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / "tshark.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        / "Wireshark"
        / "tshark.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None
