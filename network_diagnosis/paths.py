"""可执行文件与资源路径解析（开发目录 / PyInstaller frozen）。"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def bundle_root() -> Path:
    """项目根或 PyInstaller 解包目录。"""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    # network_diagnosis/paths.py -> package -> repo root
    return Path(__file__).resolve().parent.parent


def switch_console_data_dir() -> Path:
    """交换机 Console（SSH known_hosts 等）可写目录：与报告目录并列， frozen 时在 exe 旁。"""
    if getattr(sys, "frozen", False):
        p = Path(sys.executable).resolve().parent / "switch_console"
    else:
        p = bundle_root() / "switch_console"
    p.mkdir(parents=True, exist_ok=True)
    return p


def db_diagnosis_report_dir(task_id: str) -> Path:
    """单次数据库诊断或监控导出目录：`reports/db_diagnosis/<task_id>/`。"""
    d = report_root() / "db_diagnosis" / task_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def report_root() -> Path:
    """诊断报告与任务产物默认根目录（项目下 `reports/`，可写）。

    - 开发模式：仓库根目录下的 ``reports/``。
    - PyInstaller：可执行文件所在目录下的 ``reports/``（避免写入临时 ``_MEIPASS``）。
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "reports"
    return bundle_root() / "reports"


def logs_root() -> Path:
    """运行日志根目录：`logs/`（与 ``reports/`` 同级，可写）。

    - 开发模式：仓库根下 ``logs/``。
    - PyInstaller：可执行文件所在目录下 ``logs/``。
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "logs"
    return bundle_root() / "logs"


def ensure_logs_dir() -> Path:
    d = logs_root()
    d.mkdir(parents=True, exist_ok=True)
    return d


def refresh_catalog_icon_png() -> Path:
    """数据库诊断「刷新库列表」图标（PNG，矢量稿为 ``images/fa--refresh.svg``，Tk 无法直接加载 SVG）。"""
    return Path(__file__).resolve().parent / "images" / "fa--refresh.png"


def resolve_sidebar_nav_icon_png(module_key: str) -> Path | None:
    """左侧导航图标（透明底 PNG），位于 ``network_diagnosis/images/``。

    键与 ``main_app`` 中 ``nav_items`` 的 ``module_key`` 一致；若文件不存在则返回 ``None``（仅显示文字）。
    「许可」优先 ``material-symbols--license.png``，其次 ``license.png``。
    """
    img_root = Path(__file__).resolve().parent / "images"
    if module_key == "license":
        for name in ("material-symbols--license.png", "license.png"):
            p = img_root / name
            if p.is_file():
                return p
        return None

    _names: dict[str, str] = {
        "network": "material-symbols--network-wifi.png",
        "subnet": "fluent--globe-12-filled.png",
        "switch": "streamline-ultimate--ethernet-port-bold.png",
        "database": "teenyicons--database-solid.png",
        "arp_intranet": "ion--shield-checkmark.png",
        "security": "simple-icons--scan.png",
        "guide": "fa6-solid--book-open.png",
        "about": "ooui--info-filled.png",
    }
    fn = _names.get(module_key)
    if not fn:
        return None
    p = img_root / fn
    return p if p.is_file() else None


def third_party_tcping() -> Path:
    return bundle_root() / "ThirdParty" / "tcping" / "tcping.exe"


def third_party_iperf3() -> Path:
    return bundle_root() / "ThirdParty" / "iperf3" / "iperf3.exe"


def third_party_wireshark_dir() -> Path:
    return bundle_root() / "ThirdParty" / "Wireshark"


def resolve_tcping_exe() -> Path | None:
    p = third_party_tcping()
    return p if p.is_file() else None


def resolve_iperf3_exe() -> Path | None:
    p = third_party_iperf3()
    if p.is_file():
        return p
    w = shutil.which("iperf3") or shutil.which("iperf3.exe")
    return Path(w) if w else None


def iter_wireshark_installers() -> list[Path]:
    d = third_party_wireshark_dir()
    if not d.is_dir():
        return []
    exes = sorted(d.glob("*.exe"), key=lambda x: x.stat().st_mtime, reverse=True)
    return [p for p in exes if p.is_file()]


def find_tshark() -> Path | None:
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


def third_party_nmap_dir() -> Path:
    return bundle_root() / "ThirdParty" / "Nmap"


def iter_nmap_installers() -> list[Path]:
    """ThirdParty/Nmap 目录下官方安装包（*.exe），按修改时间新在前。"""
    d = third_party_nmap_dir()
    if not d.is_dir():
        return []
    exes = sorted(d.glob("*.exe"), key=lambda x: x.stat().st_mtime, reverse=True)
    return [p for p in exes if p.is_file()]


def resolve_nmap_exe_path() -> str | None:
    """探测 nmap 可执行文件：PATH → 常见 Windows 安装目录 → ThirdParty/Nmap/nmap.exe。"""
    w = shutil.which("nmap") or (shutil.which("nmap.exe") if sys.platform == "win32" else None)
    if w:
        return w
    candidates: list[Path] = []
    if sys.platform == "win32":
        candidates.extend(
            [
                Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Nmap" / "nmap.exe",
                Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Nmap" / "nmap.exe",
            ]
        )
    candidates.append(third_party_nmap_dir() / "nmap.exe")
    for c in candidates:
        try:
            if c.is_file():
                return str(c.resolve())
        except OSError:
            continue
    return None
