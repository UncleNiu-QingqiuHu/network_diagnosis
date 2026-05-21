"""管理员检测与重启引导。"""

from __future__ import annotations

import ctypes
import sys

from network_diagnosis.domain.ps_win import run_cmd


def is_windows() -> bool:
    return sys.platform == "win32"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def require_admin_message() -> str:
    return "此操作需要以管理员身份运行本程序。请关闭后右键 exe →「以管理员身份运行」。"


def schedule_reboot(*, delay_sec: int = 60, message: str | None = None) -> tuple[bool, str]:
    if not is_windows():
        return False, "当前平台不支持重启。"
    msg = message or "青丘狐网络工作台：域操作需要重启"
    code, out, err = run_cmd(["shutdown", "/r", "/t", str(delay_sec), "/c", msg], timeout=30)
    if code != 0:
        return False, err or out or f"shutdown 退出码 {code}"
    return True, f"已计划在 {delay_sec} 秒后重启。"


def cancel_scheduled_reboot() -> tuple[bool, str]:
    if not is_windows():
        return False, "当前平台不支持。"
    code, out, err = run_cmd(["shutdown", "/a"], timeout=15)
    if code != 0:
        return False, err or out or "无待取消的重启计划，或取消失败。"
    return True, "已取消计划中的重启。"
