"""Windows 子进程输出解码（ipconfig / PowerShell / Nmap）。"""

from __future__ import annotations


def decode_oem_console_output(data: bytes) -> str:
    """中文 Windows 控制台命令（如 ipconfig）默认 OEM/ANSI（GBK）。"""
    if not data:
        return ""
    for enc in ("gbk", "cp936", "utf-8-sig", "utf-8"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("gbk", errors="replace")


def decode_powershell_output(data: bytes) -> str:
    """PowerShell 5.x 管道 stdout 常为 UTF-16 LE（带/不带 BOM）。"""
    if not data:
        return ""
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", errors="replace")
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace")
    # 无 BOM 的 UTF-16 LE：ASCII 字符与 \x00 交替
    if len(data) >= 4 and data[1:2] == b"\x00" and data[3:4] == b"\x00":
        try:
            return data.decode("utf-16-le", errors="strict")
        except UnicodeDecodeError:
            pass
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp936"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def decode_nmap_output(data: bytes) -> str:
    """Nmap 在 Windows 上多为 UTF-8 或纯 ASCII。"""
    if not data:
        return ""
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp936"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")
