"""Windows PowerShell 子进程辅助（域模块）。"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from typing import Any

_PS_UTF8_PREFIX = (
    "$OutputEncoding = [Console]::OutputEncoding = "
    "New-Object System.Text.UTF8Encoding $false\n"
)


def decode_console_bytes(data: bytes) -> str:
    if not data:
        return ""
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp936"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def run_powershell(script: str, *, timeout: int = 180) -> tuple[int, str, str]:
    full = _PS_UTF8_PREFIX + script.strip()
    raw = full.encode("utf-16-le")
    enc = base64.b64encode(raw).decode("ascii")
    cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        enc,
    ]
    kwargs: dict[str, Any] = dict(capture_output=True, timeout=timeout)
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[assignment]
    r = subprocess.run(cmd, **kwargs)
    out = decode_console_bytes(r.stdout or b"").strip()
    err = decode_console_bytes(r.stderr or b"").strip()
    return r.returncode, out, err


def parse_ps_json(stdout: str) -> Any:
    t = stdout.lstrip("\ufeff").strip()
    if not t:
        return None
    return json.loads(t)


def ps_credential_var(*, var_name: str, username: str, password: str) -> str:
    """生成 PowerShell 片段：``$var_name = PSCredential``（密码经 Base64 传递，避免引号问题）。"""
    u_b64 = base64.b64encode(username.encode("utf-8")).decode("ascii")
    p_b64 = base64.b64encode(password.encode("utf-8")).decode("ascii")
    return f"""
$__u = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{u_b64}'))
$__p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{p_b64}'))
$__sec = ConvertTo-SecureString $__p -AsPlainText -Force
${var_name} = New-Object System.Management.Automation.PSCredential($__u, $__sec)
Remove-Variable __p, __sec -ErrorAction SilentlyContinue
""".strip()


def run_cmd(args: list[str], *, timeout: int = 120) -> tuple[int, str, str]:
    kwargs: dict[str, Any] = dict(capture_output=True, timeout=timeout)
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[assignment]
    r = subprocess.run(args, **kwargs)
    out = decode_console_bytes(r.stdout or b"").strip()
    err = decode_console_bytes(r.stderr or b"").strip()
    return r.returncode, out, err
