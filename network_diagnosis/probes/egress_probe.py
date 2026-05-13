"""出口公网 IP（api.ipify）与环境代理变量；Windows 附带 netsh winhttp 摘要。"""

from __future__ import annotations

import os
import subprocess
import sys
import urllib.error
import urllib.request

from network_diagnosis.model.report import EgressProbeResult


def run_egress() -> EgressProbeResult:
    winhttp = ""
    if sys.platform == "win32":
        try:
            cf = 0
            try:
                cf = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            except AttributeError:
                pass
            pr = subprocess.run(
                ["netsh", "winhttp", "show", "proxy"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=12,
                creationflags=cf,
            )
            winhttp = (pr.stdout or pr.stderr or "").strip()[-1200:]
        except (OSError, subprocess.TimeoutExpired) as e:
            winhttp = f"读取 winhttp 代理失败：{e}"

    public: str | None = None
    err = ""
    try:
        with urllib.request.urlopen(
            "https://api.ipify.org",
            timeout=6,
        ) as r:
            public = r.read().decode("utf-8", errors="replace").strip()
    except (OSError, urllib.error.URLError) as e:  # type: ignore[name-defined]
        err = str(e)

    return EgressProbeResult(
        public_ip=public,
        ipify_error=err,
        http_proxy=os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"),
        https_proxy=os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"),
        all_proxy=os.environ.get("ALL_PROXY") or os.environ.get("all_proxy"),
        no_proxy=os.environ.get("NO_PROXY") or os.environ.get("no_proxy"),
        winhttp_note=winhttp,
    )
