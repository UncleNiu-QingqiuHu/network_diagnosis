"""出口公网 IPv4（国内可访问接口，多源回退）与环境代理变量；Windows 附带 netsh winhttp 摘要。"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

from network_diagnosis.model.report import EgressProbeResult

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

_UA = "Mozilla/5.0 (compatible; QQHU-NetworkDiagnosis/1.0)"


def _first_ipv4_in_text(text: str) -> str | None:
    m = _IPV4_RE.search(text)
    return m.group(0) if m else None


def _request_text(url: str, *, timeout: float = 8.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("gbk", errors="replace")


def _fetch_public_ip_cn() -> tuple[str | None, str]:
    """依次尝试国内常用出口 IP 查询，避免依赖境外服务。"""
    errors: list[str] = []

    try:
        text = _request_text("https://myip.ipip.net", timeout=8.0)
        ip = _first_ipv4_in_text(text)
        if ip:
            return ip, ""
        errors.append("myip.ipip.net: 响应中无 IPv4")
    except (OSError, urllib.error.URLError) as e:
        errors.append(f"myip.ipip.net: {e}")

    try:
        text = _request_text("http://members.3322.org/dyndns/getip", timeout=8.0).strip()
        first = text.splitlines()[0].strip() if text else ""
        if first and _IPV4_RE.fullmatch(first):
            return first, ""
        errors.append("3322.org: 未返回单行 IPv4")
    except (OSError, urllib.error.URLError) as e:
        errors.append(f"3322.org: {e}")

    try:
        text = _request_text("http://cip.cc", timeout=8.0)
        ip = _first_ipv4_in_text(text)
        if ip:
            return ip, ""
        errors.append("cip.cc: 响应中无 IPv4")
    except (OSError, urllib.error.URLError) as e:
        errors.append(f"cip.cc: {e}")

    return None, "；".join(errors) if errors else "全部国内查询接口失败"


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

    public, err = _fetch_public_ip_cn()

    return EgressProbeResult(
        public_ip=public,
        ipify_error=err,
        http_proxy=os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"),
        https_proxy=os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"),
        all_proxy=os.environ.get("ALL_PROXY") or os.environ.get("all_proxy"),
        no_proxy=os.environ.get("NO_PROXY") or os.environ.get("no_proxy"),
        winhttp_note=winhttp,
    )
