"""DNS 解析（标准库 + 可选指定服务器子进程）。"""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from network_diagnosis.model.report import DnsAnswer


def _subprocess_no_window_kw() -> dict:
    if sys.platform == "win32" and hasattr(subprocess, "CREATE_NO_WINDOW"):
        return {"creationflags": subprocess.CREATE_NO_WINDOW}  # type: ignore[dict-item]
    return {}


def resolve_dns(
    hostname: str,
    *,
    prefer_ipv6: bool,
) -> DnsAnswer:
    family = 0
    if prefer_ipv6:
        family = socket.AF_INET6
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(
            hostname,
            None,
            family=family,
            type=socket.SOCK_STREAM,
        )
    except OSError as e:
        elapsed = (time.perf_counter() - t0) * 1000
        return DnsAnswer(
            family="ipv6" if prefer_ipv6 else "ipv4",
            addresses=[],
            elapsed_ms=elapsed,
            error=str(e),
        )
    elapsed = (time.perf_counter() - t0) * 1000
    addrs: list[str] = []
    fam_label = "mixed"
    for _fam, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in addrs:
            addrs.append(ip)
    if prefer_ipv6:
        fam_label = "ipv6"
    elif addrs and ":" not in addrs[0]:
        fam_label = "ipv4"
    elif addrs:
        fam_label = "ipv6" if ":" in addrs[0] else "ipv4"
    return DnsAnswer(family=fam_label, addresses=addrs, elapsed_ms=elapsed, error=None)


def _parse_ips_from_text(text: str) -> list[str]:
    out: list[str] = []
    for m in re.finditer(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        text,
    ):
        ip = m.group(0)
        if ip not in out:
            out.append(ip)
    for m in re.finditer(
        r"(?:(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{0,4}|::|(?:[0-9a-fA-F]{1,4}:){1,7}:)",
        text,
    ):
        s = m.group(0).strip()
        if s in (":", ":::"):
            continue
        try:
            ipaddress.ip_address(s.split("%")[0])
        except ValueError:
            continue
        if s not in out:
            out.append(s)
    return out


def resolve_dns_via_server(
    hostname: str,
    dns_server: str,
    log_dir: Path,
    *,
    prefer_ipv6: bool,
) -> DnsAnswer:
    """使用 dig 或 nslookup 向指定 DNS 查询（不依赖本机解析器顺序）。"""
    log_dir.mkdir(parents=True, exist_ok=True)
    stem = "dns_specified"
    out_p = log_dir / f"{stem}.stdout.log"
    err_p = log_dir / f"{stem}.stderr.log"
    t0 = time.perf_counter()
    qtype = "AAAA" if prefer_ipv6 else "A"
    dig = shutil.which("dig")
    if dig:
        argv = [dig, f"@{dns_server}", hostname, qtype, "+short", "+time=2", "+tries=1"]
        try:
            pr = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=12,
                **_subprocess_no_window_kw(),
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            elapsed = (time.perf_counter() - t0) * 1000
            err_p.write_text(str(e), encoding="utf-8")
            return DnsAnswer(
                family="ipv6" if prefer_ipv6 else "ipv4",
                addresses=[],
                elapsed_ms=elapsed,
                error=str(e),
            )
        out_p.write_text(pr.stdout or "", encoding="utf-8")
        err_p.write_text(pr.stderr or "", encoding="utf-8")
        lines = [ln.strip() for ln in (pr.stdout or "").splitlines() if ln.strip()]
        addrs = [x for x in lines if not x.startswith(";")]
        elapsed = (time.perf_counter() - t0) * 1000
        if pr.returncode != 0 and not addrs:
            return DnsAnswer(
                family="ipv6" if prefer_ipv6 else "ipv4",
                addresses=[],
                elapsed_ms=elapsed,
                error=(pr.stderr or pr.stdout or f"exit {pr.returncode}")[:500],
            )
        return DnsAnswer(
            family="ipv6" if prefer_ipv6 else ("ipv4" if addrs and ":" not in addrs[0] else "ipv6"),
            addresses=addrs,
            elapsed_ms=elapsed,
            error=None,
        )

    argv = ["nslookup", "-type=" + qtype, hostname, dns_server]
    try:
        pr = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            **_subprocess_no_window_kw(),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        elapsed = (time.perf_counter() - t0) * 1000
        err_p.write_text(str(e), encoding="utf-8")
        return DnsAnswer(
            family="ipv6" if prefer_ipv6 else "ipv4",
            addresses=[],
            elapsed_ms=elapsed,
            error=str(e),
        )
    blob = (pr.stdout or "") + "\n" + (pr.stderr or "")
    out_p.write_text(pr.stdout or "", encoding="utf-8")
    err_p.write_text(pr.stderr or "", encoding="utf-8")
    elapsed = (time.perf_counter() - t0) * 1000
    addrs = _parse_ips_from_text(blob)
    if pr.returncode != 0 and not addrs:
        return DnsAnswer(
            family="ipv6" if prefer_ipv6 else "ipv4",
            addresses=[],
            elapsed_ms=elapsed,
            error=(blob.strip()[-400:] or f"exit {pr.returncode}"),
        )
    fam = "mixed"
    if addrs:
        fam = "ipv6" if ":" in addrs[0] else "ipv4"
    return DnsAnswer(family=fam, addresses=addrs, elapsed_ms=elapsed, error=None)


def pick_tcp_target(dns: DnsAnswer, *, prefer_ipv6: bool) -> str | None:
    if not dns.addresses:
        return None
    if prefer_ipv6:
        for a in dns.addresses:
            if ":" in a:
                return a
    for a in dns.addresses:
        if ":" not in a:
            return a
    return dns.addresses[0]
