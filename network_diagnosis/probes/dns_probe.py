"""DNS 解析（标准库）。"""

from __future__ import annotations

import socket
import time

from network_diagnosis.model.report import DnsAnswer


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
