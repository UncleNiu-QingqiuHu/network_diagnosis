"""Nmap broadcast-dhcp-discover 多 DHCP 服务器探测。"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from collections.abc import Callable
from threading import Event

from network_diagnosis.dhcp.models import DhcpOffer, DhcpProbeRound
from network_diagnosis.dhcp.text_encoding import decode_nmap_output
from network_diagnosis.host_l3_info import _creationflags_no_window
from network_diagnosis.paths import resolve_nmap_exe_path

_RESPONSE_BLOCK_RE = re.compile(r"\|\s*Response\s+\d+\s+of\s+\d+\s*:", re.I)
_RE_SERVER_ID = re.compile(r"Server Identifier:\s*([0-9.]+)", re.I)
_RE_IP_OFFERED = re.compile(r"IP Offered:\s*([0-9.]+)", re.I)
_RE_ROUTER = re.compile(r"Router:\s*([0-9.]+)", re.I)
_RE_SUBNET = re.compile(r"Subnet Mask:\s*([0-9.]+)", re.I)
_RE_DNS = re.compile(r"Domain Name Server:\s*(.+)$", re.I)


def resolve_nmap_exe(user_path: str = "") -> str | None:
    p = (user_path or "").strip()
    if p:
        from pathlib import Path

        fp = Path(p)
        if fp.is_file():
            return str(fp.resolve())
    return resolve_nmap_exe_path()


def _parse_offers_from_nmap_output(text: str, whitelist: set[str]) -> list[DhcpOffer]:
    offers: list[DhcpOffer] = []
    if not text.strip():
        return offers

    blocks = re.split(_RESPONSE_BLOCK_RE, text)
    if len(blocks) <= 1:
        blocks = [text]

    for block in blocks:
        if not block.strip():
            continue
        lines = tuple(ln.rstrip() for ln in block.splitlines() if ln.strip())
        joined = "\n".join(lines)
        sid_m = _RE_SERVER_ID.search(joined)
        if not sid_m:
            continue
        server_id = sid_m.group(1).strip()
        yiaddr = None
        m = _RE_IP_OFFERED.search(joined)
        if m:
            yiaddr = m.group(1).strip()
        router = None
        m = _RE_ROUTER.search(joined)
        if m:
            router = m.group(1).strip()
        subnet = None
        m = _RE_SUBNET.search(joined)
        if m:
            subnet = m.group(1).strip()
        dns: list[str] = []
        m = _RE_DNS.search(joined)
        if m:
            for part in re.split(r"[,\s]+", m.group(1)):
                part = part.strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", part):
                    dns.append(part)
        offers.append(
            DhcpOffer(
                server_id=server_id,
                yiaddr=yiaddr,
                router=router,
                dns=tuple(dns),
                subnet_mask=subnet,
                in_whitelist=server_id in whitelist,
                raw_lines=lines,
            )
        )

    # 去重：同一 server_id 保留首条
    seen: set[str] = set()
    uniq: list[DhcpOffer] = []
    for o in offers:
        if o.server_id in seen:
            continue
        seen.add(o.server_id)
        uniq.append(o)
    return uniq


def run_nmap_dhcp_discover_round(
    *,
    nmap_exe: str,
    interface_ipv4: str | None,
    round_index: int,
    timeout_sec: int = 10,
) -> DhcpProbeRound:
    argv = [nmap_exe, "--script", "broadcast-dhcp-discover"]
    if interface_ipv4:
        argv.extend(["--interface", interface_ipv4])
    argv.extend(["--host-timeout", f"{max(4, timeout_sec - 2)}s"])

    try:
        pr = subprocess.run(
            argv,
            capture_output=True,
            timeout=max(timeout_sec + 15, 20),
            creationflags=_creationflags_no_window(),
        )
    except subprocess.TimeoutExpired:
        return DhcpProbeRound(round_index=round_index, error="nmap 执行超时")
    except OSError as e:
        return DhcpProbeRound(round_index=round_index, error=str(e))

    text = decode_nmap_output((pr.stdout or b"") + (pr.stderr or b""))
    err = None
    if pr.returncode != 0 and "Response" not in text:
        err = f"nmap 退出码 {pr.returncode}"
    return DhcpProbeRound(
        round_index=round_index,
        offers=[],
        raw_output=text,
        error=err,
    )


def run_dhcp_probe_rounds(
    *,
    nmap_exe: str,
    interface_ipv4: str,
    authorized_servers: tuple[str, ...],
    rounds: int = 3,
    round_timeout_sec: int = 10,
    round_interval_sec: float = 1.5,
    cancel_event: Event | None = None,
    on_round: Callable[[DhcpProbeRound], None] | None = None,
) -> tuple[list[DhcpProbeRound], str | None]:
    """执行多轮 DHCP DISCOVER 探测，返回各轮结果与全局错误。"""
    whitelist = {s.strip() for s in authorized_servers if s.strip()}
    out_rounds: list[DhcpProbeRound] = []
    n = max(1, min(int(rounds), 5))

    for i in range(1, n + 1):
        if cancel_event is not None and cancel_event.is_set():
            break
        raw_round = run_nmap_dhcp_discover_round(
            nmap_exe=nmap_exe,
            interface_ipv4=interface_ipv4,
            round_index=i,
            timeout_sec=round_timeout_sec,
        )
        offers = _parse_offers_from_nmap_output(raw_round.raw_output, whitelist)
        for o in offers:
            o.in_whitelist = o.server_id in whitelist
        probe = DhcpProbeRound(
            round_index=i,
            offers=offers,
            distinct_server_count=len({o.server_id for o in offers}),
            raw_output=raw_round.raw_output,
            error=raw_round.error,
        )
        out_rounds.append(probe)
        if on_round is not None:
            on_round(probe)
        if i < n and round_interval_sec > 0:
            if cancel_event is not None and cancel_event.wait(round_interval_sec):
                break
            elif cancel_event is None:
                time.sleep(round_interval_sec)

    if not out_rounds and sys.platform != "win32":
        return [], "DHCP 主动探测当前主要针对 Windows + Nmap 环境。"
    return out_rounds, None
