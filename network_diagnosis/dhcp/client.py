"""本机 DHCP 客户端信息采集与健康规则。"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from datetime import datetime, timedelta

from network_diagnosis.dhcp.models import DhcpClientSnapshot
from network_diagnosis.host_l3_info import _creationflags_no_window, _decode_output, _is_ipv4
from network_diagnosis.ip_scan import ping_ipv4_once

_IPCONFIG_TIMEOUT_SEC = 35
_EVENT_LOG_MAX = 20

_RE_DHCP_ENABLED = re.compile(r"(?:DHCP Enabled|DHCP 已启用).*[\.:]+\s*(Yes|No|是|否)", re.I)
_RE_DHCP_SERVER = re.compile(r"(?:DHCP Server|DHCP 服务器).*[\.:]+\s*([0-9.]+)", re.I)
_RE_LEASE_OBTAINED = re.compile(r"(?:Lease Obtained|租约获得).*[\.:]+\s*(.+)$", re.I)
_RE_LEASE_EXPIRES = re.compile(r"(?:Lease Expires|租约过期).*[\.:]+\s*(.+)$", re.I)
_RE_ADAPTER_HEADER = re.compile(r"^(?:Ethernet|Wireless|WLAN|蓝牙|VMware|Loopback|以太网|无线|本地连接|.*适配器)", re.I)


def run_ipconfig_all_text() -> tuple[str, str | None]:
    try:
        pr = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True,
            timeout=_IPCONFIG_TIMEOUT_SEC,
            creationflags=_creationflags_no_window(),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return "", str(e)
    text = _decode_output((pr.stdout or b"") + (pr.stderr or b""))
    if not text.strip():
        return "", "ipconfig /all 无输出"
    return text, None


def _parse_windows_datetime(raw: str) -> datetime | None:
    s = raw.strip()
    if not s:
        return None
    for fmt in (
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y年%m月%d日 %H:%M:%S",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    m = re.search(r"(\d{4})[年/-](\d{1,2})[月/-](\d{1,2}).*?(\d{1,2}):(\d{2}):(\d{2})", s)
    if m:
        try:
            return datetime(
                int(m.group(1)),
                int(m.group(2)),
                int(m.group(3)),
                int(m.group(4)),
                int(m.group(5)),
                int(m.group(6)),
            )
        except ValueError:
            return None
    return None


def _is_apipa(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("169.254.0.0/16")
    except ValueError:
        return False


def _address_source(dhcp_enabled: bool | None, is_apipa: bool, dhcp_server: str | None) -> str:
    if is_apipa:
        return "apipa"
    if dhcp_enabled is False:
        return "manual"
    if dhcp_enabled is True or dhcp_server:
        return "dhcp"
    return "unknown"


def parse_dhcp_client_snapshots(text: str) -> list[DhcpClientSnapshot]:
    """从 ``ipconfig /all`` 文本解析 DHCP 相关字段。"""
    from network_diagnosis.host_l3_info import _parse_ipconfig_all

    blocks = _parse_ipconfig_all(text)
    by_ip: dict[str, DhcpClientSnapshot] = {}

    sections: list[tuple[str, list[str]]] = []
    cur_title = ""
    cur_lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if line.strip().endswith(":") and (
            "adapter" in line.lower() or "适配器" in line or _RE_ADAPTER_HEADER.match(line.strip())
        ):
            if cur_title or cur_lines:
                sections.append((cur_title, cur_lines))
            cur_title = line.strip()[:-1].strip()
            cur_lines = []
            continue
        if cur_title:
            cur_lines.append(line)
    if cur_title or cur_lines:
        sections.append((cur_title, cur_lines))

    section_meta: dict[str, dict[str, object]] = {}
    for title, lines in sections:
        meta: dict[str, object] = {
            "dhcp_enabled": None,
            "dhcp_server": None,
            "lease_obtained": None,
            "lease_expires": None,
        }
        for line in lines:
            m = _RE_DHCP_ENABLED.search(line)
            if m:
                v = m.group(1).strip().lower()
                meta["dhcp_enabled"] = v in ("yes", "是")
                continue
            m = _RE_DHCP_SERVER.search(line)
            if m and _is_ipv4(m.group(1)):
                meta["dhcp_server"] = m.group(1).strip()
                continue
            m = _RE_LEASE_OBTAINED.search(line)
            if m:
                meta["lease_obtained"] = _parse_windows_datetime(m.group(1))
                continue
            m = _RE_LEASE_EXPIRES.search(line)
            if m:
                meta["lease_expires"] = _parse_windows_datetime(m.group(1))
        section_meta[title] = meta

    for b in blocks:
        meta = section_meta.get(b.description, {})
        if not meta:
            for title, m in section_meta.items():
                if b.description in title or title in b.description:
                    meta = m
                    break
        dhcp_enabled = meta.get("dhcp_enabled")  # type: ignore[assignment]
        dhcp_server = meta.get("dhcp_server")  # type: ignore[assignment]
        lease_obtained = meta.get("lease_obtained")  # type: ignore[assignment]
        lease_expires = meta.get("lease_expires")  # type: ignore[assignment]
        apipa = _is_apipa(b.ipv4)
        src = _address_source(dhcp_enabled, apipa, dhcp_server if isinstance(dhcp_server, str) else None)
        snap = DhcpClientSnapshot(
            interface_name=b.description,
            mac=b.mac,
            ipv4=b.ipv4,
            netmask=b.netmask,
            address_source=src,
            dhcp_enabled=dhcp_enabled if isinstance(dhcp_enabled, bool) else None,
            dhcp_server=dhcp_server if isinstance(dhcp_server, str) else None,
            lease_obtained=lease_obtained if isinstance(lease_obtained, datetime) else None,
            lease_expires=lease_expires if isinstance(lease_expires, datetime) else None,
            gateways=b.gateways,
            dns_servers=b.dns_servers,
            is_apipa=apipa,
        )
        by_ip[b.ipv4] = snap

    return list(by_ip.values())


def fetch_dhcp_client_event_log(max_events: int = _EVENT_LOG_MAX) -> tuple[str, str | None]:
    if sys.platform != "win32":
        return "", "非 Windows，跳过 DHCP 客户端事件日志。"
    ps = (
        f"$e = Get-WinEvent -LogName 'Microsoft-Windows-Dhcp-Client/Operational' "
        f"-MaxEvents {int(max_events)} -ErrorAction SilentlyContinue; "
        "if (-not $e) { '（无记录或日志不可用）' } else { "
        "$e | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + ' Id=' + $_.Id + ' ' + $_.Message } }"
    )
    try:
        pr = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            creationflags=_creationflags_no_window(),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return "", str(e)
    text = (pr.stdout or "").strip()
    if not text:
        err = (pr.stderr or "").strip()
        return "", err or "未能读取 DHCP 客户端事件日志"
    return text, None


def evaluate_client_health(
    snap: DhcpClientSnapshot,
    *,
    scope_cidr: str | None = None,
    ping_dhcp_server: bool = True,
) -> DhcpClientSnapshot:
    flags: list[str] = []
    reachable: bool | None = None

    if snap.is_apipa:
        flags.append("APIPA")
    if snap.address_source == "dhcp" and not snap.dhcp_server:
        flags.append("NO_DHCP_SERVER")
    if not snap.gateways:
        flags.append("GATEWAY_EMPTY")
    if not snap.dns_servers:
        flags.append("DNS_EMPTY")

    now = datetime.now()
    if snap.lease_expires is not None:
        if snap.lease_expires < now:
            flags.append("LEASE_EXPIRED")
        elif snap.lease_obtained is not None:
            total = snap.lease_expires - snap.lease_obtained
            remain = snap.lease_expires - now
            if total.total_seconds() > 0 and remain.total_seconds() < max(3600, total.total_seconds() * 0.1):
                flags.append("LEASE_EXPIRING_SOON")
        elif snap.lease_expires - now < timedelta(hours=1):
            flags.append("LEASE_EXPIRING_SOON")

    if scope_cidr and snap.address_source == "manual":
        try:
            net = ipaddress.ip_network(scope_cidr.strip(), strict=False)
            addr = ipaddress.ip_address(snap.ipv4)
            if isinstance(addr, ipaddress.IPv4Address) and addr in net:
                flags.append("STATIC_ON_DHCP_SCOPE")
        except ValueError:
            pass

    if ping_dhcp_server and snap.dhcp_server and _is_ipv4(snap.dhcp_server):
        ok, _ = ping_ipv4_once(snap.dhcp_server, 800)
        reachable = ok
        if not ok:
            flags.append("DHCP_SERVER_UNREACHABLE")

    return DhcpClientSnapshot(
        interface_name=snap.interface_name,
        mac=snap.mac,
        ipv4=snap.ipv4,
        netmask=snap.netmask,
        address_source=snap.address_source,
        dhcp_enabled=snap.dhcp_enabled,
        dhcp_server=snap.dhcp_server,
        lease_obtained=snap.lease_obtained,
        lease_expires=snap.lease_expires,
        gateways=snap.gateways,
        dns_servers=snap.dns_servers,
        is_apipa=snap.is_apipa,
        health_flags=tuple(flags),
        dhcp_server_reachable=reachable,
    )


def pick_client_for_interface(clients: list[DhcpClientSnapshot], interface_ipv4: str) -> DhcpClientSnapshot | None:
    for c in clients:
        if c.ipv4 == interface_ipv4.strip():
            return c
    return None


def format_address_source(src: str) -> str:
    return {
        "dhcp": "DHCP",
        "manual": "静态",
        "apipa": "APIPA",
        "unknown": "未知",
    }.get(src, src)
