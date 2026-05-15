"""Windows ARP 表解析与网关 MAC 一致性检测（供内网 ARP 监控页使用）。"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from dataclasses import dataclass


_MAC_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+(\S+)",
    re.MULTILINE,
)


def _creationflags_no_window() -> int:
    if sys.platform != "win32":
        return 0
    try:
        return subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    except AttributeError:
        return 0


def normalize_mac(mac: str) -> str:
    """统一为大写、连字符分隔。"""
    s = mac.strip().replace(":", "-").upper()
    parts = s.split("-")
    if len(parts) != 6:
        return s
    return "-".join(p.zfill(2)[-2:] for p in parts)


def run_arp_a_text() -> tuple[str, str | None]:
    """执行 `arp -a`，返回 (stdout 文本, 错误说明)。"""
    try:
        pr = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            timeout=20,
            creationflags=_creationflags_no_window(),
        )
    except OSError as e:
        return "", str(e)
    except subprocess.TimeoutExpired:
        return "", "arp -a 超时"
    raw = pr.stdout or b""
    text = None
    for enc in ("utf-8", "gbk", "cp936"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = raw.decode("utf-8", errors="replace")
    if pr.returncode != 0:
        err = (pr.stderr or b"").decode("utf-8", errors="replace").strip()
        return text, err or f"arp 退出码 {pr.returncode}"
    return text, None


def parse_arp_entries(arp_text: str) -> dict[str, str]:
    """IP → 规范化 MAC。"""
    out: dict[str, str] = {}
    for m in _MAC_RE.finditer(arp_text):
        ip_s, mac_s, _typ = m.group(1), m.group(2), m.group(3)
        out[ip_s.strip()] = normalize_mac(mac_s)
    return out


def ipv4_interface_network(ipv4: str, netmask: str) -> ipaddress.IPv4Network | None:
    """由地址与点分掩码得到所属网络。"""
    if not netmask or netmask.strip() == "—":
        return None
    try:
        iface = ipaddress.ip_interface(f"{ipv4.strip()}/{netmask.strip()}")
        net = iface.network
        if isinstance(net, ipaddress.IPv4Network):
            return net
    except ValueError:
        return None
    return None


def count_ips_on_network(arp_ips: dict[str, str], net: ipaddress.IPv4Network) -> int:
    """统计 ARP 表中落在该 IPv4 网段内的地址数量（含网关与本机）。"""
    n = 0
    for ip_s in arp_ips:
        try:
            a = ipaddress.ip_address(ip_s)
            if isinstance(a, ipaddress.IPv4Address) and a in net:
                n += 1
        except ValueError:
            continue
    return n


@dataclass(frozen=True)
class ArpGatewaySnapshot:
    local_ip: str
    gateway_ip: str
    gateway_mac: str | None
    network_cidr: str | None
    subnet_entry_count: int
    total_arp_entries: int
    arp_error: str | None


def build_snapshot(
    arp_text: str,
    *,
    local_ip: str,
    netmask: str,
    gateway_ip: str,
    arp_command_error: str | None,
) -> ArpGatewaySnapshot:
    entries = parse_arp_entries(arp_text)
    gw_mac = entries.get(gateway_ip.strip()) or entries.get(gateway_ip)
    net = ipv4_interface_network(local_ip, netmask)
    cidr = net.with_prefixlen if net else None
    sub_cnt = count_ips_on_network(entries, net) if net else len(entries)
    return ArpGatewaySnapshot(
        local_ip=local_ip.strip(),
        gateway_ip=gateway_ip.strip(),
        gateway_mac=gw_mac,
        network_cidr=cidr,
        subnet_entry_count=sub_cnt,
        total_arp_entries=len(entries),
        arp_error=arp_command_error,
    )
