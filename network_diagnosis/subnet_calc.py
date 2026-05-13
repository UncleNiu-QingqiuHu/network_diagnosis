"""IPv4 子网计算（标准库 ipaddress）。"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SubnetCalcResult:
    """单次计算结果，供界面展示。"""

    input_interface: str
    network_cidr: str
    network_address: str
    broadcast_address: str
    netmask: str
    wildcard_mask: str
    prefix_len: int
    total_addresses: int
    usable_hosts: int
    first_host: str
    last_host: str


_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def is_ipv4_dotted(s: str) -> bool:
    s = s.strip()
    return bool(s and _IPV4_RE.match(s))


def usable_host_count(net: ipaddress.IPv4Network) -> int:
    """可用主机数（含 /32、/31 的常见语义）。"""
    pl = net.prefixlen
    if pl >= 32:
        return 1
    if pl == 31:
        return 2
    return max(int(net.num_addresses) - 2, 0)


def _first_last_host_ip(net: ipaddress.IPv4Network) -> tuple[str, str]:
    hosts = list(net.hosts())
    if not hosts:
        a = str(net.network_address)
        return a, a
    return str(hosts[0]), str(hosts[-1])


def calc_subnet(
    ip_part: str,
    *,
    prefix_len: int | None = None,
    netmask_dotted: str | None = None,
) -> SubnetCalcResult:
    """
    根据主机 IPv4 与前缀长度或点分掩码计算所属网络。

    ``ip_part`` 不得含 ``/``；掩码与前缀二选一，若均提供则优先采用点分掩码。
    """
    addr = ip_part.strip()
    if not is_ipv4_dotted(addr):
        raise ValueError("IP 须为合法的点分 IPv4。")
    spec: str
    if netmask_dotted and netmask_dotted.strip():
        m = netmask_dotted.strip()
        if not is_ipv4_dotted(m):
            raise ValueError("子网掩码须为点分十进制 IPv4。")
        spec = f"{addr}/{m}"
    elif prefix_len is not None:
        if not 0 <= prefix_len <= 32:
            raise ValueError("前缀长度须在 0–32 之间。")
        spec = f"{addr}/{prefix_len}"
    else:
        raise ValueError("请填写前缀长度或子网掩码。")

    iface = ipaddress.ip_interface(spec)
    net = iface.network
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError("当前仅支持 IPv4。")

    first_s, last_s = _first_last_host_ip(net)
    return SubnetCalcResult(
        input_interface=spec,
        network_cidr=f"{net.network_address}/{net.prefixlen}",
        network_address=str(net.network_address),
        broadcast_address=str(net.broadcast_address),
        netmask=str(net.netmask),
        wildcard_mask=str(net.hostmask),
        prefix_len=net.prefixlen,
        total_addresses=int(net.num_addresses),
        usable_hosts=usable_host_count(net),
        first_host=first_s,
        last_host=last_s,
    )


def calc_from_cidr_combo(combo: str) -> SubnetCalcResult:
    """解析 ``192.168.1.10/24`` 或 ``192.168.1.10/255.255.255.0``。"""
    s = combo.strip()
    if "/" not in s:
        raise ValueError(
            '请使用 "IP/前缀" 或 "IP/掩码" 格式，或改用下方「单地址 + 子网」拆分填写。'
        )
    iface = ipaddress.ip_interface(s)
    net = iface.network
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError("当前仅支持 IPv4。")
    addr = str(iface.ip)
    return calc_subnet(addr, prefix_len=net.prefixlen)
