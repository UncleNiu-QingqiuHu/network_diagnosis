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
    scope_note: str
    host_role_note: str


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


def ipv4_network_scope_zh(net: ipaddress.IPv4Network) -> str:
    """本网段网络地址所属 IPv4 分类（运维可读摘要）。"""
    a = net.network_address
    if not isinstance(a, ipaddress.IPv4Address):
        return "非 IPv4"
    if a.is_loopback:
        return "环回（127.0.0.0/8）"
    if a.is_link_local:
        return "链路本地（169.254.0.0/16）"
    if a.is_multicast:
        return "组播"
    if a.is_reserved:
        return "保留地址"
    shared = ipaddress.ip_network("100.64.0.0/10")
    if a in shared:
        return "运营商共享地址空间（RFC 6598，常见 CGNAT，100.64.0.0/10）"
    if a.is_private:
        return "私有单播（RFC 1918）"
    if a.is_global:
        return "全局单播（公网）"
    return "其它"


def ipv4_host_role_zh(ip: ipaddress.IPv4Address, net: ipaddress.IPv4Network) -> str:
    """输入 IP 相对本网的角色说明。"""
    pl = net.prefixlen
    if pl >= 32:
        return "/32 单主机前缀"
    if pl == 31:
        return "/31 点对点段内地址（RFC 3021）"
    if ip == net.network_address:
        return "网络地址（通常不可分配给主机）"
    if ip == net.broadcast_address:
        return "定向广播地址（通常不可分配给主机）"
    try:
        if ip in net.hosts():
            return "可用主机地址"
    except ValueError:
        pass
    return "不在本网可用主机集合内（请检查输入）"


def subdivide_ipv4_equal_children(parent_spec: str, child_prefix: int, *, max_list: int = 64) -> str:
    """
    将父 IPv4 网等长子网划分为 ``child_prefix`` 长度的子网列表文本。

    ``max_list`` 控制最多列出的条数，超出部分以摘要行说明。
    """
    s = parent_spec.strip()
    if not s:
        raise ValueError("请填写父网 CIDR。")
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError as e:
        raise ValueError(f"父网 CIDR 无效：{e}") from e
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError("当前仅支持 IPv4 父网。")
    if not 0 <= child_prefix <= 32:
        raise ValueError("子网前缀须在 0–32 之间。")
    if child_prefix <= net.prefixlen:
        raise ValueError(f"子网前缀须大于父网前缀 /{net.prefixlen}。")

    subs = tuple(net.subnets(new_prefix=child_prefix))
    total = len(subs)
    lines: list[str] = [
        "=== 等长子网划分 ===",
        "",
        f"父网：{net.with_prefixlen}",
        f"划至前缀：/{child_prefix}",
        f"子网数量：{total}",
        "",
    ]
    cap = max(1, max_list)
    shown = subs[:cap]
    for i, sn in enumerate(shown, 1):
        lines.append(f"{i:>4}. {sn.with_prefixlen}")
    if total > len(shown):
        lines.append(f"... 省略其余 {total - len(shown)} 条（共 {total} 个子网）")
    lines.append("")
    return "\n".join(lines)


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
    hip = iface.ip
    if not isinstance(hip, ipaddress.IPv4Address):
        raise ValueError("当前仅支持 IPv4。")
    scope = ipv4_network_scope_zh(net)
    role = ipv4_host_role_zh(hip, net)
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
        scope_note=scope,
        host_role_note=role,
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
