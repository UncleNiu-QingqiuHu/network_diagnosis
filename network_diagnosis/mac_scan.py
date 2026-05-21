"""MAC 扫描：同网段 ICMP + ARP 表 + 可选主机名解析。"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from threading import Event

from network_diagnosis.arp_monitor import (
    ipv4_interface_network,
    normalize_mac,
    parse_arp_entries_full,
    run_arp_a_text,
)
from network_diagnosis.host_l3_info import AdapterIPv4Block, list_local_ipv4_adapters
from network_diagnosis.ip_scan import ping_ipv4_once, run_ping_scan
from network_diagnosis.oui_lookup import lookup_vendor

_PING_NAME_RE = re.compile(
    r"(?:Pinging|正在\s*Ping)\s+(.+?)\s+\[\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\]",
    re.I,
)
_NBT_HOST_RE = re.compile(r"^\s*([A-Z0-9][A-Z0-9_-]{0,14})\s+<00>\s+UNIQUE", re.I | re.M)


@dataclass(frozen=True)
class SelectedScanInterface:
    """本次扫描绑定的本机接口。"""

    local_ipv4: str
    netmask: str
    gateway_ipv4: str | None
    network: ipaddress.IPv4Network
    local_mac: str | None = None

    @property
    def interface_summary(self) -> str:
        return f"经本机 {self.local_ipv4} / {self.netmask}"


@dataclass
class MacScanRow:
    ip: str
    alive: bool = False
    rtt_ms: float | None = None
    mac: str | None = None
    arp_type: str = "—"
    vendor: str = "—"
    remark: str = ""
    computer_name: str = "—"


def _creationflags_no_window() -> int:
    if sys.platform != "win32":
        return 0
    try:
        return subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    except AttributeError:
        return 0


def resolve_scan_interface(
    target_ips: list[str],
    adapters: list[AdapterIPv4Block],
) -> SelectedScanInterface:
    """校验目标均在本机网段且处于同一网段，并选择重叠最大的接口。"""
    if not adapters:
        raise ValueError("未检测到可用的本机 IPv4 网卡，无法执行 MAC 扫描。")

    targets: list[ipaddress.IPv4Address] = []
    for s in target_ips:
        a = ipaddress.ip_address(s.strip())
        if not isinstance(a, ipaddress.IPv4Address):
            raise ValueError(f"仅支持 IPv4：{s}")
        targets.append(a)

    pairs: list[tuple[AdapterIPv4Block, ipaddress.IPv4Network]] = []
    for block in adapters:
        net = ipv4_interface_network(block.ipv4, block.netmask)
        if net is not None:
            pairs.append((block, net))

    if not pairs:
        raise ValueError("未检测到有效的本机 IPv4 网段配置。")

    viable: list[tuple[AdapterIPv4Block, ipaddress.IPv4Network]] = []
    for block, net in pairs:
        if all(t in net for t in targets):
            viable.append((block, net))

    if not viable:
        raise ValueError(
            "MAC 扫描仅支持本机所在网段；请调整范围或在本机对应网段网卡上操作。"
        )

    scan_net = max((net for _b, net in viable), key=lambda n: n.prefixlen)
    block = next((b for b, net in viable if net == scan_net), viable[0][0])
    net = scan_net
    gw = block.gateways[0].strip() if block.gateways else None
    if gw and not gw:
        gw = None
    return SelectedScanInterface(
        local_ipv4=block.ipv4.strip(),
        netmask=block.netmask.strip(),
        gateway_ipv4=gw,
        network=net,
        local_mac=block.mac,
    )


def _mac_duplicate_ips(arp: dict[str, tuple[str, str]]) -> set[str]:
    """返回出现 MAC 重复的 IP 集合。"""
    by_mac: dict[str, list[str]] = {}
    for ip, (mac, _typ) in arp.items():
        if not mac or mac in ("—", ""):
            continue
        by_mac.setdefault(mac, []).append(ip)
    dup_ips: set[str] = set()
    for ips in by_mac.values():
        if len(ips) > 1:
            dup_ips.update(ips)
    return dup_ips


def build_remark(
    ip: str,
    *,
    alive: bool,
    mac: str | None,
    iface: SelectedScanInterface,
    dup_ips: set[str],
) -> str:
    tags: list[str] = []
    if ip == iface.local_ipv4:
        tags.append("本机")
    if iface.gateway_ipv4 and ip == iface.gateway_ipv4:
        tags.append("网关")
    if ip in dup_ips:
        tags.append("MAC重复")
    if alive and not mac:
        tags.append("无MAC")
    return "，".join(tags)


def merge_scan_rows(
    ips: list[str],
    ping: dict[str, tuple[bool, float | None]],
    arp: dict[str, tuple[str, str]],
    iface: SelectedScanInterface,
) -> dict[str, MacScanRow]:
    dup_ips = _mac_duplicate_ips(arp)
    out: dict[str, MacScanRow] = {}
    for ip in ips:
        alive, rtt = ping.get(ip, (False, None))
        mac: str | None = None
        arp_type = "—"
        if ip in arp:
            mac, arp_type = arp[ip]
        elif ip == iface.local_ipv4 and iface.local_mac:
            # 本机地址不会出现在 arp -a 中，改用所选网卡的 MAC。
            mac = normalize_mac(iface.local_mac)
            arp_type = "local"
        vendor = lookup_vendor(mac)
        remark = build_remark(
            ip,
            alive=alive,
            mac=mac,
            iface=iface,
            dup_ips=dup_ips,
        )
        out[ip] = MacScanRow(
            ip=ip,
            alive=alive,
            rtt_ms=rtt,
            mac=mac,
            arp_type=arp_type if arp_type else "—",
            vendor=vendor,
            remark=remark,
        )
    return out


def _decode_subprocess_output(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp936"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def resolve_name_ping_a(ip: str, timeout_ms: int) -> str | None:
    """Windows ``ping -a`` 解析首行主机名。"""
    argv = ["ping", "-a", "-n", "1", "-w", str(timeout_ms), ip]
    proc_timeout = max(3.0, timeout_ms / 1000.0 + 5.0)
    try:
        p = subprocess.run(
            argv,
            capture_output=True,
            timeout=proc_timeout,
            creationflags=_creationflags_no_window(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = _decode_subprocess_output((p.stdout or b"") + (p.stderr or b""))
    m = _PING_NAME_RE.search(text)
    if not m:
        return None
    name = m.group(1).strip()
    if not name or name == ip:
        return None
    return name


def resolve_name_dns_ptr(ip: str, timeout_sec: float = 2.0) -> str | None:
    try:
        socket.setdefaulttimeout(timeout_sec)
        host, _aliases, _ = socket.gethostbyaddr(ip)
        socket.setdefaulttimeout(None)
        host = (host or "").strip().rstrip(".")
        if host and host != ip:
            return host
    except OSError:
        pass
    finally:
        try:
            socket.setdefaulttimeout(None)
        except OSError:
            pass
    return None


def resolve_name_netbios(ip: str, timeout_sec: float = 4.0) -> str | None:
    argv = ["nbtstat", "-A", ip]
    try:
        p = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout_sec,
            creationflags=_creationflags_no_window(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = _decode_subprocess_output((p.stdout or b"") + (p.stderr or b""))
    for m in _NBT_HOST_RE.finditer(text):
        name = m.group(1).strip()
        if name:
            return name
    return None


def resolve_host_labels(
    ip: str,
    *,
    timeout_ms: int,
    use_dns: bool,
    use_netbios: bool,
) -> tuple[str | None, str | None]:
    """返回 ``(计算机名, DNS 名称)``，未解析为 ``None``。"""
    computer: str | None = resolve_name_ping_a(ip, timeout_ms)
    dns_name: str | None = None
    if use_dns:
        dns_name = resolve_name_dns_ptr(ip)
        if computer is None and dns_name:
            computer = dns_name.split(".")[0] if dns_name else None
    if computer is None and use_netbios:
        computer = resolve_name_netbios(ip)
    return computer, dns_name


def run_mac_scan(
    ips: list[str],
    iface: SelectedScanInterface,
    *,
    timeout_ms: int,
    max_workers: int,
    cancel_event: Event,
    on_ping: Callable[[str, bool, float | None], None] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> tuple[dict[str, tuple[bool, float | None]], dict[str, tuple[str, str]], bool]:
    """
    阶段 A：ICMP；阶段 B：``arp -a``。

    返回 ``(ping 结果, arp 全表条目, 是否用户中止)``。
    """
    ping_out: dict[str, tuple[bool, float | None]] = {}

    def _on_each(ip: str, alive: bool, rtt: float | None) -> None:
        ping_out[ip] = (alive, rtt)
        if on_ping is not None:
            on_ping(ip, alive, rtt)

    alive_n, cancelled = run_ping_scan(
        ips,
        timeout_ms=timeout_ms,
        max_workers=max_workers,
        cancel_event=cancel_event,
        on_each=_on_each,
        on_progress=on_progress,
    )
    _ = alive_n
    if cancel_event.is_set():
        return ping_out, {}, True

    arp_text, _err = run_arp_a_text()
    arp_all = parse_arp_entries_full(arp_text)
    return ping_out, arp_all, cancelled


def run_host_label_scan(
    ips: list[str],
    *,
    timeout_ms: int,
    use_dns: bool,
    use_netbios: bool,
    max_workers: int,
    cancel_event: Event,
    on_each: Callable[[str, str | None, str | None], None],
) -> None:
    """并发解析计算机名 / DNS 名称。"""
    if max_workers < 1:
        max_workers = 1
    workers = min(max_workers, 16) if use_netbios else min(max_workers, 32)

    def task(ip: str) -> tuple[str, str | None, str | None]:
        cn, dns = resolve_host_labels(
            ip,
            timeout_ms=timeout_ms,
            use_dns=use_dns,
            use_netbios=use_netbios,
        )
        return ip, cn, dns

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(task, ip): ip for ip in ips}
        for fut in as_completed(futs):
            if cancel_event.is_set():
                ex.shutdown(wait=False, cancel_futures=True)
                break
            ip = futs[fut]
            try:
                _ip, cn, dns = fut.result()
            except Exception:
                cn, dns = None, None
            on_each(ip, cn, dns)
