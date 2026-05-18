"""IPv4 ICMP 存活扫描：调用系统 ``ping``，供「IP 扫描」页主机发现。"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event

from network_diagnosis.probes.ping_probe import _parse_ping_line, _parse_ping_summary_stats
from network_diagnosis.subnet_calc import is_ipv4_dotted

MAX_SCAN_HOSTS_HARD_LIMIT = 4096


def _creationflags() -> int:
    if sys.platform == "win32":
        try:
            return subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        except AttributeError:
            return 0
    return 0


def _decode_output(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp936"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def ping_ipv4_once(ip: str, timeout_ms: int) -> tuple[bool, float | None]:
    """对单地址发送 1 次 ICMP（Windows: ``ping -n 1``），返回是否存活与 RTT（若可解析）。"""
    argv = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    proc_timeout = max(5.0, timeout_ms / 1000.0 + 8.0)
    try:
        p = subprocess.run(
            argv,
            capture_output=True,
            timeout=proc_timeout,
            creationflags=_creationflags(),
        )
    except subprocess.TimeoutExpired:
        return False, None
    text = _decode_output((p.stdout or b"") + (p.stderr or b""))

    _sent, recv, _lost = _parse_ping_summary_stats(text)
    if recv is not None and recv >= 1:
        for line in text.splitlines():
            ps = _parse_ping_line(line)
            if ps and ps.rtt_ms is not None:
                return True, float(ps.rtt_ms)
        return True, None

    if re.search(r"Reply from|来自.+的回复", text, re.I):
        return True, None

    return False, None


def _parse_ip_range(spec: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address] | None:
    """解析 ``a.b.c.d - e.f.g.h``（允许两侧空白）；若不是双地址范围则返回 ``None``。"""
    if "/" in spec:
        return None
    parts = spec.split("-", 1)
    if len(parts) != 2:
        return None
    left, right = parts[0].strip(), parts[1].strip()
    if not is_ipv4_dotted(left) or not is_ipv4_dotted(right):
        return None
    try:
        ia = ipaddress.ip_address(left)
        ib = ipaddress.ip_address(right)
    except ValueError:
        return None
    if not isinstance(ia, ipaddress.IPv4Address) or not isinstance(ib, ipaddress.IPv4Address):
        return None
    return ia, ib


def parse_scan_targets(spec: str, *, max_hosts: int) -> tuple[list[str], str]:
    """解析扫描地址列表（顺序递增、去重）。超出 ``max_hosts`` 则抛出 ``ValueError``。"""
    raw = spec.strip()
    if not raw:
        raise ValueError("请填写 IPv4 CIDR、单个地址或起止 IP 范围（形如 192.168.1.1-192.168.1.254）。")
    if max_hosts < 1 or max_hosts > MAX_SCAN_HOSTS_HARD_LIMIT:
        raise ValueError(f"单次扫描地址上限须在 1–{MAX_SCAN_HOSTS_HARD_LIMIT} 之间。")

    rng = _parse_ip_range(raw)
    if rng is not None:
        ia, ib = rng
        lo, hi = int(ia), int(ib)
        if lo > hi:
            lo, hi = hi, lo
        span = hi - lo + 1
        if span > max_hosts:
            raise ValueError(f"范围内共 {span} 个地址，超过当前上限 {max_hosts}；请缩小范围或调高上限。")
        ips = [str(ipaddress.IPv4Address(i)) for i in range(lo, hi + 1)]
        summary = f"{ips[0]} – {ips[-1]}（共 {len(ips)} 个地址）"
        return ips, summary

    try:
        one = ipaddress.ip_address(raw)
        if isinstance(one, ipaddress.IPv4Address):
            return [str(one)], f"单个地址 {one}"
    except ValueError:
        pass

    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError as e:
        raise ValueError(f"无法解析扫描范围：{e}") from e

    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError("当前仅支持 IPv4。")

    ips: list[str] = []
    if net.prefixlen == 32:
        ips = [str(net.network_address)]
    else:
        for host in net.hosts():
            ips.append(str(host))
            if len(ips) > max_hosts:
                raise ValueError(
                    f"网段内待扫描主机超过上限 {max_hosts}（可用「起止 IP」缩小范围，或调高单次上限）。"
                )

    summary = f"{net.compressed}（{len(ips)} 个主机地址）"
    return ips, summary


def run_ping_scan(
    ips: list[str],
    *,
    timeout_ms: int,
    max_workers: int,
    cancel_event: Event,
    on_each: Callable[[str, bool, float | None], None],
    on_progress: Callable[[int, int], None] | None = None,
) -> tuple[int, bool]:
    """并发 ICMP 探测；``on_each`` 在每地址完成后调用（在工作线程内）。

    返回 ``(在线数量, 是否用户中止)``。
    """
    if max_workers < 1:
        max_workers = 1
    total = len(ips)
    alive_total = 0
    completed = 0
    cancelled = False

    executor = ThreadPoolExecutor(max_workers=max_workers)
    futures_map = {executor.submit(ping_ipv4_once, ip, timeout_ms): ip for ip in ips}
    try:
        for fut in as_completed(futures_map):
            if cancel_event.is_set():
                cancelled = True
                executor.shutdown(wait=False, cancel_futures=True)
                break
            ip = futures_map[fut]
            try:
                alive, rtt = fut.result()
            except Exception:
                alive, rtt = False, None
            if alive:
                alive_total += 1
            on_each(ip, alive, rtt)
            completed += 1
            if on_progress is not None:
                on_progress(completed, total)
    finally:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    return alive_total, cancelled
