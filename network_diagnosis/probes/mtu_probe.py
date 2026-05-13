"""IPv4 ICMP MTU 粗测：二分 ping payload（-f / -M do），估算路径 MTU。"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import sys
from pathlib import Path

from network_diagnosis.model.report import MtuProbeResult


def _is_v6_literal(host: str) -> bool:
    base = host.strip().rstrip(".").split("%", 1)[0]
    try:
        return isinstance(ipaddress.ip_address(base), ipaddress.IPv6Address)
    except ValueError:
        return False


def _ping_ok(host: str, payload: int, *, ipv6: bool, log: list[str]) -> bool:
    if ipv6:
        return False
    if sys.platform == "win32":
        argv = ["ping", "-n", "1", "-w", "4000", "-f", "-l", str(payload), host]
    else:
        if not shutil.which("ping"):
            return False
        argv = ["ping", "-c", "1", "-W", "3", "-M", "do", "-s", str(payload), host]
    cf = 0
    if sys.platform == "win32":
        try:
            cf = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        except AttributeError:
            pass
    log.append(f"> {' '.join(argv)}")
    try:
        pr = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=12,
            creationflags=cf,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        log.append(f"(异常 {e})")
        return False
    out = (pr.stdout or "") + "\n" + (pr.stderr or "")
    log.append(out.strip()[:400].replace("\r\n", "\n"))
    low = out.lower()
    ok = (
        "reply from" in low
        or "来自" in out
        or "ttl=" in low
        or "ttl=" in out.lower()
        or "bytes from" in low
    )
    bad = (
        "timed out" in low
        or "超时" in out
        or "unreachable" in low
        or "无法访问" in out
        or "packet needs to be fragmented" in low
        or "packet too big" in low
        or "frag needed" in low
        or "need to frag" in low
    )
    return ok and not bad


def run_mtu_probe(
    host: str,
    *,
    prefer_ipv6: bool,
    log_dir: Path,
) -> MtuProbeResult:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "mtu_probe.log"
    lines: list[str] = []
    lines.append(f"目标: {host}（prefer_ipv6={prefer_ipv6}）")
    if prefer_ipv6 or _is_v6_literal(host):
        msg = "当前 MTU 二分仅实现 IPv4 ICMP；IPv6 目标或未解析为 IPv4 链路的场景已跳过。"
        lines.append(msg)
        log_path.write_text("\n".join(lines), encoding="utf-8")
        return MtuProbeResult(
            target=host,
            max_icmp_payload=None,
            implied_ipv4_mtu=None,
            summary=msg,
            raw_log_path=log_path,
        )

    lo, hi = 500, 1472
    best: int | None = None
    low_bound, high_bound = lo, hi
    while low_bound <= high_bound:
        mid = (low_bound + high_bound) // 2
        if _ping_ok(host, mid, ipv6=False, log=lines):
            best = mid
            low_bound = mid + 1
        else:
            high_bound = mid - 1

    implied = (best + 28) if best is not None else None
    if best is None:
        summ = "未得到成功的 DF 探测包，可能禁 ping、目标仅 IPv6 或与 ping 实现不兼容。"
    else:
        summ = (
            f"在 IPv4 DF 探测下，最大 ICMP 数据载荷约 {best} 字节，"
            f"对应 IPv4 MTU 约 {implied}（载荷 + 20 IP 头 + 8 ICMP 头，仅供参考）。"
        )
    lines.append(summ)
    log_path.write_text("\n".join(lines), encoding="utf-8")
    return MtuProbeResult(
        target=host,
        max_icmp_payload=best,
        implied_ipv4_mtu=implied,
        summary=summ,
        raw_log_path=log_path,
    )
