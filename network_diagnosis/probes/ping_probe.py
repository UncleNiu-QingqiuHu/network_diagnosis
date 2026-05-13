"""ICMP ping（Windows ping.exe）。"""

from __future__ import annotations

import re
from pathlib import Path

from network_diagnosis.model.report import PingSample, PingStats
from network_diagnosis.probes.subproc_util import read_text_best_effort, run_to_log_files


def _parse_ping_line(line: str) -> PingSample | None:
    # 英文: Reply from 1.2.3.4: bytes=32 time=12ms TTL=54
    # 中文: 来自 1.2.3.4 的回复: 字节=32 时间=12ms TTL=54
    m = re.search(r"time[=<]([0-9]+)\s*ms", line, re.I)
    if not m:
        m = re.search(r"时间[=<]([0-9]+)\s*ms", line, re.I)
    rtt = float(m.group(1)) if m else None
    ttl_m = re.search(r"TTL[=<]([0-9]+)", line, re.I)
    if not ttl_m:
        ttl_m = re.search(r"TTL[=<]([0-9]+)", line)
    ttl = int(ttl_m.group(1)) if ttl_m else None
    if rtt is None and "TTL" not in line and "ttl" not in line.lower():
        return None
    return PingSample(rtt_ms=rtt, ttl=ttl, line=line.strip())


def run_ping(host: str, count: int, timeout_ms: int, log_dir: Path) -> PingStats:
    argv = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
    r = run_to_log_files(
        argv,
        log_dir,
        "ping",
        timeout_sec=max(30.0, count * (timeout_ms / 1000.0) + 10),
    )
    text = read_text_best_effort(r.stdout_path)
    rtts: list[float] = []
    samples: list[PingSample] = []
    for line in text.splitlines():
        ps = _parse_ping_line(line)
        if ps and ps.rtt_ms is not None:
            samples.append(ps)
            rtts.append(ps.rtt_ms)
    # Windows 汇总行: (4 丢失 = 100% 丢失) 或 Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),
    lost = 0
    received = len(rtts)
    attempted = count
    m = re.search(r"Lost\s*=\s*(\d+)", text, re.I)
    if m:
        lost = int(m.group(1))
        received = max(0, attempted - lost)
    else:
        m = re.search(r"丢失\s*=\s*(\d+)", text)
        if m:
            lost = int(m.group(1))
            received = max(0, attempted - lost)
    return PingStats(
        attempted=attempted,
        received=received,
        lost=lost,
        rtts_ms=rtts,
        raw_stdout_path=r.stdout_path,
        raw_stderr_path=r.stderr_path,
        command=argv,
    )
