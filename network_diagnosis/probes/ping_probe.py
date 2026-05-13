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


def _parse_ping_summary_stats(text: str) -> tuple[int | None, int | None, int | None]:
    """解析 Windows ping 结束时的发送/接收/丢失统计。"""
    m = re.search(
        r"Sent\s*=\s*(\d+).*?Received\s*=\s*(\d+).*?Lost\s*=\s*(\d+)",
        text,
        re.I | re.S,
    )
    if m:
        sent, recv, lost = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return sent, recv, lost
    m = re.search(
        r"已发送\s*=\s*(\d+).*?已接收\s*=\s*(\d+).*?丢失\s*=\s*(\d+)",
        text,
        re.S,
    )
    if m:
        sent, recv, lost = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return sent, recv, lost
    m = re.search(r"Packets:\s*Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)", text, re.I)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return None, None, None


def run_ping(
    host: str,
    count: int,
    timeout_ms: int,
    log_dir: Path,
    *,
    long_duration_sec: int | None = None,
) -> PingStats:
    if long_duration_sec is not None and long_duration_sec > 0:
        argv = ["ping", "-t", "-w", str(timeout_ms), host]
        stem = "ping_long"
        timeout_sec = float(long_duration_sec) + 15.0
    else:
        argv = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
        stem = "ping"
        timeout_sec = max(30.0, count * (timeout_ms / 1000.0) + 10)
    r = run_to_log_files(argv, log_dir, stem, timeout_sec=timeout_sec)
    text = read_text_best_effort(r.stdout_path)
    rtts: list[float] = []
    for line in text.splitlines():
        ps = _parse_ping_line(line)
        if ps and ps.rtt_ms is not None:
            rtts.append(ps.rtt_ms)

    sent_s, recv_s, lost_s = _parse_ping_summary_stats(text)
    if sent_s is not None:
        attempted, received, lost = sent_s, recv_s or 0, lost_s or 0
    else:
        if long_duration_sec is None:
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
        else:
            timeouts = len(re.findall(r"Request timed out|请求超时", text, re.I))
            received = len(rtts)
            lost = timeouts
            attempted = received + lost
            if attempted == 0 and received == 0:
                attempted = 1

    return PingStats(
        attempted=attempted,
        received=received,
        lost=lost,
        rtts_ms=rtts,
        raw_stdout_path=r.stdout_path,
        raw_stderr_path=r.stderr_path,
        command=argv,
    )
