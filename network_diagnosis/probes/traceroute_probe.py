"""路由追踪：Windows 使用 tracert，其他系统尝试 traceroute。"""

from __future__ import annotations

import ipaddress
import re
import shutil
import sys
from pathlib import Path

from network_diagnosis.model.report import TracerouteStats
from network_diagnosis.probes.subproc_util import RunResult, read_text_best_effort, run_to_log_files


def _use_ipv6_trace(host: str, prefer_ipv6: bool) -> bool:
    base = host.strip().rstrip(".").split("%", 1)[0]
    try:
        ipaddress.IPv6Address(base)
        return True
    except ValueError:
        return prefer_ipv6


def _build_argv(
    host: str,
    *,
    prefer_ipv6: bool,
    max_hops: int,
    hop_timeout_ms: int,
) -> tuple[list[str], str]:
    max_hops = max(2, min(64, max_hops))
    hop_timeout_ms = max(500, min(60_000, hop_timeout_ms))

    if sys.platform == "win32":
        exe = shutil.which("tracert") or "tracert"
        argv = [exe, "-d", "-h", str(max_hops), "-w", str(hop_timeout_ms)]
        if _use_ipv6_trace(host, prefer_ipv6):
            argv.insert(1, "-6")
        argv.append(host)
        return argv, "tracert"

    exe = shutil.which("traceroute") or shutil.which("traceroute6")
    if not exe:
        return [], ""
    w_sec = max(1, hop_timeout_ms // 1000)
    argv = [exe, "-n", "-m", str(max_hops), "-q", "1", "-w", str(w_sec), host]
    return argv, "traceroute"


def _outline_from_output(text: str, rc: int | None, tool: str) -> str:
    low = text.lower()
    complete = "trace complete." in low or "跟踪完成" in text
    hop_re = re.compile(r"^\s*(\d+)\s+")
    hop_lines = [ln for ln in text.splitlines() if hop_re.match(ln)]
    n = len(hop_lines)
    parts: list[str] = []
    if tool == "tracert":
        parts.append("工具：Windows tracert（ICMP，路径上设备可能不回显但仍会显示超时跃点）。")
    elif tool == "traceroute":
        parts.append("工具：traceroute（具体协议因系统实现而异）。")
    if complete:
        parts.append(f"追踪在正常结束语义下落盘（约 {n} 行跃点输出）。")
    elif n:
        parts.append(f"共约 {n} 行跃点输出；若未见「跟踪完成」，可能未到达目标或中间禁探。")
    else:
        parts.append("未解析到标准跃点行，请查看 Markdown 中原始输出或 stderr。")
    if rc not in (0, None):
        parts.append(f"进程退出码：{rc}。")
    preview = hop_lines[:10]
    if preview:
        parts.append("前几跳预览：")
        parts.extend(f"  {ln.strip()}" for ln in preview)
    return "\n".join(parts)


def run_traceroute(
    host: str,
    *,
    prefer_ipv6: bool,
    max_hops: int,
    hop_timeout_ms: int,
    log_dir: Path,
) -> TracerouteStats:
    argv, tool = _build_argv(
        host,
        prefer_ipv6=prefer_ipv6,
        max_hops=max_hops,
        hop_timeout_ms=hop_timeout_ms,
    )
    if not argv:
        note = log_dir / "traceroute_skipped.txt"
        note.write_text("未找到 traceroute 可执行文件。\n", encoding="utf-8")
        return TracerouteStats(
            target=host,
            raw_stdout_path=note,
            raw_stderr_path=note,
            command=[],
            returncode=None,
            outline="未发现 traceroute（非 Windows 时需自行安装）。本项已跳过。",
        )

    hop_sec_est = max_hops * (hop_timeout_ms / 1000.0) * 3.5 + 30.0
    timeout_sec = min(600.0, max(90.0, hop_sec_est))
    r: RunResult = run_to_log_files(argv, log_dir, "traceroute", timeout_sec=timeout_sec)
    text = read_text_best_effort(r.stdout_path)
    err = read_text_best_effort(r.stderr_path)
    if err.strip() and len(err.strip()) > 10:
        text = text + "\n[stderr]\n" + err
    outline = _outline_from_output(text, r.returncode, tool)
    return TracerouteStats(
        target=host,
        raw_stdout_path=r.stdout_path,
        raw_stderr_path=r.stderr_path,
        command=list(r.argv),
        returncode=r.returncode,
        outline=outline,
    )
