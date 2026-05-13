"""TCP 路径探测：优先 nmap --traceroute；-T traceroute（非 Windows）。"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from network_diagnosis.model.report import ShellProbeResult
from network_diagnosis.probes.subproc_util import read_text_best_effort, run_to_log_files


def _stub(log_dir: Path, msg: str) -> ShellProbeResult:
    p = log_dir / "tcp_trace_skip.txt"
    p.write_text(msg + "\n", encoding="utf-8")
    return ShellProbeResult(
        kind="skip",
        summary=msg,
        command=[],
        raw_stdout_path=p,
        raw_stderr_path=p,
        returncode=None,
    )


def run_tcp_traceroute(host: str, port: int, max_hops: int, log_dir: Path) -> ShellProbeResult:
    port = max(1, min(65535, port))
    max_hops = max(2, min(64, max_hops))
    nmap = shutil.which("nmap")
    if nmap:
        argv = [
            nmap,
            "-Pn",
            "--traceroute",
            "-p",
            str(port),
            "--host-timeout",
            "240s",
            host,
        ]
        r = run_to_log_files(argv, log_dir, "tcp_traceroute_nmap", timeout_sec=300.0)
        text = read_text_best_effort(r.stdout_path) + read_text_best_effort(r.stderr_path)
        prev = text.splitlines()[:40]
        summ = "工具：nmap --traceroute。\n" + "\n".join(prev)
        return ShellProbeResult(
            kind="nmap_traceroute",
            summary=summ or "nmap 无输出。",
            command=list(r.argv),
            raw_stdout_path=r.stdout_path,
            raw_stderr_path=r.stderr_path,
            returncode=r.returncode,
        )
    tr = shutil.which("traceroute")
    if tr and sys.platform != "win32":
        argv = [
            tr,
            "-n",
            "-T",
            "-p",
            str(port),
            "-m",
            str(max_hops),
            "-q",
            "1",
            "-w",
            "3",
            host,
        ]
        r = run_to_log_files(argv, log_dir, "tcp_traceroute", timeout_sec=240.0)
        text = read_text_best_effort(r.stdout_path)
        prev = text.splitlines()[:35]
        summ = "工具：traceroute -T。\n" + "\n".join(prev)
        return ShellProbeResult(
            kind="traceroute_tcp",
            summary=summ or "traceroute 无输出。",
            command=list(r.argv),
            raw_stdout_path=r.stdout_path,
            raw_stderr_path=r.stderr_path,
            returncode=r.returncode,
        )
    return _stub(
        log_dir,
        "未找到 nmap，且本机为 Windows 或无 traceroute -T。"
        "可在 Windows 安装 Nmap 或将 Linux 的 traceroute 加入 PATH。",
    )
