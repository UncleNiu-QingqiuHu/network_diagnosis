"""tcping 调用与输出解析（Eli Fulkerson 风格 tcping 常见输出）。"""

from __future__ import annotations

import re
from pathlib import Path

from network_diagnosis.model.report import PortFailureClass, PortProbeResult, TcpingSample
from network_diagnosis.probes.subproc_util import read_text_best_effort, run_to_log_files


def probe_tcping_version(tcping_exe: Path, log_dir: Path) -> str | None:
    stem = "tcping_version"
    # 勿用 -h：在 Eli Fulkerson tcping 中表示 HTTP 模式，而非帮助
    for argv in ([str(tcping_exe), "-v"], [str(tcping_exe)], [str(tcping_exe), "/?"]):
        r = run_to_log_files(argv, log_dir, stem, timeout_sec=15)
        out = read_text_best_effort(r.stdout_path)
        err = read_text_best_effort(r.stderr_path)
        blob = (out + "\n" + err).strip()
        if blob:
            return blob.splitlines()[0][:500]
    return None


def _parse_line(line: str) -> TcpingSample | None:
    s = line.strip()
    if not s:
        return None
    low = s.lower()
    # 仅解析单次探测行，忽略末尾统计块（否则会误判为失败探头）
    if not low.startswith("probing "):
        return None
    success = "port is open" in low or "http is open" in low
    rtt = None
    m = re.search(r"time[=<]([0-9.]+)\s*ms", s, re.I)
    if m:
        rtt = float(m.group(1))
    if "no response" in low or "timed out" in low or "time out" in low:
        return TcpingSample(success=False, rtt_ms=None, raw_line=s)
    if "refused" in low or "reset" in low:
        return TcpingSample(success=False, rtt_ms=rtt, raw_line=s)
    if success:
        return TcpingSample(success=True, rtt_ms=rtt, raw_line=s)
    if rtt is not None:
        return TcpingSample(success=True, rtt_ms=rtt, raw_line=s)
    return TcpingSample(success=False, rtt_ms=None, raw_line=s)


def classify_port(samples: list[TcpingSample]) -> PortFailureClass:
    if not samples:
        return PortFailureClass.UNKNOWN
    oks = sum(1 for x in samples if x.success)
    if oks == len(samples):
        return PortFailureClass.OK
    if oks == 0:
        text = "\n".join(x.raw_line for x in samples).lower()
        if "refused" in text:
            return PortFailureClass.REFUSED
        if "reset" in text:
            return PortFailureClass.UNREACHABLE
        if "timed out" in text or "no response" in text or "time out" in text:
            return PortFailureClass.TIMEOUT
        return PortFailureClass.ERROR
    return PortFailureClass.UNKNOWN


def run_tcping_port(
    tcping_exe: Path,
    target: str,
    port: int,
    samples: int,
    timeout_ms: int,
    log_dir: Path,
) -> PortProbeResult:
    stem = f"tcping_{port}"
    # Eli Fulkerson tcping：-w 为「每次探测等待响应」的秒数（非毫秒）；-i 为两次探测间隔（秒）
    wait_s = max(0.1, min(120.0, timeout_ms / 1000.0))
    argv: list[str] = [str(tcping_exe)]
    if ":" in target:
        argv.append("-6")
    else:
        argv.append("-4")
    argv.extend(
        [
            "-n",
            str(samples),
            "-w",
            f"{wait_s:.3f}",
            "-i",
            "0.2",
            target,
            str(port),
        ]
    )
    total_timeout = max(90.0, samples * (wait_s + 0.25) + 25.0)
    r = run_to_log_files(argv, log_dir, stem, timeout_sec=total_timeout)
    text = read_text_best_effort(r.stdout_path) + "\n" + read_text_best_effort(r.stderr_path)
    parsed: list[TcpingSample] = []
    for line in text.splitlines():
        ps = _parse_line(line)
        if ps:
            parsed.append(ps)
    if len(parsed) < samples // 2:
        # 若行解析失败，按块降级：整文件当作一条原始记录
        if text.strip():
            blob_low = text.lower()
            parsed.append(
                TcpingSample(
                    success=("port is open" in blob_low or "http is open" in blob_low),
                    rtt_ms=None,
                    raw_line=text.strip()[:2000],
                )
            )
    fc = classify_port(parsed)
    return PortProbeResult(
        port=port,
        target_used=target,
        samples=parsed,
        stdout_path=r.stdout_path,
        stderr_path=r.stderr_path,
        command=r.argv,
        failure_class=fc,
    )
