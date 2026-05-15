"""iperf3 客户端抽样（需本机可用 iperf3.exe）。"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from network_diagnosis.model.report import BandwidthProbeResult, IperfUdpQualityResult


def _win32_subprocess_kw() -> dict:
    if sys.platform != "win32":
        return {}
    out: dict = {}
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE  # type: ignore[attr-defined]
        out["startupinfo"] = si
    except (AttributeError, TypeError):
        pass
    try:
        out["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    except AttributeError:
        pass
    return out


def run_iperf_bandwidth(
    iperf3_exe: Path,
    host: str,
    port: int,
    duration_sec: int,
    parallel_streams: int,
    report_dir: Path,
) -> BandwidthProbeResult:
    duration_sec = max(2, min(600, duration_sec))
    port = max(1, min(65535, port))
    parallel_streams = max(1, min(64, int(parallel_streams)))
    stem = "bandwidth_iperf3"

    cmd = [
        str(iperf3_exe),
        "-c",
        host,
        "-p",
        str(port),
        "-t",
        str(duration_sec),
        "-P",
        str(parallel_streams),
        "-R",
        "-J",
        "--connect-timeout",
        "5000",
    ]
    out_path = report_dir / f"{stem}_stdout.json"
    err_path = report_dir / f"{stem}_stderr.txt"

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=float(duration_sec) + float(parallel_streams) * 3.0 + 45.0,
            text=True,
            encoding="utf-8",
            errors="replace",
            **_win32_subprocess_kw(),
        )
    except subprocess.TimeoutExpired:
        err_path.write_text("iperf3 subprocess timeout", encoding="utf-8")
        return BandwidthProbeResult(
            mode="iperf3",
            ok=False,
            summary="iperf3 执行超时。",
            megabits_per_second=None,
            bytes_total=None,
            duration_sec=None,
            parallel_streams=parallel_streams,
            target_label=f"{host}:{port}",
            error="timeout",
            log_stdout_path=out_path if out_path.is_file() else None,
            log_stderr_path=err_path,
            command=cmd,
        )
    except OSError as e:
        err_path.write_text(str(e), encoding="utf-8")
        return BandwidthProbeResult(
            mode="iperf3",
            ok=False,
            summary=f"无法执行 iperf3：{e}",
            megabits_per_second=None,
            bytes_total=None,
            duration_sec=None,
            parallel_streams=parallel_streams,
            target_label=f"{host}:{port}",
            error=str(e),
            log_stdout_path=None,
            log_stderr_path=err_path,
            command=cmd,
        )

    out_path.write_text(proc.stdout or "", encoding="utf-8")
    err_path.write_text(proc.stderr or "", encoding="utf-8")

    mbps: float | None = None
    seconds: float | None = None
    btes: int | None = None

    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()
        tail = tail[-400:] if len(tail) > 400 else tail
        return BandwidthProbeResult(
            mode="iperf3",
            ok=False,
            summary=f"iperf3 退出码 {proc.returncode}。",
            megabits_per_second=None,
            bytes_total=None,
            duration_sec=None,
            parallel_streams=parallel_streams,
            target_label=f"{host}:{port}",
            error=tail or f"exit {proc.returncode}",
            log_stdout_path=out_path,
            log_stderr_path=err_path,
            command=cmd,
        )

    try:
        data = json.loads(proc.stdout or "{}")
        end = data.get("end") or {}
        sr = end.get("sum_received") or end.get("sum_sent") or {}
        bps = sr.get("bits_per_second")
        if isinstance(bps, (int, float)):
            mbps = float(bps) / 1_000_000.0
        st = sr.get("seconds")
        if isinstance(st, (int, float)):
            seconds = float(st)
        by = sr.get("bytes")
        if isinstance(by, int):
            btes = by
    except (json.JSONDecodeError, TypeError, ValueError):
        return BandwidthProbeResult(
            mode="iperf3",
            ok=False,
            summary="iperf3 输出不是有效 JSON，无法解析速率。",
            megabits_per_second=None,
            bytes_total=None,
            duration_sec=None,
            parallel_streams=parallel_streams,
            target_label=f"{host}:{port}",
            error="json_parse",
            log_stdout_path=out_path,
            log_stderr_path=err_path,
            command=cmd,
        )

    if mbps is None:
        return BandwidthProbeResult(
            mode="iperf3",
            ok=False,
            summary="iperf3 结果中缺少 bits_per_second。",
            megabits_per_second=None,
            bytes_total=btes,
            duration_sec=seconds,
            parallel_streams=parallel_streams,
            target_label=f"{host}:{port}",
            error="no_bps",
            log_stdout_path=out_path,
            log_stderr_path=err_path,
            command=cmd,
        )

    summary = (
        f"iperf3 至 {host}:{port}，并行 {parallel_streams} 路，"
        f"接收约 {mbps:.1f} Mbps"
        + (f"（时长约 {seconds:.1f} s）" if seconds else "")
        + "（仅反映到该服务器的路径与窗口条件）。"
    )

    return BandwidthProbeResult(
        mode="iperf3",
        ok=True,
        summary=summary,
        megabits_per_second=mbps,
        bytes_total=btes,
        duration_sec=seconds,
        parallel_streams=parallel_streams,
        target_label=f"{host}:{port}",
        error="",
        log_stdout_path=out_path,
        log_stderr_path=err_path,
        command=cmd,
    )


def _coerce_float_metric(val: object) -> float | None:
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        s = val.strip().rstrip("%")
        try:
            return float(s)
        except ValueError:
            return None
    return None


def _udp_loss_pct_from_block(blk: dict) -> float | None:
    lp = _coerce_float_metric(blk.get("lost_percent"))
    if lp is not None:
        return lp
    lost = blk.get("lost_packets")
    pkts = blk.get("packets")
    if isinstance(lost, int) and isinstance(pkts, int) and pkts > 0:
        return 100.0 * lost / pkts
    return None


def _udp_metrics_from_json_end(end: dict) -> tuple[float | None, float | None, float | None]:
    """从 iperf3 `-J` 输出的 end 段解析 UDP 丢包率、抖动与接收 Mbps。"""
    blocks: list[dict] = []
    for key in ("sum_received", "sum_sent", "sum"):
        b = end.get(key)
        if isinstance(b, dict):
            blocks.append(b)
    streams = end.get("streams")
    if isinstance(streams, list):
        for stream in streams:
            if isinstance(stream, dict):
                u = stream.get("udp")
                if isinstance(u, dict):
                    blocks.append(u)
                blocks.append(stream)

    loss: float | None = None
    jitter: float | None = None
    mbps: float | None = None
    for blk in blocks:
        lp = _udp_loss_pct_from_block(blk)
        j = _coerce_float_metric(blk.get("jitter_ms"))
        bps = blk.get("bits_per_second")
        m = float(bps) / 1_000_000.0 if isinstance(bps, (int, float)) else None
        if lp is not None:
            loss = lp
        if j is not None:
            jitter = j
        if m is not None:
            mbps = m
        if lp is not None or j is not None:
            return loss, jitter, mbps
    for blk in blocks:
        bps = blk.get("bits_per_second")
        if isinstance(bps, (int, float)):
            return loss, jitter, float(bps) / 1_000_000.0
    return loss, jitter, mbps


def run_iperf_udp_quality(
    iperf3_exe: Path,
    host: str,
    port: int,
    duration_sec: int,
    bitrate: str,
    report_dir: Path,
) -> IperfUdpQualityResult:
    """UDP `-u` 抽样（默认配合 `-R -i 1 -J`），用于丢包与抖动辅助判定。"""
    duration_sec = max(2, min(600, duration_sec))
    port = max(1, min(65535, port))
    br = (bitrate or "").strip() or "1000M"
    stem = "bandwidth_iperf3_udp_quality"
    label = f"{host}:{port}"

    cmd = [
        str(iperf3_exe),
        "-c",
        host,
        "-p",
        str(port),
        "-u",
        "-b",
        br,
        "-t",
        str(duration_sec),
        "-R",
        "-i",
        "1",
        "-J",
        "--connect-timeout",
        "5000",
    ]
    out_path = report_dir / f"{stem}_stdout.json"
    err_path = report_dir / f"{stem}_stderr.txt"

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=float(duration_sec) + 75.0,
            text=True,
            encoding="utf-8",
            errors="replace",
            **_win32_subprocess_kw(),
        )
    except subprocess.TimeoutExpired:
        err_path.write_text("iperf3 UDP subprocess timeout", encoding="utf-8")
        return IperfUdpQualityResult(
            ok=False,
            summary="iperf3 UDP 执行超时。",
            packet_loss_pct=None,
            jitter_ms=None,
            megabits_per_second=None,
            target_label=label,
            error="timeout",
            command=cmd,
            log_stdout_path=out_path if out_path.is_file() else None,
            log_stderr_path=err_path,
        )
    except OSError as e:
        err_path.write_text(str(e), encoding="utf-8")
        return IperfUdpQualityResult(
            ok=False,
            summary=f"无法执行 iperf3 UDP：{e}",
            packet_loss_pct=None,
            jitter_ms=None,
            megabits_per_second=None,
            target_label=label,
            error=str(e),
            command=cmd,
            log_stdout_path=None,
            log_stderr_path=err_path,
        )

    out_path.write_text(proc.stdout or "", encoding="utf-8")
    err_path.write_text(proc.stderr or "", encoding="utf-8")

    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()
        tail = tail[-400:] if len(tail) > 400 else tail
        return IperfUdpQualityResult(
            ok=False,
            summary=f"iperf3 UDP 退出码 {proc.returncode}。",
            packet_loss_pct=None,
            jitter_ms=None,
            megabits_per_second=None,
            target_label=label,
            error=tail or f"exit {proc.returncode}",
            command=cmd,
            log_stdout_path=out_path,
            log_stderr_path=err_path,
        )

    loss: float | None = None
    jitter: float | None = None
    mbps: float | None = None
    try:
        data = json.loads(proc.stdout or "{}")
        end = data.get("end") or {}
        loss, jitter, mbps = _udp_metrics_from_json_end(end)
    except (json.JSONDecodeError, TypeError, ValueError):
        return IperfUdpQualityResult(
            ok=False,
            summary="iperf3 UDP 输出不是有效 JSON，无法解析。",
            packet_loss_pct=None,
            jitter_ms=None,
            megabits_per_second=None,
            target_label=label,
            error="json_parse",
            command=cmd,
            log_stdout_path=out_path,
            log_stderr_path=err_path,
        )

    if loss is None and jitter is None:
        return IperfUdpQualityResult(
            ok=False,
            summary="iperf3 UDP JSON 中未找到丢包率或抖动字段。",
            packet_loss_pct=None,
            jitter_ms=None,
            megabits_per_second=mbps,
            target_label=label,
            error="no_udp_fields",
            command=cmd,
            log_stdout_path=out_path,
            log_stderr_path=err_path,
        )

    bits = []
    if loss is not None:
        bits.append(f"丢包约 {loss:.2f}%")
    if jitter is not None:
        bits.append(f"抖动约 {jitter:.2f} ms")
    if mbps is not None:
        bits.append(f"接收约 {mbps:.1f} Mbps")
    summary = f"iperf3 UDP 至 {label}（-b {br}）：{', '.join(bits)}。"
    return IperfUdpQualityResult(
        ok=True,
        summary=summary,
        packet_loss_pct=loss,
        jitter_ms=jitter,
        megabits_per_second=mbps,
        target_label=label,
        error="",
        command=cmd,
        log_stdout_path=out_path,
        log_stderr_path=err_path,
    )
