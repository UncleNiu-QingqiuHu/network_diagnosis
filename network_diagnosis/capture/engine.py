"""抓包与分析任务编排。"""

from __future__ import annotations

import shutil
import time
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from threading import Event

from network_diagnosis.capture.analyze import (
    build_expert_warnings,
    collect_dns_queries,
    collect_packet_preview,
    collect_tls_sni,
    collect_top_tcp_flows_structured,
    collect_top_udp_flows,
    count_pcap_frames,
    count_retransmissions,
    count_tcp_rst,
    measure_pcap_duration_sec,
    parse_protocol_hierarchy,
    summarize_http_status,
)
from network_diagnosis.capture.models import CaptureSessionResult, PcapAnalysisResult
from network_diagnosis.capture.report_md import write_analysis_artifacts
from network_diagnosis.paths import packet_capture_report_dir
from network_diagnosis.probes.subproc_util import read_text_best_effort
from network_diagnosis.probes.tshark import TsharkCaptureSession, summarize_pcap
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)

ProgressFn = Callable[[str], None]


def new_task_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]


def iter_diagnosis_pcaps(limit: int = 50) -> list[Path]:
    """扫描 reports/ 下网络诊断产生的 capture_*.pcapng。"""
    from network_diagnosis.paths import report_root

    root = report_root()
    if not root.is_dir():
        return []
    found: list[Path] = []
    for p in root.rglob("capture_*.pcapng"):
        if p.is_file():
            found.append(p)
    found.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return found[:limit]


def run_live_capture(
    tshark_path: Path,
    *,
    interface_index: str,
    interface_desc: str,
    bpf_filter: str,
    timed: bool,
    duration_sec: int,
    filesize_limit_mb: int,
    stop_event: Event,
    progress: ProgressFn | None = None,
    size_poll_sec: float = 3.0,
) -> CaptureSessionResult:
    """实时抓包；调用方在工作线程中运行。"""

    def prog(msg: str) -> None:
        if progress:
            progress(msg)

    task_id = new_task_id()
    report_dir = packet_capture_report_dir(task_id)
    pcap_path = report_dir / f"capture_{task_id}.pcapng"
    started = datetime.now()

    filesize_kb = 0
    if filesize_limit_mb > 0:
        filesize_kb = filesize_limit_mb * 1024

    dur = duration_sec if timed and duration_sec > 0 else 0
    session = TsharkCaptureSession()
    prog("正在启动 tshark 抓包…")
    try:
        out_p, err_p = session.start(
            tshark_path,
            interface_index,
            pcap_path,
            bpf_filter,
            report_dir,
            duration_sec=dur,
            filesize_kb=filesize_kb,
        )
    except OSError as e:
        _log.warning("抓包启动失败 task_id=%s", task_id, exc_info=True)
        return CaptureSessionResult(
            task_id=task_id,
            started_at=started,
            stopped_at=datetime.now(),
            interface_index=interface_index,
            interface_desc=interface_desc,
            bpf_filter=bpf_filter,
            pcap_path=pcap_path,
            file_size_bytes=0,
            frame_count=None,
            status="failed",
            tshark_stdout_log=None,
            tshark_stderr_log=None,
            error_message=str(e),
        )

    prog("抓包进行中…")
    stopped_at: datetime | None = None
    status: str = "stopped"

    try:
        while session.is_running():
            if stop_event.is_set():
                prog("正在停止抓包…")
                session.stop()
                break
            if pcap_path.is_file():
                prog(f"抓包中… 当前文件约 {pcap_path.stat().st_size // 1024} KB")
            time.sleep(size_poll_sec)
        else:
            prog("抓包已自动结束（定时或大小上限）。")
        stopped_at = datetime.now()
    except Exception as e:
        status = "failed"
        stopped_at = datetime.now()
        _log.exception("抓包等待异常 task_id=%s", task_id)
        err_tail = ""
        if err_p.is_file():
            err_tail = read_text_best_effort(err_p, max_bytes=4096).strip()[-800:]
        return CaptureSessionResult(
            task_id=task_id,
            started_at=started,
            stopped_at=stopped_at,
            interface_index=interface_index,
            interface_desc=interface_desc,
            bpf_filter=bpf_filter,
            pcap_path=pcap_path,
            file_size_bytes=pcap_path.stat().st_size if pcap_path.is_file() else 0,
            frame_count=None,
            status="failed",
            tshark_stdout_log=out_p,
            tshark_stderr_log=err_p,
            error_message=f"{e}\n{err_tail}".strip(),
        )

    size = pcap_path.stat().st_size if pcap_path.is_file() else 0
    err_msg = ""
    if err_p.is_file():
        err_blob = read_text_best_effort(err_p, max_bytes=16_384).strip()
        if err_blob and size == 0:
            status = "failed"
            err_msg = err_blob[-1200:]

    frame_count: int | None = None
    if pcap_path.is_file() and pcap_path.stat().st_size > 0 and status != "failed":
        try:
            frame_count, _ = count_pcap_frames(tshark_path, pcap_path, report_dir)
        except OSError:
            frame_count = None

    _log.info(
        "抓包完成 task_id=%s status=%s frames=%s size=%s bpf=%r",
        task_id,
        status,
        frame_count,
        size,
        bpf_filter,
    )
    return CaptureSessionResult(
        task_id=task_id,
        started_at=started,
        stopped_at=stopped_at,
        interface_index=interface_index,
        interface_desc=interface_desc,
        bpf_filter=bpf_filter,
        pcap_path=pcap_path,
        file_size_bytes=size,
        frame_count=frame_count,
        status=status,  # type: ignore[arg-type]
        tshark_stdout_log=out_p,
        tshark_stderr_log=err_p,
        error_message=err_msg,
    )


def prepare_imported_pcap(
    source_path: Path,
    *,
    task_id: str | None = None,
    source_kind: str = "imported",
) -> tuple[str, Path, Path]:
    """复制导入的 pcap 到任务目录，返回 (task_id, report_dir, dest_pcap)。"""
    if not source_path.is_file():
        raise FileNotFoundError(f"文件不存在: {source_path}")
    if source_path.stat().st_size == 0:
        raise ValueError("抓包文件为空。")
    tid = task_id or new_task_id()
    report_dir = packet_capture_report_dir(tid)
    dest = report_dir / f"capture_{tid}{source_path.suffix or '.pcapng'}"
    if source_path.resolve() != dest.resolve():
        shutil.copy2(source_path, dest)
    return tid, report_dir, dest


def run_pcap_analysis(
    tshark_path: Path,
    pcap_path: Path,
    report_dir: Path,
    *,
    task_id: str,
    source: str = "imported",
    display_filter: str | None = None,
    preview_limit: int = 500,
    session: CaptureSessionResult | None = None,
    progress: ProgressFn | None = None,
) -> PcapAnalysisResult:
    """离线分析 pcap；可在实时抓包结束后调用。"""

    def prog(msg: str) -> None:
        if progress:
            progress(msg)

    analyzed_at = datetime.now()
    prog("正在统计帧数与文件信息…")
    size = pcap_path.stat().st_size if pcap_path.is_file() else 0
    frame_count, _ = count_pcap_frames(tshark_path, pcap_path, report_dir)
    duration = measure_pcap_duration_sec(tshark_path, pcap_path, report_dir)

    prog("正在生成中文摘要…")
    summary = summarize_pcap(tshark_path, pcap_path, report_dir)

    prog("正在解析协议分层…")
    hierarchy = parse_protocol_hierarchy(tshark_path, pcap_path, report_dir)

    prog("正在统计 TCP/UDP 会话与异常…")
    tcp_flows = collect_top_tcp_flows_structured(
        tshark_path, pcap_path, report_dir, display_filter=display_filter
    )
    udp_flows = collect_top_udp_flows(
        tshark_path, pcap_path, report_dir, display_filter=display_filter
    )
    retrans = count_retransmissions(tshark_path, pcap_path, report_dir, display_filter=display_filter)
    rst = count_tcp_rst(tshark_path, pcap_path, report_dir, display_filter=display_filter)
    dns = collect_dns_queries(tshark_path, pcap_path, report_dir, display_filter=display_filter)
    sni = collect_tls_sni(tshark_path, pcap_path, report_dir, display_filter=display_filter)
    http_sum = summarize_http_status(tshark_path, pcap_path, report_dir, display_filter=display_filter)
    warnings = build_expert_warnings(retransmission_count=retrans, rst_count=rst)

    prog("正在提取报文预览…")
    preview = collect_packet_preview(
        tshark_path,
        pcap_path,
        report_dir,
        display_filter=display_filter,
        limit=preview_limit,
    )

    analysis = PcapAnalysisResult(
        task_id=task_id,
        analyzed_at=analyzed_at,
        source=source,  # type: ignore[arg-type]
        pcap_path=pcap_path,
        display_filter=display_filter.strip() if display_filter and display_filter.strip() else None,
        frame_count=frame_count,
        file_size_bytes=size,
        duration_sec=duration,
        summary_plain=summary,
        protocol_hierarchy=hierarchy,
        top_tcp_flows=tcp_flows,
        top_udp_flows=udp_flows,
        retransmission_count=retrans,
        rst_count=rst,
        dns_queries=dns,
        tls_sni_list=sni,
        http_status_summary=http_sum,
        expert_warnings=warnings,
        packet_preview=preview,
        report_dir=report_dir,
    )

    prog("正在写入报告…")
    md_path, json_path = write_analysis_artifacts(
        report_dir=report_dir,
        session=session,
        analysis=analysis,
        tshark_path=str(tshark_path),
    )
    analysis.markdown_path = md_path
    analysis.analysis_json_path = json_path

    _log.info(
        "抓包分析完成 task_id=%s frames=%s source=%s display_filter=%r",
        task_id,
        frame_count,
        source,
        display_filter,
    )
    return analysis
