"""编排一次完整诊断任务，填充 DiagnosticReport。"""

from __future__ import annotations

import ipaddress
import platform
import socket
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from network_diagnosis.model.report import (
    BandwidthProbeResult,
    CaptureInfo,
    DegradationEvent,
    DiagnosticReport,
    DnsAnswer,
    EgressProbeResult,
    GuiSummary,
    HistoryCompareResult,
    HttpTlsProbeResult,
    MtuProbeResult,
    OverallStatus,
    PortFailureClass,
    PortProbeResult,
    ShellProbeResult,
    TaskMeta,
    TracerouteStats,
    UserInputSnapshot,
)
from network_diagnosis.paths import find_tshark, report_root, resolve_iperf3_exe, resolve_tcping_exe
from network_diagnosis.probes.bandwidth_http import run_http_bandwidth
from network_diagnosis.probes.bandwidth_iperf import run_iperf_bandwidth
from network_diagnosis.probes.subproc_util import read_text_best_effort
from network_diagnosis.probes.dns_probe import pick_tcp_target, resolve_dns, resolve_dns_via_server
from network_diagnosis.probes.egress_probe import run_egress
from network_diagnosis.probes.http_tls_probe import probe_https
from network_diagnosis.probes.local_context import collect_local_context
from network_diagnosis.probes.mtu_probe import run_mtu_probe
from network_diagnosis.probes.pathping_probe import run_path_quality
from network_diagnosis.probes.ping_probe import run_ping
from network_diagnosis.probes.tcping_probe import probe_tcping_version, run_tcping_port
from network_diagnosis.probes.tcp_traceroute_probe import run_tcp_traceroute
from network_diagnosis.probes.traceroute_probe import run_traceroute
from network_diagnosis.probes.tshark import (
    TsharkCaptureSession,
    pick_capture_interface_index,
    summarize_pcap,
    tshark_version_line,
)
from network_diagnosis.reporting.history_store import HistoryEntry, append_history, build_history_compare
from network_diagnosis.reporting.markdown import write_markdown_report
from network_diagnosis.quality_assessment import compute_network_quality
from network_diagnosis.version import APP_VERSION, DESIGN_DOC_REF


@dataclass
class RunOptions:
    target_host: str
    ports: list[int]
    samples_per_port: int
    tcp_timeout_ms: int
    enable_ping: bool
    enable_capture: bool
    prefer_ipv6: bool
    ping_count: int = 10
    ping_packet_timeout_ms: int = 2000
    ping_long: bool = False
    long_ping_seconds: int = 30
    enable_traceroute: bool = False
    traceroute_max_hops: int = 30
    traceroute_hop_timeout_ms: int = 4000
    bandwidth_mode: str = "off"
    bandwidth_http_url: str = "https://speed.cloudflare.com/__down?bytes=25000000"
    bandwidth_http_parallel: int = 4
    bandwidth_http_seconds: int = 15
    bandwidth_iperf_host: str = ""
    bandwidth_iperf_port: int = 5201
    bandwidth_iperf_seconds: int = 10
    optional_dns_server: str = ""
    enable_pathping: bool = False
    enable_tcp_traceroute: bool = False
    tcp_traceroute_max_hops: int = 30
    enable_http_tls_probe: bool = False
    enable_egress_probe: bool = False
    enable_mtu_probe: bool = False
    enable_history_compare: bool = True


def _normalize_bw_mode(mode: str) -> str:
    m = (mode or "").strip().lower()
    if m in ("", "off", "none", "no", "false"):
        return "off"
    if m in ("http", "http_download", "https"):
        return "http"
    if m in ("iperf3", "iperf"):
        return "iperf3"
    return "off"


def _run_bandwidth(
    options: RunOptions,
    report_dir: Path,
    progress: Callable[[str], None],
    degradations: list[DegradationEvent],
) -> BandwidthProbeResult | None:
    mode = _normalize_bw_mode(options.bandwidth_mode)
    if mode == "off":
        return None
    if mode == "http":
        url = (options.bandwidth_http_url or "").strip()
        if not url:
            degradations.append(
                DegradationEvent(
                    code="bandwidth_http_no_url",
                    message="已选择 HTTP 抽样但未填写 URL。",
                    detail="",
                )
            )
            return BandwidthProbeResult(
                mode="http",
                ok=False,
                summary="未填写下载 URL。",
                megabits_per_second=None,
                bytes_total=None,
                duration_sec=None,
                parallel_streams=None,
                target_label="",
                error="no url",
            )
        progress("正在进行 HTTP 抽样下载（吞吐估算）…")
        return run_http_bandwidth(
            url,
            options.bandwidth_http_parallel,
            options.bandwidth_http_seconds,
            report_dir,
        )

    host = (options.bandwidth_iperf_host or "").strip()
    if not host:
        degradations.append(
            DegradationEvent(
                code="bandwidth_iperf_no_host",
                message="已选择 iperf3 但未填写服务器地址。",
                detail="",
            )
        )
        return BandwidthProbeResult(
            mode="iperf3",
            ok=False,
            summary="未填写 iperf3 服务器主机名或 IP。",
            megabits_per_second=None,
            bytes_total=None,
            duration_sec=None,
            parallel_streams=None,
            target_label="",
            error="no host",
        )
    exe = resolve_iperf3_exe()
    if exe is None:
        degradations.append(
            DegradationEvent(
                code="iperf3_missing",
                message="未找到 iperf3。",
                detail="请将 iperf3.exe 放入 ThirdParty/iperf3/ 或安装并加入 PATH。",
            )
        )
        return BandwidthProbeResult(
            mode="iperf3",
            ok=False,
            summary="未找到 iperf3 可执行文件。",
            megabits_per_second=None,
            bytes_total=None,
            duration_sec=None,
            parallel_streams=None,
            target_label=f"{host}:{options.bandwidth_iperf_port}",
            error="iperf3_missing",
        )
    progress(f"正在运行 iperf3（{host}:{options.bandwidth_iperf_port}）…")
    return run_iperf_bandwidth(
        exe,
        host,
        options.bandwidth_iperf_port,
        options.bandwidth_iperf_seconds,
        report_dir,
    )


def _is_ip_literal(addr: str) -> bool:
    a = addr.strip().rstrip(".")
    try:
        ipaddress.ip_address(a)
    except ValueError:
        return False
    return True


def _host_bpf(addr: str) -> str:
    """将字面量 IP 转为 pcap bpf 主机表达式（IPv4 用 ip host，IPv6 用 ip6 host）。"""
    base = addr.strip().rstrip(".").split("%", 1)[0]
    if ":" in base:
        return f"ip6 host {base}"
    return f"ip host {base}"


def _build_capture_filter(target_ip_or_host: str, ports: list[int]) -> str:
    """构建抓包过滤器：有端口时限定为到该主机的 TCP 端口；无端口时只按主机抓，避免过窄导致空文件。"""
    port_parts = [f"tcp port {p}" for p in ports]
    port_expr = " or ".join(port_parts) if port_parts else ""

    if _is_ip_literal(target_ip_or_host):
        hp = _host_bpf(target_ip_or_host)
        if port_expr:
            return f"(({hp}) and tcp and ({port_expr}))"
        return f"({hp})"

    # 主机名不能写入 BPF；有端口时仅按 TCP 端口收（略宽）；无端口时用常见探测流量
    if port_expr:
        return f"tcp and ({port_expr})"
    return "(tcp or icmp or icmp6)"


def _build_gui_summary(
    dns: DnsAnswer,
    ping_okish: bool | None,
    port_results: list[PortProbeResult],
    degradations: list[DegradationEvent],
    md_path: Path,
    *,
    user_configured_ports: bool,
    bandwidth: BandwidthProbeResult | None,
    bandwidth_mode: str,
) -> GuiSummary:
    bullets: list[str] = []
    status = OverallStatus.OK

    if dns.error or not dns.addresses:
        status = OverallStatus.FAILED
        bullets.append("域名解析失败或没有可用地址，后续 TCP 探测可能不可靠。")
    else:
        bullets.append("域名可以解析到可用地址。")

    if ping_okish is False:
        bullets.append(
            "ICMP ping 不通或严重丢包：常见于对端禁 ping 或防火墙策略，"
            "不代表 TCP 端口一定不通。"
        )
        if status == OverallStatus.OK:
            status = OverallStatus.DEGRADED
    elif ping_okish is True:
        bullets.append("ICMP ping 有响应，基础连通性大致正常。")

    if not user_configured_ports:
        bullets.append("未配置 TCP 端口，已跳过端口连通性探测。")
    elif any(d.code == "tcping_missing" for d in degradations):
        bullets.append("已填写端口，但未找到内置 tcping，无法完成端口探测。")
    else:
        bad = [p for p in port_results if p.failure_class != PortFailureClass.OK]
        if not port_results:
            bullets.append("未能得到端口探测结果（可能未成功执行 tcping）。")
            status = OverallStatus.FAILED if status == OverallStatus.OK else status
        elif not bad:
            bullets.append("所测 TCP 端口均可建立连接。")
        elif len(bad) == len(port_results):
            status = OverallStatus.FAILED
            bullets.append("所测 TCP 端口均异常，更像对端或路径上的网络/策略问题。")
        else:
            status = OverallStatus.DEGRADED
            bullets.append(
                f"部分端口异常：{', '.join(str(p.port) for p in bad)}。"
                "建议由技术人员查看 Markdown 报告中的逐端口明细。"
            )

    for d in degradations:
        if d.code in ("capture_unavailable", "tshark_start_failed"):
            if status == OverallStatus.OK:
                status = OverallStatus.DEGRADED
            bullets.append(d.message)

    bw_mode = _normalize_bw_mode(bandwidth_mode)
    if bw_mode != "off" and bandwidth is not None:
        if bandwidth.ok:
            bullets.append(f"带宽抽样（{bandwidth.mode}）：{bandwidth.summary}")
        else:
            bullets.append(f"带宽抽样（{bandwidth.mode}）未成功：{bandwidth.summary}")

    if any(d.code == "tcping_missing" for d in degradations) and user_configured_ports:
        status = OverallStatus.FAILED

    headline = {
        OverallStatus.OK: "整体：正常",
        OverallStatus.DEGRADED: "整体：存在问题（部分项异常或已降级）",
        OverallStatus.FAILED: "整体：存在明显问题或关键依赖缺失",
    }[status]
    return GuiSummary(overall=status, headline=headline, bullets=bullets, markdown_path=md_path)


def run_diagnostic(options: RunOptions, progress: Callable[[str], None]) -> DiagnosticReport:
    task_id = uuid.uuid4().hex[:12]
    started = datetime.now().astimezone()
    root = report_root()
    report_dir = root / f"{task_id}_{started.strftime('%Y%m%d_%H%M%S')}"
    report_dir.mkdir(parents=True, exist_ok=True)
    progress(f"工作目录: {report_dir}")

    degradations: list[DegradationEvent] = []

    local = collect_local_context(report_dir)
    progress("已采集本机网络上下文（ipconfig）。")

    dns = resolve_dns(options.target_host, prefer_ipv6=options.prefer_ipv6)
    progress("DNS 解析完成。")

    dns_specified: DnsAnswer | None = None
    if (options.optional_dns_server or "").strip():
        progress("正在使用指定 DNS 服务器解析…")
        dns_specified = resolve_dns_via_server(
            options.target_host,
            options.optional_dns_server.strip(),
            report_dir,
            prefer_ipv6=options.prefer_ipv6,
        )
        progress("指定 DNS 解析完成。")

    tcp_target = pick_tcp_target(dns, prefer_ipv6=options.prefer_ipv6)
    probe_host = tcp_target or options.target_host

    tcping_exe = resolve_tcping_exe()
    tcping_path_str = str(tcping_exe) if tcping_exe else None
    tcping_ver = probe_tcping_version(tcping_exe, report_dir) if tcping_exe else None

    if tcping_exe is None:
        degradations.append(
            DegradationEvent(
                code="tcping_missing",
                message="未找到内置 tcping.exe。",
                detail="请将 tcping.exe 放入 ThirdParty/tcping/ 后重试。",
            )
        )

    tshark_path = find_tshark()
    tshark_ver = tshark_version_line(tshark_path, report_dir) if tshark_path else None

    capture = CaptureInfo(
        requested=options.enable_capture,
        ran=False,
        tshark_cmd=None,
        pcap_path=None,
        stdout_path=None,
        stderr_path=None,
        notes="",
    )
    cap_session = TsharkCaptureSession()
    pcap_path = report_dir / f"capture_{task_id}.pcapng"

    if options.enable_capture:
        if tshark_path is None:
            capture.notes = "未检测到 tshark；本轮未抓包。可通过 GUI 打开同捆 Wireshark 安装包完成安装。"
            degradations.append(
                DegradationEvent(
                    code="capture_unavailable",
                    message="抓包不可用：未找到 tshark。",
                    detail="安装 Wireshark（含 Npcap）后可启用自动抓包。",
                )
            )
        else:
            try:
                if_idx = pick_capture_interface_index(tshark_path, report_dir)
                bpf = _build_capture_filter(probe_host, options.ports)
                cmd = [
                    str(tshark_path),
                    "-i",
                    if_idx,
                    "-w",
                    str(pcap_path),
                    "-f",
                    bpf,
                ]
                out_p, err_p = cap_session.start(tshark_path, if_idx, pcap_path, bpf, report_dir)
                capture = CaptureInfo(
                    requested=True,
                    ran=True,
                    tshark_cmd=cmd,
                    pcap_path=pcap_path,
                    stdout_path=out_p,
                    stderr_path=err_p,
                    notes=f"捕获接口 (-i): `{if_idx}`；BPF: `{bpf}`",
                )
                progress("tshark 抓包已启动。")
                time.sleep(1.0)
            except OSError as e:
                capture = CaptureInfo(
                    requested=True,
                    ran=False,
                    tshark_cmd=None,
                    pcap_path=None,
                    stdout_path=None,
                    stderr_path=None,
                    notes=str(e),
                )
                degradations.append(
                    DegradationEvent(
                        code="tshark_start_failed",
                        message="抓包启动失败。",
                        detail=str(e),
                    )
                )

    ping_stats = None
    ping_okish: bool | None = None
    if options.enable_ping:
        progress("正在执行 ICMP ping…")
        if options.ping_long:
            ping_stats = run_ping(
                options.target_host,
                options.ping_count,
                options.ping_packet_timeout_ms,
                report_dir,
                long_duration_sec=max(5, int(options.long_ping_seconds)),
            )
        else:
            ping_stats = run_ping(
                options.target_host,
                options.ping_count,
                options.ping_packet_timeout_ms,
                report_dir,
            )
        if ping_stats.attempted:
            ping_okish = ping_stats.received > 0

    tr_stats: TracerouteStats | None = None
    if options.enable_traceroute:
        progress("正在执行路由追踪…")
        tr_stats = run_traceroute(
            options.target_host,
            prefer_ipv6=options.prefer_ipv6,
            max_hops=options.traceroute_max_hops,
            hop_timeout_ms=options.traceroute_hop_timeout_ms,
            log_dir=report_dir,
        )

    port_results: list[PortProbeResult] = []
    if tcping_exe is not None and options.ports:
        for p in options.ports:
            progress(f"正在 tcping 端口 {p} …")
            port_results.append(
                run_tcping_port(
                    tcping_exe,
                    probe_host,
                    p,
                    options.samples_per_port,
                    options.tcp_timeout_ms,
                    report_dir,
                )
            )

    if capture.ran:
        progress("正在停止抓包…")
        cap_session.stop()
        progress("抓包已停止。")
        if capture.stderr_path is not None and capture.stderr_path.is_file():
            err_blob = read_text_best_effort(capture.stderr_path, max_bytes=16_384)
            if err_blob.strip():
                tail = err_blob.strip()[-1800:]
                capture.notes = (
                    f"{capture.notes}\n\n---- tshark stderr（末尾，便于排查空包/权限） ----\n{tail}"
                )
        if (
            tshark_path is not None
            and capture.pcap_path is not None
            and capture.pcap_path.is_file()
        ):
            progress("正在用 tshark 分析抓包文件…")
            try:
                capture.analysis_summary = summarize_pcap(
                    tshark_path, capture.pcap_path, report_dir
                )
            except OSError:
                capture.analysis_summary = "抓包文件分析失败（tshark 调用出错）。"
            progress("抓包摘要分析完成。")

    bw: BandwidthProbeResult | None = _run_bandwidth(options, report_dir, progress, degradations)

    path_quality: ShellProbeResult | None = None
    if options.enable_pathping:
        progress("正在执行 PathPing / mtr（可能较慢）…")
        path_quality = run_path_quality(options.target_host, report_dir)

    tcp_path: ShellProbeResult | None = None
    if options.enable_tcp_traceroute:
        progress("正在执行 TCP 路径探测（nmap / traceroute -T）…")
        tport = options.ports[0] if options.ports else 443
        tcp_path = run_tcp_traceroute(
            options.target_host,
            tport,
            options.tcp_traceroute_max_hops,
            report_dir,
        )

    http_tls: HttpTlsProbeResult | None = None
    if options.enable_http_tls_probe:
        progress("正在探测 HTTPS / TLS…")
        http_tls = probe_https(options.target_host)

    egress: EgressProbeResult | None = None
    if options.enable_egress_probe:
        progress("正在探测出口公网 IP 与代理环境变量…")
        egress = run_egress()

    mtu: MtuProbeResult | None = None
    if options.enable_mtu_probe:
        progress("正在探测 IPv4 MTU（DF ping）…")
        mtu = run_mtu_probe(
            options.target_host,
            prefer_ipv6=options.prefer_ipv6,
            log_dir=report_dir,
        )

    finished = datetime.now().astimezone()
    md_path = report_dir / f"network_diagnosis_{task_id}.md"

    meta = TaskMeta(
        task_id=task_id,
        started_at=started,
        finished_at=finished,
        app_version=APP_VERSION,
        design_doc_ref=DESIGN_DOC_REF,
        hostname=socket.gethostname(),
        os_summary=platform.platform(),
        tcping_path=tcping_path_str,
        tcping_version_line=tcping_ver,
        tshark_path=str(tshark_path) if tshark_path else None,
        tshark_version_line=tshark_ver,
        report_dir=report_dir,
    )
    user_snap = UserInputSnapshot(
        target_host=options.target_host,
        ports=list(options.ports),
        samples_per_port=options.samples_per_port,
        tcp_connect_timeout_ms=options.tcp_timeout_ms,
        enable_ping=options.enable_ping,
        enable_capture=options.enable_capture,
        prefer_ipv6=options.prefer_ipv6,
        ping_count=options.ping_count,
        ping_long=options.ping_long,
        long_ping_seconds=options.long_ping_seconds,
        ping_packet_timeout_ms=options.ping_packet_timeout_ms,
        enable_traceroute=options.enable_traceroute,
        traceroute_max_hops=options.traceroute_max_hops,
        traceroute_hop_timeout_ms=options.traceroute_hop_timeout_ms,
        bandwidth_mode=_normalize_bw_mode(options.bandwidth_mode),
        bandwidth_http_url=options.bandwidth_http_url,
        bandwidth_http_parallel=options.bandwidth_http_parallel,
        bandwidth_http_seconds=options.bandwidth_http_seconds,
        bandwidth_iperf_host=options.bandwidth_iperf_host,
        bandwidth_iperf_port=options.bandwidth_iperf_port,
        bandwidth_iperf_seconds=options.bandwidth_iperf_seconds,
        optional_dns_server=(options.optional_dns_server or "").strip(),
        enable_pathping=options.enable_pathping,
        enable_tcp_traceroute=options.enable_tcp_traceroute,
        tcp_traceroute_max_hops=options.tcp_traceroute_max_hops,
        enable_http_tls_probe=options.enable_http_tls_probe,
        enable_egress_probe=options.enable_egress_probe,
        enable_mtu_probe=options.enable_mtu_probe,
        enable_history_compare=options.enable_history_compare,
    )
    gui = _build_gui_summary(
        dns,
        ping_okish,
        port_results,
        degradations,
        md_path,
        user_configured_ports=bool(options.ports),
        bandwidth=bw,
        bandwidth_mode=options.bandwidth_mode,
    )
    nq = compute_network_quality(
        dns,
        ping_stats,
        port_results,
        user_configured_ports=bool(options.ports),
        enable_ping=options.enable_ping,
        bandwidth=bw,
    )
    hist: HistoryCompareResult | None = None
    if options.enable_history_compare:
        hist = build_history_compare(
            target_host=options.target_host,
            current_task_id=task_id,
            current_grade=nq.grade,
            current_finished_iso=finished.isoformat(),
        )
    report = DiagnosticReport(
        meta=meta,
        user_input=user_snap,
        local=local,
        dns=dns,
        ping=ping_stats,
        traceroute=tr_stats,
        ports=port_results,
        capture=capture,
        degradations=degradations,
        gui=gui,
        network_quality=nq,
        bandwidth=bw,
        dns_specified=dns_specified,
        path_quality=path_quality,
        tcp_path=tcp_path,
        http_tls=http_tls,
        egress=egress,
        mtu=mtu,
        history_compare=hist,
    )
    write_markdown_report(report, md_path)
    progress(f"Markdown 报告已写入: {md_path}")
    if options.enable_history_compare:
        append_history(
            HistoryEntry(
                task_id=task_id,
                target_host=options.target_host,
                finished_at=finished.isoformat(),
                grade=nq.grade,
                report_dir=str(report_dir.resolve()),
                markdown_path=str(md_path.resolve()),
            )
        )
    return report
