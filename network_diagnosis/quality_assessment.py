"""根据 ping / tcping / DNS 结果综合评判网络质量与指标摘要。"""

from __future__ import annotations

import statistics
from collections.abc import Iterable

from network_diagnosis.model.report import (
    BandwidthProbeResult,
    DnsAnswer,
    NetworkQualityAssessment,
    PingStats,
    PortFailureClass,
    PortProbeResult,
)

_THROUGHPUT_NOTE = (
    "本工具默认未做带宽/吞吐量压测；若未手动启用下方抽样，则无 Mbps 级速率。"
    "其它指标来自 ICMP 与 TCP 连接层面的抽样，可间接反映链路稳定性与时延。"
)


def _throughput_bandwidth_body(bw: BandwidthProbeResult | None) -> tuple[str, str]:
    """得到「带宽/吞吐量」段落正文与简短的 throughput_note。"""
    if bw is None:
        return _THROUGHPUT_NOTE, _THROUGHPUT_NOTE
    if bw.ok and bw.megabits_per_second is not None:
        body = (
            f"抽样约 {bw.megabits_per_second:.1f} Mbps（{bw.mode} → {bw.target_label}）。"
            "仅为到该目标与当前窗口条件下的估计，非签约带宽。"
        )
        short = f"抽样约 {bw.megabits_per_second:.1f} Mbps（{bw.mode}）。"
        return body, short
    if bw.ok:
        tail = bw.summary or "抽样已完成。"
        body = f"{tail}（未得到统一 Mbps 汇总）。"
        return body, body[:200]
    err = " ".join(x for x in (bw.summary, bw.error) if x).strip() or "失败"
    body = f"本次抽样未成功：{err}。不作为签约带宽依据。"
    return body, body[:200]


def _mean_jitter_ipdv(rtts: list[float]) -> float | None:
    """相邻 RTT 差分绝对值的平均（常见抖动近似）。"""
    if len(rtts) < 2:
        return 0.0 if len(rtts) == 1 else None
    diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
    return sum(diffs) / len(diffs)


def _stdev_or_none(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    return float(statistics.stdev(values))


def _collect_tcp_rtts(port_results: Iterable[PortProbeResult]) -> list[float]:
    out: list[float] = []
    for pr in port_results:
        for s in pr.samples:
            if s.success and s.rtt_ms is not None:
                out.append(s.rtt_ms)
    return out


def _tcp_sample_loss_pct(port_results: list[PortProbeResult]) -> float | None:
    total = 0
    bad = 0
    for pr in port_results:
        for s in pr.samples:
            total += 1
            if not s.success:
                bad += 1
    if total == 0:
        return None
    return 100.0 * bad / total


def compute_network_quality(
    dns: DnsAnswer,
    ping: PingStats | None,
    port_results: list[PortProbeResult],
    *,
    user_configured_ports: bool,
    enable_ping: bool,
    bandwidth: BandwidthProbeResult | None = None,
) -> NetworkQualityAssessment:
    metric_lines: list[str] = []

    if dns.error or not dns.addresses:
        metric_lines.append("丢包率：—（DNS 失败，未建立有效探测）")
        metric_lines.append("时延/延迟：—")
        metric_lines.append("抖动：—")
        tb, tn = _throughput_bandwidth_body(bandwidth)
        metric_lines.append(f"带宽/吞吐量：{tb}")
        return NetworkQualityAssessment(
            grade="堵塞",
            loss_pct=None,
            avg_latency_ms=None,
            jitter_ms=None,
            throughput_note=tn,
            metric_lines=metric_lines,
        )

    loss_pct: float | None = None
    loss_source = ""

    if enable_ping and ping is not None and ping.attempted > 0:
        loss_pct = 100.0 * ping.lost / ping.attempted
        loss_source = "ICMP Ping"
    elif user_configured_ports and port_results:
        loss_pct = _tcp_sample_loss_pct(port_results)
        loss_source = "TCP 连接尝试（tcping 抽样）"

    avg_lat: float | None = None
    lat_source = ""

    if enable_ping and ping is not None and ping.rtts_ms:
        avg_lat = float(statistics.mean(ping.rtts_ms))
        lat_source = "ICMP Ping RTT"
    else:
        tcp_rtts = _collect_tcp_rtts(port_results)
        if tcp_rtts:
            avg_lat = float(statistics.mean(tcp_rtts))
            lat_source = "TCP 握手 RTT（tcping）"

    jitter_ms: float | None = None
    if enable_ping and ping is not None and len(ping.rtts_ms) >= 1:
        jitter_ms = _mean_jitter_ipdv(ping.rtts_ms)
    elif port_results:
        tcp_rtts = _collect_tcp_rtts(port_results)
        jitter_ms = _stdev_or_none(tcp_rtts)
        if jitter_ms is not None:
            lat_source = lat_source or "TCP 握手 RTT（tcping）"

    # 指标展示
    if loss_pct is not None and loss_source:
        metric_lines.append(f"丢包率：{loss_pct:.1f}%（依据 {loss_source}）")
    else:
        metric_lines.append("丢包率：—（本轮未启用 Ping 或未配置端口抽样，无法估算）")

    if avg_lat is not None and lat_source:
        metric_lines.append(f"时延/延迟：平均约 {avg_lat:.1f} ms（{lat_source}）")
    else:
        metric_lines.append("时延/延迟：—（无可用 RTT 样本）")

    if jitter_ms is not None:
        src = "ICMP" if enable_ping and ping and len(ping.rtts_ms or []) >= 2 else "TCP RTT 波动"
        metric_lines.append(f"抖动：约 {jitter_ms:.1f} ms（{src}）")
    else:
        metric_lines.append("抖动：—（样本过少）")

    tb, tn = _throughput_bandwidth_body(bandwidth)
    metric_lines.append(f"带宽/吞吐量：{tb}")

    all_ports_bad = bool(
        user_configured_ports and port_results and all(p.failure_class != PortFailureClass.OK for p in port_results)
    )
    some_ports_bad = bool(
        user_configured_ports and port_results and any(p.failure_class != PortFailureClass.OK for p in port_results)
    )

    bad_ports = [
        p
        for p in port_results
        if p.failure_class
        in (PortFailureClass.TIMEOUT, PortFailureClass.UNREACHABLE, PortFailureClass.ERROR)
    ]

    ping_hard_fail = bool(enable_ping and ping is not None and ping.attempted > 0 and ping.received == 0)

    grade: str

    if all_ports_bad and user_configured_ports:
        grade = "堵塞"
    elif ping_hard_fail and (loss_pct is None or (loss_pct is not None and loss_pct >= 25)):
        grade = "堵塞"
    elif loss_pct is not None and loss_pct >= 15:
        grade = "堵塞"
    elif avg_lat is not None and avg_lat >= 400 and loss_pct is not None and loss_pct >= 5:
        grade = "堵塞"
    elif loss_pct is not None and loss_pct >= 5:
        grade = "较差"
    elif avg_lat is not None and avg_lat >= 150:
        grade = "较差"
    elif jitter_ms is not None and jitter_ms >= 40:
        grade = "较差"
    elif some_ports_bad and bad_ports:
        grade = "较差"
    elif ping_hard_fail and not user_configured_ports:
        grade = "较差"
    elif (
        loss_pct is not None
        and loss_pct <= 2.0
        and avg_lat is not None
        and avg_lat <= 70
        and (jitter_ms is None or jitter_ms <= 25)
        and not some_ports_bad
    ):
        grade = "极佳"
    elif not enable_ping and not user_configured_ports:
        grade = "正常"
    elif avg_lat is None and loss_pct is None:
        grade = "正常"
    else:
        grade = "正常"

    return NetworkQualityAssessment(
        grade=grade,
        loss_pct=loss_pct,
        avg_latency_ms=avg_lat,
        jitter_ms=jitter_ms,
        throughput_note=tn,
        metric_lines=metric_lines,
    )
