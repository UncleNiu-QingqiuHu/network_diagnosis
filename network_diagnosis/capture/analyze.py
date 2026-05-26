"""pcap 扩展分析（协议树、会话、异常、报文预览）。"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from network_diagnosis.capture.models import ExpertWarning, FlowStat, PacketPreviewRow
from network_diagnosis.probes.subproc_util import read_text_best_effort, run_to_log_files
from network_diagnosis.probes.tshark import (
    _MATCH_PROTO_FRAMES,
    _count_pcap_frames,
    _fmt_endpoint,
    _top_tcp_flows_for_family,
)

_CONV_LINE = re.compile(
    r"^\s*(?P<a>[\d.A-Fa-f:\[\]%.]+):(?P<ap>\d+)\s*"
    r"(?:<->|→)\s*"
    r"(?P<b>[\d.A-Fa-f:\[\]%.]+):(?P<bp>\d+)\s*"
    r"(?P<rest>.*)$"
)


def _tshark_blob(r) -> str:
    return (
        read_text_best_effort(r.stdout_path) + "\n" + read_text_best_effort(r.stderr_path)
    ).strip()


def measure_pcap_duration_sec(tshark: Path, pcap_path: Path, log_dir: Path) -> float | None:
    r = run_to_log_files(
        [
            str(tshark),
            "-r",
            str(pcap_path),
            "-n",
            "-T",
            "fields",
            "-e",
            "frame.time_epoch",
        ],
        log_dir,
        "pcap_time_span",
        timeout_sec=240,
    )
    times: list[float] = []
    for line in read_text_best_effort(r.stdout_path).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            times.append(float(line))
        except ValueError:
            continue
    if len(times) < 2:
        return None
    return max(times) - min(times)


def parse_protocol_hierarchy(tshark: Path, pcap_path: Path, log_dir: Path) -> dict[str, int]:
    r = run_to_log_files(
        [str(tshark), "-r", str(pcap_path), "-n", "-q", "-z", "io,phs"],
        log_dir,
        "pcap_io_phs_ext",
        timeout_sec=240,
    )
    blob = _tshark_blob(r)
    out: dict[str, int] = {}
    for line in blob.splitlines():
        m = _MATCH_PROTO_FRAMES.search(line)
        if not m:
            continue
        name = m.group("name").strip()
        if name:
            out[name] = int(m.group("fr"))
    return out


def _parse_conv_udp(text: str, *, top_n: int = 5) -> list[FlowStat]:
    stats: list[tuple[str, int, str, int, int]] = []
    for line in text.splitlines():
        if "<->" not in line:
            continue
        left, _, right = line.partition("<->")
        left = left.strip()
        right = right.strip()
        lm = re.match(r"^(?P<h>[\d.A-Fa-f:\[\]%.]+):(?P<p>\d+)", left)
        rm = re.match(r"^(?P<h>[\d.A-Fa-f:\[\]%.]+):(?P<p>\d+)", right)
        if not lm or not rm:
            continue
        total_m = re.search(r"\b(\d+)\s+\d+\s+bytes\s*$", right)
        if not total_m:
            total_m = re.search(r"\|\s*(\d+)\s+\d+\s+bytes", line)
        if not total_m:
            continue
        try:
            cnt = int(total_m.group(1))
            ap, bp = int(lm.group("p")), int(rm.group("p"))
        except ValueError:
            continue
        stats.append((lm.group("h"), ap, rm.group("h"), bp, cnt))
    stats.sort(key=lambda x: -x[4])
    out: list[FlowStat] = []
    for h1, p1, h2, p2, cnt in stats[:top_n]:
        out.append(
            FlowStat(
                family="udp",
                endpoint_a=_fmt_endpoint(h1, p1),
                endpoint_b=_fmt_endpoint(h2, p2),
                packet_count=cnt,
            )
        )
    return out


def collect_top_udp_flows(
    tshark: Path,
    pcap_path: Path,
    log_dir: Path,
    *,
    display_filter: str | None = None,
    top_n: int = 5,
) -> list[FlowStat]:
    argv = [str(tshark), "-r", str(pcap_path), "-n", "-q", "-z", "conv,udp"]
    if display_filter and display_filter.strip():
        argv[2:2] = ["-Y", display_filter.strip()]
    r = run_to_log_files(argv, log_dir, "pcap_conv_udp", timeout_sec=240)
    return _parse_conv_udp(_tshark_blob(r), top_n=top_n)


def collect_top_tcp_flows_structured(
    tshark: Path,
    pcap_path: Path,
    log_dir: Path,
    *,
    display_filter: str | None = None,
    top_n: int = 5,
    max_packets: int = 50_000,
) -> list[FlowStat]:
    df_v4 = "tcp && ip"
    df_v6 = "tcp && ipv6"
    if display_filter and display_filter.strip():
        df_v4 = f"({display_filter.strip()}) && tcp && ip"
        df_v6 = f"({display_filter.strip()}) && tcp && ipv6"
    v4, _ = _top_tcp_flows_for_family(
        tshark,
        pcap_path,
        log_dir,
        stem="pcap_flows_v4_ext",
        display_filter=df_v4,
        fields=["ip.src", "tcp.srcport", "ip.dst", "tcp.dstport"],
        max_packets=max_packets,
    )
    v6, _ = _top_tcp_flows_for_family(
        tshark,
        pcap_path,
        log_dir,
        stem="pcap_flows_v6_ext",
        display_filter=df_v6,
        fields=["ipv6.src", "tcp.srcport", "ipv6.dst", "tcp.dstport"],
        max_packets=max_packets,
    )
    merged: list[tuple[tuple[tuple[str, int], tuple[str, int]], int, str]] = []
    for endpoints, cnt in v4:
        (h1, p1), (h2, p2) = endpoints
        merged.append((endpoints, cnt, "ipv4"))
    for endpoints, cnt in v6:
        merged.append((endpoints, cnt, "ipv6"))
    merged.sort(key=lambda x: -x[1])
    out: list[FlowStat] = []
    for endpoints, cnt, fam in merged[:top_n]:
        (h1, p1), (h2, p2) = endpoints
        out.append(
            FlowStat(
                family=fam,  # type: ignore[arg-type]
                endpoint_a=_fmt_endpoint(h1, p1),
                endpoint_b=_fmt_endpoint(h2, p2),
                packet_count=cnt,
            )
        )
    return out


def _count_display_filter(
    tshark: Path,
    pcap_path: Path,
    log_dir: Path,
    *,
    stem: str,
    display_filter: str,
    timeout_sec: float = 240,
) -> int:
    r = run_to_log_files(
        [
            str(tshark),
            "-r",
            str(pcap_path),
            "-n",
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        log_dir,
        stem,
        timeout_sec=timeout_sec,
    )
    return len([ln for ln in read_text_best_effort(r.stdout_path).splitlines() if ln.strip()])


def count_retransmissions(tshark: Path, pcap_path: Path, log_dir: Path, *, display_filter: str | None) -> int:
    df = "tcp.analysis.retransmission"
    if display_filter and display_filter.strip():
        df = f"({display_filter.strip()}) && tcp.analysis.retransmission"
    return _count_display_filter(tshark, pcap_path, log_dir, stem="pcap_retrans", display_filter=df)


def count_tcp_rst(tshark: Path, pcap_path: Path, log_dir: Path, *, display_filter: str | None) -> int:
    df = "tcp.flags.reset==1"
    if display_filter and display_filter.strip():
        df = f"({display_filter.strip()}) && tcp.flags.reset==1"
    return _count_display_filter(tshark, pcap_path, log_dir, stem="pcap_rst", display_filter=df)


def collect_dns_queries(
    tshark: Path,
    pcap_path: Path,
    log_dir: Path,
    *,
    display_filter: str | None = None,
    limit: int = 20,
) -> list[str]:
    df = "dns.flags.response==0 && dns.qry.name"
    if display_filter and display_filter.strip():
        df = f"({display_filter.strip()}) && dns.flags.response==0 && dns.qry.name"
    r = run_to_log_files(
        [
            str(tshark),
            "-r",
            str(pcap_path),
            "-n",
            "-Y",
            df,
            "-T",
            "fields",
            "-e",
            "dns.qry.name",
        ],
        log_dir,
        "pcap_dns_queries",
        timeout_sec=240,
    )
    seen: set[str] = set()
    out: list[str] = []
    for line in read_text_best_effort(r.stdout_path).splitlines():
        q = line.strip()
        if not q or q in seen:
            continue
        seen.add(q)
        out.append(q)
        if len(out) >= limit:
            break
    return out


def collect_tls_sni(
    tshark: Path,
    pcap_path: Path,
    log_dir: Path,
    *,
    display_filter: str | None = None,
    limit: int = 20,
) -> list[str]:
    df = "ssl.handshake.type==1 && tls.handshake.extensions_server_name"
    if display_filter and display_filter.strip():
        df = f"({display_filter.strip()}) && ssl.handshake.type==1 && tls.handshake.extensions_server_name"
    r = run_to_log_files(
        [
            str(tshark),
            "-r",
            str(pcap_path),
            "-n",
            "-Y",
            df,
            "-T",
            "fields",
            "-e",
            "tls.handshake.extensions_server_name",
        ],
        log_dir,
        "pcap_tls_sni",
        timeout_sec=240,
    )
    seen: set[str] = set()
    out: list[str] = []
    for line in read_text_best_effort(r.stdout_path).splitlines():
        s = line.strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= limit:
            break
    return out


def summarize_http_status(
    tshark: Path,
    pcap_path: Path,
    log_dir: Path,
    *,
    display_filter: str | None = None,
) -> str:
    df = "http.response.code"
    if display_filter and display_filter.strip():
        df = f"({display_filter.strip()}) && http.response.code"
    r = run_to_log_files(
        [
            str(tshark),
            "-r",
            str(pcap_path),
            "-n",
            "-Y",
            df,
            "-T",
            "fields",
            "-e",
            "http.response.code",
        ],
        log_dir,
        "pcap_http_codes",
        timeout_sec=240,
    )
    ctr: Counter[str] = Counter()
    for line in read_text_best_effort(r.stdout_path).splitlines():
        code = line.strip()
        if code:
            ctr[code] += 1
    if not ctr:
        return ""
    parts = [f"HTTP {code}×{cnt}" for code, cnt in sorted(ctr.items(), key=lambda x: -x[1])]
    return "；".join(parts[:10])


def collect_packet_preview(
    tshark: Path,
    pcap_path: Path,
    log_dir: Path,
    *,
    display_filter: str | None = None,
    limit: int = 500,
) -> list[PacketPreviewRow]:
    argv = [
        str(tshark),
        "-r",
        str(pcap_path),
        "-n",
        "-c",
        str(limit),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.number",
        "-e",
        "frame.time_relative",
        "-e",
        "ip.src",
        "-e",
        "ipv6.src",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.dst",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "frame.len",
        "-e",
        "_ws.col.Info",
    ]
    if display_filter and display_filter.strip():
        argv[4:4] = ["-Y", display_filter.strip()]
    r = run_to_log_files(argv, log_dir, "pcap_preview", timeout_sec=240)
    rows: list[PacketPreviewRow] = []
    for line in read_text_best_effort(r.stdout_path).splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        while len(parts) < 9:
            parts.append("")
        no_s, t_rel, ip4s, ip6s, ip4d, ip6d, proto, ln, info = parts[:9]
        try:
            no = int(no_s)
            length = int(ln) if ln.strip().isdigit() else 0
        except ValueError:
            continue
        src = ip4s.strip() or ip6s.strip() or "—"
        dst = ip4d.strip() or ip6d.strip() or "—"
        rows.append(
            PacketPreviewRow(
                no=no,
                time_relative=t_rel.strip() or "—",
                src=src,
                dst=dst,
                protocol=proto.strip() or "—",
                length=length,
                info=info.strip()[:200],
            )
        )
    return rows


def build_expert_warnings(
    *,
    retransmission_count: int | None,
    rst_count: int | None,
) -> list[ExpertWarning]:
    out: list[ExpertWarning] = []
    if retransmission_count is not None and retransmission_count > 0:
        out.append(
            ExpertWarning(
                severity="warn",
                summary="检测到 TCP 重传",
                count=retransmission_count,
            )
        )
    if rst_count is not None and rst_count > 0:
        out.append(
            ExpertWarning(
                severity="warn",
                summary="检测到 TCP RST",
                count=rst_count,
            )
        )
    return out


def count_pcap_frames(tshark: Path, pcap_path: Path, log_dir: Path) -> tuple[int, int | None]:
    return _count_pcap_frames(tshark, pcap_path, log_dir)
