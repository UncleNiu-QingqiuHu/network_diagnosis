"""tshark 抓包：探测、选网卡、起止子进程。"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

from network_diagnosis.probes.subproc_util import RunResult, read_text_best_effort, run_to_log_files


def tshark_version_line(tshark: Path, log_dir: Path) -> str | None:
    r = run_to_log_files([str(tshark), "-v"], log_dir, "tshark_version", timeout_sec=30)
    out = read_text_best_effort(r.stdout_path)
    for line in out.splitlines():
        if "TShark" in line or "tshark" in line.lower():
            return line.strip()[:500]
    err = read_text_best_effort(r.stderr_path)
    blob = (out + err).strip()
    return blob.splitlines()[0][:500] if blob else None


def _iface_choice_score(line: str) -> int:
    """越高越适合作为默认出局网卡（避免 VPN/虚拟机关联到空抓包）。"""
    low = line.lower()
    if "loopback" in low or "npcap loopback" in low:
        return -10_000
    score = 0
    for bad in (
        "vmware",
        "virtualbox",
        "hyper-v",
        "vethernet",
        "virtual ",
        "wintun",
        "tailscale",
        "zerotier",
        "fortinet",
        "wireguard",
        "tap-windows",
        "gvpn",
        "ppp",
    ):
        if bad in low:
            score -= 80
    for good in (
        "ethernet",
        "以太网",
        "wi-fi",
        "wifi",
        "wlan",
        "无线",
        "802.11",
        "gigabit",
    ):
        if good in low:
            score += 25
    return score


def pick_capture_interface_index(tshark: Path, log_dir: Path) -> str:
    r = run_to_log_files([str(tshark), "-D"], log_dir, "tshark_list_if", timeout_sec=30)
    text = read_text_best_effort(r.stdout_path)
    candidates: list[tuple[int, str, str]] = []
    fallback = "1"
    for line in text.splitlines():
        m = re.match(r"^(\d+)\.\s*(.+)$", line.strip())
        if not m:
            continue
        idx, desc = m.group(1), m.group(2)
        if "loopback" in desc.lower():
            continue
        candidates.append((_iface_choice_score(desc), idx))
    if not candidates:
        return fallback
    candidates.sort(key=lambda x: -x[0])
    return candidates[0][1]


def _creationflags() -> int:
    if sys.platform == "win32":
        try:
            return subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        except AttributeError:
            return 0
    return 0


class TsharkCaptureSession:
    def __init__(self) -> None:
        self._proc: subprocess.Popen[bytes] | None = None
        self._stdout_f = None
        self._stderr_f = None

    def start(
        self,
        tshark: Path,
        iface_idx: str,
        pcap_path: Path,
        capture_filter: str,
        log_dir: Path,
    ) -> tuple[Path, Path]:
        log_dir.mkdir(parents=True, exist_ok=True)
        out_log = log_dir / "tshark_capture.stdout.log"
        err_log = log_dir / "tshark_capture.stderr.log"
        argv = [
            str(tshark),
            "-i",
            iface_idx,
            "-w",
            str(pcap_path),
            "-f",
            capture_filter,
        ]
        self._stdout_f = out_log.open("wb")
        self._stderr_f = err_log.open("wb")
        self._proc = subprocess.Popen(  # noqa: S603
            argv,
            stdout=self._stdout_f,
            stderr=self._stderr_f,
            creationflags=_creationflags(),
        )
        return out_log, err_log

    def stop(self) -> int | None:
        proc = self._proc
        if proc is None:
            return None
        proc.terminate()
        try:
            proc.wait(timeout=45)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=20)
        rc = proc.returncode
        self._proc = None
        if self._stdout_f:
            self._stdout_f.close()
            self._stdout_f = None
        if self._stderr_f:
            self._stderr_f.close()
            self._stderr_f = None
        return rc


def _tshark_blob(r: RunResult) -> str:
    """合并一次 tshark 调用的 stdout / stderr（统计类输出常在 stderr）。"""
    return (
        read_text_best_effort(r.stdout_path) + "\n" + read_text_best_effort(r.stderr_path)
    ).strip()


def _count_pcap_frames(tshark: Path, pcap_path: Path, log_dir: Path) -> tuple[int, int | None]:
    """返回（帧数, tshark 退出码）。"""
    r = run_to_log_files(
        [str(tshark), "-r", str(pcap_path), "-n", "-T", "fields", "-e", "frame.number"],
        log_dir,
        "pcap_frame_count",
        timeout_sec=240,
    )
    txt = read_text_best_effort(r.stdout_path)
    n = len([ln for ln in txt.splitlines() if ln.strip()])
    return n, r.returncode


_MATCH_PROTO_FRAMES = re.compile(r"(?P<name>\S+)\s+frames:(?P<fr>\d+)\s+bytes:(?P<by>\d+)")


def _parse_io_phs_tcp(text: str) -> tuple[int | None, int | None, dict[str, int]]:
    """从 -z io,phs 文本解析 TCP 层帧数，以及常见子协议（tls/http）帧数。"""
    tcp_frames: int | None = None
    eth_frames: int | None = None
    sub: dict[str, int] = {}
    for line in text.splitlines():
        m = _MATCH_PROTO_FRAMES.search(line)
        if not m:
            continue
        fr = int(m.group("fr"))
        stripped = line.lstrip()
        if re.match(r"^eth\b", stripped):
            eth_frames = fr
        if re.match(r"^tcp\b", stripped):
            tcp_frames = fr
        for key in ("tls", "http", "dtls", "quic"):
            if re.match(rf"^{re.escape(key)}\b", stripped):
                sub[key] = fr
    return eth_frames, tcp_frames, sub


def _top_tcp_flows_for_family(
    tshark: Path,
    pcap_path: Path,
    log_dir: Path,
    *,
    stem: str,
    display_filter: str,
    fields: list[str],
    max_packets: int,
) -> tuple[list[tuple[tuple[tuple[str, int], tuple[str, int]], int]], int | None]:
    """返回 [((端点A,端点B), 报文数), ...] 降序；以及对应用到的报文行数。"""
    argv = [
        "-r",
        str(pcap_path),
        "-n",
        "-c",
        str(max_packets),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
    ]
    for f in fields:
        argv.extend(["-e", f])
    r = run_to_log_files([str(tshark), *argv], log_dir, stem, timeout_sec=240)
    txt = read_text_best_effort(r.stdout_path)
    ctr: Counter[tuple[tuple[str, int], tuple[str, int]]] = Counter()
    for line in txt.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < len(fields):
            continue
        a, ap, b, bp = parts[0], parts[1], parts[2], parts[3]
        if not (a and ap and b and bp):
            continue
        try:
            p1, p2 = int(ap), int(bp)
        except ValueError:
            continue
        ep1, ep2 = (a, p1), (b, p2)
        key = (ep1, ep2) if ep1 <= ep2 else (ep2, ep1)
        ctr[key] += 1
    top = sorted(ctr.items(), key=lambda x: -x[1])
    return top, r.returncode


def _fmt_endpoint(host: str, port: int) -> str:
    h = host.strip()
    try:
        ipaddress.IPv6Address(h.split("%")[0])
        return f"[{h}] 端口 {port}"
    except ValueError:
        return f"{h} 端口 {port}"


def summarize_pcap(
    tshark: Path,
    pcap_path: Path,
    log_dir: Path,
    *,
    max_flow_packets: int = 50_000,
    top_n_flows: int = 5,
) -> str:
    """用 tshark 只读 pcapng，输出面向普通人的中文摘要（非原始表格）。"""
    log_dir.mkdir(parents=True, exist_ok=True)
    out: list[str] = []

    n_frames, rc_fc = _count_pcap_frames(tshark, pcap_path, log_dir)
    if rc_fc not in (0, None):
        out.append(f"tshark 统计帧数时返回了非零退出码（{rc_fc}），下列结论仅供参考。")

    if n_frames == 0:
        return "抓包文件里几乎没有可用数据帧，可能是文件损坏、抓包极短，或尚未写入完成。"

    out.append(f"● 规模：这次抓包里一共记录了 {n_frames} 个网络帧（含各层协议头和载荷）。")

    r_phs = run_to_log_files(
        [str(tshark), "-r", str(pcap_path), "-n", "-q", "-z", "io,phs"],
        log_dir,
        "pcap_io_phs",
        timeout_sec=240,
    )
    phs_blob = _tshark_blob(r_phs)
    eth_f, tcp_f, sub = _parse_io_phs_tcp(phs_blob)

    if tcp_f is not None and n_frames > 0:
        pct = min(100.0, max(0.0, 100.0 * tcp_f / n_frames))
        out.append(
            f"● 协议大致情况：其中约有 {tcp_f} 个帧属于 TCP 层，大约占全部帧的 {pct:.0f}%。"
        )
        if tcp_f == 0:
            out.append(
                "  换句话说：这段时间里几乎看不到 TCP。"
                "常见原因包括 BPF 过滤器太窄、链路上只有 ARP/ICMP/UDP 等非 TCP 流量，或抓包窗口内对端没有发起 TCP。"
            )
        elif tcp_f > 0:
            extras: list[str] = []
            if sub.get("tls", 0) > 0:
                extras.append(f"在 TCP 里还能看到约 {sub['tls']} 帧与 TLS 加密握手或加密数据相关")
            if sub.get("http", 0) > 0:
                extras.append(f"还能看到约 {sub['http']} 帧与未加密 HTTP 有关（若有混用，通常出现在建立 TLS 之前）")
            if sub.get("dtls", 0) > 0:
                extras.append(f"另有约 {sub['dtls']} 帧与 DTLS（基于 UDP 的 TLS）有关")
            if extras:
                out.append("  " + "；".join(extras) + "。")
        if sub.get("quic", 0) > 0 and tcp_f == 0:
            out.append(
                f"  另外：统计里还能看到约 {sub['quic']} 帧 QUIC（一般跑在 UDP 上），"
                "这不算传统意义上的 TCP 网页流量。"
            )
    elif eth_f is not None:
        out.append(
            f"● 协议大致情况：能在分层统计里看到以太网层约有 {eth_f} 帧，"
            "未能可靠读出 TCP 行（可能与 tshark 版本或链路类型有关）。"
        )
    else:
        out.append(
            "● 协议大致情况：未能解析协议分层统计（io,phs），"
            "但不影响您稍后仍可用 Wireshark 打开文件人工确认。"
        )

    v4_top, rc_v4 = _top_tcp_flows_for_family(
        tshark,
        pcap_path,
        log_dir,
        stem="pcap_flows_v4",
        display_filter="tcp && ip",
        fields=["ip.src", "tcp.srcport", "ip.dst", "tcp.dstport"],
        max_packets=max_flow_packets,
    )
    v6_top, rc_v6 = _top_tcp_flows_for_family(
        tshark,
        pcap_path,
        log_dir,
        stem="pcap_flows_v6",
        display_filter="tcp && ipv6",
        fields=["ipv6.src", "tcp.srcport", "ipv6.dst", "tcp.dstport"],
        max_packets=max_flow_packets,
    )

    if rc_v4 not in (0, None) and rc_v6 not in (0, None):
        out.append(f"● 会话归纳：按四元组统计 TCP 流时 tshark 报错（IPv4 退出码 {rc_v4}，IPv6 {rc_v6}），跳过会话列表。")
    elif not v4_top and not v6_top:
        if tcp_f is not None and tcp_f > 0:
            out.append(
                "● 会话归纳：文件里虽然有 TCP 帧，但在本次抽样里没有整理出清晰的「谁连谁」四元组列表，"
                "可能是非常碎的握手、重传或字段提取边界情况，建议用 Wireshark 里「统计 → 对话」细看。"
            )
        else:
            out.append("● 会话归纳：没有可供归纳的 IPv4/IPv6 TCP 四元组流量（与上面「几乎没有 TCP」判断一致）。")
    else:
        out.append(
            f"● 会话归纳：为控制耗时，下面只在整文件的前 {max_flow_packets} 个帧里抽样统计 TCP 报文，"
            "用来描述「哪两端的地址和端口来回说话最多」，不等于精确的会话总次数。"
        )
        n_v4_sess = len(v4_top)
        n_v6_sess = len(v6_top)
        if v4_top:
            out.append(
                f"  - IPv4：至少能数出 {n_v4_sess} 组不同的双向 TCP 会话（按地址:端口合并了正反方向）。"
            )
            for i, (endpoints, cnt) in enumerate(v4_top[:top_n_flows], 1):
                (h1, p1), (h2, p2) = endpoints
                out.append(
                    f"    {i}. {_fmt_endpoint(h1, p1)} ↔ {_fmt_endpoint(h2, p2)}：约 {cnt} 个 TCP 帧（仅在抽样范围内）。"
                )
        if v6_top:
            out.append(
                f"  - IPv6：至少能数出 {n_v6_sess} 组不同的双向 TCP 会话。"
            )
            for i, (endpoints, cnt) in enumerate(v6_top[:top_n_flows], 1):
                (h1, p1), (h2, p2) = endpoints
                out.append(
                    f"    {i}. {_fmt_endpoint(h1, p1)} ↔ {_fmt_endpoint(h2, p2)}：约 {cnt} 个 TCP 帧（仅在抽样范围内）。"
                )

    out.append(
        "● 说明：以上是自动生成的「快速可读结论」，方便非技术人员理解："
        "有没有 TCP、流量大致集中在哪些端点之间。"
        "如需确认 RST、重传、TLS 握手细节等，请交给技术人员用 Wireshark 打开同一路 pcap 深入分析。"
    )
    return "\n".join(out)
