"""授权目标 TCP 端口扫描：默认纯 Python connect 扫描，可选 nmap -sT（单主机、仅 IPv4）。"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import NamedTuple

from network_diagnosis.paths import resolve_nmap_exe_path as resolve_nmap_exe_candidate

# 预设 key → 对外展示名称（GUI 下拉）
TCP_SCAN_PRESET_ITEMS: list[tuple[str, str]] = [
    ("web_common", "Web / 常见服务"),
    ("remote_admin", "远程管理"),
    ("database", "数据库"),
    ("custom", "自定义端口列表"),
]

_TCP_SCAN_PRESETS: dict[str, list[int]] = {
    "web_common": [
        21,
        22,
        25,
        53,
        80,
        110,
        143,
        443,
        445,
        993,
        995,
        1433,
        3306,
        3389,
        5432,
        8080,
        8443,
        8888,
    ],
    "remote_admin": [22, 135, 139, 445, 3389, 5985, 5986, 47001],
    "database": [1433, 1521, 3306, 5432, 6379, 27017, 9200],
}

_MAX_PORTS = 2048
_MIN_WORKERS = 1
_MAX_WORKERS = 200
_DEFAULT_WORKERS = 50
_MIN_TIMEOUT = 0.3
_MAX_TIMEOUT = 30.0


class PortProbeResult(NamedTuple):
    port: int
    state: str  # open | closed | timeout | error
    latency_ms: int | None
    banner: str | None


def _sanitize_banner(raw: bytes, *, limit: int = 240) -> str:
    t = raw.decode("utf-8", errors="replace")
    out = []
    for c in t:
        if c.isprintable():
            out.append(c)
        elif c in "\t\r\n":
            out.append(" ")
        else:
            out.append(".")
    s = "".join(out)
    s = s.replace("|", "｜")
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit] if s else ""


def parse_tcp_ports_spec(spec: str) -> list[int]:
    """解析端口列表：逗号分隔，支持 a-b 闭区间；去重升序，上限 _MAX_PORTS。"""
    spec = spec.strip()
    if not spec:
        raise ValueError("自定义端口为空：请输入端口列表（如 80,443 或 8000-8010）。")
    out: set[int] = set()
    for part in spec.split(","):
        p = part.strip()
        if not p:
            continue
        if "-" in p:
            a, b = p.split("-", 1)
            lo = int(a.strip())
            hi = int(b.strip())
            if lo > hi:
                lo, hi = hi, lo
            for x in range(lo, hi + 1):
                out.add(x)
        else:
            out.add(int(p))
    for x in out:
        if x < 1 or x > 65535:
            raise ValueError(f"端口超出范围 1–65535：{x}")
    ordered = sorted(out)
    if len(ordered) > _MAX_PORTS:
        raise ValueError(f"端口数量超过上限 {_MAX_PORTS}，请缩小范围。")
    if not ordered:
        raise ValueError("未解析到任何有效端口。")
    return ordered


def resolve_scan_target_ipv4(host: str) -> tuple[str, str]:
    """
    校验主机令牌并解析为 IPv4。
    返回 (ipv4, 说明)；多个 A 记录时仅取第一条（与设计文档一致）。
    """
    host = host.strip()
    if not host:
        raise ValueError("扫描目标不能为空。")
    if len(host) > 253:
        raise ValueError("主机名过长。")
    if any(c in host for c in (" ", "/", "\\", ":", "\t", "\n")):
        raise ValueError("请勿输入 URL、端口或路径；仅填写主机名或 IPv4 地址。")
    try:
        ip = str(ipaddress.IPv4Address(host))
        return ip, "用户输入为 IPv4，未再解析。"
    except ipaddress.AddressValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"无法解析主机名为 IPv4：{e}") from e
    if not infos:
        raise ValueError("解析结果为空（无 IPv4 记录）。")
    ip = infos[0][4][0]
    note = f"将主机名解析为 IPv4：**{ip}**（多个 A 记录时仅使用第一条）。"
    return ip, note


def _probe_tcp_port(
    ip: str,
    port: int,
    *,
    timeout: float,
    grab_banner: bool,
) -> PortProbeResult:
    t0 = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            elapsed_ms = max(0, int((time.perf_counter() - t0) * 1000))
            banner: str | None = None
            if grab_banner:
                bt = min(1.5, max(timeout, 0.5))
                sock.settimeout(bt)
                try:
                    chunk = sock.recv(4096)
                    if chunk:
                        b = _sanitize_banner(chunk)
                        banner = b if b else None
                except OSError:
                    banner = None
            return PortProbeResult(port, "open", elapsed_ms, banner)
    except TimeoutError:
        return PortProbeResult(port, "timeout", None, None)
    except ConnectionRefusedError:
        elapsed_ms = max(0, int((time.perf_counter() - t0) * 1000))
        return PortProbeResult(port, "closed", elapsed_ms, None)
    except OSError as e:
        elapsed_ms = max(0, int((time.perf_counter() - t0) * 1000))
        err = str(e).replace("|", "｜")[:120]
        return PortProbeResult(port, "error", elapsed_ms, err or None)


def _scan_tcp_python(
    ip: str,
    ports: list[int],
    *,
    max_workers: int,
    timeout: float,
    grab_banner: bool,
) -> list[PortProbeResult]:
    workers = max(_MIN_WORKERS, min(max_workers, _MAX_WORKERS, len(ports)))
    results: list[PortProbeResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        fut_map = {
            pool.submit(_probe_tcp_port, ip, p, timeout=timeout, grab_banner=grab_banner): p for p in ports
        }
        for fut in as_completed(fut_map):
            results.append(fut.result())
    results.sort(key=lambda r: r.port)
    return results


def _resolve_nmap_exe(user_path: str) -> str:
    p = user_path.strip().strip('"')
    if p:
        if os.path.isfile(p):
            return p
        raise ValueError(f"nmap 路径无效（文件不存在）：{p}")
    found = resolve_nmap_exe_candidate()
    if found:
        return found
    raise ValueError(
        "未找到 nmap。请安装至默认目录或加入 PATH，填写「nmap 路径」，"
        "或将 nmap.exe 置于 ThirdParty/Nmap/，或使用界面「检测 Nmap」。"
    )


def _xml_local_tag(tag: str) -> str:
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def _xml_find_child(parent: ET.Element, local: str) -> ET.Element | None:
    for ch in parent:
        if _xml_local_tag(ch.tag) == local:
            return ch
    return None


def _scan_tcp_nmap(
    ip: str,
    ports: list[int],
    *,
    nmap_exe: str,
) -> tuple[list[tuple[int, str, str]], str]:
    """返回 ([(port, state, fingerprint)], raw_xml_or_empty)。"""
    port_arg = ",".join(str(p) for p in ports)
    host_timeout = min(180, max(45, 30 + len(ports) // 5))
    cmd = [
        nmap_exe,
        "-sT",
        "-Pn",
        "-oX",
        "-",
        "-p",
        port_arg,
        "--host-timeout",
        f"{host_timeout}s",
        ip,
    ]
    kwargs: dict[str, object] = dict(capture_output=True, timeout=min(300, 90 + len(ports) // 3))
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    try:
        proc = subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"nmap 执行超时：{e}") from e
    raw_out = proc.stdout or b""
    raw_err = proc.stderr or b""
    xml_text = raw_out.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        err_s = raw_err.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"nmap 退出码 {proc.returncode}\n{err_s or xml_text[:2000]}")

    rows: list[tuple[int, str, str]] = []
    try:
        root = ET.fromstring(raw_out)
    except ET.ParseError as e:
        raise RuntimeError(f"无法解析 nmap XML 输出：{e}") from e

    for el in root.iter():
        if _xml_local_tag(el.tag) != "port":
            continue
        pel = el
        if pel.get("protocol") != "tcp":
            continue
        pid_s = pel.get("portid")
        if not pid_s:
            continue
        try:
            pid = int(pid_s)
        except ValueError:
            continue
        st_el = _xml_find_child(pel, "state")
        state = st_el.get("state") if st_el is not None else "unknown"
        fp = "—"
        svc_el = _xml_find_child(pel, "service")
        if svc_el is not None:
            parts = [
                svc_el.get("name") or "",
                svc_el.get("product") or "",
                svc_el.get("version") or "",
                svc_el.get("extrainfo") or "",
            ]
            fp = " ".join(x for x in parts if x).strip() or "—"
        rows.append((pid, state or "unknown", fp.replace("|", "｜")))
    rows.sort(key=lambda x: x[0])
    return rows, xml_text


def _state_label_zh(state: str) -> str:
    return {
        "open": "开放",
        "closed": "关闭",
        "filtered": "过滤/未知",
        "open|filtered": "开放|过滤",
        "closed|filtered": "关闭|过滤",
        "unfiltered": "未过滤",
        "timeout": "超时",
        "error": "错误",
    }.get(state, state)


def authorized_tcp_port_scan_markdown(
    *,
    host: str,
    preset_key: str,
    custom_ports_spec: str,
    max_workers: int,
    timeout_sec: float,
    grab_banner: bool,
    use_nmap: bool,
    nmap_exe_path: str,
) -> str:
    """生成「授权目标 — TCP 端口扫描」Markdown（调用前由 GUI 校验授权勾选）。"""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ip, resolve_note = resolve_scan_target_ipv4(host)

    if preset_key == "custom":
        ports = parse_tcp_ports_spec(custom_ports_spec)
    else:
        ports = list(_TCP_SCAN_PRESETS.get(preset_key, []))
        if not ports:
            raise ValueError(f"未知预设：{preset_key}")
    ports = sorted(set(ports))

    workers_n = max(_MIN_WORKERS, min(int(max_workers), _MAX_WORKERS))
    conn_timeout = max(_MIN_TIMEOUT, min(float(timeout_sec), _MAX_TIMEOUT))

    lines: list[str] = [
        "### 网络安全诊断（授权目标 — TCP 端口扫描）",
        "",
        f"- **扫描时刻**：{now}",
        f"- **原始输入**：`{host.replace('`', '')}`",
        f"- **解析**：{resolve_note}",
        f"- **后端**：{'nmap（`-sT`）' if use_nmap else 'Python `socket` connect'}",
        f"- **探测端口数**：{len(ports)}（仅 IPv4 TCP）",
        f"- **并发**：{workers_n}；**单端口超时**：{conn_timeout}s",
        "",
        "> 端口扫描可能被对端安全设备记录；请仅在书面授权范围内使用。\n",
    ]

    if use_nmap:
        exe = _resolve_nmap_exe(nmap_exe_path)
        lines.append(f"- **nmap 可执行文件**：`{exe}`\n")
        try:
            nmap_rows, _xml = _scan_tcp_nmap(ip, ports, nmap_exe=exe)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
            lines.append("#### 扫描失败\n\n```\n" + str(e).replace("```", "'''")[:8000] + "\n```\n")
            return "\n".join(lines)

        opens = [r for r in nmap_rows if r[1] == "open"]
        lines.append(
            f"- **摘要（nmap）**：共 **{len(nmap_rows)}** 条端口记录；**开放 {len(opens)}**。\n"
        )
        lines.append("| 端口 | 状态 | 服务 / 指纹（nmap） |")
        lines.append("|---:|---|---|")
        for pid, st, fp in nmap_rows:
            lines.append(f"| {pid} | {_state_label_zh(st)} | {fp} |")
        lines.append("")
        return "\n".join(lines)

    results = _scan_tcp_python(
        ip, ports, max_workers=workers_n, timeout=conn_timeout, grab_banner=grab_banner
    )
    opens = [r for r in results if r.state == "open"]
    closed_n = sum(1 for r in results if r.state == "closed")
    timeout_n = sum(1 for r in results if r.state == "timeout")
    err_n = sum(1 for r in results if r.state == "error")

    lines.append(
        f"- **摘要**：开放 **{len(opens)}**，连接被拒绝 **{closed_n}**，超时 **{timeout_n}**，其它错误 **{err_n}**。\n"
    )

    lines.append("#### 探测结果\n")
    lines.append("")
    lines.append("| 端口 | 状态 | 延迟(ms) | Banner / 备注 |")
    lines.append("|---:|---|---:|---|")
    max_rows = 256
    if len(results) <= max_rows:
        for r in results:
            lat = str(r.latency_ms) if r.latency_ms is not None else "—"
            if r.state == "open":
                note = (r.banner or "—").replace("\n", " ")
            elif r.state == "error":
                note = (r.banner or "—").replace("\n", " ")
            else:
                note = "—"
            lines.append(f"| {r.port} | {_state_label_zh(r.state)} | {lat} | {note} |")
    else:
        for r in opens:
            lat = str(r.latency_ms) if r.latency_ms is not None else "—"
            note = (r.banner or "—").replace("\n", " ")
            lines.append(f"| {r.port} | {_state_label_zh(r.state)} | {lat} | {note} |")
        lines.append(
            f"| … | … | … | 端口数超过 {max_rows}，未展开非开放端口；请缩小列表或分批扫描 |"
        )
        lines.append("")
        return "\n".join(lines)
