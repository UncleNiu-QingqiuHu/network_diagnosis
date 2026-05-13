"""安全诊断采集：本机暴露面、防火墙摘要、目标 TLS/响应头、DNS 对比（Windows 为主）。"""

from __future__ import annotations

import base64
import hashlib
import json
import platform
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
)

_PS_UTF8_PREFIX = (
    "$OutputEncoding = [Console]::OutputEncoding = "
    "New-Object System.Text.UTF8Encoding $false\n"
)


def _decode_console_bytes(data: bytes) -> str:
    """解码 PowerShell 管道输出：优先 UTF-8（含 BOM），退回中文 Windows 常用的 GBK/CP936。"""
    if not data:
        return ""
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp936"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _run_powershell(script: str, *, timeout: int = 120) -> str:
    full = _PS_UTF8_PREFIX + script.strip()
    raw = full.encode("utf-16-le")
    enc = base64.b64encode(raw).decode("ascii")
    r = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            enc,
        ],
        capture_output=True,
        timeout=timeout,
    )
    out = _decode_console_bytes(r.stdout or b"").strip()
    err = _decode_console_bytes(r.stderr or b"").strip()
    if r.returncode != 0:
        return f"PowerShell 退出码 {r.returncode}\n{err or out}"
    return out if out else err


def _parse_ps_json(stdout: str) -> Any:
    t = stdout.lstrip("\ufeff").strip()
    if not t:
        return None
    return json.loads(t)


def collect_tcp_listeners_markdown() -> str:
    if sys.platform != "win32":
        return "## TCP 监听端口\n\n当前实现依赖 Windows `Get-NetTCPConnection`，请在 Windows 上运行本模块。\n"

    ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
$list = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
  $pid = $_.OwningProcess
  $proc = ''
  try { $proc = (Get-Process -Id $pid -ErrorAction Stop).ProcessName } catch { $proc = '' }
  [PSCustomObject]@{
    LocalAddress = [string]$_.LocalAddress
    LocalPort = [int]$_.LocalPort
    OwningProcess = [int]$pid
    ProcessName = [string]$proc
  }
})
$list | Sort-Object LocalPort, LocalAddress | ConvertTo-Json -Depth 4 -Compress
"""
    raw = _run_powershell(ps, timeout=90)
    lines: list[str] = ["## TCP 监听端口", ""]
    try:
        data = _parse_ps_json(raw)
    except json.JSONDecodeError:
        return "\n".join(lines + ["采集失败（非 JSON 输出）：", "", "```", raw[:8000], "```", ""])
    if data is None:
        return "\n".join(lines + ["（无监听连接或暂无数据）", ""])
    rows = data if isinstance(data, list) else [data]
    if not rows:
        return "\n".join(lines + ["（无监听端口）", ""])
    lines.append("| 绑定地址 | 端口 | PID | 进程 |")
    lines.append("|---|---:|---:|---|")
    for item in rows:
        if not isinstance(item, dict):
            continue
        la = str(item.get("LocalAddress", ""))
        lp = str(item.get("LocalPort", ""))
        pid = str(item.get("OwningProcess", ""))
        pn = str(item.get("ProcessName", "")) or "—"
        flag = ""
        if la in ("0.0.0.0", "::"):
            flag = " ⚠ 全网卡"
        lines.append(f"| {la}{flag} | {lp} | {pid} | {pn} |")
    lines.append("")
    lines.append(
        "> **说明**：`0.0.0.0` / `::` 表示监听所有接口；是否「有风险」需结合业务与防火墙策略人工判断。\n"
    )
    return "\n".join(lines)


def collect_firewall_summary_markdown() -> str:
    if sys.platform != "win32":
        return "## 防火墙摘要\n\n当前实现依赖 `Get-NetFirewallProfile` / `Get-NetFirewallRule`，请在 Windows 上运行。\n"

    ps_profiles = r"""
$ErrorActionPreference = 'SilentlyContinue'
Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress
"""
    ps_rules = r"""
$ErrorActionPreference = 'SilentlyContinue'
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
  Select-Object -First 60 DisplayName, Profile, Direction, Action |
  ConvertTo-Json -Compress
"""
    out: list[str] = ["## Windows 防火墙摘要", ""]
    prof_raw = _run_powershell(ps_profiles, timeout=60)
    try:
        prof_data = _parse_ps_json(prof_raw)
    except json.JSONDecodeError:
        out.append("### 配置文件状态\n\n采集失败：\n\n```\n" + prof_raw[:4000] + "\n```\n")
    else:
        out.append("### 配置文件状态\n")
        if prof_data is None:
            out.append("（无数据）\n")
        else:
            rows = prof_data if isinstance(prof_data, list) else [prof_data]
            out.append("| 配置文件 | 已启用 |")
            out.append("|---|---|")
            for item in rows:
                if isinstance(item, dict):
                    out.append(f"| {item.get('Name', '')} | {item.get('Enabled', '')} |")
            out.append("")
        out.append("> 可运行 `wf.msc` 打开高级安全 Windows 防火墙进行管理。\n\n")

    rules_raw = _run_powershell(ps_rules, timeout=120)
    out.append("### 入站「允许」规则（最多 60 条，仅供参考）\n")
    try:
        rules_data = _parse_ps_json(rules_raw)
    except json.JSONDecodeError:
        out.append("采集失败：\n\n```\n" + rules_raw[:4000] + "\n```\n")
        return "\n".join(out)
    if rules_data is None:
        out.append("（无规则数据）\n")
        return "\n".join(out)
    rrows = rules_data if isinstance(rules_data, list) else [rules_data]
    if not rrows:
        out.append("（无允许规则或无法枚举）\n")
        return "\n".join(out)
    out.append("| 显示名称 | 配置文件 | 方向 | 操作 |")
    out.append("|---|---|---|---|")
    for item in rrows:
        if isinstance(item, dict):
            out.append(
                "| "
                + str(item.get("DisplayName", ""))[:80]
                + " | "
                + str(item.get("Profile", ""))
                + " | "
                + str(item.get("Direction", ""))
                + " | "
                + str(item.get("Action", ""))
                + " |"
            )
    out.append("")
    return "\n".join(out)


def _rdns_common_name(field: Any) -> str:
    if not field:
        return "—"
    for seq in field:
        for pair in seq:
            if len(pair) >= 2 and pair[0] == "commonName":
                return str(pair[1])
    return "—"


def _cert_date(v: Any) -> str:
    if v is None:
        return "—"
    if isinstance(v, str):
        try:
            if re.match(r"^\d{14}Z$", v):
                return datetime.strptime(v, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc).isoformat()
            dt = parsedate_to_datetime(v)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except (TypeError, ValueError, OverflowError):
            return str(v)
    return str(v)


def check_https_target_markdown(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return "## HTTPS / 响应头\n\n请填写 URL。\n"
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlparse(url)
    host = p.hostname
    if not host:
        return "## HTTPS / 响应头\n\n无法解析主机名。\n"
    port = p.port or (443 if p.scheme.lower() == "https" else 80)
    lines: list[str] = ["## HTTPS / 安全响应头", "", f"- **URL**：`{url}`", f"- **解析主机**：`{host}`:{port}", ""]

    if p.scheme.lower() == "https":
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=12) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    peercert = ssock.getpeercert()
        except (OSError, ssl.SSLError) as e:
            lines.append(f"### TLS 握手失败\n\n```\n{e}\n```\n")
            return "\n".join(lines)

        lines.append("### 证书（握手成功）\n")
        if peercert:
            cn_sub = _rdns_common_name(peercert.get("subject"))
            cn_iss = _rdns_common_name(peercert.get("issuer"))
            lines.append(f"- **主题 CN**：`{cn_sub}`")
            lines.append(f"- **颁发者 CN**：`{cn_iss}`")
            nb = _cert_date(peercert.get("notBefore"))
            na = _cert_date(peercert.get("notAfter"))
            lines.append(f"- **notBefore**：{nb}")
            lines.append(f"- **notAfter**：{na}")
            lines.append("")
        else:
            lines.append("（未能以字典形式读取证书字段；已建立 TLS 会话。）\n")
        if cert_bin:
            fp = hashlib.sha256(cert_bin).hexdigest()
            lines.append(f"- **证书 SHA-256（指纹）**：`{fp}`")
            lines.append("")

    # HTTP(S) headers
    try:
        req = Request(url, headers={"User-Agent": "QingqiuhuSecurityDiag/1.0"}, method="GET")
        with urlopen(req, timeout=20) as resp:
            status = getattr(resp, "status", 0)
            lines.append(f"### HTTP 响应\n\n- **状态码**：{status}\n")
            lines.append("### 常见安全响应头\n")
            hdrs = resp.headers
            for name in _SECURITY_HEADERS:
                v = hdrs.get(name) or hdrs.get(name.lower())
                if v:
                    lines.append(f"- **{name}**：`{v[:500]}{'…' if len(v) > 500 else ''}`")
                else:
                    lines.append(f"- **{name}**：（未设置）")
            lines.append("")
    except HTTPError as e:
        lines.append(f"### HTTP 响应\n\n- **状态码**：{e.code}（{e.reason}）\n")
        lines.append("### 常见安全响应头\n")
        hdrs = e.headers
        for name in _SECURITY_HEADERS:
            v = hdrs.get(name) or hdrs.get(name.lower())
            if v:
                lines.append(f"- **{name}**：`{v[:500]}{'…' if len(v) > 500 else ''}`")
            else:
                lines.append(f"- **{name}**：（未设置）")
        lines.append("")
    except URLError as e:
        lines.append(f"### HTTP 请求失败\n\n```\n{e.reason}\n```\n")

    return "\n".join(lines)


def compare_dns_markdown(hostname: str, alt_dns: str) -> str:
    hostname = (hostname or "").strip()
    alt_dns = (alt_dns or "").strip()
    if not hostname:
        return "## DNS 对比\n\n请填写主机名（可从 HTTPS URL 自动解析）。\n"
    if not alt_dns:
        return "## DNS 对比\n\n请填写用于对比的 DNS 服务器 IP（如 `223.5.5.5`）。\n"

    lines: list[str] = ["## DNS 解析对比", "", f"- **主机名**：`{hostname}`", f"- **对比 DNS**：`{alt_dns}`", ""]

    sys_a: list[str] = []
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
            if fam == socket.AF_INET:
                sys_a.append(sa[0])
    except OSError as e:
        lines.append(f"### 系统解析器（失败）\n\n```\n{e}\n```\n")
    else:
        sys_a = sorted(set(sys_a))
        lines.append("### 系统解析（getaddrinfo，A/AAAA 中的 IPv4）\n")
        lines.append(", ".join(f"`{x}`" for x in sys_a) if sys_a else "（无 IPv4 结果）")
        lines.append("")

    if sys.platform != "win32":
        lines.append("### 指定 DNS（仅 Windows）\n\n非 Windows 环境未调用 `Resolve-DnsName`。\n")
        return "\n".join(lines)

    ps = f"""
$ErrorActionPreference = 'Stop'
$r = Resolve-DnsName -Name '{hostname.replace("'", "''")}' -Type A -DnsOnly -Server '{alt_dns.replace("'", "''")}' -ErrorAction Stop |
  Select-Object -ExpandProperty IPAddress
@($r) | ConvertTo-Json -Compress
"""
    raw = _run_powershell(ps, timeout=45)
    alt_list: list[str] = []
    try:
        data = _parse_ps_json(raw)
    except json.JSONDecodeError:
        lines.append("### 指定 DNS 解析\n\n采集失败：\n\n```\n" + raw[:2000] + "\n```\n")
        return "\n".join(lines)
    if isinstance(data, list):
        alt_list = [str(x) for x in data]
    elif data is not None:
        alt_list = [str(data)]
    lines.append(f"### 指定 DNS 解析（A 记录）\n\n{', '.join(f'`{x}`' for x in alt_list) if alt_list else '（无结果）'}\n")
    sa_set, aa_set = set(sys_a), set(alt_list)
    if sa_set and aa_set and sa_set != aa_set:
        lines.append("\n> **提示**：系统解析与指定 DNS 的 A 记录不一致，可能为 split-DNS 设计，也可能是配置异常，请结合现网文档判断。\n")
    elif sa_set == aa_set and sa_set:
        lines.append("\n> **提示**：当前样本下 IPv4 结果一致。\n")
    return "\n".join(lines)


def full_report_preamble() -> str:
    host = platform.node()
    ts = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    return "\n".join(
        [
            "# 安全诊断报告（摘要）",
            "",
            f"- **生成时间**：{ts}",
            f"- **计算机名**：{host}",
            f"- **Python**：{sys.version.split()[0]} · **平台**：{sys.platform}",
            "",
            "> 本报告仅供授权范围内的基线检查；远程探测请遵守企业与法律要求。",
            "",
        ]
    )
