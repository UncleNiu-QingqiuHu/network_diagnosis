"""域诊断与组策略只读采集。"""

from __future__ import annotations

import json
import re
import socket
import sys
import uuid
from datetime import datetime

from network_diagnosis.domain.models import DomainDiagnosisResult, DomainIdentity, GpResultReport, GpScope
from network_diagnosis.domain.ps_win import parse_ps_json, run_cmd, run_powershell
from network_diagnosis.paths import domain_ops_report_dir


def new_task_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]


def _tcp_probe(host: str, port: int, timeout: float = 3.0) -> bool | None:
    if not host:
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _ping_host(host: str) -> bool | None:
    if not host or sys.platform != "win32":
        return None
    code, out, _ = run_cmd(["ping", "-n", "1", "-w", "2000", host], timeout=15)
    return code == 0 and ("TTL=" in out.upper() or "ttl=" in out)


def fetch_domain_identity() -> DomainIdentity:
    if sys.platform != "win32":
        return DomainIdentity()
    script = r"""
$ProgressPreference='SilentlyContinue'
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
[PSCustomObject]@{
  ComputerName = [string]$env:COMPUTERNAME
  DnsHostName = [string]$os.CSName
  Domain = [string]$cs.Domain
  Workgroup = [string]$cs.Workgroup
  PartOfDomain = [bool]$cs.PartOfDomain
} | ConvertTo-Json -Compress
"""
    code, out, err = run_powershell(script, timeout=40)
    if code != 0:
        return DomainIdentity(computer_name=__import__("os").environ.get("COMPUTERNAME", ""))
    try:
        data = parse_ps_json(out)
    except json.JSONDecodeError:
        return DomainIdentity(computer_name=__import__("os").environ.get("COMPUTERNAME", ""))
    if not isinstance(data, dict):
        return DomainIdentity()
    return DomainIdentity(
        computer_name=str(data.get("ComputerName") or ""),
        dns_host_name=str(data.get("DnsHostName") or ""),
        domain=str(data.get("Domain") or ""),
        workgroup=str(data.get("Workgroup") or ""),
        part_of_domain=bool(data.get("PartOfDomain")),
    )


def _analyze_diagnosis(
    identity: DomainIdentity,
    *,
    secure_channel_ok: bool | None,
    srv_lookup: str,
    ping_dc_ok: bool | None,
    time_status: str,
    probe_domain_dns: str,
) -> tuple[list[str], list[str]]:
    conclusions: list[str] = []
    recommendations: list[str] = []

    if identity.part_of_domain:
        conclusions.append(f"本机已加入域 **{identity.domain}**。")
        if secure_channel_ok is True:
            conclusions.append("安全通道（Secure Channel）正常。")
        elif secure_channel_ok is False:
            conclusions.append("安全通道异常，可能出现「信任关系失败」。")
            recommendations.append("尝试 **修复域信任**（需域凭据）。")
        if ping_dc_ok is False:
            conclusions.append("无法 Ping 通域控 IP（可能被 ICMP 禁止，需结合端口探测）。")
        if ping_dc_ok is False and secure_channel_ok is False:
            recommendations.append("检查 DNS、VPN、防火墙与到域控的网络连通性。")
    else:
        conclusions.append(f"本机处于工作组 **{identity.workgroup}**，未加入域。")
        if probe_domain_dns:
            recommendations.append("确认 DNS 可解析域 SRV 记录后，可使用 **加入域**。")

    if srv_lookup and ("找不到" in srv_lookup or "can't find" in srv_lookup.lower() or "Non-existent" in srv_lookup):
        conclusions.append("未能解析域 LDAP SRV 记录。")
        recommendations.append("检查 DNS 后缀、域 DNS 名是否正确，或是否需接入内网/VPN。")

    if time_status and any(k in time_status for k in ("unsynchronized", "未同步", "Leap", "误差")):
        conclusions.append("系统时间同步可能异常。")
        recommendations.append("执行 `w32tm /resync` 或确认能访问时间源后再修复域信任。")

    if not recommendations and identity.part_of_domain and secure_channel_ok is not False:
        recommendations.append("若策略未生效，可尝试 **更新域策略** 或 **查看域策略**。")

    return conclusions, recommendations


def run_domain_diagnosis(*, probe_domain_dns: str = "") -> DomainDiagnosisResult:
    task_id = new_task_id()
    ts = datetime.now()
    identity = fetch_domain_identity()
    raw: dict[str, str] = {}

    secure_ok: bool | None = None
    secure_detail = ""
    dc_name = ""
    dc_ip = ""
    srv_lookup = ""
    ping_dc_ok: bool | None = None
    tcp_389: bool | None = None
    tcp_445: bool | None = None
    time_status = ""
    pending_reboot = False
    enabled_locals: tuple[str, ...] = ()

    domain_for_probe = probe_domain_dns.strip() or (identity.domain if identity.part_of_domain else "")

    if sys.platform != "win32":
        return DomainDiagnosisResult(
            task_id=task_id,
            timestamp=ts,
            identity=identity,
            conclusions=["当前模块仅支持 Windows。"],
            probe_domain_dns=domain_for_probe,
        )

    if identity.part_of_domain:
        sc_script = r"""
$ProgressPreference='SilentlyContinue'
try {
  $ok = Test-ComputerSecureChannel
  [PSCustomObject]@{ Ok = [bool]$ok } | ConvertTo-Json -Compress
} catch {
  [PSCustomObject]@{ Ok = $null; Error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
}
"""
        code, out, err = run_powershell(sc_script, timeout=60)
        raw["secure_channel"] = out or err
        try:
            sc_data = parse_ps_json(out)
            if isinstance(sc_data, dict):
                if sc_data.get("Ok") is None:
                    secure_ok = None
                    secure_detail = str(sc_data.get("Error") or err)
                else:
                    secure_ok = bool(sc_data.get("Ok"))
                    secure_detail = "正常" if secure_ok else "失败"
        except json.JSONDecodeError:
            secure_detail = out or err

        nl_code, nl_out, nl_err = run_cmd(["nltest", "/dsgetdc:" + identity.domain], timeout=30)
        raw["nltest"] = nl_out or nl_err
        if nl_code == 0 and nl_out:
            m = re.search(r"\\\\([^\s\\]+)", nl_out)
            if m:
                dc_name = m.group(1)
            m_ip = re.search(r"Address:\s*([0-9a-fA-F.:]+)", nl_out)
            if m_ip:
                dc_ip = m_ip.group(1).strip("[]")
            if dc_ip:
                ping_dc_ok = _ping_host(dc_ip)
                tcp_389 = _tcp_probe(dc_ip, 389)
                tcp_445 = _tcp_probe(dc_ip, 445)

    if domain_for_probe:
        srv_q = f"_ldap._tcp.dc._msdcs.{domain_for_probe.rstrip('.')}"
        ns_code, ns_out, ns_err = run_cmd(["nslookup", "-type=SRV", srv_q], timeout=45)
        srv_lookup = ns_out or ns_err
        raw["srv_lookup"] = srv_lookup

    w32_code, w32_out, w32_err = run_cmd(["w32tm", "/query", "/status"], timeout=30)
    time_status = w32_out or w32_err
    raw["w32tm"] = time_status

    reboot_script = r"""
$ProgressPreference='SilentlyContinue'
$pending = $false
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
  $pending = $true
}
if (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
    -Name PendingFileRenameOperations -EA SilentlyContinue) {
  $pending = $true
}
[PSCustomObject]@{ PendingReboot = [bool]$pending } | ConvertTo-Json -Compress
"""
    _, rb_out, _ = run_powershell(reboot_script, timeout=30)
    raw["pending_reboot"] = rb_out
    try:
        rb = parse_ps_json(rb_out)
        if isinstance(rb, dict):
            pending_reboot = bool(rb.get("PendingReboot"))
    except json.JSONDecodeError:
        pass

    users_script = r"""
$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='SilentlyContinue'
if (-not (Get-Command Get-LocalUser -EA SilentlyContinue)) { '[]'; exit 0 }
@(Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object { [string]$_.Name }) | ConvertTo-Json -Compress
"""
    _, u_out, _ = run_powershell(users_script, timeout=60)
    raw["local_users"] = u_out
    try:
        udata = parse_ps_json(u_out)
        if isinstance(udata, list):
            enabled_locals = tuple(str(x) for x in udata)
        elif isinstance(udata, str):
            enabled_locals = (udata,)
    except json.JSONDecodeError:
        pass

    conclusions, recommendations = _analyze_diagnosis(
        identity,
        secure_channel_ok=secure_ok,
        srv_lookup=srv_lookup,
        ping_dc_ok=ping_dc_ok,
        time_status=time_status,
        probe_domain_dns=domain_for_probe,
    )

    result = DomainDiagnosisResult(
        task_id=task_id,
        timestamp=ts,
        identity=identity,
        secure_channel_ok=secure_ok,
        secure_channel_detail=secure_detail,
        dc_name=dc_name,
        dc_ip=dc_ip,
        srv_lookup=srv_lookup[:4000] if srv_lookup else "",
        ping_dc_ok=ping_dc_ok,
        tcp_389_ok=tcp_389,
        tcp_445_ok=tcp_445,
        time_status=time_status[:2000] if time_status else "",
        pending_reboot=pending_reboot,
        enabled_local_users=enabled_locals,
        probe_domain_dns=domain_for_probe,
        conclusions=conclusions,
        recommendations=recommendations,
        raw_sections=raw,
    )

    out_dir = domain_ops_report_dir(task_id)
    from network_diagnosis.domain.report_md import render_diagnosis_markdown

    (out_dir / "report.md").write_text(render_diagnosis_markdown(result), encoding="utf-8")
    (out_dir / "diagnosis.json").write_text(
        json.dumps(
            {
                "task_id": task_id,
                "timestamp": ts.isoformat(),
                "identity": identity.__dict__,
                "secure_channel_ok": secure_ok,
                "dc_name": dc_name,
                "dc_ip": dc_ip,
                "conclusions": conclusions,
                "recommendations": recommendations,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return result


def run_gpresult(*, scope: GpScope = "both") -> GpResultReport:
    task_id = new_task_id()
    ts = datetime.now()
    out_dir = domain_ops_report_dir(task_id)
    html_path = out_dir / "gpresult.html"
    text_path = out_dir / "gpresult_stdout.txt"

    if sys.platform != "win32":
        rep = GpResultReport(
            task_id=task_id,
            timestamp=ts,
            scope=scope,
            error="当前平台不支持 gpresult。",
        )
        return rep

    scope_args: list[str] = []
    if scope == "user":
        scope_args = ["/scope", "user"]
    elif scope == "computer":
        scope_args = ["/scope", "computer"]

    h_args = ["gpresult", "/h", str(html_path), "/f", *scope_args]
    h_code, h_out, h_err = run_cmd(h_args, timeout=180)
    combined_h = "\n".join(x for x in (h_out, h_err) if x)
    if h_code != 0 and not html_path.is_file():
        rep = GpResultReport(
            task_id=task_id,
            timestamp=ts,
            scope=scope,
            error=combined_h or f"gpresult /h 退出码 {h_code}",
        )
        from network_diagnosis.domain.report_md import render_gpresult_markdown

        (out_dir / "report.md").write_text(render_gpresult_markdown(rep), encoding="utf-8")
        return rep

    r_args = ["gpresult", "/r", *scope_args]
    r_code, r_out, r_err = run_cmd(r_args, timeout=120)
    text_summary = r_out or r_err or combined_h
    text_path.write_text(text_summary, encoding="utf-8", errors="replace")

    rep = GpResultReport(
        task_id=task_id,
        timestamp=ts,
        scope=scope,
        text_summary=text_summary,
        html_path=str(html_path) if html_path.is_file() else "",
        text_path=str(text_path),
        error=None if r_code == 0 or text_summary else f"gpresult /r 退出码 {r_code}",
    )
    from network_diagnosis.domain.report_md import render_gpresult_markdown

    (out_dir / "report.md").write_text(render_gpresult_markdown(rep), encoding="utf-8")
    return rep
