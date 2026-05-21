"""域写操作：gpupdate、信任修复、改名、加域、退域。"""

from __future__ import annotations

import json
import re
from datetime import datetime

from network_diagnosis.domain.collect import fetch_domain_identity, new_task_id
from network_diagnosis.domain.elevation import is_admin, require_admin_message
from network_diagnosis.domain.models import DomainOperationResult
from network_diagnosis.domain.ps_win import parse_ps_json, ps_credential_var, run_cmd, run_powershell
from network_diagnosis.paths import domain_ops_report_dir
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)

_NETBIOS_NAME = re.compile(r"^[A-Za-z0-9-]{1,15}$")


def _save_operation_report(result: DomainOperationResult) -> None:
    from network_diagnosis.domain.report_md import render_operation_markdown

    out_dir = domain_ops_report_dir(result.task_id)
    (out_dir / "report.md").write_text(render_operation_markdown(result), encoding="utf-8")
    meta = {
        "task_id": result.task_id,
        "timestamp": result.timestamp.isoformat(),
        "operation": result.operation,
        "success": result.success,
        "needs_reboot": result.needs_reboot,
        "needs_logoff": result.needs_logoff,
        "metadata": result.metadata,
    }
    (out_dir / "operation.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def _admin_fail(kind: str) -> DomainOperationResult:
    return DomainOperationResult(
        task_id=new_task_id(),
        timestamp=datetime.now(),
        operation=kind,  # type: ignore[arg-type]
        success=False,
        message=require_admin_message(),
    )


def _parse_gpupdate_hints(output: str) -> tuple[bool, bool]:
    text = output.lower()
    needs_logoff = any(
        k in output
        for k in (
            "需要重新登录",
            "需要注销",
            "logoff",
            "sign out",
            "用户策略更新成功，但需要",
        )
    )
    needs_reboot = any(
        k in output
        for k in (
            "需要重新启动",
            "需要重启",
            "restart",
            "reboot",
            "计算机策略更新成功，但需要",
        )
    )
    if "reboot is required" in text:
        needs_reboot = True
    if "logoff" in text and "policy" in text:
        needs_logoff = True
    return needs_logoff, needs_reboot


def run_gpupdate() -> DomainOperationResult:
    """刷新本机计算机策略与当前登录用户的组策略（gpupdate /force）。"""
    task_id = new_task_id()
    ts = datetime.now()
    if not is_admin():
        return _admin_fail("gpupdate")

    code, out, err = run_cmd(["gpupdate", "/force", "/wait:0"], timeout=300)
    detail = "\n".join(x for x in (out, err) if x)
    needs_logoff, needs_reboot = _parse_gpupdate_hints(detail)
    success = code == 0
    msg = "组策略更新完成。" if success else f"组策略更新失败（退出码 {code}）。"
    if needs_logoff:
        msg += " 部分用户策略需 **注销** 后生效。"
    if needs_reboot:
        msg += " 部分计算机策略需 **重启** 后生效。"

    result = DomainOperationResult(
        task_id=task_id,
        timestamp=ts,
        operation="gpupdate",
        success=success,
        message=msg,
        needs_reboot=needs_reboot,
        needs_logoff=needs_logoff,
        detail=detail,
        metadata={"scope": "computer_and_current_user"},
    )
    _log.info("domain operation=gpupdate success=%s", success)
    _save_operation_report(result)
    return result


def run_repair_trust(*, username: str, password: str) -> DomainOperationResult:
    task_id = new_task_id()
    ts = datetime.now()
    if not is_admin():
        return _admin_fail("repair_trust")

    identity = fetch_domain_identity()
    if not identity.part_of_domain:
        result = DomainOperationResult(
            task_id=task_id,
            timestamp=ts,
            operation="repair_trust",
            success=False,
            message="本机未加入域，无需修复信任。",
        )
        _save_operation_report(result)
        return result

    cred_block = ps_credential_var(var_name="cred", username=username, password=password)
    script = f"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
{cred_block}
$before = Test-ComputerSecureChannel
if ($before) {{
  @{{ Success = $true; AlreadyOk = $true; After = $true }} | ConvertTo-Json -Compress
  exit 0
}}
Test-ComputerSecureChannel -Repair -Credential $cred | Out-Null
$after = Test-ComputerSecureChannel
@{{ Success = [bool]$after; AlreadyOk = $false; After = [bool]$after }} | ConvertTo-Json -Compress
"""
    code, out, err = run_powershell(script, timeout=180)
    detail = "\n".join(x for x in (out, err) if x)
    success = False
    msg = ""
    try:
        data = parse_ps_json(out)
        if isinstance(data, dict):
            if data.get("AlreadyOk"):
                success = True
                msg = "安全通道已正常，无需修复。"
            elif data.get("After"):
                success = True
                msg = "域信任修复成功，安全通道已恢复。"
            else:
                msg = "域信任修复失败，请检查域凭据、网络与时间同步。"
        else:
            msg = detail or "修复失败（无法解析 PowerShell 输出）。"
    except json.JSONDecodeError:
        msg = detail or f"PowerShell 退出码 {code}"

    if code != 0 and not success:
        msg = detail or msg

    result = DomainOperationResult(
        task_id=task_id,
        timestamp=ts,
        operation="repair_trust",
        success=success,
        message=msg,
        detail=detail,
        metadata={"domain": identity.domain},
    )
    _log.info("domain operation=repair_trust domain=%s success=%s", identity.domain, success)
    _save_operation_report(result)
    return result


def run_rename_computer(
    *,
    new_name: str,
    domain_username: str = "",
    domain_password: str = "",
) -> DomainOperationResult:
    task_id = new_task_id()
    ts = datetime.now()
    if not is_admin():
        return _admin_fail("rename")

    name = new_name.strip()
    if not _NETBIOS_NAME.match(name):
        return DomainOperationResult(
            task_id=task_id,
            timestamp=ts,
            operation="rename",
            success=False,
            message="计算机名无效：须为 1–15 位字母、数字或连字符。",
        )

    identity = fetch_domain_identity()
    if identity.part_of_domain and (not domain_username or not domain_password):
        return DomainOperationResult(
            task_id=task_id,
            timestamp=ts,
            operation="rename",
            success=False,
            message="已入域机器重命名需要域凭据。",
        )

    cred_block = ""
    rename_line = f"Rename-Computer -NewName '{name.replace(chr(39), chr(39)+chr(39))}' -Force"
    if identity.part_of_domain:
        cred_block = ps_credential_var(var_name="cred", username=domain_username, password=domain_password)
        rename_line = (
            f"Rename-Computer -NewName '{name.replace(chr(39), chr(39)+chr(39))}' "
            "-DomainCredential $cred -Force"
        )

    script = f"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
{cred_block}
{rename_line}
@{{ Success = $true; NewName = '{name.replace(chr(39), chr(39)+chr(39))}' }} | ConvertTo-Json -Compress
"""
    code, out, err = run_powershell(script, timeout=120)
    detail = "\n".join(x for x in (out, err) if x)
    success = code == 0 and "Success" in out
    msg = f"计算机已重命名为 **{name}**。" if success else (detail or "重命名失败。")

    result = DomainOperationResult(
        task_id=task_id,
        timestamp=ts,
        operation="rename",
        success=success,
        message=msg,
        needs_reboot=True,
        detail=detail,
        metadata={"new_name": name, "was_domain_joined": str(identity.part_of_domain)},
    )
    _log.info("domain operation=rename new_name=%s success=%s", name, success)
    _save_operation_report(result)
    return result


def run_join_domain(
    *,
    domain_dns: str,
    join_username: str,
    join_password: str,
    post_join_user: str,
    ou_path: str = "",
    local_group: str = "Power Users",
) -> DomainOperationResult:
    task_id = new_task_id()
    ts = datetime.now()
    if not is_admin():
        return _admin_fail("join_domain")

    domain = domain_dns.strip().rstrip(".")
    if not domain:
        return DomainOperationResult(
            task_id=task_id,
            timestamp=ts,
            operation="join_domain",
            success=False,
            message="请填写域 DNS 名。",
        )

    identity = fetch_domain_identity()
    if identity.part_of_domain:
        return DomainOperationResult(
            task_id=task_id,
            timestamp=ts,
            operation="join_domain",
            success=False,
            message=f"本机已在域 **{identity.domain}** 中，请先退域。",
        )

    post_user = post_join_user.strip()
    if not post_user:
        return DomainOperationResult(
            task_id=task_id,
            timestamp=ts,
            operation="join_domain",
            success=False,
            message="请填写加域后要加入 Power Users 的域用户（如 CORP\\zhangsan）。",
        )

    ou = ou_path.strip()
    ou_arg = ""
    if ou:
        ou_esc = ou.replace("'", "''")
        ou_arg = f"-OUPath '{ou_esc}'"

    cred_block = ps_credential_var(var_name="joinCred", username=join_username, password=join_password)
    post_esc = post_user.replace("'", "''")
    group_esc = local_group.replace("'", "''")
    domain_esc = domain.replace("'", "''")

    script = f"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
{cred_block}
Add-Computer -DomainName '{domain_esc}' -Credential $joinCred {ou_arg} -Force -PassThru | Out-Null
Add-LocalGroupMember -Group '{group_esc}' -Member '{post_esc}' -ErrorAction Stop
if (Get-LocalGroupMember -Group 'Administrators' -Member '{post_esc}' -ErrorAction SilentlyContinue) {{
  Remove-LocalGroupMember -Group 'Administrators' -Member '{post_esc}' -ErrorAction SilentlyContinue
}}
@{{ Success = $true; Domain = '{domain_esc}'; PostJoinUser = '{post_esc}' }} | ConvertTo-Json -Compress
"""
    code, out, err = run_powershell(script, timeout=300)
    detail = "\n".join(x for x in (out, err) if x)
    success = code == 0 and "Success" in out
    msg = (
        f"已加入域 **{domain}**；用户 **{post_user}** 已加入本地 **{local_group}**。"
        if success
        else (detail or "加域失败。")
    )

    result = DomainOperationResult(
        task_id=task_id,
        timestamp=ts,
        operation="join_domain",
        success=success,
        message=msg,
        needs_reboot=True,
        detail=detail,
        metadata={"domain": domain, "post_join_user": post_user, "local_group": local_group},
    )
    _log.info("domain operation=join_domain domain=%s user=%s success=%s", domain, post_user, success)
    _save_operation_report(result)
    return result


def run_unjoin_domain(
    *,
    unjoin_username: str,
    unjoin_password: str,
    workgroup: str = "WORKGROUP",
) -> DomainOperationResult:
    task_id = new_task_id()
    ts = datetime.now()
    if not is_admin():
        return _admin_fail("unjoin_domain")

    identity = fetch_domain_identity()
    if not identity.part_of_domain:
        return DomainOperationResult(
            task_id=task_id,
            timestamp=ts,
            operation="unjoin_domain",
            success=False,
            message="本机未加入域。",
        )

    wg = workgroup.strip() or "WORKGROUP"
    cred_block = ps_credential_var(var_name="cred", username=unjoin_username, password=unjoin_password)
    wg_esc = wg.replace("'", "''")

    script = f"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
{cred_block}
Remove-Computer -UnjoinDomainCredential $cred -WorkgroupName '{wg_esc}' -Force -PassThru | Out-Null
@{{ Success = $true; Workgroup = '{wg_esc}' }} | ConvertTo-Json -Compress
"""
    code, out, err = run_powershell(script, timeout=180)
    detail = "\n".join(x for x in (out, err) if x)
    success = code == 0 and "Success" in out
    msg = f"已退出域，工作组设为 **{wg}**。" if success else (detail or "退域失败。")

    result = DomainOperationResult(
        task_id=task_id,
        timestamp=ts,
        operation="unjoin_domain",
        success=success,
        message=msg,
        needs_reboot=True,
        detail=detail,
        metadata={"workgroup": wg, "former_domain": identity.domain},
    )
    _log.info("domain operation=unjoin_domain workgroup=%s success=%s", wg, success)
    _save_operation_report(result)
    return result
