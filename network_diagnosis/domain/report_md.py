"""域模块 Markdown 报告。"""

from __future__ import annotations

from network_diagnosis.domain.models import (
    DomainDiagnosisResult,
    DomainOperationResult,
    GpResultReport,
)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not headers:
        return ""
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        pad = list(row) + [""] * (len(headers) - len(row))
        lines.append("| " + " | ".join(str(pad[i]).replace("|", "｜") for i in range(len(headers))) + " |")
    return "\n".join(lines)


def render_diagnosis_markdown(result: DomainDiagnosisResult) -> str:
    idn = result.identity
    lines = [
        "# 域诊断报告",
        "",
        f"- 任务 ID: `{result.task_id}`",
        f"- 时间: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## 计算机身份",
        "",
        _table(
            ["项目", "值"],
            [
                ["计算机名", idn.computer_name or "—"],
                ["DNS 主机名", idn.dns_host_name or "—"],
                ["属于域", "是" if idn.part_of_domain else "否"],
                ["域 / DNS 域", idn.domain or "—"],
                ["工作组", idn.workgroup or "—"],
            ],
        ),
        "",
    ]

    if idn.part_of_domain or result.probe_domain_dns:
        sc = "—"
        if result.secure_channel_ok is True:
            sc = "正常"
        elif result.secure_channel_ok is False:
            sc = "异常"
        lines.extend(
            [
                "## 域连通与安全通道",
                "",
                _table(
                    ["项目", "值"],
                    [
                        ["安全通道", sc],
                        ["域控名称", result.dc_name or "—"],
                        ["域控 IP", result.dc_ip or "—"],
                        ["Ping 域控", _yn(result.ping_dc_ok)],
                        ["TCP 389", _yn(result.tcp_389_ok)],
                        ["TCP 445", _yn(result.tcp_445_ok)],
                        ["探测域 DNS", result.probe_domain_dns or "—"],
                        ["待重启", "是" if result.pending_reboot else "否"],
                    ],
                ),
                "",
            ]
        )

    if result.enabled_local_users:
        lines.extend(
            [
                "## 已启用本地用户",
                "",
                ", ".join(f"`{u}`" for u in result.enabled_local_users),
                "",
            ]
        )

    if result.conclusions:
        lines.append("## 结论")
        lines.append("")
        for c in result.conclusions:
            lines.append(f"- {c}")
        lines.append("")

    if result.recommendations:
        lines.append("## 建议")
        lines.append("")
        for r in result.recommendations:
            lines.append(f"- {r}")
        lines.append("")

    if result.srv_lookup:
        lines.extend(["## SRV 查询节选", "", "```", result.srv_lookup[:3000], "```", ""])

    if result.time_status:
        lines.extend(["## 时间同步（w32tm）", "", "```", result.time_status[:1500], "```", ""])

    return "\n".join(lines)


def _yn(v: bool | None) -> str:
    if v is True:
        return "是"
    if v is False:
        return "否"
    return "—"


def render_gpresult_markdown(report: GpResultReport) -> str:
    scope_labels = {"both": "用户 + 计算机", "user": "仅用户", "computer": "仅计算机"}
    lines = [
        "# 本机组策略结果",
        "",
        f"- 任务 ID: `{report.task_id}`",
        f"- 时间: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 范围: {scope_labels.get(report.scope, report.scope)}",
        "",
        "> 本报告反映 **本机当前登录上下文** 下已生效的组策略合并结果。",
        "",
    ]
    if report.error:
        lines.extend(["## 错误", "", report.error, ""])
    if report.html_path:
        lines.extend([f"- HTML 报告: `{report.html_path}`", ""])
    if report.text_summary:
        lines.extend(["## gpresult /r 摘要", "", "```", report.text_summary[:12000], "```", ""])
    return "\n".join(lines)


def render_operation_markdown(result: DomainOperationResult) -> str:
    op_labels = {
        "gpupdate": "更新域策略",
        "repair_trust": "域信任修复",
        "rename": "计算机重命名",
        "join_domain": "加入域",
        "unjoin_domain": "退出域",
    }
    lines = [
        f"# {op_labels.get(result.operation, result.operation)}",
        "",
        f"- 任务 ID: `{result.task_id}`",
        f"- 时间: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 结果: **{'成功' if result.success else '失败'}**",
        "",
        "## 摘要",
        "",
        result.message,
        "",
    ]
    if result.metadata:
        rows = [[k, v] for k, v in result.metadata.items()]
        lines.extend(["## 元数据", "", _table(["项", "值"], rows), ""])

    if result.needs_reboot or result.needs_logoff:
        lines.append("## 后续操作")
        lines.append("")
        if result.needs_logoff:
            lines.append("- 部分策略需 **注销** 后生效。")
        if result.needs_reboot:
            lines.append("- **必须重启计算机** 后，加域/退域/重命名才会完全生效。")
            lines.append("- 重启前请保存其他工作。")
        lines.append("")

    if result.detail:
        lines.extend(["## 详细输出", "", "```", result.detail[:15000], "```", ""])

    return "\n".join(lines)
