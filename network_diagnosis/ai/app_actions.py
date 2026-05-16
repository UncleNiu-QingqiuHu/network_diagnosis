"""将工作台各功能暴露给 AI 工具调用（可在后台线程执行）。"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from network_diagnosis.ai.report_summary import summarize_diagnostic_report
from network_diagnosis.db_diagnosis.runner import DbConnectConfig, run_full_diagnosis
from network_diagnosis.gui.main_app_common import parse_ports
from network_diagnosis.runner import RunOptions, run_diagnostic
from network_diagnosis.runtime_log import get_logger
from network_diagnosis.subnet_calc import calc_from_cidr_combo

if TYPE_CHECKING:
    from network_diagnosis.gui.main_app import NetworkDiagnosisApp

_log = get_logger(__name__)


class AppActions:
    """绑定主窗口，供 AI 在工具循环中调用各模块能力。"""

    def __init__(self, app: NetworkDiagnosisApp) -> None:
        self._app = app

    def _on_main(self, fn: Callable[[], None]) -> None:
        try:
            self._app.after(0, fn)
        except Exception as e:
            _log.exception("调度主线程失败: %s", e)

    def run_network_diagnosis(
        self,
        *,
        target_host: str,
        ports: str = "80,443",
        enable_ping: bool = True,
        enable_traceroute: bool = False,
        enable_capture: bool = False,
    ) -> str:
        host = (target_host or "").strip()
        if not host:
            return "错误：未提供 target_host。"
        try:
            port_list = parse_ports(ports) if (ports or "").strip() else []
        except ValueError as e:
            return f"端口列表格式错误：{e}"

        opts = RunOptions(
            target_host=host,
            ports=port_list,
            samples_per_port=10,
            tcp_timeout_ms=1000,
            enable_ping=enable_ping,
            enable_capture=enable_capture,
            prefer_ipv6=False,
            enable_traceroute=enable_traceroute,
        )
        logs: list[str] = []

        def prog(msg: str) -> None:
            logs.append(msg)

        _log.info("AI 发起网络诊断 host=%s ports=%s", host, port_list)
        try:
            rep = run_diagnostic(opts, prog)
        except Exception as e:
            _log.exception("AI 网络诊断失败")
            return f"网络诊断执行失败：{e}\n\n过程日志：\n" + "\n".join(logs[-40:])

        summary = summarize_diagnostic_report(rep, include_markdown_excerpt=True)
        if logs:
            tail = "\n".join(logs[-25:])
            summary = summary + "\n\n--- 执行过程（末段日志）---\n" + tail
        return summary

    def calculate_subnet(self, cidr: str) -> str:
        s = (cidr or "").strip()
        if not s:
            return "错误：请提供 cidr，例如 192.168.1.10/24。"
        try:
            r = calc_from_cidr_combo(s)
        except ValueError as e:
            return f"子网计算失败：{e}"
        return (
            f"输入：{r.input_interface}\n"
            f"网络 CIDR：{r.network_cidr}\n"
            f"网络地址：{r.network_address}\n"
            f"广播地址：{r.broadcast_address}\n"
            f"子网掩码：{r.netmask}\n"
            f"通配符掩码：{r.wildcard_mask}\n"
            f"前缀长度：/{r.prefix_len}\n"
            f"地址总数：{r.total_addresses}\n"
            f"可用主机数：{r.usable_hosts}\n"
            f"首可用主机：{r.first_host}\n"
            f"末可用主机：{r.last_host}\n"
            f"地址分类：{r.scope_note}\n"
            f"输入 IP 角色：{r.host_role_note}"
        )

    def run_database_diagnosis(
        self,
        *,
        engine: str,
        host: str,
        port: int = 3306,
        user: str = "",
        password: str = "",
        database: str = "",
    ) -> str:
        eng = (engine or "mysql").strip().lower()
        if not database.strip():
            return "错误：请提供 database（库名或 Oracle Service Name）。"
        cfg = DbConnectConfig(
            engine=eng,
            host=(host or "127.0.0.1").strip(),
            port=int(port),
            user=user,
            password=password,
            database=database.strip(),
        )
        _log.info("AI 发起数据库诊断 engine=%s host=%s db=%s", eng, cfg.host, cfg.database)
        try:
            rep = run_full_diagnosis(cfg)
        except Exception as e:
            _log.exception("AI 数据库诊断失败")
            return f"数据库诊断失败：{e}"
        err_part = ""
        if rep.errors:
            err_part = "\n错误摘要：\n" + "\n".join(f"  • {x}" for x in rep.errors[:8])
        return (
            f"数据库诊断已完成。\n"
            f"引擎：{rep.engine}\n"
            f"任务 ID：{rep.task_id}\n"
            f"Markdown 报告：{rep.markdown_path}\n"
            f"章节数：{len(rep.sections)}\n"
            f"{err_part}\n"
            f"请根据报告路径中的 Markdown 向用户解读关键发现；若连接失败，请说明可能原因与下一步。"
        )

    def navigate_module(self, module_key: str) -> str:
        key = (module_key or "").strip()
        from network_diagnosis.ai.tools import _MODULE_LABELS

        label = _MODULE_LABELS.get(key, key)

        def do_nav() -> None:
            if key in self._app._view_frames or key in ("guide", "about", "license"):
                self._app._select_module(key)
            else:
                _log.warning("AI 请求未知模块 key=%s", key)

        self._on_main(do_nav)
        return f"已请求切换到「{label}」页面（module_key={key}）。请继续用自然语言向用户说明。"
