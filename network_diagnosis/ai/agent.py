"""多轮对话 + 工具调用循环（支持流式输出与 skills 约束）。"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from network_diagnosis.ai.app_actions import AppActions
from network_diagnosis.ai.client import LlmClientError, chat_completion_stream
from network_diagnosis.ai.config import LlmConfig
from network_diagnosis.ai.skills_loader import build_skills_system_section, scan_skills
from network_diagnosis.ai.tools import TOOL_DEFINITIONS, execute_tool
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)

MAX_TOOL_ROUNDS = 10

SYSTEM_PROMPT_BASE = """你是「青丘狐网络工作台」内置 AI 助手，帮助运维人员完成网络诊断、子网计算、数据库诊断等任务。

规则：
1. 用简体中文回复，语气专业、简洁。
2. 当用户要求诊断网络、测连通性、查 DNS/端口/延迟时，必须调用 run_network_diagnosis，并根据工具返回的摘要与报告向用户解读，给出可操作建议。
3. 子网、掩码、CIDR 相关问题调用 calculate_subnet。
4. 用户明确提供数据库连接信息并要求诊断时，调用 run_database_diagnosis；勿编造连接参数。
5. 需要用户在图形界面手动操作时，可调用 navigate_module 切换对应功能页。
6. 不要声称已执行某操作 unless 已通过工具完成；执行较长任务前可简短说明正在做什么。
7. 涉及安全扫描、端口扫描等敏感操作，提醒用户仅在授权环境使用。"""


def build_system_prompt() -> str:
    skills = scan_skills()
    section = build_skills_system_section(skills)
    if section:
        return SYSTEM_PROMPT_BASE + section
    return SYSTEM_PROMPT_BASE


def _ensure_system_message(working: list[dict[str, Any]]) -> None:
    prompt = build_system_prompt()
    if not working:
        working.insert(0, {"role": "system", "content": prompt})
        return
    if working[0].get("role") == "system":
        working[0] = {"role": "system", "content": prompt}
    else:
        working.insert(0, {"role": "system", "content": prompt})


def run_agent_chat(
    cfg: LlmConfig,
    actions: AppActions,
    messages: list[dict[str, Any]],
    *,
    on_status: Callable[[str], None] | None = None,
    on_delta: Callable[[str], None] | None = None,
    on_stream_start: Callable[[], None] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """
    执行一轮用户对话（可含多轮 tool 调用）。
    最终回复以流式推送 on_delta；工具执行阶段仅 on_status。
    返回 (助手最终文本, 更新后的 messages)。
    """
    working = list(messages)
    _ensure_system_message(working)

    def status(msg: str) -> None:
        if on_status:
            on_status(msg)

    for round_i in range(MAX_TOOL_ROUNDS):
        status("正在思考…" if round_i == 0 else f"正在处理工具结果（第 {round_i + 1} 轮）…")

        stream_started = False

        def delta_cb(piece: str) -> None:
            nonlocal stream_started
            if not stream_started:
                stream_started = True
                if on_stream_start:
                    on_stream_start()
            if on_delta:
                on_delta(piece)

        try:
            assistant_msg = chat_completion_stream(
                cfg,
                working,
                tools=TOOL_DEFINITIONS,
                on_delta=delta_cb if on_delta else None,
            )
        except LlmClientError:
            raise

        tool_calls = assistant_msg.get("tool_calls")
        if not stream_started and not tool_calls:
            content_once = assistant_msg.get("content") or ""
            if content_once:
                if on_stream_start:
                    on_stream_start()
                if on_delta:
                    on_delta(str(content_once))

        working.append(assistant_msg)

        if not tool_calls:
            content = assistant_msg.get("content") or ""
            return str(content).strip(), working

        if not isinstance(tool_calls, list):
            raise LlmClientError("tool_calls 格式异常。")

        for tc in tool_calls:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
            name = str(fn.get("name", ""))
            args_raw = fn.get("arguments") or "{}"
            tc_id = tc.get("id") or f"call_{round_i}"
            status(f"正在执行：{name}…")
            result = execute_tool(actions, name, str(args_raw))
            working.append(
                {
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "content": result,
                }
            )
            _log.debug("工具 %s 结果长度=%d", name, len(result))

    raise LlmClientError(f"工具调用超过最大轮数（{MAX_TOOL_ROUNDS}），请缩小请求范围后重试。")
