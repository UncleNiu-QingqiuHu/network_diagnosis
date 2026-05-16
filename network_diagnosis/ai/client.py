"""OpenAI 兼容 Chat Completions HTTP 客户端（含 SSE 流式）。"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import requests

from network_diagnosis.ai.config import LlmConfig
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)


class LlmClientError(Exception):
    pass


def _request_headers(cfg: LlmConfig) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {cfg.api_key.strip()}",
        "Content-Type": "application/json",
    }


def _is_deepseek_api(cfg: LlmConfig) -> bool:
    return "deepseek.com" in cfg.normalized_base().lower()


def normalize_messages_for_api(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    规范化发往 API 的消息列表。
    DeepSeek 思考模式 + 工具调用时，assistant 消息必须带回 ``reasoning_content``。
    """
    out: list[dict[str, Any]] = []
    for m in messages:
        msg = dict(m)
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            if "reasoning_content" not in msg:
                msg["reasoning_content"] = ""
        out.append(msg)
    return out


def _build_body(
    cfg: LlmConfig,
    messages: list[dict[str, Any]],
    *,
    tools: list[dict[str, Any]] | None,
    stream: bool,
) -> dict[str, Any]:
    api_messages = normalize_messages_for_api(messages)
    body: dict[str, Any] = {
        "model": cfg.model.strip(),
        "messages": api_messages,
        "max_tokens": cfg.max_tokens,
        "stream": stream,
    }
    if _is_deepseek_api(cfg):
        # 思考模式忽略 temperature；显式启用 thinking（deepseek-v4-pro / deepseek-reasoner）
        body["reasoning_effort"] = "high"
        body["thinking"] = {"type": "enabled"}
    else:
        body["temperature"] = cfg.temperature
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    return body


def _merge_tool_call_delta(accum: dict[int, dict[str, Any]], delta_tc: list[Any]) -> None:
    for item in delta_tc:
        if not isinstance(item, dict):
            continue
        idx = int(item.get("index", 0))
        slot = accum.setdefault(
            idx,
            {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
        )
        if item.get("id"):
            slot["id"] = item["id"]
        fn = item.get("function")
        if isinstance(fn, dict):
            if fn.get("name"):
                slot["function"]["name"] = str(slot["function"]["name"]) + str(fn["name"])
            if fn.get("arguments"):
                slot["function"]["arguments"] = str(slot["function"]["arguments"]) + str(fn["arguments"])


def _accumulated_tool_calls(accum: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    return [accum[i] for i in sorted(accum.keys())]


def chat_completion_stream(
    cfg: LlmConfig,
    messages: list[dict[str, Any]],
    *,
    tools: list[dict[str, Any]] | None = None,
    on_delta: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """
    流式请求，通过 on_delta 推送文本片段。
    返回与非流式一致的 assistant message 字典（含 content / tool_calls）。
    """
    if not cfg.is_ready():
        raise LlmClientError("请先配置 API Key 与模型名称。")

    url = cfg.chat_completions_url()
    body = _build_body(cfg, messages, tools=tools, stream=True)

    try:
        resp = requests.post(
            url,
            headers=_request_headers(cfg),
            json=body,
            timeout=cfg.timeout_sec,
            stream=True,
        )
    except requests.RequestException as e:
        raise LlmClientError(f"无法连接大模型服务：{e}") from e

    if resp.status_code >= 400:
        detail = resp.text[:800] if resp.text else resp.reason
        raise LlmClientError(f"API 返回 {resp.status_code}：{detail}")

    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    tool_accum: dict[int, dict[str, Any]] = {}
    finish_reason: str | None = None

    try:
        for raw_line in resp.iter_lines(decode_unicode=True):
            if not raw_line:
                continue
            line = raw_line.strip() if isinstance(raw_line, str) else raw_line.decode("utf-8", errors="replace").strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                chunk = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if not isinstance(chunk, dict):
                continue
            choices = chunk.get("choices")
            if not choices or not isinstance(choices, list):
                continue
            ch0 = choices[0]
            if not isinstance(ch0, dict):
                continue
            if ch0.get("finish_reason"):
                finish_reason = str(ch0["finish_reason"])
            delta = ch0.get("delta")
            if not isinstance(delta, dict):
                continue
            reasoning_piece = delta.get("reasoning_content")
            if reasoning_piece:
                reasoning_parts.append(str(reasoning_piece))
            piece = delta.get("content")
            if piece:
                content_parts.append(str(piece))
                if on_delta:
                    on_delta(str(piece))
            delta_tc = delta.get("tool_calls")
            if isinstance(delta_tc, list):
                _merge_tool_call_delta(tool_accum, delta_tc)
    finally:
        resp.close()

    content = "".join(content_parts)
    reasoning = "".join(reasoning_parts)
    tool_calls = _accumulated_tool_calls(tool_accum)
    msg: dict[str, Any] = {"role": "assistant", "content": content or None}
    if reasoning:
        msg["reasoning_content"] = reasoning
    elif tool_calls:
        # 思考模式 + 工具调用：即使为空也保留字段，便于后续轮次回传
        msg["reasoning_content"] = ""
    if tool_calls:
        msg["tool_calls"] = tool_calls
    _log.debug(
        "流式完成 finish=%s content_len=%d reasoning_len=%d tool_calls=%d",
        finish_reason,
        len(content),
        len(reasoning),
        len(tool_calls),
    )
    return msg


def chat_completion(
    cfg: LlmConfig,
    messages: list[dict[str, Any]],
    *,
    tools: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not cfg.is_ready():
        raise LlmClientError("请先配置 API Key 与模型名称。")

    url = cfg.chat_completions_url()
    body = _build_body(cfg, messages, tools=tools, stream=False)

    try:
        resp = requests.post(url, headers=_request_headers(cfg), json=body, timeout=cfg.timeout_sec)
    except requests.RequestException as e:
        raise LlmClientError(f"无法连接大模型服务：{e}") from e

    if resp.status_code >= 400:
        detail = resp.text[:800] if resp.text else resp.reason
        raise LlmClientError(f"API 返回 {resp.status_code}：{detail}")

    try:
        data = resp.json()
    except ValueError as e:
        raise LlmClientError("响应不是合法 JSON。") from e

    if not isinstance(data, dict):
        raise LlmClientError("响应格式异常。")
    return data


def test_connection(cfg: LlmConfig) -> str:
    collected: list[str] = []

    def _on_delta(s: str) -> None:
        collected.append(s)

    msg = chat_completion_stream(
        cfg,
        [
            {"role": "system", "content": "你是连通性测试助手，请用一句话确认在线。"},
            {"role": "user", "content": "ping"},
        ],
        on_delta=_on_delta,
    )
    content = msg.get("content") or "".join(collected)
    if not content:
        return "连接成功（模型返回空内容）。"
    return str(content).strip()
