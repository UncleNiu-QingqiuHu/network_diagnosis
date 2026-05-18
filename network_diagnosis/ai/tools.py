"""OpenAI 兼容 function tools 定义与执行。"""

from __future__ import annotations

import json
from typing import Any

from network_diagnosis.ai.app_actions import AppActions
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "run_network_diagnosis",
            "description": (
                "对本程序内置的网络诊断引擎发起一次完整探测（DNS、Ping、TCP 端口等），"
                "返回结构化摘要供你解读。用户要求排查连通性、延迟、端口、DNS 等问题时使用。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_host": {
                        "type": "string",
                        "description": "目标主机名或 IP，例如 www.baidu.com",
                    },
                    "ports": {
                        "type": "string",
                        "description": "TCP 端口列表，英文逗号分隔，例如 80,443；留空则不测端口",
                    },
                    "enable_ping": {
                        "type": "boolean",
                        "description": "是否启用 ICMP Ping，默认 true",
                    },
                    "enable_traceroute": {
                        "type": "boolean",
                        "description": "是否启用 tracert 路由追踪，默认 false",
                    },
                    "enable_capture": {
                        "type": "boolean",
                        "description": "是否抓包（需本机 Wireshark/tshark），默认 false",
                    },
                },
                "required": ["target_host"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "calculate_subnet",
            "description": (
                "IPv4 子网计算：支持 192.168.1.10/24 或 192.168.1.10/255.255.255.0 等格式。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cidr": {
                        "type": "string",
                        "description": "IP/前缀 或 IP/掩码，例如 10.0.0.5/24",
                    },
                },
                "required": ["cidr"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_database_diagnosis",
            "description": (
                "对数据库发起一次完整诊断（连接、版本、库表概况等），返回 Markdown 报告路径与摘要。"
                "仅在用户明确提供连接信息且授权后调用。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "engine": {
                        "type": "string",
                        "enum": ["sqlite", "mysql", "postgresql", "sqlserver", "oracle"],
                    },
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                    "user": {"type": "string"},
                    "password": {"type": "string"},
                    "database": {"type": "string", "description": "库名；Oracle 填 Service Name"},
                },
                "required": ["engine", "host", "database"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "navigate_module",
            "description": (
                "切换到工作台左侧某一功能页，便于用户查看图形界面或手动操作。"
                "module_key: ai_assistant, network, subnet, ip_scan, switch, database, arp_intranet, "
                "security, code_sign, ssl_cert, guide, about, license"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "module_key": {"type": "string"},
                    "reason": {"type": "string", "description": "切换原因（简短中文）"},
                },
                "required": ["module_key"],
            },
        },
    },
]

_MODULE_LABELS: dict[str, str] = {
    "ai_assistant": "AI助手",
    "network": "网络诊断",
    "subnet": "子网计算",
    "ip_scan": "IP扫描",
    "switch": "交换机配置",
    "database": "数据库诊断",
    "arp_intranet": "ARP安全",
    "security": "安全诊断",
    "code_sign": "数字签名",
    "ssl_cert": "SSL证书",
    "guide": "使用帮助",
    "about": "关于",
    "license": "许可",
}


def execute_tool(actions: AppActions, name: str, arguments_json: str) -> str:
    try:
        args = json.loads(arguments_json) if arguments_json.strip() else {}
    except json.JSONDecodeError as e:
        return f"工具参数 JSON 无效：{e}"
    if not isinstance(args, dict):
        return "工具参数须为 JSON 对象。"

    _log.info("AI 工具调用 name=%s args=%s", name, {k: v for k, v in args.items() if k != "password"})

    try:
        if name == "run_network_diagnosis":
            return actions.run_network_diagnosis(
                target_host=str(args.get("target_host", "")).strip(),
                ports=str(args.get("ports", "80,443")),
                enable_ping=bool(args.get("enable_ping", True)),
                enable_traceroute=bool(args.get("enable_traceroute", False)),
                enable_capture=bool(args.get("enable_capture", False)),
            )
        if name == "calculate_subnet":
            return actions.calculate_subnet(str(args.get("cidr", "")).strip())
        if name == "run_database_diagnosis":
            return actions.run_database_diagnosis(
                engine=str(args.get("engine", "mysql")),
                host=str(args.get("host", "127.0.0.1")),
                port=int(args.get("port", 3306)),
                user=str(args.get("user", "")),
                password=str(args.get("password", "")),
                database=str(args.get("database", "")),
            )
        if name == "navigate_module":
            key = str(args.get("module_key", "")).strip()
            return actions.navigate_module(key)
        return f"未知工具：{name}"
    except Exception as e:
        _log.exception("工具执行失败 name=%s", name)
        return f"工具执行失败：{e}"
