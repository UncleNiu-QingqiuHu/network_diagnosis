"""大模型连接配置（本地 JSON 持久化）。"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from network_diagnosis.paths import ai_assistant_config_path
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)

DEFAULT_API_BASE = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"


@dataclass
class LlmConfig:
    api_base: str = DEFAULT_API_BASE
    api_key: str = ""
    model: str = DEFAULT_MODEL
    temperature: float = 0.3
    max_tokens: int = 4096
    timeout_sec: int = 120

    def normalized_base(self) -> str:
        b = (self.api_base or "").strip().rstrip("/")
        return b or DEFAULT_API_BASE

    def is_ready(self) -> bool:
        return bool(self.api_key.strip()) and bool(self.model.strip())

    def chat_completions_url(self) -> str:
        base = self.normalized_base()
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"


def load_llm_config() -> LlmConfig:
    path = ai_assistant_config_path()
    if not path.is_file():
        return LlmConfig()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return LlmConfig()
        return LlmConfig(
            api_base=str(raw.get("api_base", DEFAULT_API_BASE)),
            api_key=str(raw.get("api_key", "")),
            model=str(raw.get("model", DEFAULT_MODEL)),
            temperature=float(raw.get("temperature", 0.3)),
            max_tokens=int(raw.get("max_tokens", 4096)),
            timeout_sec=int(raw.get("timeout_sec", 120)),
        )
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as e:
        _log.warning("读取 AI 配置失败 path=%s: %s", path, e)
        return LlmConfig()


def save_llm_config(cfg: LlmConfig) -> None:
    path = ai_assistant_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = asdict(cfg)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    _log.info("已保存 AI 配置 path=%s model=%s", path, cfg.model)
