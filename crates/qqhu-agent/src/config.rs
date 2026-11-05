//! 模型接入配置与持久化。
//!
//! 只支持 OpenAI 兼容协议（`POST {base}/chat/completions`），这一套覆盖了
//! DeepSeek、Kimi、通义千问、智谱、硅基流动、vLLM、Ollama 等绝大多数服务，
//! 也包含 OpenAI 本身。少一层协议适配，换来的是一处配置即可对接。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_MAX_TOKENS: u32 = 4096;
/// 上限做保护：部分服务按 max_tokens 直接拒绝超大值，填错会整轮失败。
pub const MAX_TOKENS_LIMIT: u32 = 32768;
const DEFAULT_TEMPERATURE: f32 = 0.3;

fn default_max_tokens() -> u32 {
    DEFAULT_MAX_TOKENS
}

fn default_temperature() -> f32 {
    DEFAULT_TEMPERATURE
}

fn default_true() -> bool {
    true
}

/// 一条模型配置。**不含 API Key** —— Key 存在系统凭据管理器里，按 `id` 关联。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelConfig {
    pub id: String,
    /// 展示名，用户自己起，如「DeepSeek 生产」
    pub name: String,
    /// 形如 `https://api.deepseek.com/v1`
    pub base_url: String,
    /// 形如 `deepseek-chat`
    pub model: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
}

impl ModelConfig {
    /// 校验并归一化。返回的副本里 base_url 已去掉尾部斜杠。
    pub fn normalized(&self) -> Result<Self, String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err("请填写模型名称（展示用）。".into());
        }
        let model = self.model.trim();
        if model.is_empty() {
            return Err("请填写模型 ID，例如 deepseek-chat。".into());
        }
        let base_url = normalize_base_url(&self.base_url)?;
        if !(1..=MAX_TOKENS_LIMIT).contains(&self.max_tokens) {
            return Err(format!("max_tokens 需在 1–{MAX_TOKENS_LIMIT} 之间。"));
        }
        if !(0.0..=2.0).contains(&self.temperature) {
            return Err("temperature 需在 0–2 之间。".into());
        }
        Ok(Self {
            id: if self.id.trim().is_empty() {
                new_id()
            } else {
                self.id.clone()
            },
            name: name.to_string(),
            base_url,
            model: model.to_string(),
            max_tokens: self.max_tokens,
            temperature: self.temperature,
        })
    }

    /// 补全后的对话接口地址。
    pub fn chat_url(&self) -> String {
        let base = self.base_url.trim_end_matches('/');
        if base.ends_with("/chat/completions") {
            base.to_string()
        } else {
            format!("{base}/chat/completions")
        }
    }
}

/// 校验 BaseURL：必须 https（本地回环允许 http，便于接 Ollama / vLLM）。
pub fn normalize_base_url(input: &str) -> Result<String, String> {
    let raw = input.trim().trim_end_matches('/');
    if raw.is_empty() {
        return Err("请填写接口地址（BaseURL）。".into());
    }
    let lower = raw.to_ascii_lowercase();
    let is_https = lower.starts_with("https://");
    let is_loopback_http = lower.starts_with("http://localhost")
        || lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://[::1]");
    if !is_https && !is_loopback_http {
        return Err("接口地址必须是 https://（本机 localhost 可用 http://）。".into());
    }
    if lower.contains(' ') {
        return Err("接口地址不能包含空格。".into());
    }
    Ok(raw.to_string())
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

/// 全局配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentConfig {
    #[serde(default)]
    pub models: Vec<ModelConfig>,
    /// 当前使用的模型 id
    #[serde(default)]
    pub active_model: Option<String>,
    /// 是否允许 Agent 调用本机命令（默认关闭）
    #[serde(default)]
    pub allow_commands: bool,
    /// 每条命令执行前是否要用户确认（默认开启）
    #[serde(default = "default_true")]
    pub confirm_commands: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            models: Vec::new(),
            active_model: None,
            allow_commands: false,
            confirm_commands: true,
        }
    }
}

impl AgentConfig {
    pub fn active(&self) -> Option<&ModelConfig> {
        let id = self.active_model.as_ref()?;
        self.models.iter().find(|m| &m.id == id)
    }

    /// 删除模型后把 active 指向第一个可用项，避免界面停在已删模型上。
    pub fn normalize_active(&mut self) {
        let ok = self
            .active_model
            .as_ref()
            .map(|id| self.models.iter().any(|m| &m.id == id))
            .unwrap_or(false);
        if !ok {
            self.active_model = self.models.first().map(|m| m.id.clone());
        }
    }
}

/// 配置文件读写。目录布局：`<安装目录>/agent/config.json`。
pub struct AgentStore {
    root: PathBuf,
}

impl AgentStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join("config.json")
    }

    pub fn skills_dir(&self) -> PathBuf {
        self.root.join("skills")
    }

    /// 读配置。文件不存在或损坏时返回默认值 —— 配置坏了不该让整个模块打不开。
    pub fn load(&self) -> AgentConfig {
        let Ok(text) = std::fs::read_to_string(self.config_path()) else {
            return AgentConfig::default();
        };
        let mut cfg: AgentConfig = serde_json::from_str(&text).unwrap_or_default();
        cfg.normalize_active();
        cfg
    }

    pub fn save(&self, cfg: &AgentConfig) -> Result<(), String> {
        std::fs::create_dir_all(&self.root).map_err(|e| format!("创建配置目录失败：{e}"))?;
        let text = serde_json::to_string_pretty(cfg).map_err(|e| format!("序列化配置失败：{e}"))?;
        std::fs::write(self.config_path(), text).map_err(|e| format!("写入配置失败：{e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> ModelConfig {
        ModelConfig {
            id: "m1".into(),
            name: "DeepSeek".into(),
            base_url: "https://api.deepseek.com/v1/".into(),
            model: "deepseek-chat".into(),
            max_tokens: 2048,
            temperature: 0.3,
        }
    }

    #[test]
    fn normalizes_trailing_slash() {
        let m = model().normalized().unwrap();
        assert_eq!(m.base_url, "https://api.deepseek.com/v1");
        assert_eq!(m.chat_url(), "https://api.deepseek.com/v1/chat/completions");
    }

    #[test]
    fn accepts_full_endpoint_without_duplicating() {
        let mut m = model();
        m.base_url = "https://api.example.com/v1/chat/completions".into();
        assert_eq!(
            m.normalized().unwrap().chat_url(),
            "https://api.example.com/v1/chat/completions"
        );
    }

    #[test]
    fn rejects_plain_http_except_loopback() {
        let mut m = model();
        m.base_url = "http://api.deepseek.com/v1".into();
        assert!(m.normalized().is_err());
        m.base_url = "http://localhost:11434/v1".into();
        assert!(m.normalized().is_ok());
        m.base_url = "http://127.0.0.1:8000/v1".into();
        assert!(m.normalized().is_ok());
    }

    #[test]
    fn rejects_empty_name_and_model() {
        let mut m = model();
        m.name = "  ".into();
        assert!(m.normalized().is_err());
        let mut m = model();
        m.model = "".into();
        assert!(m.normalized().is_err());
    }

    #[test]
    fn validates_token_and_temperature_bounds() {
        let mut m = model();
        m.max_tokens = 0;
        assert!(m.normalized().is_err());
        m.max_tokens = MAX_TOKENS_LIMIT + 1;
        assert!(m.normalized().is_err());
        m.max_tokens = 1024;
        m.temperature = 2.5;
        assert!(m.normalized().is_err());
    }

    #[test]
    fn config_round_trip_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let store = AgentStore::new(dir.path());
        let mut cfg = store.load();
        assert!(cfg.models.is_empty());
        // 默认不允许执行命令，且要求确认 —— 安全默认值
        assert!(!cfg.allow_commands);
        assert!(cfg.confirm_commands);

        cfg.models.push(model());
        cfg.active_model = None;
        store.save(&cfg).unwrap();

        let loaded = store.load();
        assert_eq!(loaded.models.len(), 1);
        // 未指定 active 时自动指向唯一的模型
        assert_eq!(loaded.active_model.as_deref(), Some("m1"));
    }

    #[test]
    fn corrupt_config_falls_back_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let store = AgentStore::new(dir.path());
        std::fs::create_dir_all(store.root()).unwrap();
        std::fs::write(store.config_path(), "{ not json").unwrap();
        assert!(store.load().models.is_empty());
    }

    #[test]
    fn normalize_active_drops_missing_model() {
        let mut cfg = AgentConfig {
            models: vec![model()],
            active_model: Some("gone".into()),
            ..Default::default()
        };
        cfg.normalize_active();
        assert_eq!(cfg.active_model.as_deref(), Some("m1"));
    }
}
