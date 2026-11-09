//! 青丘湖网络工作台 —— AI Agent 支撑层。
//!
//! 分层：
//! - [`config`]：模型接入配置（OpenAI 兼容），不存 API Key
//! - [`secrets`]：API Key 走系统凭据管理器
//! - [`skills`]：扫描/导入/启停技能（只读扫描其它 Agent 目录，导入是复制）
//! - [`prompt`]：角色与边界，系统提示词的唯一来源
//! - [`chat`]：流式对话与工具调用协议
//! - [`tools`]：工具定义与命令白名单（执行在应用层）
//! - [`session`]：对话历史落盘（一个会话一个文件，不维护全局索引）
//!
//! 这一层刻意不依赖 Tauri：所有逻辑都能直接跑单测，界面只是它的调用方。

pub mod chat;
pub mod config;
pub mod prompt;
pub mod secrets;
pub mod session;
pub mod skills;
pub mod tools;

pub use chat::{stream_completion, ChatMessage, ToolCall, TurnResult};
pub use config::{AgentConfig, AgentStore, ModelConfig};
pub use secrets::SecretStore;
pub use session::{Session, SessionStore, SessionSummary, StoredMessage, StoredTool};

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("{0}")]
    Config(String),

    #[error("{0}")]
    Skill(String),

    #[error("{0}")]
    Http(String),

    #[error("模型返回错误：{0}")]
    Api(String),

    #[error("已取消")]
    Cancelled,
}
