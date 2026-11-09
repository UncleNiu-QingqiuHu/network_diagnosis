//! 对话会话的落盘与列表。
//!
//! 一个会话 = 一个 JSON 文件，不维护全局索引：索引文件一旦与目录不同步，
//! 用户就会看到「列表里有、点开是空的」，比慢一点糟得多。列表靠扫目录 +
//! 读每个文件头部得到，几千个会话以内无感。
//!
//! 落盘范围只含**对话可见内容**（用户消息、助手回复、工具标签），
//! 不含完整工具输出 —— 那东西动辄几十 KB，存下来会把会话文件撑爆，
//! 而用户切回来看的其实是「当时调了什么、成没成」。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::AgentError;

/// 单条消息的最大字符数，超出截断（防止一次贴进巨量日志把文件撑大）。
const MAX_MESSAGE_CHARS: usize = 20_000;
/// 单个会话保留的最大消息条数，超出从头丢弃。
const MAX_MESSAGES: usize = 400;
/// 最多保留的会话数，超出删除最旧的。
pub const MAX_SESSIONS: usize = 100;
/// 标题最大长度（字符）。
const TITLE_CHARS: usize = 24;

/// 消息里记录的工具调用摘要。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredTool {
    pub name: String,
    /// ok / error
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredMessage {
    /// user / assistant
    pub role: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<StoredTool>,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// 本会话首次对话时所用的模型名。报告里要写清楚结论是哪个模型给的，
    /// 换过模型的话以首次为准（会话中途换模型属于少数情况）。
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub messages: Vec<StoredMessage>,
}

/// 列表项：不带消息正文，避免为了显示一个列表把所有会话读进内存。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub id: String,
    pub title: String,
    pub updated_at: DateTime<Utc>,
    pub message_count: usize,
    /// 最后一条用户消息，列表里做副标题
    pub last_user_text: String,
}

impl Session {
    pub fn empty(id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            title: "新对话".to_string(),
            created_at: now,
            updated_at: now,
            model: None,
            messages: Vec::new(),
        }
    }

    /// 追加一条消息，并在必要时把标题从首条用户消息推导出来。
    pub fn push(&mut self, mut msg: StoredMessage) {
        msg.text = truncate_chars(&msg.text, MAX_MESSAGE_CHARS);
        if msg.role == "user" && self.messages.iter().all(|m| m.role != "user") {
            self.title = derive_title(&msg.text);
        }
        self.messages.push(msg);
        if self.messages.len() > MAX_MESSAGES {
            let drop = self.messages.len() - MAX_MESSAGES;
            self.messages.drain(..drop);
        }
        self.updated_at = Utc::now();
    }

    pub fn summary(&self) -> SessionSummary {
        SessionSummary {
            id: self.id.clone(),
            title: self.title.clone(),
            updated_at: self.updated_at,
            message_count: self.messages.len(),
            last_user_text: self
                .messages
                .iter()
                .rev()
                .find(|m| m.role == "user")
                .map(|m| truncate_chars(&m.text, 60))
                .unwrap_or_default(),
        }
    }
}

/// 由首条用户消息生成标题。
///
/// 不调用模型：标题生成多一次请求、多一份等待，而且模型挂掉时连会话都没有名字。
/// 取首行 + 去多余空白 + 截断，够用了。
pub fn derive_title(text: &str) -> String {
    let first_line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let cleaned = first_line.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.is_empty() {
        return "新对话".to_string();
    }
    let cut = truncate_chars(&cleaned, TITLE_CHARS);
    if cut.chars().count() < cleaned.chars().count() {
        format!("{cut}…")
    } else {
        cut
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect()
}

// ---------------------------------------------------------------- 存储

pub struct SessionStore {
    root: PathBuf,
}

impl SessionStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        let _ = std::fs::create_dir_all(&root);
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_of(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }

    pub fn new_id() -> String {
        let now = Utc::now();
        format!(
            "{}-{}",
            now.format("%Y%m%d%H%M%S"),
            &uuid::Uuid::new_v4().simple().to_string()[..6]
        )
    }

    /// 列出全部会话，按更新时间倒序。
    ///
    /// 单个文件坏了不影响整张列表：跳过并继续，否则一个半截文件会让用户
    /// 所有历史都打不开。
    pub fn list(&self) -> Vec<SessionSummary> {
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut out: Vec<SessionSummary> = entries
            .flatten()
            .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
            .filter_map(|e| {
                let text = std::fs::read_to_string(e.path()).ok()?;
                let s: Session = serde_json::from_str(&text).ok()?;
                Some(s.summary())
            })
            .collect();
        out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        out
    }

    pub fn get(&self, id: &str) -> Option<Session> {
        // id 直接拼进文件名，必须挡住路径穿越
        if !is_safe_id(id) {
            return None;
        }
        let text = std::fs::read_to_string(self.path_of(id)).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// 保存（新增或覆盖），随后按上限裁剪最旧的会话。
    pub fn save(&self, session: &Session) -> Result<(), AgentError> {
        if !is_safe_id(&session.id) {
            return Err(AgentError::Config(format!("会话 id 非法：{}", session.id)));
        }
        let path = self.path_of(&session.id);
        let text = serde_json::to_string_pretty(session)
            .map_err(|e| AgentError::Config(format!("序列化会话失败：{e}")))?;
        write_atomic(&path, &text)
            .map_err(|e| AgentError::Config(format!("写入会话失败：{e}")))?;
        self.prune();
        Ok(())
    }

    pub fn rename(&self, id: &str, title: &str) -> Result<Session, AgentError> {
        let mut s = self
            .get(id)
            .ok_or_else(|| AgentError::Config(format!("找不到会话 {id}")))?;
        let t = title.trim();
        if !t.is_empty() {
            s.title = truncate_chars(t, 60);
            self.save(&s)?;
        }
        Ok(s)
    }

    pub fn delete(&self, id: &str) -> Result<(), AgentError> {
        if !is_safe_id(id) {
            return Err(AgentError::Config(format!("会话 id 非法：{id}")));
        }
        let path = self.path_of(id);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| AgentError::Config(format!("删除会话失败：{e}")))?;
        }
        Ok(())
    }

    /// 只保留最新的 [`MAX_SESSIONS`] 个。
    ///
    /// 先数文件个数再决定要不要读内容：每次保存都全量解析一遍会话文件
    /// 是没必要的开销。
    pub fn prune(&self) {
        let count = std::fs::read_dir(&self.root)
            .map(|e| {
                e.flatten()
                    .filter(|x| x.path().extension().map(|v| v == "json").unwrap_or(false))
                    .count()
            })
            .unwrap_or(0);
        if count <= MAX_SESSIONS {
            return;
        }
        let list = self.list();
        for s in list.into_iter().skip(MAX_SESSIONS) {
            let _ = std::fs::remove_file(self.path_of(&s.id));
        }
    }
}

/// id 只允许字母数字与 `-`，避免 `../` 这类路径穿越。
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text)?;
    // Windows 上 rename 覆盖已存在文件会失败，先删目标
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(tag: &str) -> SessionStore {
        let dir = std::env::temp_dir().join(format!("qqhu-sess-{tag}-{}", SessionStore::new_id()));
        SessionStore::new(dir)
    }

    fn msg(role: &str, text: &str) -> StoredMessage {
        StoredMessage {
            role: role.into(),
            text: text.into(),
            tools: Vec::new(),
            at: Utc::now(),
        }
    }

    #[test]
    fn title_comes_from_first_user_message() {
        let mut s = Session::empty("a1");
        assert_eq!(s.title, "新对话");
        s.push(msg("user", "\n\n  本机网段里有哪些设备在线？ \n第二行"));
        assert_eq!(s.title, "本机网段里有哪些设备在线？");

        // 后续用户消息不改标题
        s.push(msg("user", "换个问题"));
        assert_eq!(s.title, "本机网段里有哪些设备在线？");
    }

    #[test]
    fn long_title_is_truncated_with_ellipsis() {
        let long = "这是一条非常长的提问".repeat(10);
        let t = derive_title(&long);
        assert!(t.ends_with('…'));
        assert!(t.chars().count() <= TITLE_CHARS + 1);
    }

    #[test]
    fn blank_prompt_falls_back_to_default_title() {
        assert_eq!(derive_title("   \n\n  "), "新对话");
    }

    #[test]
    fn saves_and_lists_newest_first() {
        let store = temp_store("list");
        let mut a = Session::empty("s1");
        a.push(msg("user", "第一个会话"));
        a.updated_at = Utc::now() - chrono::Duration::minutes(10);
        store.save(&a).unwrap();

        let mut b = Session::empty("s2");
        b.push(msg("user", "第二个会话"));
        store.save(&b).unwrap();

        let list = store.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, "s2", "最近更新的排前面");
        assert_eq!(list[0].title, "第二个会话");
        assert_eq!(list[0].message_count, 1);
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn round_trip_keeps_tool_chips() {
        let store = temp_store("roundtrip");
        let mut s = Session::empty("s1");
        s.push(StoredMessage {
            role: "assistant".into(),
            text: "网关可达".into(),
            tools: vec![StoredTool {
                name: "ping_host".into(),
                status: "ok".into(),
                preview: "4/4 收到".into(),
            }],
            at: Utc::now(),
        });
        store.save(&s).unwrap();

        let got = store.get("s1").unwrap();
        assert_eq!(got.messages.len(), 1);
        assert_eq!(got.messages[0].tools[0].name, "ping_host");
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn rejects_path_traversal_ids() {
        let store = temp_store("safe");
        assert!(store.get("../../secret").is_none());
        assert!(store.save(&Session::empty("../evil")).is_err());
        assert!(store.delete("..").is_err());
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn corrupt_file_is_skipped_not_fatal() {
        let store = temp_store("corrupt");
        let mut good = Session::empty("ok1");
        good.push(msg("user", "正常"));
        store.save(&good).unwrap();
        std::fs::write(store.root().join("broken.json"), "{ 半个文件").unwrap();

        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "ok1");
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn caps_message_count_and_truncates_huge_text() {
        let mut s = Session::empty("cap");
        for i in 0..(MAX_MESSAGES + 7) {
            s.push(msg("assistant", &format!("第 {i} 条")));
        }
        assert_eq!(s.messages.len(), MAX_MESSAGES);
        // 留下的是最新的
        assert_eq!(s.messages.last().unwrap().text, format!("第 {} 条", MAX_MESSAGES + 6));

        let mut t = Session::empty("big");
        t.push(msg("user", &"x".repeat(MAX_MESSAGE_CHARS + 100)));
        assert_eq!(t.messages[0].text.chars().count(), MAX_MESSAGE_CHARS);
    }

    #[test]
    fn rename_updates_title_and_ignores_blank() {
        let store = temp_store("rename");
        let mut s = Session::empty("s1");
        s.push(msg("user", "原标题"));
        store.save(&s).unwrap();

        let r = store.rename("s1", "  自定义标题  ").unwrap();
        assert_eq!(r.title, "自定义标题");

        let r = store.rename("s1", "   ").unwrap();
        assert_eq!(r.title, "自定义标题", "空白标题不应清掉原名");

        assert!(store.rename("nope", "x").is_err());
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn delete_removes_file() {
        let store = temp_store("del");
        let s = Session::empty("s1");
        store.save(&s).unwrap();
        assert!(store.get("s1").is_some());
        store.delete("s1").unwrap();
        assert!(store.get("s1").is_none());
        // 重复删除不报错
        store.delete("s1").unwrap();
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn prune_keeps_only_latest() {
        let store = temp_store("prune");
        let mut old = Session::empty("oldest");
        old.updated_at = Utc::now() - chrono::Duration::days(30);
        store.save(&old).unwrap();
        // 直接写够 MAX_SESSIONS 个更新一点的
        for i in 0..MAX_SESSIONS {
            let mut s = Session::empty(format!("s{i}"));
            s.updated_at = Utc::now() - chrono::Duration::seconds(MAX_SESSIONS as i64 - i as i64);
            store.save(&s).unwrap();
        }
        let list = store.list();
        assert!(list.len() <= MAX_SESSIONS);
        assert!(
            !list.iter().any(|s| s.id == "oldest"),
            "最旧的应被裁掉"
        );
        let _ = std::fs::remove_dir_all(store.root());
    }
}
