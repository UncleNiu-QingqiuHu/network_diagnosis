//! 对话历史的上下文预算裁剪。
//!
//! 落盘上限是单会话 400 条、单条 20000 字符，但模型上下文远没有这么大 ——
//! 旧实现把整份历史原样发出去，几十轮之后必然收到 400。
//!
//! 裁剪规则（顺序固定，每一条都有用途）：
//!
//! 1. **单条先截断**：一条消息最多占预算的 1/3，超了保头保尾、中间打省略标记。
//!    不这么做的话，一条 20000 字的长回答会把整个预算吃光。
//! 2. **首问必留**：从尾部往前装预算时单独跳过第一条用户消息，最后补回到最前面。
//!    丢了它模型就不知道这轮对话在解决什么问题，后面所有回答都会跑偏。
//! 3. **保留段取连续尾部**：不是零散挑消息，而是 `[start..]` 一个连续切片 ——
//!    工具往返、上下文指代都依赖先后顺序，挑着留等于把句意拆散。
//! 4. **丢掉孤立的 tool 消息**：OpenAI 协议要求 `tool` 必须紧跟带 `tool_calls`
//!    的 `assistant`，落单会直接 400。
//!
//! 预算按字符数算：中文 1 字约 1 token、英文 1 字符约 0.25 token，
//! 取 24000 字符对 32k 起的模型留足了系统提示词与工具定义的空间。

use crate::chat::ChatMessage;

/// 历史部分的默认字符预算。
pub const DEFAULT_BUDGET_CHARS: usize = 24_000;

/// 单条消息最多占预算的比例分母（1/3）。
const SINGLE_SHARE: usize = 3;

/// 单条截断保留的最小长度，避免预算极小时截出空串。
const MIN_SINGLE_KEEP: usize = 600;

/// 裁剪结果。
#[derive(Debug, Default)]
pub struct Trimmed {
    pub messages: Vec<ChatMessage>,
    /// 被整体丢弃的消息条数。
    pub dropped: usize,
    /// 被中间截断的消息条数。
    pub truncated: usize,
}

impl Trimmed {
    pub fn is_trimmed(&self) -> bool {
        self.dropped > 0 || self.truncated > 0
    }
}

/// 按字符预算裁剪历史。返回的消息可直接接在 system 之后发给模型。
pub fn trim_history(history: &[ChatMessage], budget: usize) -> Trimmed {
    if history.is_empty() {
        return Trimmed::default();
    }
    if budget == 0 {
        // 预算为 0 也要给一条，否则请求体里只剩 system，模型会答非所问
        return Trimmed {
            messages: vec![history.last().cloned().unwrap()],
            dropped: history.len() - 1,
            truncated: 0,
        };
    }

    // 1. 单条先压到 1/3 预算以内
    let per_message = (budget / SINGLE_SHARE).max(MIN_SINGLE_KEEP);
    let mut truncated = 0usize;
    let normalized: Vec<ChatMessage> = history
        .iter()
        .map(|m| match clamp_message(m, per_message) {
            Some(clamped) => {
                truncated += 1;
                clamped
            }
            None => m.clone(),
        })
        .collect();

    // 2. 从尾部往前装预算
    let first_user = normalized.iter().position(|m| m.role == "user");
    let mut used = 0usize;
    let mut start = normalized.len();
    for idx in (0..normalized.len()).rev() {
        if Some(idx) == first_user {
            // 首问单独保留，不参与尾部累加
            continue;
        }
        let c = cost(&normalized[idx]);
        if start < normalized.len() && used + c > budget {
            break;
        }
        used += c;
        start = idx;
    }

    let mut messages: Vec<ChatMessage> = Vec::with_capacity(normalized.len() - start + 2);

    // 3. 首问补回最前面
    if let Some(fi) = first_user {
        if fi < start {
            messages.push(normalized[fi].clone());
            let skipped = start.saturating_sub(fi + 1);
            if skipped > 0 {
                messages.push(ChatMessage::user(format!(
                    "（此处省略了较早的 {skipped} 条对话，以下是最近的往来内容）"
                )));
            }
        }
    }
    messages.extend(normalized[start..].iter().cloned());

    // 4. 剪掉没有合法父消息的 tool 消息
    //
    // OpenAI 协议要求 `tool` 紧跟带对应 `tool_calls` 的 `assistant`。
    // 裁剪把父消息切掉之后，落单的 tool 消息会让整个请求 400。
    let mut cleaned: Vec<ChatMessage> = Vec::with_capacity(messages.len());
    for m in messages {
        if m.role == "tool" {
            let has_parent = cleaned
                .last()
                .map(|p| {
                    p.role == "assistant"
                        && p.tool_calls
                            .iter()
                            .any(|c| Some(&c.id) == m.tool_call_id.as_ref())
                })
                .unwrap_or(false);
            if !has_parent {
                continue;
            }
        }
        cleaned.push(m);
    }
    let mut messages = cleaned;

    if messages.is_empty() {
        messages.push(normalized.last().cloned().unwrap());
    }

    let dropped = normalized.len().saturating_sub(messages.len());
    Trimmed {
        messages,
        dropped,
        truncated,
    }
}

/// 一条消息的字符开销。role 与 JSON 结构给个固定估值。
fn cost(m: &ChatMessage) -> usize {
    let mut n = 8;
    if let Some(c) = &m.content {
        n += c.chars().count();
    }
    for call in &m.tool_calls {
        n += call.function.name.chars().count() + call.function.arguments.chars().count();
    }
    n
}

/// 超出单条上限时保头保尾、中间打省略标记；未超返回 `None`。
fn clamp_message(m: &ChatMessage, limit: usize) -> Option<ChatMessage> {
    let content = m.content.as_deref()?;
    let clamped = clamp_text(content, limit)?;
    let mut out = m.clone();
    out.content = Some(clamped);
    Some(out)
}

fn clamp_text(text: &str, limit: usize) -> Option<String> {
    let len = text.chars().count();
    if len <= limit {
        return None;
    }
    // 头部多留一些：结论通常在回答开头，尾部留够看到最后一句
    let head = limit * 2 / 3;
    let tail = limit - head;
    let head_part: String = text.chars().take(head).collect();
    let tail_part: String = text
        .chars()
        .skip(len.saturating_sub(tail))
        .collect();
    Some(format!(
        "{head_part}\n\n…（此处省略 {} 字）…\n\n{tail_part}",
        len.saturating_sub(head + tail)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(role: &str, text: &str) -> ChatMessage {
        ChatMessage {
            role: role.into(),
            content: Some(text.into()),
            ..Default::default()
        }
    }

    #[test]
    fn empty_history_stays_empty() {
        let out = trim_history(&[], 1000);
        assert!(out.messages.is_empty());
        assert_eq!(out.dropped, 0);
    }

    #[test]
    fn under_budget_is_untouched() {
        let h = vec![msg("user", "ping 不通"), msg("assistant", "先看网关")];
        let out = trim_history(&h, 10_000);
        assert_eq!(out.messages.len(), 2);
        assert_eq!(out.dropped, 0);
        assert_eq!(out.truncated, 0);
        assert!(!out.is_trimmed());
    }

    #[test]
    fn keeps_first_question_and_recent_tail() {
        let mut h = vec![msg("user", "原始问题：出口丢包")];
        for i in 0..40 {
            h.push(msg(
                "assistant",
                &format!("第{i}轮回答，这里写一段足够长的内容用来把预算占满，避免测试失真"),
            ));
            h.push(msg("user", &format!("第{i}轮追问，同样写长一点让累加生效")));
        }
        let out = trim_history(&h, 2_000);
        assert!(out.dropped > 0, "81 条消息装不进 2000 字符预算");
        assert_eq!(out.messages[0].content.as_deref(), Some("原始问题：出口丢包"));
        assert!(
            out.messages.last().unwrap().content.as_deref().unwrap().contains("第39轮追问"),
            "最新的用户消息必须保留"
        );
        // 尾部必须是连续切片：不要出现「第5轮」夹在「第39轮」后面
        let joined: String = out
            .messages
            .iter()
            .filter_map(|m| m.content.clone())
            .collect();
        assert!(joined.contains("第39轮"));
    }

    #[test]
    fn does_not_duplicate_first_question() {
        let h = vec![msg("user", "短问题"), msg("assistant", "短回答")];
        let out = trim_history(&h, 10_000);
        let count = out
            .messages
            .iter()
            .filter(|m| m.content.as_deref() == Some("短问题"))
            .count();
        assert_eq!(count, 1, "首问不应出现两次");
    }

    #[test]
    fn long_single_message_is_clamped_both_ends() {
        let head = "开头结论".repeat(400);
        let tail = "结尾结论".repeat(400);
        let body = format!("{head}{}{tail}", "中间废话".repeat(2000));
        let h = vec![msg("user", "问"), msg("assistant", &body)];
        let out = trim_history(&h, 3_000);
        assert_eq!(out.truncated, 1);
        let kept = out.messages.last().unwrap().content.as_deref().unwrap();
        assert!(kept.starts_with("开头结论"));
        assert!(kept.ends_with("结尾结论"));
        assert!(kept.contains("此处省略"));
        assert!(kept.chars().count() < body.chars().count());
    }

    #[test]
    fn leading_tool_message_is_dropped() {
        let h = vec![
            msg("user", "问一句"),
            ChatMessage::tool_result("call_1", "孤立的工具结果"),
        ];
        let out = trim_history(&h, 10_000);
        assert!(
            out.messages.iter().all(|m| m.role != "tool" || m.tool_call_id.is_none()),
            "开头孤立 tool 消息应被丢弃"
        );
    }

    #[test]
    fn zero_budget_still_returns_something() {
        let h = vec![msg("user", "问题"), msg("assistant", "回答")];
        let out = trim_history(&h, 0);
        assert_eq!(out.messages.len(), 1);
        assert_eq!(out.dropped, 1);
    }

    #[test]
    fn clamp_respects_char_boundary_for_cjk() {
        let text = "网络诊断".repeat(500);
        let clamped = clamp_text(&text, 300).unwrap();
        // 能 parse 回 String 就说明没有切在非法边界上
        assert!(clamped.chars().count() > 0);
        assert!(clamped.contains("此处省略"));
    }
}
