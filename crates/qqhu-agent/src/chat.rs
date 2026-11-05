//! OpenAI 兼容的流式对话客户端。
//!
//! 只做一件事：把 `POST {base}/chat/completions` 的 SSE 流解析成
//! 「文本增量 + 工具调用」。协议细节集中在这里，上层不需要关心 transporter。
//!
//! 调试这类代码最怕「攒完再解析」：真实分片会把一行 JSON 从中间切开，
//! 所以必须按字节流缓冲、按换行切行，[`StreamAccumulator`] 的单测就是锁这个。

use crate::config::ModelConfig;
use crate::AgentError;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type", default = "default_type")]
    pub kind: String,
    pub function: FunctionCall,
}

fn default_type() -> String {
    "function".to_string()
}

/// 一条对话消息。字段为空时不序列化，避免给服务端塞无关字段。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChatMessage {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    pub fn system(text: impl Into<String>) -> Self {
        Self {
            role: "system".into(),
            content: Some(text.into()),
            ..Default::default()
        }
    }

    pub fn user(text: impl Into<String>) -> Self {
        Self {
            role: "user".into(),
            content: Some(text.into()),
            ..Default::default()
        }
    }

    pub fn assistant(text: impl Into<String>) -> Self {
        Self {
            role: "assistant".into(),
            content: Some(text.into()),
            ..Default::default()
        }
    }

    pub fn tool_result(tool_call_id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            role: "tool".into(),
            content: Some(text.into()),
            tool_call_id: Some(tool_call_id.into()),
            ..Default::default()
        }
    }

    /// 带工具调用的 assistant 消息（下一轮要原样回传给服务端）。
    pub fn assistant_with_tools(text: Option<String>, calls: Vec<ToolCall>) -> Self {
        Self {
            role: "assistant".into(),
            content: text.filter(|t| !t.is_empty()),
            tool_calls: calls,
            tool_call_id: None,
        }
    }
}

/// 一轮模型输出的结果。
#[derive(Debug, Default)]
pub struct TurnResult {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub finish_reason: Option<String>,
}

/// SSE 增量累加器（纯逻辑，可单测）。
#[derive(Default)]
pub struct StreamAccumulator {
    pub content: String,
    pub finish_reason: Option<String>,
    /// 按 index 归并的流式工具调用
    calls: Vec<PartialCall>,
}

#[derive(Default, Clone)]
struct PartialCall {
    id: String,
    name: String,
    arguments: String,
}

impl StreamAccumulator {
    /// 处理一条 `data:` 负载，返回本次新增的文本增量（若有）。
    pub fn apply(&mut self, data: &str) -> Result<Option<String>, AgentError> {
        let value: serde_json::Value = serde_json::from_str(data)
            .map_err(|e| AgentError::Api(format!("模型返回了无法解析的数据块：{e}")))?;

        // 部分服务在流里直接塞错误对象
        if let Some(err) = value.get("error") {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("模型服务返回错误");
            return Err(AgentError::Api(msg.to_string()));
        }

        let Some(choice) = value
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
        else {
            return Ok(None);
        };

        if let Some(reason) = choice.get("finish_reason").and_then(|r| r.as_str()) {
            self.finish_reason = Some(reason.to_string());
        }

        let Some(delta) = choice.get("delta") else {
            return Ok(None);
        };

        // 工具调用：按 index 累积，id/name 只在第一片出现，arguments 分多片
        if let Some(calls) = delta.get("tool_calls").and_then(|t| t.as_array()) {
            for call in calls {
                let index = call.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                while self.calls.len() <= index {
                    self.calls.push(PartialCall::default());
                }
                let slot = &mut self.calls[index];
                if let Some(id) = call.get("id").and_then(|v| v.as_str()) {
                    if !id.is_empty() {
                        slot.id = id.to_string();
                    }
                }
                if let Some(func) = call.get("function") {
                    if let Some(name) = func.get("name").and_then(|v| v.as_str()) {
                        slot.name.push_str(name);
                    }
                    if let Some(args) = func.get("arguments").and_then(|v| v.as_str()) {
                        slot.arguments.push_str(args);
                    }
                }
            }
        }

        let text = delta
            .get("content")
            .and_then(|c| c.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        if let Some(t) = &text {
            self.content.push_str(t);
        }
        Ok(text)
    }

    /// 归并成最终结果。
    pub fn finish(self) -> TurnResult {
        let mut calls: Vec<ToolCall> = self
            .calls
            .into_iter()
            .filter(|c| !c.name.is_empty())
            .map(|c| ToolCall {
                id: if c.id.is_empty() {
                    format!("call_{}", uuid::Uuid::new_v4().simple())
                } else {
                    c.id
                },
                kind: "function".to_string(),
                function: FunctionCall {
                    name: c.name,
                    arguments: if c.arguments.trim().is_empty() {
                        "{}".to_string()
                    } else {
                        c.arguments
                    },
                },
            })
            .collect();
        // 极少数服务不下发 id，按顺序补
        for (i, call) in calls.iter_mut().enumerate() {
            if call.id.is_empty() {
                call.id = format!("call_{i}");
            }
        }
        TurnResult {
            content: self.content,
            tool_calls: calls,
            finish_reason: self.finish_reason,
        }
    }
}

/// 发一次流式请求。`on_delta` 每收到一段文本就回调一次（用于界面逐字显示）。
pub async fn stream_completion(
    client: &reqwest::Client,
    cfg: &ModelConfig,
    api_key: &str,
    messages: &[ChatMessage],
    tools: &[serde_json::Value],
    cancel: &AtomicBool,
    on_delta: &(dyn Fn(&str) + Send + Sync),
) -> Result<TurnResult, AgentError> {
    if api_key.trim().is_empty() {
        return Err(AgentError::Config(
            "该模型还没有配置 API Key，请先在设置里填写。".into(),
        ));
    }

    let mut body = serde_json::json!({
        "model": cfg.model,
        "messages": messages,
        "stream": true,
        "max_tokens": cfg.max_tokens,
        "temperature": cfg.temperature,
    });
    if !tools.is_empty() {
        body["tools"] = serde_json::Value::Array(tools.to_vec());
        body["tool_choice"] = serde_json::Value::String("auto".into());
    }

    let resp = client
        .post(cfg.chat_url())
        .bearer_auth(api_key)
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .json(&body)
        .send()
        .await
        .map_err(|e| AgentError::Http(format!("连接模型服务失败：{e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(map_http_error(status.as_u16(), &text));
    }

    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut acc = StreamAccumulator::default();

    while let Some(chunk) = stream.next().await {
        if cancel.load(Ordering::Relaxed) {
            return Err(AgentError::Cancelled);
        }
        let bytes = chunk.map_err(|e| AgentError::Http(format!("读取数据流失败：{e}")))?;
        buf.push_str(&String::from_utf8_lossy(&bytes));

        // 按行切；最后一段可能是不完整的行，留在缓冲里等下一块
        while let Some(pos) = buf.find('\n') {
            let line = buf[..pos].trim_end_matches('\r').to_string();
            buf.drain(..=pos);
            let Some(rest) = line.strip_prefix("data:") else {
                continue; // 空行、注释行、event: 行都跳过
            };
            let data = rest.trim();
            if data.is_empty() {
                continue;
            }
            if data == "[DONE]" {
                return Ok(acc.finish());
            }
            if let Some(delta) = acc.apply(data)? {
                on_delta(&delta);
            }
        }
    }

    // 流结束但没收到 [DONE]：按已有内容收尾（部分服务就是这样）
    Ok(acc.finish())
}

/// 把 HTTP 错误翻成能直接指导操作的中文。
fn map_http_error(status: u16, body: &str) -> AgentError {
    let snippet: String = body.chars().take(300).collect();
    let hint = match status {
        401 | 403 => "（API Key 无效、已过期，或没有该模型的权限）",
        404 => "（接口地址不存在，检查 BaseURL 是否少了 /v1）",
        429 => "（触发频率限制或余额不足，稍后再试）",
        500..=599 => "（模型服务端异常，稍后再试）",
        _ => "",
    };
    AgentError::Http(format!("模型服务返回 HTTP {status}{hint}：{snippet}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_delta() {
        let mut acc = StreamAccumulator::default();
        let d = acc
            .apply(r#"{"choices":[{"delta":{"content":"你好"},"finish_reason":null}]}"#)
            .unwrap();
        assert_eq!(d.as_deref(), Some("你好"));
        assert_eq!(acc.finish().content, "你好");
    }

    #[test]
    fn accumulates_tool_call_arguments_across_chunks() {
        let mut acc = StreamAccumulator::default();
        acc.apply(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"ping_host","arguments":""}}]}}]}"#,
        )
        .unwrap();
        acc.apply(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"host\":"}}]}}]}"#,
        )
        .unwrap();
        acc.apply(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"1.1.1.1\"}"}}]}}]}"#,
        )
        .unwrap();

        let turn = acc.finish();
        assert_eq!(turn.tool_calls.len(), 1);
        assert_eq!(turn.tool_calls[0].id, "call_a");
        assert_eq!(turn.tool_calls[0].function.name, "ping_host");
        assert_eq!(turn.tool_calls[0].function.arguments, r#"{"host":"1.1.1.1"}"#);
    }

    #[test]
    fn merges_parallel_tool_calls_by_index() {
        let mut acc = StreamAccumulator::default();
        acc.apply(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"ping","arguments":"{}"}},{"index":1,"id":"b","function":{"name":"ssl","arguments":"{}"}}]}}]}"#,
        )
        .unwrap();
        let turn = acc.finish();
        assert_eq!(turn.tool_calls.len(), 2);
        assert_eq!(turn.tool_calls[1].function.name, "ssl");
    }

    #[test]
    fn empty_arguments_default_to_object() {
        let mut acc = StreamAccumulator::default();
        acc.apply(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"x","function":{"name":"f","arguments":""}}]}}]}"#,
        )
        .unwrap();
        assert_eq!(acc.finish().tool_calls[0].function.arguments, "{}");
    }

    #[test]
    fn surfaces_error_payload() {
        let mut acc = StreamAccumulator::default();
        let err = acc
            .apply(r#"{"error":{"message":"insufficient quota"}}"#)
            .unwrap_err();
        assert!(err.to_string().contains("insufficient quota"));
    }

    #[test]
    fn ignores_non_content_chunks() {
        let mut acc = StreamAccumulator::default();
        assert!(acc.apply(r#"{"choices":[]}"#).unwrap().is_none());
        assert!(acc
            .apply(r#"{"choices":[{"delta":{},"finish_reason":null}]}"#)
            .unwrap()
            .is_none());
    }

    #[test]
    fn captures_finish_reason() {
        let mut acc = StreamAccumulator::default();
        acc.apply(r#"{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#)
            .unwrap();
        assert_eq!(acc.finish().finish_reason.as_deref(), Some("tool_calls"));
    }

    #[test]
    fn http_errors_carry_actionable_hints() {
        let e = map_http_error(401, "unauthorized").to_string();
        assert!(e.contains("API Key 无效"));
        let e = map_http_error(404, "").to_string();
        assert!(e.contains("/v1"));
        let e = map_http_error(429, "rate").to_string();
        assert!(e.contains("频率限制"));
    }

    #[test]
    fn message_serialization_skips_empty_fields() {
        let m = ChatMessage::user("hi");
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["role"], "user");
        assert!(v.get("tool_calls").is_none());
        assert!(v.get("tool_call_id").is_none());

        let t = ChatMessage::tool_result("call_1", "ok");
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["role"], "tool");
        assert_eq!(v["tool_call_id"], "call_1");
    }
}
