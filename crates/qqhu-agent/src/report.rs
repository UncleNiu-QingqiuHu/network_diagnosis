//! 把一段会话导出成可交付的 Markdown 报告。
//!
//! 面向的真实场景：运维在 Agent 里排查完一个问题，需要把结论贴进工单、
//! 发给供应商，或者存档待复查。所以报告要能独立看懂 —— 结论在最前，
//! 过程可追溯（谁问的、调了什么工具、结果如何），末尾说明哪些是实测、哪些是推断。
//!
//! 渲染是纯函数：不读磁盘、不读配置，环境信息由调用方传入，便于单测。

use crate::session::{Session, StoredMessage};
use crate::AgentError;
use chrono::{DateTime, Local, Utc};
use std::path::{Path, PathBuf};

/// 报告抬头需要、但会话文件里没有的环境信息。
#[derive(Debug, Clone)]
pub struct ReportContext {
    /// 会话所用模型（会话里没记录时由调用方填当前激活模型）
    pub model: String,
    pub version: String,
    pub hostname: String,
    pub os: String,
    pub report_dir: PathBuf,
}

/// 工具的内部名 → 中文名。报告是给人看的，不暴露 `subnet_calc` 这种标识。
const TOOL_ZH: &[(&str, &str)] = &[
    ("subnet_calc", "子网计算"),
    ("ping_host", "Ping 探测"),
    ("trace_route", "路由追踪"),
    ("check_ssl", "证书检查"),
    ("run_command", "系统命令"),
];

fn tool_label(name: &str) -> &str {
    TOOL_ZH
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| *v)
        .unwrap_or(name)
}

/// 表格单元格转义：竖线会撑破列，换行会把行拆开。
fn cell(s: &str) -> String {
    s.replace('|', "\\|")
        .replace(['\r', '\n'], " ")
        .trim()
        .to_string()
}

fn short(s: &str, max: usize) -> String {
    let one_line = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() <= max {
        return one_line;
    }
    let mut out: String = one_line.chars().take(max).collect();
    out.push('…');
    out
}

fn local(t: &DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string()
}

/// 工具调用表。结论与过程都要用，抽成一处避免两套写法。
fn tool_table(md: &mut String, tools: &[crate::session::StoredTool]) {
    md.push_str("| 工具 | 结果 | 摘要 |\n|---|---|---|\n");
    for t in tools {
        let status = if t.status == "ok" { "成功" } else { "失败" };
        md.push_str(&format!(
            "| {}（{}） | {} | {} |\n",
            tool_label(&t.name),
            t.name,
            status,
            cell(&short(&t.preview, 120))
        ));
    }
    md.push('\n');
}

/// 会话里最后一条助手回复作为「结论」，其余消息按顺序构成「排查过程」。
fn split_conclusion(messages: &[StoredMessage]) -> (Option<&StoredMessage>, Vec<&StoredMessage>) {
    match messages.iter().rposition(|m| m.role == "assistant") {
        Some(idx) => (
            Some(&messages[idx]),
            messages
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != idx)
                .map(|(_, m)| m)
                .collect(),
        ),
        None => (None, messages.iter().collect()),
    }
}

/// 渲染报告正文。
pub fn render(session: &Session, ctx: &ReportContext, exported_at: DateTime<Utc>) -> String {
    let (conclusion, rest) = split_conclusion(&session.messages);
    let mut md = String::new();

    md.push_str(&format!("# AI 诊断记录 · {}\n\n", session.title));

    match conclusion {
        Some(m) if !m.text.trim().is_empty() => {
            md.push_str(&format!("> 结论：{}\n\n", short(&m.text, 90)));
        }
        _ => {
            md.push_str("> 结论：（本次会话没有助手回复，仅有提问记录）\n\n");
        }
    }

    md.push_str("## 会话信息\n\n");
    md.push_str("| 项 | 值 |\n|---|---|\n");
    let row = |md: &mut String, k: &str, v: &str| {
        md.push_str(&format!("| {} | {} |\n", k, cell(v)));
    };
    row(&mut md, "会话 ID", &session.id);
    row(&mut md, "创建时间", &local(&session.created_at));
    row(&mut md, "最后更新", &local(&session.updated_at));
    row(&mut md, "消息数", &session.messages.len().to_string());
    row(&mut md, "所用模型", &ctx.model);
    row(&mut md, "程序版本", &ctx.version);
    row(&mut md, "执行主机", &ctx.hostname);
    row(&mut md, "操作系统", &ctx.os);
    row(&mut md, "报告目录", &ctx.report_dir.to_string_lossy());
    md.push('\n');

    // 问题必须单独成节：报告的读者要知道「在查什么」，
    // 只给结论不给问题，写出来就没法独立看懂。
    md.push_str("## 问题\n\n");
    match session.messages.iter().rev().find(|m| m.role == "user") {
        Some(q) if !q.text.trim().is_empty() => {
            md.push_str(q.text.trim());
            md.push_str("\n\n");
        }
        _ => md.push_str("（会话中没有提问记录）\n\n"),
    }

    md.push_str("## 结论与建议\n\n");
    match conclusion {
        Some(m) if !m.text.trim().is_empty() => {
            md.push_str(m.text.trim());
            md.push_str("\n\n");
            // 结论往往正是靠工具实测得出的，这些记录不能因为「在结论里」
            // 就丢掉，否则报告失去可追溯性
            if !m.tools.is_empty() {
                md.push_str("**结论所依据的工具调用**\n\n");
                tool_table(&mut md, &m.tools);
            }
        }
        _ => {
            md.push_str("（没有助手回复可引用）\n\n");
        }
    }

    // 一问一答时「过程」只剩用户那句提问，没有信息量；
    // 有中间讨论才值得单列一节，否则整节省略。
    let has_dialog = rest.iter().any(|m| m.role == "assistant");
    if has_dialog {
        md.push_str("## 排查过程\n\n");
        for (i, m) in rest.iter().enumerate() {
            let who = if m.role == "user" { "用户" } else { "助手" };
            md.push_str(&format!("### {}. {}\n\n", i + 1, who));
            let text = m.text.trim();
            md.push_str(if text.is_empty() { "（空）" } else { text });
            md.push_str("\n\n");

            if !m.tools.is_empty() {
                md.push_str("**工具调用**\n\n");
                tool_table(&mut md, &m.tools);
            }
        }
    }

    md.push_str("## 说明\n\n");
    md.push_str(&format!(
        "- 本报告由「青丘湖网络工作台」AI Agent 会话导出，导出时间 {}。\n",
        local(&exported_at)
    ));
    md.push_str("- 工具调用记录中的数值来自本机实测；未标注来源的分析属于模型推断，采纳前建议复核。\n");
    md.push_str("- 会话 ID 可用于在应用内定位原始对话；本次导出不包含模型思考过程。\n");

    md
}

/// 渲染并落盘到 `<base>/<session_id>/report.md`，返回报告路径。
pub fn export(
    session: &Session,
    ctx: &ReportContext,
    base: &Path,
) -> Result<PathBuf, AgentError> {
    if session.id.is_empty() {
        return Err(AgentError::Config("会话 id 为空，无法导出。".into()));
    }
    let dir = base.join(&session.id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| AgentError::Config(format!("创建报告目录失败：{e}")))?;

    let mut ctx = ctx.clone();
    ctx.report_dir = dir.clone();

    let markdown = render(session, &ctx, Utc::now());
    let path = dir.join("report.md");
    std::fs::write(&path, markdown)
        .map_err(|e| AgentError::Config(format!("写入报告失败：{e}")))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::StoredTool;

    fn ctx() -> ReportContext {
        ReportContext {
            model: "DeepSeek V3（deepseek-chat）".into(),
            version: "4.0.0-alpha.14".into(),
            hostname: "DEVOPS".into(),
            os: "Windows x86_64".into(),
            report_dir: PathBuf::from("reports/agent/x"),
        }
    }

    fn msg(role: &str, text: &str) -> StoredMessage {
        StoredMessage {
            role: role.into(),
            text: text.into(),
            tools: Vec::new(),
            at: Utc::now(),
        }
    }

    fn session(messages: Vec<StoredMessage>) -> Session {
        let mut s = Session::empty("20261109150507-abc123");
        s.title = "三楼交换机丢包排查".into();
        s.messages = messages;
        s
    }

    #[test]
    fn last_assistant_becomes_conclusion_and_is_not_repeated() {
        let s = session(vec![
            msg("user", "三楼监控掉线"),
            msg("assistant", "先查网关"),
            msg("user", "网关正常"),
            msg("assistant", "那就是下联线路问题，结论：更换模块。"),
        ]);
        let md = render(&s, &ctx(), Utc::now());

        assert!(md.starts_with("# AI 诊断记录 · 三楼交换机丢包排查"));
        // 结论区引用最后一条
        assert!(md.contains("> 结论：那就是下联线路问题"));
        // 引用行里必然出现结论原文，判断「有没有重复」要看过程段
        let process = md.split("## 排查过程").nth(1).expect("应有过程段");
        assert!(
            !process.contains("那就是下联线路问题"),
            "结论不应出现在排查过程里"
        );
        // 前面的讨论保留在过程里
        assert!(md.contains("先查网关"));
        assert!(md.contains("网关正常"));
        assert!(md.contains("## 排查过程"));
        // 问题节取最后一条提问
        assert!(md.contains("## 问题"));
    }

    #[test]
    fn tool_calls_render_as_table_with_chinese_label() {
        let mut a = msg("assistant", "算一下");
        a.tools = vec![
            StoredTool {
                name: "subnet_calc".into(),
                status: "ok".into(),
                preview: "可用主机 1022 个".into(),
            },
            StoredTool {
                name: "run_command".into(),
                status: "error".into(),
                preview: "用户拒绝执行".into(),
            },
            StoredTool {
                name: "unknown_tool".into(),
                status: "ok".into(),
                preview: String::new(),
            },
        ];
        let s = session(vec![msg("user", "10.20.30.40/22"), a, msg("assistant", "结论在此")]);
        let md = render(&s, &ctx(), Utc::now());

        assert!(md.contains("| 子网计算（subnet_calc） | 成功 | 可用主机 1022 个 |"));
        assert!(md.contains("| 系统命令（run_command） | 失败 | 用户拒绝执行 |"));
        // 未知工具回落到原名，不能丢
        assert!(md.contains("unknown_tool"));
    }

    #[test]
    fn pipes_and_newlines_do_not_break_tables() {
        let mut a = msg("assistant", "结论");
        a.tools = vec![StoredTool {
            name: "ping_host".into(),
            status: "ok".into(),
            preview: "a|b\n第二行".into(),
        }];
        let s = session(vec![msg("user", "ping"), a]);
        let md = render(&s, &ctx(), Utc::now());

        // 单元格里不能出现裸竖线和换行
        let line = md
            .lines()
            .find(|l| l.contains("Ping 探测"))
            .expect("应有工具行");
        assert!(line.contains("a\\|b"), "竖线需转义：{line}");
        assert!(line.contains("第二行"), "换行应被压平在同一行：{line}");
        assert!(line.trim_end().ends_with('|'));
    }

    #[test]
    fn conclusion_keeps_its_own_tool_records() {
        let mut a = msg("assistant", "结论：1022 个主机");
        a.tools = vec![StoredTool {
            name: "subnet_calc".into(),
            status: "ok".into(),
            preview: "可用主机 1022 个".into(),
        }];
        let s = session(vec![msg("user", "算一下"), a]);
        let md = render(&s, &ctx(), Utc::now());

        assert!(md.contains("结论所依据的工具调用"));
        assert!(md.contains("| 子网计算（subnet_calc） | 成功 |"));
        // 一问一答不输出过程节，但问题必须在
        assert!(!md.contains("## 排查过程"));
        assert!(md.contains("## 问题"));
        assert!(md.contains("算一下"));
    }

    #[test]
    fn session_without_reply_still_renders() {
        let s = session(vec![msg("user", "只问了一句")]);
        let md = render(&s, &ctx(), Utc::now());
        assert!(md.contains("没有助手回复"));
        assert!(md.contains("会话 ID"));
        // 问题独立成节：没有过程也不能丢上下文
        assert!(md.contains("## 问题"));
        assert!(md.contains("只问了一句"));
        // 没有对话过程就别硬撑一节空壳
        assert!(!md.contains("## 排查过程"));
    }

    #[test]
    fn empty_session_does_not_panic() {
        let s = session(vec![]);
        let md = render(&s, &ctx(), Utc::now());
        assert!(md.contains("# AI 诊断记录"));
        assert!(md.contains("没有助手回复"));
        assert!(md.contains("会话中没有提问记录"));
        assert!(!md.contains("## 排查过程"));
    }

    #[test]
    fn long_conclusion_is_shortened_in_quote_only() {
        let long = "很长的结论".repeat(100);
        let s = session(vec![msg("user", "q"), msg("assistant", &long)]);
        let md = render(&s, &ctx(), Utc::now());

        let quote = md
            .lines()
            .find(|l| l.starts_with("> 结论："))
            .expect("应有结论行");
        assert!(quote.ends_with('…'), "摘要应截断");
        // 正文里保留全文
        assert!(md.contains(&long));
    }

    #[test]
    fn export_writes_file_under_session_dir() {
        let base = std::env::temp_dir().join(format!("qqhu-agent-report-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let s = session(vec![msg("user", "q"), msg("assistant", "结论")]);

        let path = export(&s, &ctx(), &base).unwrap();
        assert!(path.exists());
        assert!(path.ends_with("report.md"));
        assert!(path.parent().unwrap().ends_with(&s.id));

        let text = std::fs::read_to_string(&path).unwrap();
        // 报告目录要写成实际落盘目录，而不是调用方传进来的旧值
        assert!(text.contains(&base.join(&s.id).to_string_lossy().to_string()));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn export_rejects_empty_id() {
        let mut s = session(vec![]);
        s.id = String::new();
        let base = std::env::temp_dir().join("qqhu-agent-report-bad");
        assert!(export(&s, &ctx(), &base).is_err());
    }
}
