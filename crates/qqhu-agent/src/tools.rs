//! 工具定义与命令白名单。
//!
//! 工具分两类：
//! 1. **内置诊断**：直接调用本应用已有能力（子网计算 / ping / 路由追踪 / 证书检查），
//!    结果是结构化数据，随时可用。
//! 2. **系统命令**：仅当用户显式开启后才出现在工具列表里，且只允许一组只读命令。
//!    真正的进程启动在应用层完成，这里负责「允许什么」的判定 —— 放在独立 crate
//!    里是为了能直接单测，不依赖 GUI。
//!
//! 白名单是最终防线：即使模型被诱导，也只能调到这几个只读命令。

use serde_json::{json, Value};

/// 允许执行的程序及其参数约束。
pub const ALLOWED_PROGRAMS: [&str; 7] = [
    "ping", "tracert", "nslookup", "arp", "ipconfig", "route", "netstat",
];

/// 明显不属于「只读诊断」的参数，直接拒绝。
const FORBIDDEN_FLAGS: [&str; 6] = ["-f", "/?", "-?", "-j", "-k", "-R"];

/// 构造工具列表。`allow_commands` 为假时不暴露 `run_command`，
/// 模型连「我能执行命令」都不知道，比事后拒绝更干净。
pub fn definitions(allow_commands: bool) -> Vec<Value> {
    let mut out = vec![
        json!({
            "type": "function",
            "function": {
                "name": "subnet_calc",
                "description": "计算 IPv4 子网：网络地址、广播地址、可用地址范围、容量、掩码。用户问网段划分、掩码换算、能放多少台设备时用。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip": { "type": "string", "description": "IPv4 地址，例如 192.168.60.58" },
                        "prefix_len": { "type": "integer", "description": "前缀长度 0-32，例如 24" }
                    },
                    "required": ["ip", "prefix_len"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "ping_host",
                "description": "对目标发 ICMP 探测，返回丢包率、最小/平均/最大延迟与每次结果。判断「通不通、稳不稳」时用。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "host": { "type": "string", "description": "IP 或域名" },
                        "count": { "type": "integer", "description": "探测次数，默认 5，最大 10" }
                    },
                    "required": ["host"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "trace_route",
                "description": "逐跳追踪到目标的路由路径，定位在哪一跳开始不通。需要 IPv4。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "host": { "type": "string", "description": "IP 或域名" },
                        "max_hops": { "type": "integer", "description": "最大跳数，默认 20，最大 30" }
                    },
                    "required": ["host"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "check_ssl",
                "description": "检查目标的 TLS 证书：是否受信任、有效期剩余天数、域名是否匹配、证书链与算法。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "host": { "type": "string", "description": "域名，可带端口，例如 example.com:443" },
                        "port": { "type": "integer", "description": "端口，默认 443" }
                    },
                    "required": ["host"]
                }
            }
        }),
    ];

    if allow_commands {
        out.push(json!({
            "type": "function",
            "function": {
                "name": "run_command",
                "description": "在本机执行**只读**网络诊断命令（ping / tracert / nslookup / arp / ipconfig / route print / netstat）。每次执行都需要用户确认。只在内置工具不够用时使用，例如需要查看本机网卡配置或 ARP 表。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "program": {
                            "type": "string",
                            "description": "命令名，只能是 ping、tracert、nslookup、arp、ipconfig、route、netstat 之一"
                        },
                        "args": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "参数数组，不要包含管道、重定向或分号"
                        }
                    },
                    "required": ["program", "args"]
                }
            }
        }));
    }
    out
}

/// 校验待执行的命令，返回归一化后的 (程序名, 参数)。
///
/// 拒绝的情况都要给出人话原因，因为这条错误会直接回到模型、再显示给用户。
pub fn validate_command(program: &str, args: &[String]) -> Result<(String, Vec<String>), String> {
    let program = program.trim().to_ascii_lowercase();
    if program.is_empty() {
        return Err("命令名为空。".into());
    }
    if program.contains(['/', '\\', ' ']) {
        return Err(format!("命令名不能包含路径或空格：{program}"));
    }
    if !ALLOWED_PROGRAMS.contains(&program.as_str()) {
        return Err(format!(
            "命令 `{program}` 不在允许列表内。只允许：{}。",
            ALLOWED_PROGRAMS.join(" / ")
        ));
    }
    if args.len() > 10 {
        return Err("参数过多（上限 10 个）。".into());
    }

    let mut clean: Vec<String> = Vec::with_capacity(args.len());
    for arg in args {
        let a = arg.trim();
        if a.is_empty() {
            return Err("参数不能为空字符串。".into());
        }
        if a.chars().count() > 64 {
            return Err(format!("单个参数过长：{}", a.chars().take(20).collect::<String>()));
        }
        // 直接 spawn 不经 shell，这里再拦一次是防御纵深
        if a.chars()
            .any(|c| matches!(c, '&' | '|' | ';' | '>' | '<' | '`' | '$' | '\n' | '\r' | '"' | '\''))
        {
            return Err(format!("参数包含不允许的字符：{a}"));
        }
        if a.chars().any(|c| c.is_whitespace()) {
            return Err(format!("参数不能包含空格（请拆成多个参数）：{a}"));
        }
        let lower = a.to_ascii_lowercase();
        if FORBIDDEN_FLAGS.contains(&lower.as_str()) {
            return Err(format!("参数 `{a}` 不属于只读诊断，已拒绝。"));
        }
        clean.push(a.to_string());
    }

    // 各命令的额外约束
    match program.as_str() {
        "ping" => {
            if clean.iter().any(|a| a.eq_ignore_ascii_case("-t")) {
                return Err("`ping -t` 会无限执行，请改用 -n 指定次数。".into());
            }
            if clean.is_empty() {
                return Err("ping 需要目标地址。".into());
            }
        }
        "tracert" => {
            if clean.is_empty() {
                return Err("tracert 需要目标地址。".into());
            }
        }
        "route" => {
            // 只允许 route print：增删路由会改系统状态
            if clean.first().map(|s| s.as_str()) != Some("print") {
                return Err("route 只允许 `print` 子命令。".into());
            }
        }
        "netstat" => {
            if !clean.iter().any(|a| matches!(a.as_str(), "-an" | "-rn" | "-ano")) {
                return Err("netstat 只允许 -an / -rn / -ano。".into());
            }
        }
        "ipconfig" => {
            if !clean.is_empty() && !clean.iter().all(|a| a.eq_ignore_ascii_case("/all")) {
                return Err("ipconfig 只允许不带参数或 /all。".into());
            }
        }
        _ => {}
    }
    Ok((program, clean))
}

/// 结果输出截断：模型不需要几万行，留头留尾更利于判断。
pub fn truncate_output(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let head: String = text.chars().take(max_chars / 2).collect();
    let tail: String = text
        .chars()
        .rev()
        .take(max_chars / 4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}\n…（输出过长已截断，共 {} 字符）…\n{tail}", text.chars().count())
}

/// 命令输出的一句话摘要。
///
/// 完整输出可能几十行，工具标签和报告表格里只放得下一行。优先取统计行
/// （「丢失 = 0」这类），它比开头的命令行更有信息量。
pub fn summarize_command(output: &str) -> String {
    let lines: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return "（无输出）".to_string();
    }
    if let Some(stat) = lines
        .iter()
        .find(|l| l.contains("丢失") || l.to_ascii_lowercase().contains("loss"))
    {
        return truncate_output(stat, 120);
    }
    let head: Vec<&str> = lines.iter().take(2).copied().collect();
    truncate_output(&head.join(" · "), 120)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_list_hides_commands_by_default() {
        let names = |allow| -> Vec<String> {
            definitions(allow)
                .into_iter()
                .filter_map(|t| {
                    t.pointer("/function/name")
                        .and_then(|n| n.as_str())
                        .map(str::to_string)
                })
                .collect()
        };
        let off = names(false);
        assert!(off.contains(&"ping_host".to_string()));
        assert!(!off.contains(&"run_command".to_string()));

        let on = names(true);
        assert!(on.contains(&"run_command".to_string()));
    }

    #[test]
    fn every_tool_has_description_and_schema() {
        for tool in definitions(true) {
            let f = tool.pointer("/function").unwrap();
            assert_eq!(tool["type"], "function");
            assert!(!f["name"].as_str().unwrap().is_empty());
            assert!(f["description"].as_str().unwrap().chars().count() > 10);
            assert_eq!(f["parameters"]["type"], "object");
        }
    }

    #[test]
    fn accepts_typical_readonly_commands() {
        assert!(validate_command("ping", &["-n".into(), "4".into(), "192.168.1.1".into()]).is_ok());
        assert!(validate_command("tracert", &["-h".into(), "10".into(), "1.1.1.1".into()]).is_ok());
        assert!(validate_command("route", &["print".into()]).is_ok());
        assert!(validate_command("netstat", &["-an".into()]).is_ok());
        assert!(validate_command("ipconfig", &["/all".into()]).is_ok());
        assert!(validate_command("nslookup", &["example.com".into()]).is_ok());
    }

    #[test]
    fn rejects_program_outside_allowlist() {
        assert!(validate_command("cmd", &["/c".into(), "dir".into()]).is_err());
        assert!(validate_command("powershell", &[]).is_err());
        assert!(validate_command("", &[]).is_err());
        // 路径拼接也不能绕过
        assert!(validate_command("C:/Windows/System32/ping", &[]).is_err());
    }

    #[test]
    fn rejects_state_changing_subcommands() {
        assert!(validate_command("route", &["add".into()]).is_err());
        assert!(validate_command("netstat", &["-s".into()]).is_err());
        assert!(validate_command("ipconfig", &["/release".into()]).is_err());
        assert!(validate_command("ping", &["-t".into(), "1.1.1.1".into()]).is_err());
    }

    #[test]
    fn rejects_shell_metacharacters() {
        for bad in ["1.1.1.1;dir", "a&b", "x|y", ">out.txt", "`id`", "$HOME", "a b"] {
            assert!(
                validate_command("ping", &[bad.into()]).is_err(),
                "应当拒绝：{bad}"
            );
        }
    }

    #[test]
    fn rejects_empty_and_huge_args() {
        assert!(validate_command("ping", &["".into()]).is_err());
        assert!(validate_command("ping", &["x".repeat(80)]).is_err());
        let many: Vec<String> = (0..12).map(|i| i.to_string()).collect();
        assert!(validate_command("ping", &many).is_err());
    }

    #[test]
    fn truncation_keeps_head_and_tail() {
        let text = "A".repeat(5000);
        let out = truncate_output(&text, 1000);
        assert!(out.contains("已截断"));
        assert!(out.chars().count() < 1200);
        assert!(out.starts_with('A'));
        assert!(out.ends_with('A'));
    }

    #[test]
    fn short_output_is_untouched() {
        assert_eq!(truncate_output("ok", 100), "ok");
    }
}
