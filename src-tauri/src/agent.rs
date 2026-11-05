//! AI Agent：模型配置、技能、工具调用与对话循环。
//!
//! 边界设计（这是本模块最重要的部分）：
//! 1. **角色与禁止事项写在系统提示词里**（[`qqhu_agent::prompt`]），模型知道自己该拒绝什么；
//! 2. **能力由工具白名单兜底**，即使提示词被绕过，也只能调到只读诊断；
//! 3. **命令执行默认关闭**，开启后每条命令仍需用户点确认；
//! 4. API Key 只进系统凭据管理器，配置文件里永远不出现。

use crate::paths;
use chrono::Utc;
use qqhu_agent::chat::{ChatMessage, ToolCall};
use qqhu_agent::config::{AgentConfig, AgentStore, ModelConfig};
use qqhu_agent::prompt::{self, PromptCtx};
use qqhu_agent::skills::{self, Skill, SkillCandidate};
use qqhu_agent::{secrets, tools, AgentError};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};

/// 一轮对话里最多允许几次「模型 → 工具 → 模型」的往返。
const MAX_ROUNDS: usize = 6;
/// 工具输出回填给模型前先截断。
const TOOL_OUTPUT_LIMIT: usize = 4000;
/// 等用户点确认的最长时间。
const CONFIRM_TIMEOUT_SECS: u64 = 120;
/// 单条命令的执行超时。
const COMMAND_TIMEOUT_SECS: u64 = 20;

pub const DELTA_EVENT: &str = "agent-delta";
pub const TOOL_EVENT: &str = "agent-tool";
pub const CONFIRM_EVENT: &str = "agent-confirm";

/// 运行期状态：取消开关、待确认请求、并发保护。
#[derive(Default)]
pub struct AgentState {
    cancel: Arc<AtomicBool>,
    pending: Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>,
    busy: AtomicBool,
}

impl AgentState {
    fn reset(&self) {
        self.cancel.store(false, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------- 视图

/// 返回给界面的模型视图：配置 + 是否已存 Key（不返回 Key 本身）。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelView {
    #[serde(flatten)]
    pub config: ModelConfig,
    pub has_key: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentConfigView {
    pub models: Vec<ModelView>,
    pub active_model: Option<String>,
    pub allow_commands: bool,
    pub confirm_commands: bool,
    /// 凭据存放后端（系统凭据管理器 / 本地文件）
    pub vault_backend: String,
    pub skills: Vec<Skill>,
    /// 扫描根（存在才有），让用户知道技能是从哪来的
    pub scan_roots: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatReply {
    pub content: String,
    pub rounds: usize,
    /// 是否被用户中断
    pub cancelled: bool,
}

fn store() -> AgentStore {
    AgentStore::new(paths::agent_dir())
}

fn secret_store() -> secrets::SecretStore {
    secrets::store(paths::agent_dir().join("secrets"))
}

fn config_view(cfg: &AgentConfig) -> AgentConfigView {
    let vault = secret_store();
    let models = cfg
        .models
        .iter()
        .map(|m| ModelView {
            config: m.clone(),
            has_key: vault.get(&secrets::model_key(&m.id)).ok().flatten().is_some(),
        })
        .collect();
    AgentConfigView {
        models,
        active_model: cfg.active_model.clone(),
        allow_commands: cfg.allow_commands,
        confirm_commands: cfg.confirm_commands,
        vault_backend: vault.backend().to_string(),
        skills: skills::list(&store()),
        scan_roots: skills::existing_roots(Some(store().root()))
            .into_iter()
            .map(|(p, label)| format!("{label}：{}", p.display()))
            .collect(),
    }
}

// ---------------------------------------------------------------- 配置命令

#[tauri::command]
pub fn agent_config() -> AgentConfigView {
    config_view(&store().load())
}

/// 新增或修改模型。`key` 非空时一并写入凭据管理器 ——
/// 新增模型的 id 由后端生成，前端拿不到，所以必须一次调用完成。
#[tauri::command]
pub fn agent_save_model(
    model: ModelConfig,
    key: Option<String>,
) -> Result<AgentConfigView, String> {
    let model = model.normalized()?;
    if let Some(k) = key.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
        secret_store()
            .set(&secrets::model_key(&model.id), k)
            .map_err(|e| e.to_string())?;
    }
    let st = store();
    let mut cfg = st.load();
    match cfg.models.iter_mut().find(|m| m.id == model.id) {
        Some(slot) => *slot = model,
        None => cfg.models.push(model),
    }
    cfg.normalize_active();
    st.save(&cfg)?;
    Ok(config_view(&cfg))
}

#[tauri::command]
pub fn agent_delete_model(id: String) -> Result<AgentConfigView, String> {
    let st = store();
    let mut cfg = st.load();
    cfg.models.retain(|m| m.id != id);
    cfg.normalize_active();
    st.save(&cfg)?;
    // 一并清掉凭据，别把不用的 Key 留在系统里
    let _ = secret_store().delete(&secrets::model_key(&id));
    Ok(config_view(&cfg))
}

#[tauri::command]
pub fn agent_set_key(id: String, key: String) -> Result<(), String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("API Key 不能为空。".into());
    }
    secret_store()
        .set(&secrets::model_key(&id), key)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn agent_set_active_model(id: String) -> Result<AgentConfigView, String> {
    let st = store();
    let mut cfg = st.load();
    if !cfg.models.iter().any(|m| m.id == id) {
        return Err(format!("找不到模型 {id}"));
    }
    cfg.active_model = Some(id);
    st.save(&cfg)?;
    Ok(config_view(&cfg))
}

/// 开关命令执行能力。这是「边界」的总闸，默认关闭。
#[tauri::command]
pub fn agent_set_options(
    allow_commands: bool,
    confirm_commands: bool,
) -> Result<AgentConfigView, String> {
    let st = store();
    let mut cfg = st.load();
    cfg.allow_commands = allow_commands;
    cfg.confirm_commands = confirm_commands;
    st.save(&cfg)?;
    Ok(config_view(&cfg))
}

// ---------------------------------------------------------------- 技能命令

#[tauri::command]
pub fn agent_skills() -> Vec<Skill> {
    skills::list(&store())
}

#[tauri::command]
pub fn agent_scan_skills() -> Vec<SkillCandidate> {
    let st = store();
    let imported: Vec<String> = skills::list(&st).into_iter().map(|s| s.source).collect();
    // 项目目录按当前工作目录算，开发态是仓库根，发布态是安装目录
    let project = std::env::current_dir().ok();
    skills::scan_all(project.as_deref(), &imported)
}

#[tauri::command]
pub fn agent_import_skill(path: String) -> Result<Skill, String> {
    skills::import(&store(), std::path::Path::new(&path)).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn agent_set_skill_enabled(slug: String, enabled: bool) -> Result<Skill, String> {
    skills::set_enabled(&store(), &slug, enabled).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn agent_delete_skill(slug: String) -> Result<(), String> {
    skills::delete(&store(), &slug).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- 对话

#[tauri::command]
pub fn agent_cancel(state: tauri::State<'_, AgentState>) {
    state.cancel.store(true, Ordering::Relaxed);
}

#[tauri::command]
pub fn agent_confirm(state: tauri::State<'_, AgentState>, request_id: String, approved: bool) {
    if let Ok(mut pending) = state.pending.lock() {
        if let Some(tx) = pending.remove(&request_id) {
            let _ = tx.send(approved);
        }
    }
}

/// 发一轮对话。历史由前端持有并整体传上来，后端只在本次请求内追加工具消息。
#[tauri::command]
pub async fn agent_chat(
    app: AppHandle,
    state: tauri::State<'_, AgentState>,
    messages: Vec<ChatMessage>,
    module: Option<String>,
) -> Result<ChatReply, String> {
    if state.busy.swap(true, Ordering::SeqCst) {
        return Err("上一条消息还在处理中。".into());
    }
    state.reset();
    let result = run_chat(&app, &state, messages, module).await;
    state.busy.store(false, Ordering::SeqCst);
    result.map_err(|e| e.to_string())
}

async fn run_chat(
    app: &AppHandle,
    state: &AgentState,
    history: Vec<ChatMessage>,
    module: Option<String>,
) -> Result<ChatReply, AgentError> {
    let st = store();
    let cfg = st.load();
    let model = cfg
        .active()
        .cloned()
        .ok_or_else(|| AgentError::Config("还没有选择模型，请先在设置里添加并启用一个模型。".into()))?;
    let key = secret_store()
        .get(&secrets::model_key(&model.id))
        .map_err(|e| AgentError::Config(e.to_string()))?
        .ok_or_else(|| {
            AgentError::Config(format!("模型「{}」还没有配置 API Key。", model.name))
        })?;

    // 技能正文 + 角色边界一起进系统提示词
    let skill_contents = skills::enabled_contents(&st, skills::MAX_SKILL_CHARS);
    let system = prompt::system_prompt(&PromptCtx {
        module: module.as_deref(),
        allow_commands: cfg.allow_commands,
        skills: &skill_contents,
    });

    let mut msgs = Vec::with_capacity(history.len() + 2);
    msgs.push(ChatMessage::system(system));
    msgs.extend(history.into_iter().filter(|m| m.role != "system"));

    let tool_defs = tools::definitions(cfg.allow_commands);
    let client = secrets::http_client();
    let mut spoken = String::new();

    for round in 0..MAX_ROUNDS {
        let turn = {
            let handle = app.clone();
            let cb = move |delta: &str| {
                let _ = handle.emit(DELTA_EVENT, delta);
            };
            qqhu_agent::stream_completion(
                &client,
                &model,
                &key,
                &msgs,
                &tool_defs,
                &state.cancel,
                &cb,
            )
            .await?
        };

        spoken.push_str(&turn.content);
        if turn.tool_calls.is_empty() {
            return Ok(ChatReply {
                content: spoken,
                rounds: round + 1,
                cancelled: false,
            });
        }

        // 模型要调工具：先把这条 assistant 消息原样回传，再逐个执行
        msgs.push(ChatMessage::assistant_with_tools(
            Some(turn.content).filter(|c| !c.is_empty()),
            turn.tool_calls.clone(),
        ));

        for call in &turn.tool_calls {
            if state.cancel.load(Ordering::Relaxed) {
                return Ok(ChatReply {
                    content: spoken,
                    rounds: round + 1,
                    cancelled: true,
                });
            }
            let outcome = run_tool(app, state, &cfg, call).await;
            match &outcome {
                Ok(text) => {
                    let _ = app.emit(
                        TOOL_EVENT,
                        json!({
                            "id": call.id,
                            "name": call.function.name,
                            "status": "ok",
                            "preview": tools::truncate_output(text, 400),
                        }),
                    );
                    msgs.push(ChatMessage::tool_result(
                        call.id.clone(),
                        tools::truncate_output(text, TOOL_OUTPUT_LIMIT),
                    ));
                }
                Err(e) => {
                    let _ = app.emit(
                        TOOL_EVENT,
                        json!({
                            "id": call.id,
                            "name": call.function.name,
                            "status": "error",
                            "preview": e,
                        }),
                    );
                    // 失败也要回填，让模型据此调整策略而不是重复同样的调用
                    msgs.push(ChatMessage::tool_result(
                        call.id.clone(),
                        format!("工具执行失败：{e}"),
                    ));
                }
            }
        }
    }

    Ok(ChatReply {
        content: format!(
            "{spoken}\n\n（已达到单轮工具调用上限 {MAX_ROUNDS} 次，先停在这里。可以让我继续。）"
        ),
        rounds: MAX_ROUNDS,
        cancelled: false,
    })
}

// ---------------------------------------------------------------- 工具执行

async fn run_tool(
    app: &AppHandle,
    state: &AgentState,
    cfg: &AgentConfig,
    call: &ToolCall,
) -> Result<String, String> {
    let args: Value = serde_json::from_str(&call.function.arguments)
        .map_err(|e| format!("参数不是合法 JSON：{e}"))?;

    // 白名单二次校验：运行时不依赖提示词，只看这里
    let known = ["subnet_calc", "ping_host", "trace_route", "check_ssl"];
    let is_command = call.function.name == "run_command";
    if !known.contains(&call.function.name.as_str()) && !(is_command && cfg.allow_commands) {
        return Err(format!("工具 `{}` 未启用。", call.function.name));
    }

    match call.function.name.as_str() {
        "subnet_calc" => {
            let ip = args
                .get("ip")
                .and_then(|v| v.as_str())
                .ok_or("缺少 ip 参数")?;
            let prefix = args
                .get("prefix_len")
                .and_then(|v| v.as_u64())
                .ok_or("缺少 prefix_len 参数")? as u8;
            let r = qqhu_core::calc_subnet(ip, Some(prefix), None).map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&r).unwrap_or_default())
        }
        "ping_host" => {
            let host = args
                .get("host")
                .and_then(|v| v.as_str())
                .ok_or("缺少 host 参数")?;
            let count = args
                .get("count")
                .and_then(|v| v.as_u64())
                .unwrap_or(5)
                .clamp(1, 10) as u32;
            let opts = qqhu_probe::PingOptions {
                count,
                ..Default::default()
            };
            let stats = qqhu_probe::ping_host(host, &opts)
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&stats).unwrap_or_default())
        }
        "trace_route" => {
            let host = args
                .get("host")
                .and_then(|v| v.as_str())
                .ok_or("缺少 host 参数")?;
            let hops = args
                .get("max_hops")
                .and_then(|v| v.as_u64())
                .unwrap_or(20)
                .clamp(1, 30) as u8;
            let opts = qqhu_probe::TraceOptions {
                max_hops: hops,
                ..Default::default()
            };
            let report = qqhu_probe::trace_route(host, &opts, |_| {})
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&report).unwrap_or_default())
        }
        "check_ssl" => {
            let host = args
                .get("host")
                .and_then(|v| v.as_str())
                .ok_or("缺少 host 参数")?;
            let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(443) as u16;
            let target = if host.contains(':') || port == 443 {
                host.to_string()
            } else {
                format!("{host}:{port}")
            };
            let report = qqhu_probe::check_certificate(&target, Default::default())
                .await
                .map_err(|e| e)?;
            Ok(serde_json::to_string_pretty(&report).unwrap_or_default())
        }
        "run_command" => run_command(app, state, cfg, &args).await,
        other => Err(format!("未知工具：{other}")),
    }
}

/// 执行白名单内的只读命令。先过白名单，再要用户确认，最后才 spawn。
async fn run_command(
    app: &AppHandle,
    state: &AgentState,
    cfg: &AgentConfig,
    args: &Value,
) -> Result<String, String> {
    if !cfg.allow_commands {
        return Err("命令执行未开启，无法执行系统命令。".into());
    }
    let program = args
        .get("program")
        .and_then(|v| v.as_str())
        .ok_or("缺少 program 参数")?;
    let raw_args: Vec<String> = args
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let (program, cmd_args) = tools::validate_command(program, &raw_args)?;

    if cfg.confirm_commands {
        let request_id = format!("cmd-{}", uuid::Uuid::new_v4().simple());
        let (tx, mut rx) = tokio::sync::oneshot::channel::<bool>();
        if let Ok(mut pending) = state.pending.lock() {
            pending.insert(request_id.clone(), tx);
        }
        let _ = app.emit(
            CONFIRM_EVENT,
            json!({ "id": request_id, "program": program, "args": cmd_args }),
        );

        // 等待期间必须同时盯住取消信号：只等超时的话，用户点「停止」
        // 或刷新页面后，这次对话会一直占着 busy 到 120 秒。
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(CONFIRM_TIMEOUT_SECS);
        let approved = loop {
            tokio::select! {
                r = &mut rx => break matches!(r, Ok(true)),
                _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => {
                    if state.cancel.load(Ordering::Relaxed) || std::time::Instant::now() >= deadline {
                        break false;
                    }
                }
            }
        };
        if !approved {
            if let Ok(mut pending) = state.pending.lock() {
                pending.remove(&request_id);
            }
            return Err("用户拒绝执行该命令。".into());
        }
    }

    run_process(&program, &cmd_args).await
}

async fn run_process(program: &str, args: &[String]) -> Result<String, String> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    // Windows 下不要弹控制台窗口
    #[cfg(windows)]
    {
        #[allow(unused_imports)]
        use std::os::windows::process::CommandExt;
        #[allow(unused_unsafe)]
        unsafe {
            cmd.creation_flags(0x0800_0000);
        }
    }

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(COMMAND_TIMEOUT_SECS),
        cmd.output(),
    )
    .await
    .map_err(|_| format!("命令执行超时（{COMMAND_TIMEOUT_SECS} 秒）。"))?
    .map_err(|e| format!("启动命令失败：{e}"))?;

    // Windows 控制台程序默认是 ANSI 代码页，这里按本地编码解码更接近用户看到的
    let stdout = decode_output(&output.stdout);
    let stderr = decode_output(&output.stderr);
    let mut text = String::new();
    if !stdout.trim().is_empty() {
        text.push_str(&stdout);
    }
    if !stderr.trim().is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str("[stderr]\n");
        text.push_str(&stderr);
    }
    if text.trim().is_empty() {
        text = format!("（命令无输出，退出码 {}）", output.status.code().unwrap_or(-1));
    }
    Ok(text)
}

/// 优先按 UTF-8 解码，失败再按 GBK 兼容（中文 Windows 的命令输出常是 GBK）。
fn decode_output(bytes: &[u8]) -> String {
    match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(_) => {
            // 没有引入 encoding 库：GBK 里常用汉字用 lossy 会变「?」，
            // 但至少不会让整段输出丢掉；后续如确有需要再引入 encoding_rs。
            String::from_utf8_lossy(bytes).to_string()
        }
    }
}

/// 供「关于」页或调试用的简单状态。
#[tauri::command]
pub fn agent_status() -> Value {
    let cfg = store().load();
    json!({
        "models": cfg.models.len(),
        "active": cfg.active_model,
        "allowCommands": cfg.allow_commands,
        "skills": skills::list(&store()).len(),
        "checkedAt": Utc::now().to_rfc3339(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_prefers_utf8() {
        assert_eq!(decode_output("中文".as_bytes()), "中文");
    }

    #[test]
    fn decode_never_panics_on_invalid_bytes() {
        let raw = [0xff, 0xfe, 0x41];
        assert!(!decode_output(&raw).is_empty());
    }
}
