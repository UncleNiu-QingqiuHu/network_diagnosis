//! Tauri IPC 契约。
//!
//! 约定：所有命令的出入参都走 `serde(rename_all = "camelCase")`，
//! 与 `src/lib/types.ts` 一一对应。前端不硬编码模块清单，
//! 而是由 [`app_info`] 返回，平台差异在这里统一收敛。

use qqhu_core::{calc_from_cidr_combo, calc_subnet, subdivide_ipv4_equal_children, SubnetCalcResult};
use qqhu_sys::{host, CapabilitySet, CapabilityLevel, PlatformKind};
use serde::Serialize;

pub const APP_NAME: &str = "青丘湖网络工作台";
pub const APP_NAME_EN: &str = "Qingqiuhu Network Workbench";
pub const AUTHOR_NAME: &str = "Mr. Z";
pub const AUTHOR_EMAIL: &str = "mr.zed@qq.com";
pub const AUTHOR_QQ: &str = "40061980";
pub const AUTHOR_QQ_GROUP: &str = "292621190";
pub const WEBSITE_URL: &str = "https://www.qingqiuhu.net";
pub const REPO_URL: &str = "https://github.com/UncleNiu-QingqiuHu/network_diagnosis";
pub const COMMUNITY_URL: &str = "https://www.pheks.com/community/";
pub const COPYRIGHT: &str = "Copyright © 2025-2026 Mr. Z";
pub const LICENSE_NAME: &str = "MIT License";

/// 许可全文在编译期嵌入，运行期不依赖外部文件（避免打包漏带）。
pub const LICENSE_TEXT: &str = include_str!("../../LICENSE");

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleInfo {
    pub key: String,
    pub label: String,
    /// 侧栏分组：core / net / tool
    pub group: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    pub platform: PlatformKind,
    pub platform_display: String,
    pub hostname: String,
    pub os_summary: String,
    pub elevated: bool,
    pub capabilities: CapabilitySet,
    pub modules: Vec<ModuleInfo>,
}

fn module(key: &str, label: &str, group: &str) -> ModuleInfo {
    ModuleInfo {
        key: key.into(),
        label: label.into(),
        group: group.into(),
    }
}

/// 当前构建可用的模块清单。
///
/// v0.1 只登记已排期的 5 个模块（AI Agent 是常驻右栏，不占导航位）。
/// 后续每实现一个功能，在这里追加一行即可，前端自动出现。
fn available_modules(caps: &CapabilitySet) -> Vec<ModuleInfo> {
    let mut out = Vec::new();

    let push_if = |out: &mut Vec<ModuleInfo>, level: CapabilityLevel, key: &str, label: &str, group: &str| {
        if level.is_usable() {
            out.push(module(key, label, group));
        }
    };

    push_if(&mut out, caps.network_probe, "network", "网络诊断", "core");
    push_if(&mut out, caps.subnet, "subnet", "子网计算", "core");
    push_if(&mut out, caps.ip_scan, "ipScan", "IP 扫描", "net");
    push_if(&mut out, caps.mac_scan, "macScan", "MAC 扫描", "net");
    push_if(&mut out, caps.ssl_cert, "sslCert", "SSL 证书", "tool");

    // 关于与许可为纯信息页，与平台能力无关，恒定可用。
    out.push(module("about", "关于", "info"));
    out.push(module("license", "许可", "info"));

    out
}

/// 「关于」页所需的静态信息 + 运行环境快照。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AboutInfo {
    pub name: String,
    pub name_en: String,
    pub version: String,
    pub platform_display: String,
    pub hostname: String,
    pub os_summary: String,
    pub elevated: bool,
    pub author: String,
    pub email: String,
    pub qq: String,
    pub qq_group: String,
    pub website: String,
    pub repository: String,
    pub community: String,
    pub copyright: String,
    pub license: String,
}

#[tauri::command]
pub fn about_info() -> AboutInfo {
    let h = host();
    AboutInfo {
        name: APP_NAME.into(),
        name_en: APP_NAME_EN.into(),
        version: qqhu_core::APP_VERSION.into(),
        platform_display: h.kind().display().into(),
        hostname: h.hostname(),
        os_summary: h.os_summary(),
        elevated: h.is_elevated(),
        author: AUTHOR_NAME.into(),
        email: AUTHOR_EMAIL.into(),
        qq: AUTHOR_QQ.into(),
        qq_group: AUTHOR_QQ_GROUP.into(),
        website: WEBSITE_URL.into(),
        repository: REPO_URL.into(),
        community: COMMUNITY_URL.into(),
        copyright: COPYRIGHT.into(),
        license: LICENSE_NAME.into(),
    }
}

#[tauri::command]
pub fn license_text() -> &'static str {
    LICENSE_TEXT
}

pub fn build_app_info() -> AppInfo {
    let h = host();
    let caps = h.capabilities();
    AppInfo {
        version: qqhu_core::APP_VERSION.to_string(),
        platform: h.kind(),
        platform_display: h.kind().display().to_string(),
        hostname: h.hostname(),
        os_summary: h.os_summary(),
        elevated: h.is_elevated(),
        modules: available_modules(&caps),
        capabilities: caps,
    }
}

#[tauri::command]
pub fn app_info() -> AppInfo {
    build_app_info()
}

#[tauri::command]
pub fn subnet_calc(
    ip: String,
    prefix: Option<u8>,
    netmask: Option<String>,
) -> Result<SubnetCalcResult, String> {
    calc_subnet(&ip, prefix, netmask.as_deref()).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn subnet_from_cidr(combo: String) -> Result<SubnetCalcResult, String> {
    calc_from_cidr_combo(&combo).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn subnet_subdivide(parent: String, child_prefix: u8, max_list: usize) -> Result<String, String> {
    subdivide_ipv4_equal_children(&parent, child_prefix, max_list).map_err(|e| e.to_string())
}

/// AI Agent 通道。
///
/// 骨架阶段先把 IPC 打通、错误路径跑通；真正的 LLM 流式调用在 M4 接入
/// （复用旧版 OpenAI 兼容协议 + tool calling）。
#[tauri::command]
pub fn ai_chat(_message: String) -> Result<String, String> {
    Err("AI 通道尚未接入模型（计划 M4 实现，复用旧版 OpenAI 兼容协议）。".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modules_follow_capabilities() {
        let info = build_app_info();
        let keys: Vec<&str> = info.modules.iter().map(|m| m.key.as_str()).collect();
        assert!(keys.contains(&"subnet"), "子网计算必须始终可用");
        assert!(keys.contains(&"about"), "关于页恒定可用");
        assert!(keys.contains(&"license"), "许可页恒定可用");
        assert!(!keys.contains(&"aiChat"), "AI 是常驻侧栏，不应出现在导航");
    }

    #[test]
    fn license_text_is_embedded() {
        assert!(LICENSE_TEXT.contains("MIT License"));
        assert!(LICENSE_TEXT.contains("Mr. Z"));
        assert!(!LICENSE_TEXT.contains("[year]"), "许可占位符必须已替换");
    }

    #[test]
    fn app_info_serializes_camel_case() {
        let json = serde_json::to_string(&build_app_info()).unwrap();
        assert!(json.contains("\"platformDisplay\""));
        assert!(json.contains("\"osSummary\""));
    }
}
