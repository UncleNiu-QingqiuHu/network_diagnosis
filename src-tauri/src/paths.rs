//! 可写目录解析。
//!
//! 开发态落在仓库根的 `reports/`，发布态落在可执行文件同级，
//! 与旧版 Python 实现的便携式约定保持一致。
//!
//! TODO(跨平台): macOS 的 .app 包内部只读、Linux AppImage 为只读挂载，
//! 正式支持这两个平台时需改为 Application Support / XDG 目录。

use std::path::PathBuf;

#[cfg(debug_assertions)]
fn install_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/src-tauri
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(not(debug_assertions))]
fn install_root() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

pub fn report_root() -> PathBuf {
    install_root().join("reports")
}

/// IP 扫描结果目录：`reports/ipscan/`，CSV 导出落在这里。
pub fn ipscan_dir() -> PathBuf {
    let dir = report_root().join("ipscan");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// MAC 扫描结果目录：`reports/macscan/`。
pub fn macscan_dir() -> PathBuf {
    let dir = report_root().join("macscan");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 证书库目录：`pki/`，内含 `cas/` 与 `certs/`。
///
/// 注意：按用户选择，CA 私钥与证书私钥以明文 PEM 保存在这里，
/// 界面必须明确提示位置，避免用户误以为有口令保护。
pub fn pki_dir() -> PathBuf {
    let dir = install_root().join("pki");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// AI Agent 目录：`agent/`，内含 `config.json` 与 `skills/`。
///
/// 模型 API Key 不在这里 —— 它走系统凭据管理器，目录里只有模型元信息。
pub fn agent_dir() -> PathBuf {
    let dir = install_root().join("agent");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 配置目录：`config/`，用户可放 `oui.csv` 扩展厂商库。
pub fn config_dir() -> PathBuf {
    let dir = install_root().join("config");
    let _ = std::fs::create_dir_all(&dir);
    dir
}
