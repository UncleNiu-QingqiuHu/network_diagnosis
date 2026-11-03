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

/// 配置目录：`config/`，用户可放 `oui.csv` 扩展厂商库。
pub fn config_dir() -> PathBuf {
    let dir = install_root().join("config");
    let _ = std::fs::create_dir_all(&dir);
    dir
}
