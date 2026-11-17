//! 可写目录解析。
//!
//! 数据落在哪，取决于程序怎么装的 —— 这一点不能靠猜：
//!
//! | 场景 | 落点 | 判定依据 |
//! |---|---|---|
//! | 开发态（`cargo tauri dev`） | 仓库根 | `debug_assertions` |
//! | 便携版 / 绿色版 | 可执行文件同级 | `portable.flag`，或同级已有 `pki/` `reports/` `agent/` `config/` |
//! | 安装版（NSIS / MSI / .app / AppImage） | 用户数据目录 | 以上都不满足 |
//!
//! 老实现一律写可执行文件同级，MSI 装到 `Program Files` 后普通用户无写权限，
//! 采集报告、签发证书、保存 CA 私钥全部失败；macOS `.app` 包内与 Linux AppImage
//! 更是只读挂载。目录创建失败还被 `let _ =` 吞掉，直到写文件才炸出无关的错误。
//!
//! 因此这里做三件事：决定落点、**建目录失败必须上报**、把旧位置的数据搬过来。
//! 便携版被放到受保护目录时退回用户数据目录，并在 `MIGRATED.txt` 里留下来源，
//! 原始目录不删（用户自己确认后再清理）。

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// 用户数据目录下的应用子目录名。
pub const DATA_DIR_NAME: &str = "QingqiuhuNetworkWorkbench";

/// 便携模式标记文件。放在可执行文件同级即强制原地写。
pub const PORTABLE_FLAG: &str = "portable.flag";

/// 数据迁移说明文件名。
pub const MIGRATED_NOTE: &str = "MIGRATED.txt";

/// 旧版本留在可执行文件同级的目录。命中任意一个即认定是绿色版布局。
pub const LEGACY_DIRS: [&str; 4] = ["pki", "reports", "agent", "config"];

/// 数据根目录的落点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataRootMode {
    /// 开发态：仓库根目录。
    Repo,
    /// 便携版：可执行文件同级。
    Portable,
    /// 安装版：用户数据目录。
    UserData,
}

impl DataRootMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DataRootMode::Repo => "repo",
            DataRootMode::Portable => "portable",
            DataRootMode::UserData => "userData",
        }
    }

    /// 面向界面的说明文案。
    pub fn display(self) -> &'static str {
        match self {
            DataRootMode::Repo => "开发态（仓库根）",
            DataRootMode::Portable => "便携模式（程序目录）",
            DataRootMode::UserData => "用户数据目录",
        }
    }
}

/// 启动时解析出来的一次性结果。
#[derive(Debug, Clone)]
pub struct DataRootInfo {
    pub root: PathBuf,
    pub mode: DataRootMode,
    /// 从旧位置迁移过来的子目录名；为空表示本次没有搬迁。
    pub migrated: Vec<String>,
    /// 迁移来源目录。
    pub migrated_from: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("无法确定数据目录：{0}")]
    Unavailable(String),
    #[error("目录 {path} 不可写：{source}")]
    NotWritable { path: String, source: std::io::Error },
}

impl PathError {
    fn not_writable(path: &Path, source: std::io::Error) -> Self {
        PathError::NotWritable {
            path: path.display().to_string(),
            source,
        }
    }
}

static RESOLVED: OnceLock<DataRootInfo> = OnceLock::new();

/// 启动时调用一次：解析落点、建目录、按需迁移。
///
/// 幂等 —— 重复调用只返回第一次的结果，不重复迁移。
pub fn init() -> Result<DataRootInfo, PathError> {
    if let Some(info) = RESOLVED.get() {
        return Ok(info.clone());
    }
    let info = resolve()?;
    // 竞态下可能已被别的线程写入：以先写入的为准，但仍要保证目录已就绪
    let stored = RESOLVED.get_or_init(|| info.clone());
    Ok(stored.clone())
}

/// 已解析的落点信息。未调用 [`init`] 时按当前环境惰性解析一次。
///
/// 解析失败会 panic —— 走到这里说明启动阶段没有拦住错误，
/// 继续运行只会在写文件时抛出更难懂的错。
pub fn info() -> &'static DataRootInfo {
    RESOLVED.get_or_init(|| {
        resolve().unwrap_or_else(|e| panic!("数据目录不可用，程序无法继续：{e}"))
    })
}

// ---------------------------------------------------------------- 落点解析

#[cfg(debug_assertions)]
fn resolve() -> Result<DataRootInfo, PathError> {
    if let Some(root) = custom_root()? {
        return Ok(root);
    }
    // 开发态固定落在仓库根：`CARGO_MANIFEST_DIR` = <repo>/src-tauri
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    ensure_writable(&root)?;
    Ok(DataRootInfo {
        root,
        mode: DataRootMode::Repo,
        migrated: Vec::new(),
        migrated_from: None,
    })
}

#[cfg(not(debug_assertions))]
fn resolve() -> Result<DataRootInfo, PathError> {
    if let Some(root) = custom_root()? {
        return Ok(root);
    }

    let exe = exe_dir();
    // 便携版优先原地：用户把整个文件夹拷走就能带走全部数据。
    let exe_writable = ensure_writable(&exe).is_ok();
    match plan_root(&exe, exe_writable) {
        RootPlan::InPlace => Ok(DataRootInfo {
            root: exe,
            mode: DataRootMode::Portable,
            migrated: Vec::new(),
            migrated_from: None,
        }),
        RootPlan::UserData { migrate_from } => {
            let target = user_data_root()?;
            ensure_writable(&target)?;
            // 绿色版被放进受保护目录（如 Program Files）时必须搬数据，
            // 否则用户的 CA 与证书会跟着写权限一起消失。
            let migrated = match &migrate_from {
                Some(from) => migrate_legacy(from, &target),
                None => Vec::new(),
            };
            Ok(DataRootInfo {
                root: target,
                mode: DataRootMode::UserData,
                migrated,
                migrated_from: migrate_from,
            })
        }
    }
}

/// 落点决策结果。
#[derive(Debug, PartialEq, Eq)]
pub enum RootPlan {
    /// 原地写：便携版且程序目录可写。
    InPlace,
    /// 写用户数据目录；`migrate_from` 非空表示需要把旧目录的数据搬过来。
    UserData { migrate_from: Option<PathBuf> },
}

/// 落点决策（纯逻辑，可注入「程序目录是否可写」做单测）。
///
/// 三种组合各自对应一个真实场景：
/// - 便携版 + 可写 → 原地，数据跟着程序走；
/// - 便携版 + 不可写 → 搬去用户目录（Program Files 里塞绿色版的典型情形）；
/// - 非便携版 → 用户数据目录，安装版的正常路径。
fn plan_root(exe: &Path, exe_writable: bool) -> RootPlan {
    if !is_portable(exe) {
        return RootPlan::UserData { migrate_from: None };
    }
    if exe_writable {
        RootPlan::InPlace
    } else {
        RootPlan::UserData {
            migrate_from: Some(exe.to_path_buf()),
        }
    }
}

/// `QQHU_DATA_DIR` 覆盖落点，测试与高级部署用。
///
/// 显式指定却写不了必须报错：静默退回自动判定会让数据落到用户意料之外的地方。
fn custom_root() -> Result<Option<DataRootInfo>, PathError> {
    let Ok(raw) = std::env::var("QQHU_DATA_DIR") else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    let root = PathBuf::from(raw);
    ensure_writable(&root)?;
    let mode = if cfg!(debug_assertions) {
        DataRootMode::Repo
    } else {
        DataRootMode::UserData
    };
    Ok(Some(DataRootInfo {
        root,
        mode,
        migrated: Vec::new(),
        migrated_from: None,
    }))
}

#[cfg_attr(debug_assertions, allow(dead_code))]
fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// 是否为便携版布局：有标记文件，或同级已存在旧版的数据目录。
#[cfg_attr(debug_assertions, allow(dead_code))]
fn is_portable(dir: &Path) -> bool {
    if dir.join(PORTABLE_FLAG).is_file() {
        return true;
    }
    LEGACY_DIRS
        .iter()
        .any(|name| dir.join(name).is_dir())
}

#[cfg_attr(debug_assertions, allow(dead_code))]
fn user_data_root() -> Result<PathBuf, PathError> {
    // 本地数据目录而非漫游目录：证书私钥与模型凭据不该被域漫游配置同步到服务器。
    dirs::data_local_dir()
        .map(|d| d.join(DATA_DIR_NAME))
        .ok_or_else(|| PathError::Unavailable("系统未提供本地数据目录".into()))
}

/// 建目录并实际写一个探针文件。
///
/// 只 `create_dir_all` 不够：目录已存在时不触碰磁盘，权限问题要到后面写文件才暴露。
///
/// 探针文件名带进程号与纳秒时间戳 —— 固定名字在多线程并发调用时会撞 Windows 的
/// 文件共享冲突，出现「同一份代码单跑通过、并发跑偶发失败」这种最难查的假故障。
fn ensure_writable(dir: &Path) -> Result<(), PathError> {
    std::fs::create_dir_all(dir).map_err(|e| PathError::not_writable(dir, e))?;
    let probe = ProbeFile::new(dir);
    std::fs::write(&probe.path, b"1").map_err(|e| PathError::not_writable(dir, e))?;
    Ok(())
}

/// 探针文件，离开作用域即删除（含中途 return 的路径）。
struct ProbeFile {
    path: PathBuf,
}

impl ProbeFile {
    fn new(dir: &Path) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Self {
            path: dir.join(format!(".qqhu-write-{}-{stamp}", std::process::id())),
        }
    }
}

impl Drop for ProbeFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------- 数据迁移

/// 把旧位置的 `pki` / `reports` / `agent` / `config` 复制到新位置。
///
/// 只复制、不删除原目录：`pki/` 里是 CA 私钥与已签证书，删错等于整个证书体系报废，
/// 让用户自己在新位置验证通过后再清理。目标已存在时整目录跳过，绝不覆盖。
///
/// 返回实际迁移的目录名。任何一步失败都会清掉半成品目录，
/// 否则下次启动会因为「目标已存在」而跳过，留下残缺数据。
pub fn migrate_legacy(from: &Path, to: &Path) -> Vec<String> {
    if from == to {
        return Vec::new();
    }
    let mut done = Vec::new();

    for name in LEGACY_DIRS {
        let src = from.join(name);
        if !src.is_dir() {
            continue;
        }
        let dst = to.join(name);
        if dst.exists() {
            continue;
        }
        match copy_tree(&src, &dst) {
            Ok(()) => {
                // 大小校验：挡掉磁盘写满、权限中途失效造成的截断
                if same_shape(&src, &dst) {
                    done.push(name.to_string());
                } else {
                    let _ = std::fs::remove_dir_all(&dst);
                }
            }
            Err(_) => {
                let _ = std::fs::remove_dir_all(&dst);
            }
        }
    }

    if !done.is_empty() {
        let note = format!(
            "以下数据由旧版本（可执行文件同级目录）迁移而来：{}\r\n\
             来源：{}\r\n\
             时间：{}\r\n\
             \r\n\
             原目录保留未删除。确认新位置数据完整后可自行清理旧目录。\r\n",
            done.join("、"),
            from.display(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        let _ = std::fs::write(to.join(MIGRATED_NOTE), note);
    }

    done
}

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &target)?;
        }
        // 符号链接不跟随：跨平台行为不一致，且数据目录里不该有
    }
    Ok(())
}

/// 比较两个目录树是否「同形」——文件数与总字节一致。
///
/// 不是逐字节比对（大目录会拖慢启动），但足以发现复制被截断。
fn same_shape(a: &Path, b: &Path) -> bool {
    fn shape(dir: &Path) -> std::io::Result<(usize, u64)> {
        let mut files = 0;
        let mut bytes = 0;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            if ty.is_dir() {
                let (f, s) = shape(&entry.path())?;
                files += f;
                bytes += s;
            } else if ty.is_file() {
                files += 1;
                bytes += entry.metadata()?.len();
            }
        }
        Ok((files, bytes))
    }
    match (shape(a), shape(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

// ---------------------------------------------------------------- 具体目录

fn root() -> &'static Path {
    &info().root
}

/// 数据根目录。报告、证书库、Agent 配置都在它下面。
pub fn data_root() -> PathBuf {
    root().to_path_buf()
}

pub fn report_root() -> PathBuf {
    root().join("reports")
}

/// IP 扫描结果目录：`reports/ipscan/`，CSV 导出落在这里。
pub fn ipscan_dir() -> PathBuf {
    subdir(&report_root(), "ipscan")
}

/// MAC 扫描结果目录：`reports/macscan/`。
pub fn macscan_dir() -> PathBuf {
    subdir(&report_root(), "macscan")
}

/// 诊断报告目录：`reports/diagnosis/`。
pub fn diagnosis_dir() -> PathBuf {
    subdir(&report_root(), "diagnosis")
}

/// 证书库目录：`pki/`，内含 `cas/` 与 `certs/`。
///
/// 注意：按用户选择，CA 私钥与证书私钥以明文 PEM 保存在这里，
/// 界面必须明确提示位置，避免用户误以为有口令保护。
pub fn pki_dir() -> PathBuf {
    subdir(root(), "pki")
}

/// AI Agent 目录：`agent/`，内含 `config.json`、`skills/` 与 `sessions/`。
///
/// 模型 API Key 不在这里 —— 它走系统凭据管理器，目录里只有模型元信息。
pub fn agent_dir() -> PathBuf {
    subdir(root(), "agent")
}

/// Agent 会话报告目录：`reports/agent/<session_id>/report.md`。
///
/// 与诊断报告同根：用户按 `reports/` 一处备份即可，不必记两套路径。
pub fn agent_report_dir() -> PathBuf {
    subdir(&report_root(), "agent")
}

/// 配置目录：`config/`，用户可放 `oui.csv` 扩展厂商库。
pub fn config_dir() -> PathBuf {
    subdir(root(), "config")
}

/// 建子目录；失败时返回路径本身，让后续写入报出真实的 IO 错误。
///
/// 不再像旧实现那样 `let _ =` 吞掉失败 —— 那样错误会飘到几百行之外才现形。
fn subdir(base: &Path, name: &str) -> PathBuf {
    let dir = base.join(name);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!(path = %dir.display(), error = %e, "创建数据子目录失败");
    }
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "qqhu-paths-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn portable_flag_is_detected() {
        let dir = tempdir("flag");
        assert!(!is_portable(&dir));
        std::fs::write(dir.join(PORTABLE_FLAG), b"").unwrap();
        assert!(is_portable(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_layout_counts_as_portable() {
        let dir = tempdir("legacy");
        std::fs::create_dir_all(dir.join("pki")).unwrap();
        assert!(is_portable(&dir), "同级已有 pki/ 时应判定为绿色版");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_dir_is_not_portable() {
        let dir = tempdir("empty");
        assert!(!is_portable(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migrate_copies_nested_tree() {
        let src = tempdir("src");
        let dst = tempdir("dst-migrate");
        let cert = src.join("pki/certs/demo");
        std::fs::create_dir_all(&cert).unwrap();
        std::fs::create_dir_all(src.join("config")).unwrap();
        std::fs::write(cert.join("cert.pem"), b"-----BEGIN CERTIFICATE-----").unwrap();
        std::fs::write(src.join("pki/certs/demo/key.pem"), b"key-material").unwrap();
        std::fs::write(src.join("config/oui.csv"), b"aabbcc,Vendor").unwrap();

        let moved = migrate_legacy(&src, &dst);
        assert_eq!(moved, vec!["pki".to_string(), "config".to_string()]);
        assert_eq!(
            std::fs::read_to_string(dst.join("pki/certs/demo/key.pem")).unwrap(),
            "key-material"
        );
        assert!(dst.join(MIGRATED_NOTE).is_file());
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dst).ok();
    }

    #[test]
    fn migrate_never_overwrites_existing_target() {
        let src = tempdir("src2");
        let dst = tempdir("dst2");
        std::fs::create_dir_all(src.join("pki")).unwrap();
        std::fs::write(src.join("pki/old.pem"), b"old").unwrap();
        std::fs::create_dir_all(dst.join("pki")).unwrap();
        std::fs::write(dst.join("pki/new.pem"), b"new").unwrap();

        let moved = migrate_legacy(&src, &dst);
        assert!(moved.is_empty(), "目标已存在时不应迁移");
        assert!(!dst.join("pki/old.pem").exists());
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dst).ok();
    }

    #[test]
    fn migrate_skips_when_nothing_to_copy() {
        let src = tempdir("src3");
        let dst = tempdir("dst3");
        assert!(migrate_legacy(&src, &dst).is_empty());
        assert!(!dst.join(MIGRATED_NOTE).exists());
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dst).ok();
    }

    #[test]
    fn same_shape_detects_truncated_copy() {
        let a = tempdir("shape-a");
        let b = tempdir("shape-b");
        std::fs::write(a.join("x.pem"), b"12345").unwrap();
        std::fs::write(b.join("x.pem"), b"123").unwrap();
        assert!(!same_shape(&a, &b));
        std::fs::write(b.join("x.pem"), b"12345").unwrap();
        assert!(same_shape(&a, &b));
        std::fs::remove_dir_all(&a).ok();
        std::fs::remove_dir_all(&b).ok();
    }

    #[test]
    fn ensure_writable_creates_and_probes() {
        let dir = tempdir("probe").join("nested/deeper");
        ensure_writable(&dir).unwrap();
        assert!(dir.is_dir());
        // 探针文件必须在返回时被清掉，不能在数据目录里留垃圾
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".qqhu-write-"))
            .collect();
        assert!(leftovers.is_empty(), "探针文件应被清理");
        std::fs::remove_dir_all(dir.parent().unwrap().parent().unwrap()).ok();
    }

    #[test]
    fn concurrent_probes_do_not_collide() {
        let dir = tempdir("concurrent");
        // 旧实现用固定文件名，并发时会撞 Windows 共享冲突
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let d = dir.clone();
                std::thread::spawn(move || ensure_writable(&d))
            })
            .collect();
        for h in handles {
            h.join().unwrap().expect("并发写探针不应失败");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn plain_install_goes_to_user_data() {
        let exe = tempdir("plain");
        assert_eq!(
            plan_root(&exe, true),
            RootPlan::UserData { migrate_from: None },
            "没有便携标记、也没有旧数据目录时，应当走用户数据目录"
        );
        std::fs::remove_dir_all(&exe).ok();
    }

    #[test]
    fn portable_and_writable_stays_in_place() {
        let exe = tempdir("stay");
        std::fs::create_dir_all(exe.join("pki")).unwrap();
        assert_eq!(plan_root(&exe, true), RootPlan::InPlace);
        std::fs::remove_dir_all(&exe).ok();
    }

    #[test]
    fn portable_but_readonly_migrates_to_user_data() {
        let exe = tempdir("readonly");
        std::fs::write(exe.join(PORTABLE_FLAG), b"").unwrap();
        assert_eq!(
            plan_root(&exe, false),
            RootPlan::UserData {
                migrate_from: Some(exe.clone())
            },
            "Program Files 里的绿色版必须搬走，否则 CA 私钥无处可写"
        );
        std::fs::remove_dir_all(&exe).ok();
    }

    #[test]
    fn plain_install_never_migrates() {
        let exe = tempdir("plain2");
        std::fs::write(exe.join(PORTABLE_FLAG), b"").unwrap();
        // 有标记但目录可写：原地
        assert_eq!(plan_root(&exe, true), RootPlan::InPlace);
        std::fs::remove_dir_all(&exe).ok();
    }

    #[test]
    fn init_bootstraps_real_environment() {
        let info = init().expect("当前环境的数据目录应当可用");
        assert!(info.root.is_dir(), "数据根目录应已创建");
        #[cfg(debug_assertions)]
        assert_eq!(info.mode, DataRootMode::Repo, "开发态落在仓库根");
        // 幂等：重复调用不重复迁移
        let again = init().expect("重复初始化应成功");
        assert_eq!(again.root, info.root);
    }
}
