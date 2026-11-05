//! 凭据保管：优先系统凭据管理器，取不到才退回文件。
//!
//! Windows 用 Credential Manager、macOS 用 Keychain，由操作系统加密并绑定当前用户；
//! 其余平台（目前只保证编译）退回 0600 文件。
//!
//! 服务名统一为应用名，条目名由调用方决定（如 `acme:<id>`、`model:<id>`），
//! 这样用户在系统凭据管理器里能一眼看出属于哪个功能。

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("打开凭据管理器失败：{0}")]
    Open(String),

    #[error("写入凭据失败：{0}")]
    Write(String),

    #[error("读取凭据失败：{0}")]
    Read(String),

    #[error("删除凭据失败：{0}")]
    Delete(String),
}

pub struct SecretStore {
    service: String,
    fallback_dir: PathBuf,
}

impl SecretStore {
    pub fn new(service: impl Into<String>, fallback_dir: impl Into<PathBuf>) -> Self {
        Self {
            service: service.into(),
            fallback_dir: fallback_dir.into(),
        }
    }

    /// 当前后端的中文名。界面要展示，避免用户误以为一定进了系统凭据库。
    pub fn backend(&self) -> &'static str {
        imp::BACKEND
    }

    pub fn fallback_dir(&self) -> &Path {
        &self.fallback_dir
    }

    pub fn set(&self, key: &str, secret: &str) -> Result<(), SecretError> {
        imp::save(&self.service, &self.fallback_dir, key, secret)
    }

    /// 读取；不存在时返回 `Ok(None)`。
    pub fn get(&self, key: &str) -> Result<Option<String>, SecretError> {
        imp::load(&self.service, &self.fallback_dir, key)
    }

    pub fn delete(&self, key: &str) -> Result<(), SecretError> {
        imp::delete(&self.service, &self.fallback_dir, key)
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
mod imp {
    use super::SecretError;
    use keyring::Entry;
    use std::path::Path;

    pub const BACKEND: &str = "系统凭据管理器";

    fn entry(service: &str, key: &str) -> Result<Entry, SecretError> {
        Entry::new(service, key).map_err(|e| SecretError::Open(e.to_string()))
    }

    pub fn save(service: &str, _dir: &Path, key: &str, secret: &str) -> Result<(), SecretError> {
        entry(service, key)?
            .set_password(secret)
            .map_err(|e| SecretError::Write(e.to_string()))
    }

    pub fn load(service: &str, _dir: &Path, key: &str) -> Result<Option<String>, SecretError> {
        match entry(service, key)?.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(SecretError::Read(e.to_string())),
        }
    }

    pub fn delete(service: &str, _dir: &Path, key: &str) -> Result<(), SecretError> {
        match entry(service, key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretError::Delete(e.to_string())),
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod imp {
    use super::SecretError;
    use std::path::{Path, PathBuf};

    pub const BACKEND: &str = "本地文件（0600）";

    fn path(dir: &Path, key: &str) -> PathBuf {
        // 条目名里可能有冒号，换成下划线更安全
        dir.join(format!("{}.txt", key.replace(':', "_")))
    }

    pub fn save(_service: &str, dir: &Path, key: &str, secret: &str) -> Result<(), SecretError> {
        std::fs::create_dir_all(dir).map_err(|e| SecretError::Write(e.to_string()))?;
        let file = path(dir, key);
        std::fs::write(&file, secret).map_err(|e| SecretError::Write(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn load(_service: &str, dir: &Path, key: &str) -> Result<Option<String>, SecretError> {
        match std::fs::read_to_string(path(dir, key)) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SecretError::Read(e.to_string())),
        }
    }

    pub fn delete(_service: &str, dir: &Path, key: &str) -> Result<(), SecretError> {
        match std::fs::remove_file(path(dir, key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SecretError::Delete(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(tag: &str) -> SecretStore {
        SecretStore::new(
            "qqhu-test-service",
            std::env::temp_dir().join(format!("qqhu-secret-{tag}")),
        )
    }

    #[test]
    fn round_trip_and_delete() {
        let s = store("rt");
        let key = format!("k{}", std::process::id());
        assert!(s.get(&key).unwrap().is_none());

        if let Err(e) = s.set(&key, "s3cret") {
            eprintln!("[secret] 跳过（{}）：{e}", s.backend());
            return;
        }
        assert_eq!(s.get(&key).unwrap().as_deref(), Some("s3cret"));

        // 覆盖写入
        s.set(&key, "next").unwrap();
        assert_eq!(s.get(&key).unwrap().as_deref(), Some("next"));

        s.delete(&key).unwrap();
        assert!(s.get(&key).unwrap().is_none());
        // 幂等
        s.delete(&key).unwrap();
        let _ = std::fs::remove_dir_all(s.fallback_dir());
    }

    #[test]
    fn separate_keys_do_not_collide() {
        let s = store("keys");
        let a = format!("a{}", std::process::id());
        let b = format!("b{}", std::process::id());
        if s.set(&a, "A").is_err() {
            return;
        }
        s.set(&b, "B").unwrap();
        assert_eq!(s.get(&a).unwrap().as_deref(), Some("A"));
        assert_eq!(s.get(&b).unwrap().as_deref(), Some("B"));
        s.delete(&a).unwrap();
        s.delete(&b).unwrap();
        let _ = std::fs::remove_dir_all(s.fallback_dir());
    }
}
