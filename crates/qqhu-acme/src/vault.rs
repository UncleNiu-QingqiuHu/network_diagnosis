//! DNS 凭据保管。
//!
//! 自动续期需要在无人值守时写 DNS 记录，因此必须把 AccessKey 存下来。
//! 这比证书私钥更敏感 —— 私钥只影响一张证书，AccessKey 能改整个域名的解析。
//!
//! 所以优先用**系统凭据管理器**（Windows Credential Manager / macOS Keychain），
//! 由操作系统加密并绑定当前用户；只有拿不到凭据管理器的平台才退回文件，
//! 文件模式下收紧到 0600，并在界面明确提示。

use crate::model::DnsCredentials;
use crate::AcmeError;
use std::path::{Path, PathBuf};

/// 凭据管理器里的服务名，统一前缀便于用户在系统里辨识与清理。
const SERVICE: &str = "qingqiuhu-network-workbench";

pub struct CredentialVault {
    fallback_dir: PathBuf,
}

impl CredentialVault {
    pub fn new(fallback_dir: impl Into<PathBuf>) -> Self {
        Self {
            fallback_dir: fallback_dir.into(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.fallback_dir
    }

    /// 当前后端的中文名，界面要显示，避免用户误以为一定进了系统凭据库。
    pub fn backend(&self) -> &'static str {
        imp::BACKEND
    }

    fn entry_name(id: &str) -> String {
        format!("acme:{id}")
    }

    pub fn save(&self, id: &str, creds: &DnsCredentials) -> Result<(), AcmeError> {
        let payload = serde_json::to_string(creds)
            .map_err(|e| AcmeError::Io(format!("序列化凭据失败：{e}")))?;
        imp::save(&self.fallback_dir, &Self::entry_name(id), &payload)
    }

    /// 读取凭据；不存在时返回 `None`（而不是报错）。
    pub fn load(&self, id: &str) -> Result<Option<DnsCredentials>, AcmeError> {
        let Some(text) = imp::load(&self.fallback_dir, &Self::entry_name(id))? else {
            return Ok(None);
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| AcmeError::Io(format!("凭据文件损坏：{e}")))
    }

    pub fn delete(&self, id: &str) -> Result<(), AcmeError> {
        imp::delete(&self.fallback_dir, &Self::entry_name(id))
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
mod imp {
    use crate::AcmeError;
    use keyring::Entry;
    use std::path::Path;

    pub const BACKEND: &str = "系统凭据管理器";

    pub fn save(_dir: &Path, name: &str, secret: &str) -> Result<(), AcmeError> {
        let entry = Entry::new(super::SERVICE, name)
            .map_err(|e| AcmeError::Io(format!("打开凭据管理器失败：{e}")))?;
        entry
            .set_password(secret)
            .map_err(|e| AcmeError::Io(format!("写入凭据管理器失败：{e}")))
    }

    pub fn load(_dir: &Path, name: &str) -> Result<Option<String>, AcmeError> {
        let entry = Entry::new(super::SERVICE, name)
            .map_err(|e| AcmeError::Io(format!("打开凭据管理器失败：{e}")))?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(AcmeError::Io(format!("读取凭据管理器失败：{e}"))),
        }
    }

    pub fn delete(_dir: &Path, name: &str) -> Result<(), AcmeError> {
        let entry = Entry::new(super::SERVICE, name)
            .map_err(|e| AcmeError::Io(format!("打开凭据管理器失败：{e}")))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(AcmeError::Io(format!("删除凭据失败：{e}"))),
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod imp {
    use crate::AcmeError;
    use std::path::Path;

    pub const BACKEND: &str = "本地文件（0600）";

    fn path(dir: &Path, name: &str) -> std::path::PathBuf {
        // 名字里有冒号，文件名换成下划线更安全
        dir.join(format!("{}.json", name.replace(':', "_")))
    }

    pub fn save(dir: &Path, name: &str, secret: &str) -> Result<(), AcmeError> {
        std::fs::create_dir_all(dir).map_err(|e| AcmeError::Io(format!("创建目录失败：{e}")))?;
        let file = path(dir, name);
        std::fs::write(&file, secret).map_err(|e| AcmeError::Io(format!("写入凭据失败：{e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn load(dir: &Path, name: &str) -> Result<Option<String>, AcmeError> {
        match std::fs::read_to_string(path(dir, name)) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AcmeError::Io(format!("读取凭据失败：{e}"))),
        }
    }

    pub fn delete(dir: &Path, name: &str) -> Result<(), AcmeError> {
        match std::fs::remove_file(path(dir, name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AcmeError::Io(format!("删除凭据失败：{e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> DnsCredentials {
        DnsCredentials {
            access_key_id: "test-ak".into(),
            access_key_secret: "test-sk".into(),
        }
    }

    #[test]
    fn save_load_delete_round_trip() {
        let dir = std::env::temp_dir().join("qqhu-acme-vault-test");
        let vault = CredentialVault::new(&dir);
        let id = format!("vault-{}", uuid::Uuid::new_v4().simple());

        assert!(vault.load(&id).unwrap().is_none());

        if let Err(e) = vault.save(&id, &creds()) {
            // 无凭据管理器的环境（CI / 无桌面会话）跳过，不算失败
            eprintln!("[vault] 跳过（{}）：{e}", vault.backend());
            return;
        }
        let loaded = vault.load(&id).unwrap().unwrap();
        assert_eq!(loaded.access_key_id, "test-ak");
        assert_eq!(loaded.access_key_secret, "test-sk");

        vault.delete(&id).unwrap();
        assert!(vault.load(&id).unwrap().is_none());
        // 删除不存在的条目不应报错
        vault.delete(&id).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backend_is_reported() {
        let vault = CredentialVault::new(std::env::temp_dir().join("qqhu-acme-vault-b"));
        assert!(!vault.backend().is_empty());
    }
}
