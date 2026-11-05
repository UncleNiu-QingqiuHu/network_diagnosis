//! ACME 的 DNS 凭据保管。
//!
//! 自动续期需要在无人值守时写 DNS 记录，因此必须把 AccessKey 存下来。
//! 这比证书私钥更敏感 —— 私钥只影响一张证书，AccessKey 能改整个域名的解析。
//!
//! 实际存储交给 [`qqhu_secret`]：系统凭据管理器优先，取不到才退回 0600 文件。

use crate::model::DnsCredentials;
use crate::AcmeError;
use qqhu_secret::SecretStore;
use std::path::Path;

/// 凭据管理器里的服务名，与 Agent 等其它模块共用同一前缀。
const SERVICE: &str = "qingqiuhu-network-workbench";

pub struct CredentialVault {
    inner: SecretStore,
}

impl CredentialVault {
    pub fn new(fallback_dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            inner: SecretStore::new(SERVICE, fallback_dir),
        }
    }

    pub fn root(&self) -> &Path {
        self.inner.fallback_dir()
    }

    /// 当前后端的中文名，界面要显示，避免用户误以为一定进了系统凭据库。
    pub fn backend(&self) -> &'static str {
        self.inner.backend()
    }

    fn entry_name(id: &str) -> String {
        format!("acme:{id}")
    }

    pub fn save(&self, id: &str, creds: &DnsCredentials) -> Result<(), AcmeError> {
        let payload = serde_json::to_string(creds)
            .map_err(|e| AcmeError::Io(format!("序列化凭据失败：{e}")))?;
        self.inner
            .set(&Self::entry_name(id), &payload)
            .map_err(|e| AcmeError::Io(e.to_string()))
    }

    /// 读取凭据；不存在时返回 `None`（而不是报错）。
    pub fn load(&self, id: &str) -> Result<Option<DnsCredentials>, AcmeError> {
        let Some(text) = self
            .inner
            .get(&Self::entry_name(id))
            .map_err(|e| AcmeError::Io(e.to_string()))?
        else {
            return Ok(None);
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| AcmeError::Io(format!("凭据格式损坏：{e}")))
    }

    pub fn delete(&self, id: &str) -> Result<(), AcmeError> {
        self.inner
            .delete(&Self::entry_name(id))
            .map_err(|e| AcmeError::Io(e.to_string()))
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
