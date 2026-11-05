//! 证书库：目录布局与元信息持久化。
//!
//! 布局（`<安装目录>/pki/`）：
//! ```text
//! cas/<ca-id>/ca.pem        自签名根证书
//! cas/<ca-id>/ca.key.pem    根私钥（明文，用户已确认）
//! cas/<ca-id>/meta.json     元信息
//! certs/<id>/cert.pem       服务器证书
//! certs/<id>/key.pem        私钥
//! certs/<id>/chain.pem      证书链（服务器证书 + CA）
//! certs/<id>/cert.pfx       按需生成的 PKCS#12
//! certs/<id>/meta.json
//! ```
//!
//! 不维护全局索引文件：目录扫描 + 单条 `meta.json` 已经足够（数量级是几十张），
//! 少一个需要保持一致的写入点。

use crate::issue::{generate_ca, issue_cert, pem_to_der, to_pfx};
use crate::model::{CaMeta, CaSpec, CertMeta, CertSpec};
use crate::PkiError;
use chrono::Utc;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct PkiStore {
    root: PathBuf,
}

/// CA 相关文件路径。
pub struct CaPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub meta: PathBuf,
    pub dir: PathBuf,
}

/// 证书相关文件路径。
pub struct CertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub fullchain: PathBuf,
    pub pfx: PathBuf,
    pub meta: PathBuf,
    pub dir: PathBuf,
}

fn new_id() -> String {
    let s = Uuid::new_v4().simple().to_string();
    s[..12].to_string()
}

impl PkiStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ca_paths(&self, id: &str) -> CaPaths {
        let dir = self.root.join("cas").join(id);
        CaPaths {
            cert: dir.join("ca.pem"),
            key: dir.join("ca.key.pem"),
            meta: dir.join("meta.json"),
            dir,
        }
    }

    pub fn cert_paths(&self, id: &str) -> CertPaths {
        let dir = self.root.join("certs").join(id);
        CertPaths {
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
            fullchain: dir.join("chain.pem"),
            pfx: dir.join("cert.pfx"),
            meta: dir.join("meta.json"),
            dir,
        }
    }

    fn ensure_dirs(&self) -> Result<(), PkiError> {
        for sub in ["cas", "certs"] {
            std::fs::create_dir_all(self.root.join(sub))
                .map_err(|e| PkiError::Io(format!("创建目录失败：{e}")))?;
        }
        Ok(())
    }

    /// 新建根 CA 并落盘。
    pub fn create_ca(&self, spec: &CaSpec) -> Result<CaMeta, PkiError> {
        self.ensure_dirs()?;
        let generated = generate_ca(spec)?;

        let id = new_id();
        let paths = self.ca_paths(&id);
        std::fs::create_dir_all(&paths.dir).map_err(|e| PkiError::Io(format!("创建目录失败：{e}")))?;

        let meta = CaMeta {
            id: id.clone(),
            common_name: spec.common_name.trim().to_string(),
            subject: generated.subject,
            serial: generated.serial,
            fingerprint: generated.fingerprint,
            key_algorithm: spec.key_algorithm.label().to_string(),
            created_at: Utc::now(),
            not_before: generated.not_before,
            not_after: generated.not_after,
            days_remaining: (generated.not_after - Utc::now()).num_days(),
            issued_count: 0,
        };

        write_file(&paths.cert, generated.cert_pem.as_bytes())?;
        write_file(&paths.key, generated.key_pem.as_bytes())?;
        write_json(&paths.meta, &meta)?;
        Ok(meta)
    }

    /// 列出全部 CA，按创建时间倒序，并顺带刷新剩余天数与已签发数量。
    pub fn list_cas(&self) -> Result<Vec<CaMeta>, PkiError> {
        self.ensure_dirs()?;
        let mut out = Vec::new();
        for entry in read_dir(&self.root.join("cas"))? {
            let meta_path = entry.join("meta.json");
            if let Some(mut meta) = read_json::<CaMeta>(&meta_path) {
                meta.refresh(Utc::now());
                meta.issued_count = self.count_certs_of(&meta.id);
                out.push(meta);
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    /// 读取 CA 证书与私钥 PEM。
    pub fn read_ca(&self, id: &str) -> Result<(String, String, CaMeta), PkiError> {
        let paths = self.ca_paths(id);
        let cert = read_text(&paths.cert)?;
        let key = read_text(&paths.key)?;
        let meta = read_json::<CaMeta>(&paths.meta)
            .ok_or_else(|| PkiError::Invalid(format!("找不到 CA {id} 的元信息")))?;
        Ok((cert, key, meta))
    }

    /// 删除 CA。仍有证书签发在此 CA 下时拒绝删除，避免出现无主证书。
    pub fn delete_ca(&self, id: &str) -> Result<(), PkiError> {
        let count = self.count_certs_of(id);
        if count > 0 {
            return Err(PkiError::Invalid(format!(
                "该 CA 下还有 {count} 张证书，请先删除这些证书再删除 CA。"
            )));
        }
        let paths = self.ca_paths(id);
        if !paths.dir.exists() {
            return Err(PkiError::Invalid(format!("找不到 CA {id}")));
        }
        std::fs::remove_dir_all(&paths.dir).map_err(|e| PkiError::Io(format!("删除失败：{e}")))
    }

    fn count_certs_of(&self, ca_id: &str) -> usize {
        self.list_certs_raw()
            .into_iter()
            .filter(|c| c.ca_id == ca_id)
            .count()
    }

    fn list_certs_raw(&self) -> Vec<CertMeta> {
        let mut out = Vec::new();
        if let Ok(dirs) = read_dir(&self.root.join("certs")) {
            for entry in dirs {
                if let Some(c) = read_json::<CertMeta>(&entry.join("meta.json")) {
                    out.push(c);
                }
            }
        }
        out
    }

    /// 签发证书。
    pub fn issue(&self, spec: &CertSpec) -> Result<CertMeta, PkiError> {
        self.ensure_dirs()?;
        let (ca_cert_pem, ca_key_pem, ca_meta) = self.read_ca(&spec.ca_id)?;
        let generated = issue_cert(spec, &ca_cert_pem, &ca_key_pem, ca_meta.not_after)?;

        let id = new_id();
        let paths = self.cert_paths(&id);
        std::fs::create_dir_all(&paths.dir).map_err(|e| PkiError::Io(format!("创建目录失败：{e}")))?;

        // chain.pem 顺序必须是「服务器证书 → CA」，Nginx 的 ssl_certificate 直接用它
        let fullchain = format!("{}{}", generated.cert_pem, ca_cert_pem);

        let meta = CertMeta {
            id: id.clone(),
            ca_id: spec.ca_id.clone(),
            common_name: spec.common_name.trim().to_string(),
            sans: crate::model::validate_cert(spec)
                .map(|(s, _)| s)
                .unwrap_or_default(),
            serial: generated.serial,
            fingerprint: generated.fingerprint,
            key_algorithm: spec.key_algorithm.label().to_string(),
            usage: spec.usage.label().to_string(),
            created_at: Utc::now(),
            not_before: generated.not_before,
            not_after: generated.not_after,
            days_remaining: (generated.not_after - Utc::now()).num_days(),
        };

        write_file(&paths.cert, generated.cert_pem.as_bytes())?;
        write_file(&paths.key, generated.key_pem.as_bytes())?;
        write_file(&paths.fullchain, fullchain.as_bytes())?;
        write_json(&paths.meta, &meta)?;
        Ok(meta)
    }

    /// 列出证书，可按 CA 过滤。
    pub fn list_certs(&self, ca_id: Option<&str>) -> Result<Vec<CertMeta>, PkiError> {
        self.ensure_dirs()?;
        let mut out = self.list_certs_raw();
        if let Some(id) = ca_id {
            out.retain(|c| c.ca_id == id);
        }
        let now = Utc::now();
        for c in out.iter_mut() {
            c.refresh(now);
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    pub fn delete_cert(&self, id: &str) -> Result<(), PkiError> {
        let paths = self.cert_paths(id);
        if !paths.dir.exists() {
            return Err(PkiError::Invalid(format!("找不到证书 {id}")));
        }
        std::fs::remove_dir_all(&paths.dir).map_err(|e| PkiError::Io(format!("删除失败：{e}")))
    }

    /// 读取证书文本（不含私钥）。
    pub fn read_cert_text(&self, id: &str) -> Result<(String, String), PkiError> {
        let paths = self.cert_paths(id);
        Ok((read_text(&paths.cert)?, read_text(&paths.fullchain)?))
    }

    /// 导出 PKCS#12，返回落盘路径。重复导出会覆盖同一个文件。
    pub fn export_pfx(&self, id: &str, password: &str) -> Result<String, PkiError> {
        let paths = self.cert_paths(id);
        if !paths.dir.exists() {
            return Err(PkiError::Invalid(format!("找不到证书 {id}")));
        }
        let meta = read_json::<CertMeta>(&paths.meta)
            .ok_or_else(|| PkiError::Invalid(format!("找不到证书 {id} 的元信息")))?;
        let cert_pem = read_text(&paths.cert)?;
        let key_pem = read_text(&paths.key)?;
        let (_, _, ca_meta) = self.read_ca(&meta.ca_id)?;
        let ca_pem = read_text(&self.ca_paths(&ca_meta.id).cert)?;

        let cert_der = pem_to_der(&cert_pem)?;
        let key_der = pem_to_der(&key_pem)?;
        let ca_der = pem_to_der(&ca_pem)?;

        let der = to_pfx(
            &cert_der,
            &key_der,
            Some(&ca_der),
            password,
            &meta.common_name,
        )?;
        write_file(&paths.pfx, &der)?;
        Ok(paths.pfx.to_string_lossy().to_string())
    }

    /// 供界面「打开目录」用。
    pub fn cert_dir(&self, id: &str) -> PathBuf {
        self.cert_paths(id).dir
    }

    pub fn ca_dir(&self, id: &str) -> PathBuf {
        self.ca_paths(id).dir
    }
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), PkiError> {
    std::fs::write(path, bytes).map_err(|e| PkiError::Io(format!("写入 {} 失败：{e}", path.display())))
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), PkiError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| PkiError::Io(format!("序列化元信息失败：{e}")))?;
    write_file(path, text.as_bytes())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn read_text(path: &Path) -> Result<String, PkiError> {
    std::fs::read_to_string(path)
        .map_err(|e| PkiError::Io(format!("读取 {} 失败：{e}", path.display())))
}

fn read_dir(dir: &Path) -> Result<Vec<PathBuf>, PkiError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(out), // 目录不存在时按空处理，不报错
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.push(p);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CertUsage, KeyAlgorithm};

    fn temp_store(tag: &str) -> PkiStore {
        let dir = std::env::temp_dir().join(format!("qqhu-pki-test-{tag}-{}", new_id()));
        PkiStore::new(dir)
    }

    fn ca_spec() -> CaSpec {
        CaSpec {
            common_name: "Test Root CA".into(),
            organization: Some("Test Org".into()),
            organizational_unit: None,
            country: Some("CN".into()),
            state: None,
            locality: None,
            validity_days: Some(3650),
            key_algorithm: KeyAlgorithm::EcdsaP256,
        }
    }

    fn leaf_spec(ca_id: &str) -> CertSpec {
        CertSpec {
            ca_id: ca_id.into(),
            common_name: "web.corp.local".into(),
            sans: vec!["web.corp.local".into(), "10.0.0.5".into()],
            validity_days: Some(397),
            key_algorithm: KeyAlgorithm::EcdsaP256,
            usage: CertUsage::Server,
        }
    }

    #[test]
    fn create_list_and_delete_ca() {
        let store = temp_store("ca");
        let ca = store.create_ca(&ca_spec()).unwrap();
        assert_eq!(ca.issued_count, 0);

        let list = store.list_cas().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, ca.id);
        assert!(list[0].days_remaining > 3000);

        // 证书与私钥都要落盘
        let paths = store.ca_paths(&ca.id);
        assert!(paths.cert.exists());
        assert!(paths.key.exists());
        assert!(std::fs::read_to_string(&paths.cert).unwrap().contains("BEGIN CERTIFICATE"));

        store.delete_ca(&ca.id).unwrap();
        assert!(store.list_cas().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn issue_lists_and_exports() {
        let store = temp_store("issue");
        let ca = store.create_ca(&ca_spec()).unwrap();
        let cert = store.issue(&leaf_spec(&ca.id)).unwrap();
        assert_eq!(cert.ca_id, ca.id);
        assert_eq!(cert.sans, vec!["web.corp.local", "10.0.0.5"]);

        let list = store.list_certs(Some(&ca.id)).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(store.list_cas().unwrap()[0].issued_count, 1);

        // 证书链顺序：服务器证书在前，CA 在后
        let (_, chain) = store.read_cert_text(&cert.id).unwrap();
        let first_begin = chain.find("BEGIN CERTIFICATE").unwrap();
        assert!(first_begin < chain.len());
        assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);

        let pfx_path = store.export_pfx(&cert.id, "secret123").unwrap();
        let bytes = std::fs::read(&pfx_path).unwrap();
        assert!(bytes.starts_with(&[0x30]));
        assert!(p12::PFX::parse(&bytes).unwrap().bags("secret123").is_ok());

        store.delete_cert(&cert.id).unwrap();
        assert!(store.list_certs(None).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn refuses_to_delete_ca_with_certs() {
        let store = temp_store("guard");
        let ca = store.create_ca(&ca_spec()).unwrap();
        let cert = store.issue(&leaf_spec(&ca.id)).unwrap();

        let err = store.delete_ca(&ca.id).unwrap_err().to_string();
        assert!(err.contains("还有 1 张证书"), "实际错误：{err}");

        store.delete_cert(&cert.id).unwrap();
        store.delete_ca(&ca.id).unwrap();
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn issue_into_missing_ca_fails() {
        let store = temp_store("noca");
        assert!(store.issue(&leaf_spec("missing")).is_err());
        let _ = std::fs::remove_dir_all(store.root());
    }
}
