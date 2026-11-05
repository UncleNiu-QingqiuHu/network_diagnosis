//! 证书库：账户凭据与签发结果落盘。
//!
//! 布局（`<安装目录>/pki/acme/`）：
//! ```text
//! accounts/<hash>.json    ACME 账户凭据（含账户私钥，按目录地址区分）
//! certs/<id>/cert.pem     站点证书（仅叶子）
//! certs/<id>/chain.pem    完整链（叶子 + 中间证书），Nginx 直接用
//! certs/<id>/key.pem      私钥（PKCS#8）
//! certs/<id>/cert.pfx     按需导出的 PKCS#12
//! certs/<id>/meta.json    元信息
//! ```
//!
//! 账户是「目录地址」维度的：Let's Encrypt 正式与测试环境是两套独立账户，
//! 混用会报 key 不匹配。

use crate::model::AcmeCertMeta;
use crate::AcmeError;
use std::path::{Path, PathBuf};

pub struct AcmeStore {
    root: PathBuf,
}

fn new_id() -> String {
    let s = uuid::Uuid::new_v4().simple().to_string();
    s[..12].to_string()
}

impl AcmeStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn cert_dir(&self, id: &str) -> PathBuf {
        self.root.join("certs").join(id)
    }

    fn ensure_dirs(&self) -> Result<(), AcmeError> {
        for sub in ["accounts", "certs"] {
            std::fs::create_dir_all(self.root.join(sub))
                .map_err(|e| AcmeError::Io(format!("创建目录失败：{e}")))?;
        }
        Ok(())
    }

    /// 账户文件名由目录地址派生：同一地址稳定命中同一个文件。
    pub fn account_path(&self, directory: &str) -> PathBuf {
        let digest = ring::digest::digest(&ring::digest::SHA256, directory.as_bytes());
        let hash = hex::encode(&digest.as_ref()[..8]);
        self.root.join("accounts").join(format!("{hash}.json"))
    }

    pub fn load_account(
        &self,
        directory: &str,
    ) -> Option<instant_acme::AccountCredentials> {
        let text = std::fs::read_to_string(self.account_path(directory)).ok()?;
        let json: serde_json::Value = serde_json::from_str(&text).ok()?;
        serde_json::from_value(json.get("credentials")?.clone()).ok()
    }

    pub fn save_account(
        &self,
        directory: &str,
        credentials: &instant_acme::AccountCredentials,
    ) -> Result<(), AcmeError> {
        self.ensure_dirs()?;
        let payload = serde_json::json!({
            "directory": directory,
            "credentials": credentials,
        });
        let text = serde_json::to_string_pretty(&payload)
            .map_err(|e| AcmeError::Io(format!("序列化账户凭据失败：{e}")))?;
        std::fs::write(self.account_path(directory), text)
            .map_err(|e| AcmeError::Io(format!("保存账户凭据失败：{e}")))
    }

    /// 保存一次签发的全部产物。
    pub fn save_cert(
        &self,
        meta: &AcmeCertMeta,
        cert_pem: &str,
        key_pem: &str,
        chain_pem: &str,
    ) -> Result<(), AcmeError> {
        self.ensure_dirs()?;
        let dir = self.cert_dir(&meta.id);
        std::fs::create_dir_all(&dir).map_err(|e| AcmeError::Io(format!("创建目录失败：{e}")))?;
        std::fs::write(dir.join("cert.pem"), cert_pem)
            .map_err(|e| AcmeError::Io(format!("写入证书失败：{e}")))?;
        std::fs::write(dir.join("key.pem"), key_pem)
            .map_err(|e| AcmeError::Io(format!("写入私钥失败：{e}")))?;
        std::fs::write(dir.join("chain.pem"), chain_pem)
            .map_err(|e| AcmeError::Io(format!("写入证书链失败：{e}")))?;
        let text = serde_json::to_string_pretty(meta)
            .map_err(|e| AcmeError::Io(format!("序列化元信息失败：{e}")))?;
        std::fs::write(dir.join("meta.json"), text)
            .map_err(|e| AcmeError::Io(format!("写入元信息失败：{e}")))
    }

    /// 列出全部证书，按创建时间倒序，并刷新剩余天数。
    pub fn list(&self) -> Vec<AcmeCertMeta> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(self.root.join("certs")) else {
            return out;
        };
        let now = chrono::Utc::now();
        for entry in entries.flatten() {
            let path = entry.path().join("meta.json");
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            if let Ok(mut meta) = serde_json::from_str::<AcmeCertMeta>(&text) {
                meta.refresh(now);
                out.push(meta);
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        out
    }

    pub fn delete(&self, id: &str) -> Result<(), AcmeError> {
        let dir = self.cert_dir(id);
        if !dir.exists() {
            return Err(AcmeError::Invalid(format!("找不到证书 {id}")));
        }
        std::fs::remove_dir_all(&dir).map_err(|e| AcmeError::Io(format!("删除失败：{e}")))
    }

    /// 读取单张证书的元信息（不刷新剩余天数）。
    pub fn get(&self, id: &str) -> Option<AcmeCertMeta> {
        let text = std::fs::read_to_string(self.cert_dir(id).join("meta.json")).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// 只更新元信息，不动证书文件。
    ///
    /// 自动续期失败时把原因写回，让界面能显示「上次失败：xxx」，
    /// 同时作为退避判定的依据。
    pub fn update_meta(&self, meta: &AcmeCertMeta) -> Result<(), AcmeError> {
        let dir = self.cert_dir(&meta.id);
        if !dir.exists() {
            return Err(AcmeError::Invalid(format!("找不到证书 {}", meta.id)));
        }
        let text = serde_json::to_string_pretty(meta)
            .map_err(|e| AcmeError::Io(format!("序列化元信息失败：{e}")))?;
        std::fs::write(dir.join("meta.json"), text)
            .map_err(|e| AcmeError::Io(format!("写入元信息失败：{e}")))
    }

    /// 读取证书 / 私钥 / 完整链。
    pub fn read_texts(&self, id: &str) -> Result<(String, String, String), AcmeError> {
        let dir = self.cert_dir(id);
        let read = |name: &str| -> Result<String, AcmeError> {
            std::fs::read_to_string(dir.join(name))
                .map_err(|e| AcmeError::Io(format!("读取 {name} 失败：{e}")))
        };
        Ok((read("cert.pem")?, read("key.pem")?, read("chain.pem")?))
    }

    /// 导出 PKCS#12：打包叶子证书、私钥与中间证书。
    pub fn export_pfx(&self, id: &str, password: &str) -> Result<String, AcmeError> {
        if password.len() < 4 {
            return Err(AcmeError::Invalid(
                "PFX 口令至少 4 位：Windows 导入时对空口令兼容性很差。".into(),
            ));
        }
        let dir = self.cert_dir(id);
        let (cert_pem, key_pem, chain_pem) = self.read_texts(id)?;
        let cert_der = pem_to_der(&cert_pem)?;
        let key_der = pem_to_der(&key_pem)?;
        // 链里最后一张通常是中间证书，作为 pfx 的 CA 一起打包
        let ca_der = split_pem(&chain_pem)
            .into_iter()
            .skip(1)
            .last()
            .map(|block| pem_to_der(&block))
            .transpose()?;

        let pfx = p12::PFX::new(&cert_der, &key_der, ca_der.as_deref(), password, id)
            .ok_or(AcmeError::Cert("PKCS#12 打包失败。".into()))?;
        let path = dir.join("cert.pfx");
        std::fs::write(&path, pfx.to_der())
            .map_err(|e| AcmeError::Io(format!("写入 PFX 失败：{e}")))?;
        Ok(path.to_string_lossy().to_string())
    }

    /// 生成一个不重复的证书 ID。
    pub fn next_id(&self) -> String {
        new_id()
    }
}

/// 把 PEM 拆成独立的块（每块含头尾行）。
pub fn split_pem(pem: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    for line in pem.lines() {
        if line.starts_with("-----BEGIN") {
            current.clear();
        }
        if !current.is_empty() {
            current.push('\n');
        }
        current.push_str(line);
        if line.starts_with("-----END") {
            current.push('\n');
            blocks.push(current.clone());
            current.clear();
        }
    }
    blocks
}

/// PEM → DER。
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, AcmeError> {
    use base64::Engine;
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| AcmeError::Cert(format!("PEM 解码失败：{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(tag: &str) -> AcmeStore {
        let dir = std::env::temp_dir().join(format!("qqhu-acme-test-{tag}-{}", new_id()));
        AcmeStore::new(dir)
    }

    fn meta(id: &str) -> AcmeCertMeta {
        let now = chrono::Utc::now();
        AcmeCertMeta {
            id: id.into(),
            primary_domain: "test.example.com".into(),
            domains: vec!["test.example.com".into()],
            directory: "https://acme.example/directory".into(),
            staging: false,
            provider: "测试".into(),
            serial: "0a1b".into(),
            fingerprint: "AA:BB".into(),
            created_at: now,
            not_before: now,
            not_after: now + chrono::Duration::days(90),
            days_remaining: 90,
            auto_renew: false,
            provider_key: "aliyun".into(),
            renew_count: 0,
            last_attempt_at: None,
            last_error: None,
            renewed_at: None,
        }
    }

    /// 造一张真证书，避免测试里全是假 PEM。
    fn make_cert() -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn saves_lists_and_deletes() {
        let store = temp_store("list");
        let (cert, key) = make_cert();
        let chain = format!("{cert}{cert}");
        let m = meta("abc123");
        store.save_cert(&m, &cert, &key, &chain).unwrap();

        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "abc123");
        assert_eq!(list[0].domains, vec!["test.example.com"]);

        let (c, k, ch) = store.read_texts("abc123").unwrap();
        assert!(c.contains("BEGIN CERTIFICATE"));
        assert!(k.contains("PRIVATE KEY"));
        assert_eq!(split_pem(&ch).len(), 2);

        store.delete("abc123").unwrap();
        assert!(store.list().is_empty());
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn account_file_is_scoped_by_directory() {
        let store = temp_store("acct");
        let a = store.account_path("https://acme-v02.api.letsencrypt.org/directory");
        let b = store.account_path("https://acme-staging-v02.api.letsencrypt.org/directory");

        // 正式与测试环境是两套独立账户，绝不能落到同一个文件
        assert_ne!(a, b);
        assert_eq!(
            a,
            store.account_path("https://acme-v02.api.letsencrypt.org/directory")
        );
        // 未登录过时不应有文件
        assert!(store
            .load_account("https://acme-v02.api.letsencrypt.org/directory")
            .is_none());
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn update_meta_keeps_cert_files() {
        let store = temp_store("meta");
        let (cert, key) = make_cert();
        store.save_cert(&meta("m1"), &cert, &key, &cert).unwrap();

        let mut m = store.get("m1").unwrap();
        m.auto_renew = true;
        m.last_error = Some("上次失败".into());
        store.update_meta(&m).unwrap();

        let again = store.get("m1").unwrap();
        assert!(again.auto_renew);
        assert_eq!(again.last_error.as_deref(), Some("上次失败"));
        // 证书文件不受影响
        assert!(store.read_texts("m1").is_ok());

        // 不存在的 id 必须报错，避免静默丢更新
        let mut ghost = again.clone();
        ghost.id = "nope".into();
        assert!(store.update_meta(&ghost).is_err());
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn exports_pfx() {
        let store = temp_store("pfx");
        let (cert, key) = make_cert();
        store
            .save_cert(&meta("pfx1"), &cert, &key, &cert)
            .unwrap();
        let path = store.export_pfx("pfx1", "secret123").unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.first(), Some(&0x30));
        assert!(p12::PFX::parse(&bytes).unwrap().bags("secret123").is_ok());
        // 口令错误必须解不开，否则等于没加密
        assert!(p12::PFX::parse(&bytes).unwrap().bags("wrong").is_err());

        assert!(store.export_pfx("pfx1", "").is_err());
        let _ = std::fs::remove_dir_all(store.root());
    }

    #[test]
    fn split_pem_keeps_order_and_count() {
        let (cert, _) = make_cert();
        let joined = format!("{cert}{cert}{cert}");
        let blocks = split_pem(&joined);
        assert_eq!(blocks.len(), 3);
        for b in blocks {
            assert!(b.starts_with("-----BEGIN CERTIFICATE-----"));
            assert!(b.ends_with("-----\n"));
        }
    }
}
