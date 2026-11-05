//! 青丘湖网络工作台 —— 私有 CA 与证书签发。
//!
//! 三层职责：
//! - [`model`]：输入校验与数据结构（纯逻辑，可单测）
//! - [`issue`]：用 rcgen 生成密钥与证书、打包 PKCS#12（不碰文件）
//! - [`store`]：目录布局与元信息持久化
//!
//! 暂不支持 RSA 密钥：rcgen 的 ring 后端只能生成 ECDSA P-256 与 Ed25519，
//! RSA 需要 aws-lc-rs 后端（额外编译依赖 cmake / nasm），留待确有需要时再引入。

pub mod issue;
pub mod model;
pub mod store;

pub use model::{
    normalize_sans, validate_ca, validate_cert, CaMeta, CaSpec, CertMeta, CertSpec, CertUsage,
    KeyAlgorithm, DEFAULT_CA_DAYS, DEFAULT_LEAF_DAYS, MAX_CA_DAYS, MAX_LEAF_DAYS,
};
pub use store::{CaPaths, CertPaths, PkiStore};

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("密钥生成失败：{0}")]
    Key(String),

    #[error("证书生成失败：{0}")]
    Cert(String),

    #[error("CA 证书或私钥无法使用：{0}")]
    CaLoad(String),

    #[error("PKCS#12 打包失败")]
    Pfx,

    #[error("{0}")]
    Invalid(String),

    #[error("{0}")]
    Io(String),
}
