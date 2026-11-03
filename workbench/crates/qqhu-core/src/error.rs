//! 统一错误类型。所有对外文案保持中文，便于与旧版报告逐句对拍。

use thiserror::Error;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("IP 须为合法的点分 IPv4：{0}")]
    InvalidIpv4(String),

    #[error("子网掩码须为点分十进制 IPv4：{0}")]
    InvalidNetmask(String),

    #[error("前缀长度须在 0–32 之间：{0}")]
    InvalidPrefix(i64),

    #[error("请填写前缀长度或子网掩码。")]
    MissingPrefix,

    #[error("当前仅支持 IPv4。")]
    Ipv6Unsupported,

    #[error("父网 CIDR 无效：{0}")]
    InvalidParentCidr(String),

    #[error("子网前缀须大于父网前缀 /{0}。")]
    ChildPrefixTooSmall(u8),

    #[error("请使用 \"IP/前缀\" 或 \"IP/掩码\" 格式，或改用「单地址 + 子网」拆分填写。")]
    BadCidrCombo,
}
