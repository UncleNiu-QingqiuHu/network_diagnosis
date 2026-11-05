//! API Key 保管与 HTTP 客户端。
//!
//! Key 一律进系统凭据管理器，配置 JSON 里只留模型元信息；
//! 条目名 `model:<id>`，用户可以在系统凭据管理器里按前缀辨认。

pub use qqhu_secret::SecretStore;

/// 与 ACME 共用同一个服务名，条目名区分功能。
pub const SERVICE: &str = "qingqiuhu-network-workbench";

/// 模型的 Key 条目名。
pub fn model_key(model_id: &str) -> String {
    format!("model:{model_id}")
}

/// 构造凭据存储。`fallback_dir` 只在没有凭据管理器的平台用得上。
pub fn store(fallback_dir: impl Into<std::path::PathBuf>) -> SecretStore {
    SecretStore::new(SERVICE, fallback_dir)
}

/// 全局复用的 HTTP 客户端（连接池复用，避免每次对话重新握手）。
pub fn http_client() -> reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            // reqwest 用的是「不自带加密后端」的构建，必须显式安装 ring provider
            let _ = rustls::crypto::ring::default_provider().install_default();
            reqwest::Client::builder()
                .user_agent(concat!("qqhu-agent/", env!("CARGO_PKG_VERSION")))
                .connect_timeout(std::time::Duration::from_secs(15))
                // 流式响应要留足时间，但仍要有兜底，避免界面永远转圈
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .unwrap_or_default()
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names_are_prefixed() {
        assert_eq!(model_key("abc"), "model:abc");
    }

    #[test]
    fn client_is_reusable() {
        let a = http_client();
        let b = http_client();
        // 同一个 OnceLock 里取出来的应该是同一份
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }
}
