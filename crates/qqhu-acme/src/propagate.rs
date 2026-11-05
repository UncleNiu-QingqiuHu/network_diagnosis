//! TXT 记录的传播确认。
//!
//! 记录写进服务商 API 不等于全网可见：权威 DNS 有缓存，递归解析器也有 TTL。
//! 直接调 `set_ready()` 让 Let's Encrypt 去查，失败后整单就废了，
//! 所以先自己查一遍，查到再交给 CA。

use std::time::Duration;

/// 依次尝试的 DoH 端点。
///
/// 优先国内（阿里公共 DNS），失败再走 Cloudflare —— 只用一个源时，
/// 该源故障会让所有签发卡住。
const DOH_ENDPOINTS: [&str; 2] = [
    "https://dns.alidns.com/resolve",
    "https://cloudflare-dns.com/dns-query",
];

/// 查询一次，判断 TXT 值是否已出现在权威应答里。
pub async fn txt_present(fqdn: &str, expected: &str) -> bool {
    let client = crate::http_client();
    for endpoint in DOH_ENDPOINTS {
        let resp = client
            .get(endpoint)
            .query(&[("name", fqdn), ("type", "TXT")])
            .header(reqwest::header::ACCEPT, "application/dns-json")
            .send()
            .await;
        let Ok(resp) = resp else { continue };
        let Ok(json) = resp.json::<serde_json::Value>().await else {
            continue;
        };
        let Some(answers) = json.get("Answer").and_then(|v| v.as_array()) else {
            continue;
        };
        for answer in answers {
            // type 16 = TXT
            if answer.get("type").and_then(|t| t.as_u64()) != Some(16) {
                continue;
            }
            if let Some(data) = answer.get("data").and_then(|d| d.as_str()) {
                if unquote(data) == expected {
                    return true;
                }
            }
        }
    }
    false
}

/// 轮询等待 TXT 生效，返回是否在超时前看到。
pub async fn wait_for_txt(fqdn: &str, expected: &str, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if txt_present(fqdn, expected).await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

fn unquote(value: &str) -> &str {
    let v = value.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        &v[1..v.len() - 1]
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unquotes_doh_txt_payload() {
        assert_eq!(unquote("\"abc\""), "abc");
        assert_eq!(unquote("abc"), "abc");
        // 长的 TXT 会被拆成多段，这里只保证不 panic
        assert_eq!(unquote("\"a\" \"b\""), "a\" \"b");
    }
}
