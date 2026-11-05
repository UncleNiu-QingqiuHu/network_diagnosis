//! 阿里云云解析 DNS（RPC 风格 API，签名版本 1.0）。
//!
//! 签名要点：
//! 1. 所有公共参数 + 业务参数按参数名排序，做 RFC 3986 编码后拼成 `k=v&k=v`；
//! 2. `StringToSign = "POST&%2F&" + 编码后的规范化查询串`；
//! 3. `Signature = Base64(HMAC-SHA1(AccessKeySecret + "&", StringToSign))`。
//!
//! AccessKey 需要 `AliyunDNSFullAccess`（或至少云解析的读、写权限）。

use super::{percent_encode, DnsCredentials};
use crate::AcmeError;
use serde_json::Value;
use std::collections::BTreeMap;

const ENDPOINT: &str = "https://alidns.aliyuncs.com/";
const API_VERSION: &str = "2015-01-09";

pub struct AliyunDns {
    creds: DnsCredentials,
    http: reqwest::Client,
}

impl AliyunDns {
    pub fn new(creds: DnsCredentials) -> Self {
        Self {
            creds,
            http: crate::http_client(),
        }
    }

    /// 发起一次 RPC 调用。
    async fn call(
        &self,
        action: &str,
        params: Vec<(&str, String)>,
    ) -> Result<Value, AcmeError> {
        let mut map: BTreeMap<String, String> = BTreeMap::new();
        map.insert("Action".into(), action.to_string());
        map.insert("Version".into(), API_VERSION.to_string());
        map.insert("Format".into(), "JSON".into());
        map.insert("AccessKeyId".into(), self.creds.access_key_id.clone());
        map.insert("SignatureMethod".into(), "HMAC-SHA1".into());
        map.insert("SignatureVersion".into(), "1.0".into());
        map.insert("SignatureNonce".into(), uuid::Uuid::new_v4().simple().to_string());
        map.insert(
            "Timestamp".into(),
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        );
        for (k, v) in params {
            map.insert(k.to_string(), v);
        }

        let canonical = canonical_query(&map);
        let signature = sign_rpc(&canonical, &self.creds.access_key_secret);
        let body = format!("{canonical}&Signature={}", percent_encode(&signature));

        let resp = self
            .http
            .post(ENDPOINT)
            .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| AcmeError::Dns(format!("请求阿里云 DNS 失败：{e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| AcmeError::Dns(format!("读取阿里云响应失败：{e}")))?;
        let json: Value = serde_json::from_str(&text).map_err(|_| {
            AcmeError::Dns(format!(
                "阿里云返回了非 JSON 响应（HTTP {status}）：{}",
                truncate(&text, 200)
            ))
        })?;

        // 出错时 SDK 与网关都会带 Code / Message 字段
        if let Some(code) = json.get("Code").and_then(Value::as_str) {
            let message = json
                .get("Message")
                .and_then(Value::as_str)
                .unwrap_or("（无描述）");
            return Err(AcmeError::Dns(format!("阿里云 DNS 报错：{code} — {message}")));
        }
        if !status.is_success() {
            return Err(AcmeError::Dns(format!(
                "阿里云 DNS 返回 HTTP {status}：{}",
                truncate(&text, 200)
            )));
        }
        Ok(json)
    }

    pub async fn list_zones(&self) -> Result<Vec<String>, AcmeError> {
        let mut out = Vec::new();
        let mut page = 1;
        loop {
            let json = self
                .call(
                    "DescribeDomains",
                    vec![
                        ("PageNumber", page.to_string()),
                        ("PageSize", "100".into()),
                    ],
                )
                .await?;

            let items = json
                .pointer("/Domains/Domain")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for item in &items {
                if let Some(name) = item.get("DomainName").and_then(Value::as_str) {
                    out.push(name.to_ascii_lowercase());
                }
            }
            let total = json
                .get("TotalCount")
                .and_then(Value::as_i64)
                .unwrap_or(out.len() as i64);
            if items.is_empty() || (out.len() as i64) >= total || page >= 20 {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    pub async fn add_txt(&self, zone: &str, rr: &str, value: &str) -> Result<String, AcmeError> {
        let json = self
            .call(
                "AddDomainRecord",
                vec![
                    ("DomainName", zone.to_string()),
                    ("RR", rr.to_string()),
                    ("Type", "TXT".into()),
                    ("Value", value.to_string()),
                    // 600 是各套餐都支持的最小 TTL，验证记录本来也是临时的
                    ("TTL", "600".into()),
                ],
            )
            .await?;
        json.get("RecordId")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .ok_or_else(|| AcmeError::Dns("阿里云未返回记录 ID。".into()))
    }

    /// 返回 `(记录 ID, 值)` 列表。
    pub async fn find_txt(
        &self,
        zone: &str,
        rr: &str,
    ) -> Result<Vec<(String, String)>, AcmeError> {
        let json = self
            .call(
                "DescribeDomainRecords",
                vec![
                    ("DomainName", zone.to_string()),
                    ("RRKeyWord", rr.to_string()),
                    ("Type", "TXT".into()),
                    ("PageSize", "100".into()),
                ],
            )
            .await?;
        let items = json
            .pointer("/DomainRecords/Record")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        for item in items {
            let id = item.get("RecordId").and_then(Value::as_str).unwrap_or_default();
            let name = item.get("RR").and_then(Value::as_str).unwrap_or_default();
            let value = item.get("Value").and_then(Value::as_str).unwrap_or_default();
            // RRKeyWord 是模糊匹配，这里必须再精确比一次
            if name.eq_ignore_ascii_case(rr) && !id.is_empty() {
                out.push((id.to_string(), unquote(value)));
            }
        }
        Ok(out)
    }

    pub async fn delete_record(&self, record_id: &str) -> Result<(), AcmeError> {
        self.call("DeleteDomainRecord", vec![("RecordId", record_id.to_string())])
            .await?;
        Ok(())
    }
}

/// 去掉 TXT 值外层可能存在的引号。
pub fn unquote(value: &str) -> String {
    let v = value.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// 规范化查询串：按 key 排序，key/value 都做 RFC 3986 编码。
pub fn canonical_query(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// 计算签名。独立成函数便于用固定输入做单测。
pub fn sign_rpc(canonical_query: &str, secret: &str) -> String {
    sign_rpc_with("POST", canonical_query, secret)
}

/// 指定 HTTP 方法的签名实现。
///
/// 实际调用固定用 POST，单独暴露方法名是为了能用官方文档的 GET 样例做校验。
pub fn sign_rpc_with(method: &str, canonical_query: &str, secret: &str) -> String {
    use base64::Engine;
    let string_to_sign = format!("{method}&%2F&{}", percent_encode(canonical_query));
    // 阿里云的规则是「Secret + &」整体作为 HMAC 密钥
    let material = format!("{secret}&");
    let key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        material.as_bytes(),
    );
    let tag = ring::hmac::sign(&key, string_to_sign.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn canonical_query_is_sorted_and_encoded() {
        let q = canonical_query(&map(&[
            ("Type", "TXT"),
            ("Action", "AddDomainRecord"),
            ("Value", "a b"),
        ]));
        assert_eq!(q, "Action=AddDomainRecord&Type=TXT&Value=a%20b");
    }

    #[test]
    fn signature_is_stable_for_fixed_input() {
        // 同样的输入必须得到同样的签名，否则重试会失败
        let a = sign_rpc("Action=DescribeDomains&Version=2015-01-09", "secret");
        let b = sign_rpc("Action=DescribeDomains&Version=2015-01-09", "secret");
        assert_eq!(a, b);
        assert_ne!(a, sign_rpc("Action=DescribeDomains&Version=2015-01-09", "other"));
        // Base64 编码的 HMAC-SHA1 固定为 28 字节
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD.decode(a).unwrap();
        assert_eq!(raw.len(), 20);
    }

    #[test]
    fn matches_official_signature_sample() {
        // 阿里云官方文档的签名示例（ECS DescribeRegions）。
        // 用 GET 方法，签名结果固定为 OLeaidS1JvxuMvnyHOwuJ+uX5qY=；
        // 这个用例能把「排序 / 编码 / 密钥拼接 / Base64」四个环节一起锁住。
        let params = map(&[
            ("Timestamp", "2016-02-23T12:46:24Z"),
            ("Format", "XML"),
            ("AccessKeyId", "testid"),
            ("Action", "DescribeRegions"),
            ("SignatureMethod", "HMAC-SHA1"),
            ("SignatureNonce", "3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf"),
            ("Version", "2014-05-26"),
            ("SignatureVersion", "1.0"),
        ]);
        let sig = sign_rpc_with("GET", &canonical_query(&params), "testsecret");
        assert_eq!(sig, "OLeaidS1JvxuMvnyHOwuJ+uX5qY=");
    }

    #[test]
    fn unquotes_txt_value() {
        assert_eq!(unquote("\"abc\""), "abc");
        assert_eq!(unquote("abc"), "abc");
        assert_eq!(unquote(" \"abc\" "), "abc");
    }
}
