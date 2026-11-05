//! 腾讯云 DNSPod（API 3.0 风格，TC3-HMAC-SHA256 签名）。
//!
//! 签名要点：
//! 1. 先拼规范化请求 `CanonicalRequest`（方法 / 路径 / 查询串 / 头部 / 签名头 / 载荷哈希）；
//! 2. `StringToSign` 再套一层时间戳与服务名；
//! 3. 密钥逐级派生：`TC3+SecretKey` → 日期 → 服务名 → `tc3_request`。
//!
//! AccessKey 需要 DNSPod 的读写权限（QcloudDNSPodFullAccess）。

use super::DnsCredentials;
use crate::AcmeError;
use serde_json::{json, Value};

const ENDPOINT: &str = "https://dnspod.tencentcloudapi.com/";
const HOST: &str = "dnspod.tencentcloudapi.com";
const SERVICE: &str = "dnspod";
const API_VERSION: &str = "2021-03-23";
const CONTENT_TYPE: &str = "application/json; charset=utf-8";
const SIGNED_HEADERS: &str = "content-type;host;x-tc-action";

pub struct TencentDns {
    creds: DnsCredentials,
    http: reqwest::Client,
}

impl TencentDns {
    pub fn new(creds: DnsCredentials) -> Self {
        Self {
            creds,
            http: crate::http_client(),
        }
    }

    async fn call(&self, action: &str, payload: Value) -> Result<Value, AcmeError> {
        let body = serde_json::to_string(&payload)
            .map_err(|e| AcmeError::Dns(format!("构造请求失败：{e}")))?;
        let timestamp = chrono::Utc::now().timestamp();
        let date = chrono::DateTime::from_timestamp(timestamp, 0)
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());

        let canonical_request = canonical_request(action, &body);
        let string_to_sign = string_to_sign(timestamp, &date, &canonical_request);
        let signature = sign_tc3(&self.creds.access_key_secret, &date, &string_to_sign);

        let authorization = format!(
            "TC3-HMAC-SHA256 Credential={}/{}/{}/tc3_request, SignedHeaders={}, Signature={}",
            self.creds.access_key_id, date, SERVICE, SIGNED_HEADERS, signature
        );

        let resp = self
            .http
            .post(ENDPOINT)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE)
            .header("X-TC-Action", action)
            .header("X-TC-Timestamp", timestamp.to_string())
            .header("X-TC-Version", API_VERSION)
            .body(body)
            .send()
            .await
            .map_err(|e| AcmeError::Dns(format!("请求腾讯云 DNSPod 失败：{e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| AcmeError::Dns(format!("读取腾讯云响应失败：{e}")))?;
        let json: Value = serde_json::from_str(&text).map_err(|_| {
            AcmeError::Dns(format!(
                "腾讯云返回了非 JSON 响应（HTTP {status}）：{}",
                truncate(&text, 200)
            ))
        })?;

        let response = json.get("Response").cloned().unwrap_or(Value::Null);
        if let Some(err) = response.get("Error") {
            let code = err.get("Code").and_then(Value::as_str).unwrap_or("Unknown");
            let message = err.get("Message").and_then(Value::as_str).unwrap_or("（无描述）");
            return Err(AcmeError::Dns(format!("腾讯云 DNSPod 报错：{code} — {message}")));
        }
        if !status.is_success() {
            return Err(AcmeError::Dns(format!(
                "腾讯云 DNSPod 返回 HTTP {status}：{}",
                truncate(&text, 200)
            )));
        }
        Ok(response)
    }

    pub async fn list_zones(&self) -> Result<Vec<String>, AcmeError> {
        let mut out = Vec::new();
        let mut offset = 0;
        loop {
            let resp = self
                .call(
                    "DescribeDomainList",
                    json!({ "Offset": offset, "Limit": 100 }),
                )
                .await?;
            let items = resp
                .get("DomainList")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for item in &items {
                if let Some(name) = item.get("Name").and_then(Value::as_str) {
                    out.push(name.to_ascii_lowercase());
                }
            }
            let total = resp
                .pointer("/DomainCountInfo/AllTotal")
                .and_then(Value::as_i64)
                .unwrap_or(out.len() as i64);
            if items.is_empty() || (out.len() as i64) >= total || offset >= 2000 {
                break;
            }
            offset += items.len() as i64;
        }
        Ok(out)
    }

    pub async fn add_txt(&self, zone: &str, rr: &str, value: &str) -> Result<String, AcmeError> {
        let resp = self
            .call(
                "CreateRecord",
                json!({
                    "Domain": zone,
                    "Subdomain": rr,
                    "RecordType": "TXT",
                    // 默认线路即可；显式指定可以避免某些账号把线路置空
                    "RecordLine": "默认",
                    "Value": value,
                    "TTL": 600
                }),
            )
            .await?;
        resp.get("RecordId")
            .map(record_id_to_string)
            .ok_or_else(|| AcmeError::Dns("腾讯云未返回记录 ID。".into()))
    }

    pub async fn find_txt(
        &self,
        zone: &str,
        rr: &str,
    ) -> Result<Vec<(String, String)>, AcmeError> {
        let resp = self
            .call(
                "DescribeRecordList",
                json!({
                    "Domain": zone,
                    "Subdomain": rr,
                    "RecordType": "TXT",
                    "Limit": 100
                }),
            )
            .await?;
        let items = resp
            .get("RecordList")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        for item in items {
            let name = item.get("Name").and_then(Value::as_str).unwrap_or_default();
            let value = item.get("Value").and_then(Value::as_str).unwrap_or_default();
            if let Some(id) = item.get("RecordId") {
                // 服务端过滤已经足够，这里再精确比一次名字，防止模糊匹配
                if name.eq_ignore_ascii_case(rr) {
                    out.push((record_id_to_string(id), super::aliyun::unquote(value)));
                }
            }
        }
        Ok(out)
    }

    pub async fn delete_record(&self, zone: &str, record_id: &str) -> Result<(), AcmeError> {
        let id: u64 = record_id
            .parse()
            .map_err(|_| AcmeError::Dns(format!("记录 ID 不是数字：{record_id}")))?;
        self.call("DeleteRecord", json!({ "Domain": zone, "RecordId": id }))
            .await?;
        Ok(())
    }
}

/// 记录 ID 有时是数字、有时是字符串，统一转成字符串使用。
fn record_id_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    hex::encode(digest.as_ref())
}

/// 规范化请求串。抽成独立函数是为了能用固定输入做断言。
pub fn canonical_request(action: &str, body: &str) -> String {
    format!(
        "POST\n/\n\ncontent-type:{CONTENT_TYPE}\nhost:{HOST}\nx-tc-action:{}\n\n{SIGNED_HEADERS}\n{}",
        action.to_ascii_lowercase(),
        sha256_hex(body.as_bytes())
    )
}

pub fn string_to_sign(timestamp: i64, date: &str, canonical_request: &str) -> String {
    format!(
        "TC3-HMAC-SHA256\n{timestamp}\n{date}/{SERVICE}/tc3_request\n{}",
        sha256_hex(canonical_request.as_bytes())
    )
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&k, data).as_ref().to_vec()
}

/// 逐级派生密钥并签名，返回小写十六进制。
pub fn sign_tc3(secret_key: &str, date: &str, string_to_sign: &str) -> String {
    let secret_date = hmac_sha256(format!("TC3{secret_key}").as_bytes(), date.as_bytes());
    let secret_service = hmac_sha256(&secret_date, SERVICE.as_bytes());
    let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
    hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_request_has_exact_shape() {
        let cr = canonical_request("DescribeDomainList", "{}");
        let expected = format!(
            "POST\n/\n\ncontent-type:application/json; charset=utf-8\n\
             host:dnspod.tencentcloudapi.com\nx-tc-action:describedomainlist\n\n\
             content-type;host;x-tc-action\n{}",
            sha256_hex(b"{}")
        );
        assert_eq!(cr, expected);
        // 头部之后必须有一个空行，少了它腾讯云会直接签名不匹配
        assert!(cr.contains("\n\ncontent-type;host;x-tc-action\n"));
    }

    #[test]
    fn string_to_sign_includes_date_and_service() {
        let sts = string_to_sign(1_700_000_000, "2023-11-14", "CR");
        assert!(sts.starts_with("TC3-HMAC-SHA256\n1700000000\n2023-11-14/dnspod/tc3_request\n"));
        assert_eq!(sts.lines().count(), 4);
    }

    #[test]
    fn signature_is_64_hex_chars_and_deterministic() {
        let sig = sign_tc3("secret", "2023-11-14", "STS");
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(sig, sign_tc3("secret", "2023-11-14", "STS"));
        assert_ne!(sig, sign_tc3("secret", "2023-11-15", "STS"));
    }

    #[test]
    fn signature_matches_independent_implementation() {
        // 用 Python 独立实现同一套 TC3 流程算出的值，
        // 防止「自己算、自己验」那种永远通过的测试。
        let body = r#"{"Limit":100,"Offset":0}"#;
        let cr = canonical_request("DescribeDomainList", body);
        let sts = string_to_sign(1_700_000_000, "2023-11-14", &cr);
        let sig = sign_tc3("testsecret", "2023-11-14", &sts);
        assert_eq!(
            sig,
            "ea7e9e8a9d54e8a785dc7ac7609c00f333c445caba1584af5f93c63775c19353"
        );
    }

    #[test]
    fn record_id_handles_number_and_string() {
        assert_eq!(record_id_to_string(&json!(123)), "123");
        assert_eq!(record_id_to_string(&json!("456")), "456");
    }
}
