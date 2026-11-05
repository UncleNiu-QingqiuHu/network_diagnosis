//! TLS 证书探测。
//!
//! 做两件事：
//! 1. 用**系统根证书**正常握手，判断目标证书链是否被本机信任；
//! 2. 不论信任与否，都取出完整证书链做解析（自签、过期、域名不符的证书也能看）。
//!
//! 第 2 步用一个「接受任意证书」的校验器单独连一次 —— 只读取证书，不做任何
//! 受影响的操作，连接随即关闭。这样排查线上证书问题不必先受浏览器/客户端阻拦。

use chrono::{DateTime, Utc};
use qqhu_core::sslcert::{assess, build_warnings, hostname_matches, CertInfo, CertStatus, SslCheckReport};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

/// 默认 HTTPS 端口。
pub const DEFAULT_TLS_PORT: u16 = 443;

#[derive(Debug, Clone, Copy)]
pub struct SslCheckOptions {
    pub timeout_ms: u64,
}

impl Default for SslCheckOptions {
    fn default() -> Self {
        Self { timeout_ms: 8000 }
    }
}

/// 解析用户输入的目标。
///
/// 接受：`example.com`、`example.com:8443`、`https://example.com/a/b`、
/// `https://example.com:8443`、`192.168.1.1`、`[::1]:443`。
/// 非 443 端口必须在输入里写明。
pub fn parse_target(input: &str) -> Result<(String, u16), String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("请填写目标域名或 IP。".into());
    }

    // 去掉协议与路径，只留 host[:port]
    let mut s = raw;
    for scheme in ["https://", "http://", "wss://"] {
        if let Some(rest) = s.strip_prefix(scheme) {
            s = rest;
            break;
        }
    }
    let s = s.split(['/', '?', '#']).next().unwrap_or("").trim();
    if s.is_empty() {
        return Err(format!("无法从「{raw}」中解析出主机名。"));
    }

    // 主机名与端口拆分。IPv6 有两种写法，必须单独处理，
    // 否则 `::1` 会被 `rsplit_once(':')` 误拆成主机 `::` 加端口 `1`。
    let (host, port): (String, u16) = if let Some(rest) = s.strip_prefix('[') {
        // 形如 [::1]:443 或 [::1]
        let (inside, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("IPv6 地址缺少右括号：{s}"))?;
        let port = match after.strip_prefix(':') {
            Some(p) if !p.is_empty() => p
                .parse::<u16>()
                .map_err(|_| format!("端口无效：{p}"))?,
            _ => DEFAULT_TLS_PORT,
        };
        (inside.to_string(), port)
    } else if s.matches(':').count() > 1 {
        // 裸 IPv6 字面量，不带端口
        (s.to_string(), DEFAULT_TLS_PORT)
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                let port: u16 = p.parse().map_err(|_| format!("端口无效：{p}"))?;
                (h.to_string(), port)
            }
            _ => (s.to_string(), DEFAULT_TLS_PORT),
        }
    };

    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(format!("无法从「{raw}」中解析出主机名。"));
    }
    if port == 0 {
        return Err("端口必须大于 0。".into());
    }
    Ok((host.to_ascii_lowercase(), port))
}

static PROVIDER_INIT: Once = Once::new();

fn ensure_provider() {
    PROVIDER_INIT.call_once(|| {
        // 已安装过时 install_default 返回 Err，属正常情况，忽略即可
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// 接受任意服务器证书的校验器：仅用于「读取证书内容」这条只读路径。
#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn insecure_config() -> Arc<rustls::ClientConfig> {
    ensure_provider();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("默认协议版本应当可用")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    Arc::new(cfg)
}

fn trusted_config() -> Arc<rustls::ClientConfig> {
    ensure_provider();
    let mut roots = rustls::RootCertStore::empty();

    // 系统根：Windows 证书存储 / macOS Keychain / Linux ca-certificates。
    // 企业内网自建根证书若已装入系统，这里同样会信任。
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }

    // Mozilla 根：主流浏览器（Chrome / Edge / Firefox）用的是自带根存储，
    // 新根证书往往先进入 Mozilla 列表，Windows 系统的根列表要等系统更新才跟进。
    // 只认系统根会把浏览器正常访问的站点误判为「不受信任」，两套取并集更贴近真实体验。
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
}

struct Handshake {
    chain: Vec<CertificateDer<'static>>,
    tls_version: String,
    cipher_suite: String,
}

async fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
    match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
        Err(_) => Err(format!("连接 {host}:{port} 超时（{} ms）。", timeout.as_millis())),
        Ok(Err(e)) => Err(format!("无法连接 {host}:{port}：{e}")),
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
    }
}

async fn handshake(
    host: &str,
    port: u16,
    cfg: Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> Result<Handshake, String> {
    let stream = connect(host, port, timeout).await?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| format!("主机名「{host}」不是合法的 TLS 服务器名。"))?;

    let connector = TlsConnector::from(cfg);
    let fut = connector.connect(server_name, stream);
    let conn = match tokio::time::timeout(timeout, fut).await {
        Err(_) => return Err(format!("TLS 握手超时（{} ms）。", timeout.as_millis())),
        Ok(Err(e)) => return Err(format!("TLS 握手失败：{e}")),
        Ok(Ok(c)) => c,
    };

    let (_, session) = conn.get_ref();
    let tls_version = session
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".into());
    let cipher_suite = session
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "unknown".into());
    let chain = session.peer_certificates().map(|c| c.to_vec()).unwrap_or_default();

    Ok(Handshake {
        chain,
        tls_version,
        cipher_suite,
    })
}

/// 检查一个目标的证书。返回结构化报告；连接层面的失败以 `Err` 返回。
pub async fn check_certificate(
    input: &str,
    opts: SslCheckOptions,
) -> Result<SslCheckReport, String> {
    let started = Instant::now();
    let (host, port) = parse_target(input)?;
    let timeout = Duration::from_millis(opts.timeout_ms.clamp(1000, 30_000));

    // 先取一次解析结果，报告里展示实际连的 IP
    let remote_ip = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| format!("解析 {host} 失败：{e}"))?
        .next()
        .map(|s| s.ip().to_string())
        .unwrap_or_else(|| "unknown".into());

    // 信任校验与取证书分开两次握手：前者失败时后者仍要能拿到内容
    let trusted_attempt = handshake(&host, port, trusted_config(), timeout).await;

    let (handshake, trusted, trust_error) = match trusted_attempt {
        Ok(h) => {
            if h.chain.is_empty() {
                // 极少数服务端不发证书（如某些私有协议），只能再要一次
                let h2 = handshake(&host, port, insecure_config(), timeout).await?;
                (h2, false, Some("服务端未在信任握手时提供证书".to_string()))
            } else {
                (h, true, None)
            }
        }
        Err(e) => {
            let h2 = handshake(&host, port, insecure_config(), timeout).await?;
            (h2, false, Some(e))
        }
    };

    let now = Utc::now();
    let mut chain: Vec<CertInfo> = handshake
        .chain
        .iter()
        .enumerate()
        .filter_map(|(i, der)| parse_cert(der.as_ref(), i == 0, now))
        .collect();

    if chain.is_empty() {
        return Err("已建立 TLS 连接，但服务器未提供可解析的 X.509 证书。".into());
    }

    let leaf = &chain[0];
    let hostname_ok = hostname_matches(&host, &leaf.sans, leaf.common_name.as_deref());

    let mut report = SslCheckReport {
        host: host.clone(),
        port,
        checked_at: now,
        remote_ip,
        tls_version: handshake.tls_version,
        cipher_suite: handshake.cipher_suite,
        chain: std::mem::take(&mut chain),
        hostname_matched: hostname_ok,
        trusted,
        trust_error,
        duration_ms: started.elapsed().as_millis() as u64,
        warnings: Vec::new(),
    };
    report.warnings = build_warnings(&report);
    Ok(report)
}

fn parse_cert(der: &[u8], is_leaf: bool, now: DateTime<Utc>) -> Option<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let not_before = to_utc(cert.validity().not_before.timestamp());
    let not_after = to_utc(cert.validity().not_after.timestamp());

    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.to_string());

    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(d) => sans.push(d.to_string()),
                GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = ip_from_octets(bytes) {
                        sans.push(ip);
                    }
                }
                _ => {}
            }
        }
    }

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    let mut info = CertInfo {
        subject: subject.clone(),
        issuer: issuer.clone(),
        common_name,
        serial: cert.raw_serial_as_string(),
        not_before,
        not_after,
        status: CertStatus::Valid,
        days_remaining: 0,
        sans,
        signature_algorithm: oid_name(&cert.signature_algorithm.algorithm),
        key_algorithm: oid_name(&cert.public_key().algorithm.algorithm),
        key_bits: key_bits(&cert),
        is_ca: cert
            .basic_constraints()
            .ok()
            .flatten()
            .map(|b| b.value.ca)
            .unwrap_or(false),
        self_signed: subject == issuer,
        sha256_fingerprint: fingerprint(der),
        is_leaf,
    };
    assess(&mut info, now);
    Some(info)
}

fn to_utc(ts: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(ts, 0).unwrap_or_else(Utc::now)
}

fn ip_from_octets(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => Some(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(bytes);
            Some(std::net::Ipv6Addr::from(a).to_string())
        }
        _ => None,
    }
}

/// OID → 可读名称。只覆盖证书里最常出现的算法，其余回退点分数字。
fn oid_name(oid: &x509_parser::oid_registry::Oid) -> String {
    match oid.to_id_string().as_str() {
        "1.2.840.113549.1.1.1" => "rsaEncryption".into(),
        "1.2.840.113549.1.1.5" => "sha1WithRSA".into(),
        "1.2.840.113549.1.1.11" => "sha256WithRSA".into(),
        "1.2.840.113549.1.1.12" => "sha384WithRSA".into(),
        "1.2.840.113549.1.1.13" => "sha512WithRSA".into(),
        "1.2.840.113549.1.1.10" => "rsassaPss".into(),
        "1.2.840.10045.2.1" => "id-ecPublicKey".into(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".into(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".into(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".into(),
        "1.2.840.10040.4.1" => "dsa".into(),
        "1.3.101.112" => "Ed25519".into(),
        "1.3.101.113" => "Ed448".into(),
        other => other.to_string(),
    }
}

fn key_bits(cert: &X509Certificate) -> Option<u32> {
    use x509_parser::public_key::PublicKey;
    match cert.public_key().parsed().ok()? {
        PublicKey::RSA(rsa) => Some(rsa.key_size() as u32),
        PublicKey::EC(ec) => {
            // 公钥点为非压缩格式（0x04 + X + Y）时，位宽 = (长度 - 1) / 2 * 8
            let len = ec.data().len();
            if len > 1 && len % 2 == 1 {
                Some(((len - 1) / 2 * 8) as u32)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_various_target_forms() {
        assert_eq!(parse_target("example.com").unwrap(), ("example.com".into(), 443));
        assert_eq!(parse_target(" Example.COM ").unwrap(), ("example.com".into(), 443));
        assert_eq!(
            parse_target("https://example.com/path?q=1").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            parse_target("https://example.com:8443/a").unwrap(),
            ("example.com".into(), 8443)
        );
        assert_eq!(parse_target("192.168.60.10:9443").unwrap(), ("192.168.60.10".into(), 9443));
        assert_eq!(parse_target("[::1]:443").unwrap(), ("::1".into(), 443));
        assert_eq!(parse_target("::1").unwrap(), ("::1".into(), 443));
    }

    #[test]
    fn rejects_bad_targets() {
        assert!(parse_target("").is_err());
        assert!(parse_target("   ").is_err());
        assert!(parse_target("https://").is_err());
        assert!(parse_target("example.com:0").is_err());
    }

    /// 真实网络探测：允许失败（离线环境），但不许 panic。
    #[tokio::test]
    async fn check_public_certificate() {
        let opts = SslCheckOptions { timeout_ms: 8000 };
        match check_certificate("example.com", opts).await {
            Ok(r) => {
                assert_eq!(r.port, 443);
                assert!(!r.chain.is_empty());
                assert!(r.chain[0].is_leaf);
                assert!(!r.chain[0].sha256_fingerprint.is_empty());
                assert!(r.hostname_matched, "example.com 的主机名应当匹配");
                eprintln!(
                    "[sslcert] trusted={} tls={} chain={} err={:?}",
                    r.trusted,
                    r.tls_version,
                    r.chain.len(),
                    r.trust_error
                );
            }
            Err(e) => eprintln!("[sslcert] 跳过真实探测：{e}"),
        }
    }
}
