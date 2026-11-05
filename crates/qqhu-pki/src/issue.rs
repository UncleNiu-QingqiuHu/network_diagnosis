//! 证书生成与签发（rcgen）。
//!
//! 只负责「造字节」：不读写文件、不决定目录。落盘与索引在 `store`。
//! 这样签发逻辑可以直接单测，也不受路径影响。

use crate::model::{validate_ca, validate_cert, CaSpec, CertSpec, CertUsage, KeyAlgorithm};
use crate::PkiError;
use chrono::{DateTime, Duration, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SerialNumber,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// rcgen 的有效期字段是 `time::OffsetDateTime`，这里统一做一次转换。
fn to_offset(dt: DateTime<Utc>) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(dt.timestamp()).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// 生成好的 CA 材料。
pub struct GeneratedCa {
    pub cert_pem: String,
    pub key_pem: String,
    pub subject: String,
    pub serial: String,
    pub fingerprint: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

/// 生成好的站点证书材料。
pub struct GeneratedCert {
    pub cert_pem: String,
    pub key_pem: String,
    /// 证书 DER，打包 PFX 时直接用
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub serial: String,
    pub fingerprint: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

fn key_for(alg: KeyAlgorithm) -> Result<KeyPair, PkiError> {
    let rcgen_alg = match alg {
        KeyAlgorithm::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        KeyAlgorithm::Ed25519 => &rcgen::PKCS_ED25519,
    };
    KeyPair::generate_for(rcgen_alg).map_err(|e| PkiError::Key(e.to_string()))
}

fn build_dn(cn: &str, org: Option<&str>, ou: Option<&str>, country: Option<&str>, state: Option<&str>, locality: Option<&str>) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn.trim());
    if let Some(v) = country.map(str::trim).filter(|s| !s.is_empty()) {
        dn.push(DnType::CountryName, v.to_ascii_uppercase());
    }
    if let Some(v) = state.map(str::trim).filter(|s| !s.is_empty()) {
        dn.push(DnType::StateOrProvinceName, v);
    }
    if let Some(v) = locality.map(str::trim).filter(|s| !s.is_empty()) {
        dn.push(DnType::LocalityName, v);
    }
    if let Some(v) = org.map(str::trim).filter(|s| !s.is_empty()) {
        dn.push(DnType::OrganizationName, v);
    }
    if let Some(v) = ou.map(str::trim).filter(|s| !s.is_empty()) {
        dn.push(DnType::OrganizationalUnitName, v);
    }
    dn
}

/// 从 DER 取标准的 subject 串。
///
/// 自己拼 DN 的顺序与证书实际编码顺序不一致（DER 里 C 通常在前），
/// 展示与比对都以证书内容为准，避免「界面写的和证书里的不一样」。
fn subject_of(der: &[u8]) -> String {
    use x509_parser::prelude::FromDer;
    x509_parser::prelude::X509Certificate::from_der(der)
        .ok()
        .map(|(_, c)| c.subject().to_string())
        .unwrap_or_default()
}

/// 可读的 DN 串，用于界面与日志。
fn dn_string(cn: &str, org: Option<&str>, ou: Option<&str>, country: Option<&str>) -> String {
    let mut parts = vec![format!("CN={}", cn.trim())];
    if let Some(v) = org.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("O={v}"));
    }
    if let Some(v) = ou.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("OU={v}"));
    }
    if let Some(v) = country.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("C={}", v.to_ascii_uppercase()));
    }
    parts.join(", ")
}

/// 生成随机序列号。
///
/// 用「种子 + 纳秒时间 + 进程号」派生，单机签发足够避免碰撞；
/// 首字节清零最高位，保证按 ASN.1 解释为正整数。
fn random_serial(seed: &str) -> SerialNumber {
    let mut h = Sha256::new();
    h.update(seed.as_bytes());
    h.update(Utc::now().timestamp_nanos_opt().unwrap_or(0).to_be_bytes());
    h.update(std::process::id().to_be_bytes());
    let digest = h.finalize();
    let mut bytes = digest[..16].to_vec();
    bytes[0] &= 0x7f;
    if bytes[0] == 0 {
        bytes[0] = 1;
    }
    SerialNumber::from_slice(&bytes)
}

fn hex_serial(serial: &SerialNumber) -> String {
    serial.to_bytes().iter().map(|b| format!("{b:02X}")).collect()
}

fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// 生成自签名根 CA。
pub fn generate_ca(spec: &CaSpec) -> Result<GeneratedCa, PkiError> {
    let days = validate_ca(spec).map_err(PkiError::Invalid)?;
    let now = Utc::now();
    let not_before = now - Duration::days(1);
    let not_after = now + Duration::days(days as i64);

    let key = key_for(spec.key_algorithm)?;
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|e| PkiError::Cert(e.to_string()))?;
    params.distinguished_name = build_dn(
        &spec.common_name,
        spec.organization.as_deref(),
        spec.organizational_unit.as_deref(),
        spec.country.as_deref(),
        spec.state.as_deref(),
        spec.locality.as_deref(),
    );
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.not_before = to_offset(not_before);
    params.not_after = to_offset(not_after);
    let serial = random_serial(&format!("ca:{}", spec.common_name));
    params.serial_number = Some(serial.clone());

    let cert = params.self_signed(&key).map_err(|e| PkiError::Cert(e.to_string()))?;

    let fallback_subject = dn_string(
        &spec.common_name,
        spec.organization.as_deref(),
        spec.organizational_unit.as_deref(),
        spec.country.as_deref(),
    );
    let parsed_subject = subject_of(cert.der());
    Ok(GeneratedCa {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        subject: if parsed_subject.is_empty() {
            fallback_subject
        } else {
            parsed_subject
        },
        serial: hex_serial(&serial),
        fingerprint: fingerprint(cert.der()),
        not_before,
        not_after,
    })
}

/// 用指定 CA 签发站点/客户端证书。
///
/// `ca_not_after` 用来限制子证书不得超过 CA 的有效期 —— 否则会出现
/// 「证书链校验失败但每张证书看起来都没过期」这种难查的问题。
pub fn issue_cert(
    spec: &CertSpec,
    ca_cert_pem: &str,
    ca_key_pem: &str,
    ca_not_after: DateTime<Utc>,
) -> Result<GeneratedCert, PkiError> {
    let (sans, days) = validate_cert(spec).map_err(PkiError::Invalid)?;
    let now = Utc::now();
    let not_before = now - Duration::days(1);

    let mut not_after = now + Duration::days(days as i64);
    if not_after > ca_not_after {
        not_after = ca_not_after;
    }
    if not_after <= now {
        return Err(PkiError::Invalid(
            "签发失败：CA 证书已过期或剩余有效期不足一天，请先新建 CA。".to_string(),
        ));
    }

    let ca_key = KeyPair::from_pem(ca_key_pem).map_err(|e| PkiError::CaLoad(e.to_string()))?;
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key)
        .map_err(|e| PkiError::CaLoad(format!("CA 证书解析失败：{e}")))?;

    let key = key_for(spec.key_algorithm)?;
    let mut params =
        CertificateParams::new(sans.clone()).map_err(|e| PkiError::Cert(e.to_string()))?;

    params.distinguished_name = build_dn(&spec.common_name, None, None, None, None, None);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = match spec.usage {
        CertUsage::Server => vec![ExtendedKeyUsagePurpose::ServerAuth],
        CertUsage::Client => vec![ExtendedKeyUsagePurpose::ClientAuth],
        CertUsage::Both => vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ],
    };
    params.not_before = to_offset(not_before);
    params.not_after = to_offset(not_after);
    let serial = random_serial(&format!("leaf:{}:{}", spec.common_name, sans.join(",")));
    params.serial_number = Some(serial.clone());

    let cert = params
        .signed_by(&key, &issuer)
        .map_err(|e| PkiError::Cert(e.to_string()))?;

    Ok(GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
        serial: hex_serial(&serial),
        fingerprint: fingerprint(cert.der()),
        not_before,
        not_after,
    })
}

/// 打包 PKCS#12（.pfx / .p12）。
///
/// Windows 双击导入、IIS 绑定都要求这个格式。`password` 允许为空串，
/// 但 Windows 导入时对空口令的兼容性较差，界面上建议至少 4 位。
pub fn to_pfx(
    cert_der: &[u8],
    key_der: &[u8],
    ca_der: Option<&[u8]>,
    password: &str,
    friendly_name: &str,
) -> Result<Vec<u8>, PkiError> {
    let pfx = p12::PFX::new(cert_der, key_der, ca_der, password, friendly_name)
        .ok_or(PkiError::Pfx)?;
    Ok(pfx.to_der())
}

/// PEM → DER（去掉头尾与换行后 base64 解码）。仅用于导出时取 CA DER。
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, PkiError> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64_decode(&body).ok_or_else(|| PkiError::Invalid("PEM 解码失败".to_string()))
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = TABLE.iter().position(|&t| t == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca_spec() -> CaSpec {
        CaSpec {
            common_name: "QingqiuHu Test Root CA".into(),
            organization: Some("QingqiuHu".into()),
            organizational_unit: Some("IT".into()),
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
            sans: vec!["web.corp.local".into(), "192.168.60.10".into()],
            validity_days: Some(397),
            key_algorithm: KeyAlgorithm::EcdsaP256,
            usage: CertUsage::Server,
        }
    }

    #[test]
    fn generates_ca_with_expected_fields() {
        let ca = generate_ca(&ca_spec()).unwrap();
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem.contains("PRIVATE KEY"));
        assert!(ca.subject.contains("CN=QingqiuHu Test Root CA"), "实际：{}", ca.subject);
        assert!(ca.subject.contains("CN"));
        assert!(ca.subject.contains("O=QingqiuHu"));
        assert!(ca.not_after > ca.not_before);
        assert!(ca.fingerprint.split(':').count() == 32);
        assert!(!ca.serial.is_empty());
    }

    #[test]
    fn issues_cert_signed_by_ca() {
        let ca = generate_ca(&ca_spec()).unwrap();
        let leaf = issue_cert(&leaf_spec("ca1"), &ca.cert_pem, &ca.key_pem, ca.not_after).unwrap();

        assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(!leaf.cert_der.is_empty());
        assert!(!leaf.key_der.is_empty());

        // 用 x509-parser 回读：签发者必须与 CA 主体一致
        use x509_parser::prelude::FromDer;
        let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(&leaf.cert_der).unwrap();
        assert_eq!(parsed.issuer().to_string(), ca.subject);
        assert_eq!(parsed.subject().to_string(), "CN=web.corp.local");

        // SAN 应同时包含 DNS 与 IP
        let sans = parsed.subject_alternative_name().unwrap().unwrap();
        let mut dns = Vec::new();
        let mut ips = Vec::new();
        for n in &sans.value.general_names {
            match n {
                x509_parser::extensions::GeneralName::DNSName(d) => dns.push(d.to_string()),
                x509_parser::extensions::GeneralName::IPAddress(b) => {
                    ips.push(format!("{:?}", b))
                }
                _ => {}
            }
        }
        assert_eq!(dns, vec!["web.corp.local"]);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn leaf_validity_is_capped_by_ca() {
        let mut ca = ca_spec();
        ca.validity_days = Some(10);
        let ca = generate_ca(&ca).unwrap();

        let mut leaf = leaf_spec("ca1");
        leaf.validity_days = Some(397);
        let cert = issue_cert(&leaf, &ca.cert_pem, &ca.key_pem, ca.not_after).unwrap();
        assert!(
            cert.not_after <= ca.not_after,
            "子证书不得晚于 CA 过期：{} > {}",
            cert.not_after,
            ca.not_after
        );
    }

    #[test]
    fn rejects_issue_when_ca_expired() {
        let ca = generate_ca(&ca_spec()).unwrap();
        let past = Utc::now() - Duration::days(1);
        assert!(issue_cert(&leaf_spec("ca1"), &ca.cert_pem, &ca.key_pem, past).is_err());
    }

    #[test]
    fn pfx_roundtrips_with_password() {
        let ca = generate_ca(&ca_spec()).unwrap();
        let leaf = issue_cert(&leaf_spec("ca1"), &ca.cert_pem, &ca.key_pem, ca.not_after).unwrap();

        let ca_der = pem_to_der(&ca.cert_pem).unwrap();
        let pfx_der = to_pfx(
            &leaf.cert_der,
            &leaf.key_der,
            Some(&ca_der),
            "testpass",
            "web.corp.local",
        )
        .unwrap();
        assert!(!pfx_der.is_empty());

        // 用同一份 DER 解析回来，且口令错误时必须拿不到数据
        let parsed = p12::PFX::parse(&pfx_der).unwrap();
        assert!(parsed.mac_data.as_ref().map(|m| m.verify_mac(&parsed.auth_safe.to_der(), b"testpass")).unwrap_or(false)
            || parsed.bags("testpass").is_ok());
        assert!(parsed.bags("wrongpass").is_err());
    }

    #[test]
    fn pem_to_der_handles_crlf_and_padding() {
        let ca = generate_ca(&ca_spec()).unwrap();
        let der = pem_to_der(&ca.cert_pem.replace('\n', "\r\n")).unwrap();
        assert!(der.starts_with(&[0x30]));
    }
}
