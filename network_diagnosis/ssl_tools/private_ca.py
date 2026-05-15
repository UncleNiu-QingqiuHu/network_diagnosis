"""使用 cryptography 生成私有根 CA 与站点证书（SAN：DNS / IPv4 / IPv6）。"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _pem_private(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def generate_ca(
    *,
    common_name: str,
    days_valid: int,
    key_size: int = 4096,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _parse_san_tokens(tokens: list[str]) -> tuple[list[str], list[x509.GeneralName]]:
    dns_names: list[str] = []
    sans: list[x509.GeneralName] = []
    for raw in tokens:
        s = raw.strip()
        if not s:
            continue
        try:
            ip = ipaddress.ip_address(s)
            gn = x509.IPAddress(ip)
        except ValueError:
            dns_names.append(s)
            gn = x509.DNSName(s)
        sans.append(gn)
    return dns_names, sans


def generate_site_signed_by_ca(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    *,
    common_name: str,
    san_tokens: list[str],
    days_valid: int,
    key_size: int = 2048,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    _, sans = _parse_san_tokens(san_tokens)
    if not sans:
        raise ValueError("至少需要一个 SAN（域名或 IP）")

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    san_ext = x509.SubjectAlternativeName(sans)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days_valid))
        .add_extension(san_ext, critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return server_key, cert


def write_private_bundle(
    out_dir: Path,
    *,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    site_key: rsa.RSAPrivateKey,
    site_cert: x509.Certificate,
    pfx_password: str | None,
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "ca_key": out_dir / "private-ca.key.pem",
        "ca_cert": out_dir / "private-ca.crt.pem",
        "site_key": out_dir / "private-site.key.pem",
        "site_cert": out_dir / "private-site.crt.pem",
        "fullchain": out_dir / "private-site.fullchain.pem",
    }
    paths["ca_key"].write_bytes(_pem_private(ca_key))
    paths["ca_cert"].write_bytes(_pem_cert(ca_cert))
    paths["site_key"].write_bytes(_pem_private(site_key))
    paths["site_cert"].write_bytes(_pem_cert(site_cert))
    paths["fullchain"].write_bytes(_pem_cert(site_cert) + _pem_cert(ca_cert))
    if pfx_password:
        pwd = pfx_password.encode()
        enc: serialization.KeySerializationEncryption = serialization.BestAvailableEncryption(pwd)
        p12 = pkcs12.serialize_key_and_certificates(
            name=b"private-site",
            key=site_key,
            cert=site_cert,
            cas=[ca_cert],
            encryption_algorithm=enc,
        )
        pfx_path = out_dir / "private-site.pfx"
        pfx_path.write_bytes(p12)
        paths["pfx"] = pfx_path
    return paths
