"""Let's Encrypt ACME v2 + DNS-01（阿里云 / 腾讯云 DNS）。"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from network_diagnosis.ssl_tools import dns_aliyun, dns_common, dns_tencent
from network_diagnosis.version import APP_DISPLAY_NAME, APP_VERSION

_DIRECTORY_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
_DIRECTORY_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


def _log_lines(cb: Callable[[str], None], msg: str) -> None:
    for line in msg.splitlines():
        cb(line)


def _save_acc_key(acc_key: jose.JWKRSA, path: Path) -> None:
    key = getattr(acc_key, "key", None)
    if key is None:
        raise TypeError("无效的 ACME 账户密钥")
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)


def _load_or_create_acc_key(acc_path: Path, log: Callable[[str], None]) -> tuple[jose.JWKRSA, bool]:
    """返回 (账户 JWK, 是否为新密钥)。新密钥调用方负责写入 acc_path。"""
    if acc_path.is_file():
        pem = acc_path.read_bytes()
        priv = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(priv, rsa.RSAPrivateKey):
            raise ValueError("账户密钥必须为 RSA PEM")
        log(f"已加载 ACME 账户密钥：{acc_path}")
        return jose.JWKRSA(key=priv), False
    log("生成新的 ACME 账户密钥（RSA 2048）…")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return jose.JWKRSA(key=key), True


def _collect_dns01(orderr: messages.OrderResource) -> list[tuple[messages.AuthorizationResource, messages.ChallengeBody]]:
    pairs: list[tuple[messages.AuthorizationResource, messages.ChallengeBody]] = []
    for authz in orderr.authorizations:
        dom = authz.body.identifier.value
        chosen = None
        for cb in authz.body.challenges:
            if isinstance(cb.chall, challenges.DNS01):
                chosen = cb
                break
        if chosen is None:
            raise RuntimeError(f"Let's Encrypt 未对域名 {dom} 提供 DNS-01，无法继续")
        pairs.append((authz, chosen))
    return pairs


def _txt_value(validation: object) -> str:
    if isinstance(validation, bytes):
        return validation.decode()
    return str(validation)


def issue_via_dns01(
    *,
    domains: list[str],
    staging: bool,
    mailto: str | None,
    dns_provider: Literal["aliyun", "tencent"],
    aliyun_access_key_id: str | None,
    aliyun_access_key_secret: str | None,
    tencent_secret_id: str | None,
    tencent_secret_key: str | None,
    tencent_record_line: str,
    apex_domain: str | None,
    output_dir: Path,
    account_key_file: Path | None,
    propagation_seconds: float,
    log: Callable[[str], None],
) -> dict[str, Path]:
    """申请证书并写入 output_dir；返回写入路径字典。"""
    domains_norm = dns_common.normalize_domains(domains)
    if not domains_norm:
        raise ValueError("请填写至少一个域名")

    apex = (apex_domain or "").strip().lower().rstrip(".") or dns_common.guess_apex(domains_norm)
    output_dir.mkdir(parents=True, exist_ok=True)

    acc_path = account_key_file if account_key_file is not None else output_dir / "letsencrypt-account.pem"
    acc_key, acc_new = _load_or_create_acc_key(acc_path, log)
    if acc_new:
        _save_acc_key(acc_key, acc_path)
        log(f"已保存 ACME 账户密钥：{acc_path}")

    ua = f"{APP_DISPLAY_NAME}/{APP_VERSION}"
    net = client.ClientNetwork(acc_key, user_agent=ua)

    directory_url = _DIRECTORY_STAGING if staging else _DIRECTORY_PRODUCTION
    directory = client.ClientV2.get_directory(directory_url, net)
    client_acme = client.ClientV2(directory, net=net)

    contact = ()
    if mailto and mailto.strip():
        contact = (f"mailto:{mailto.strip()}",)

    log("向 Let's Encrypt 注册 / 查询账户…")
    reg = messages.NewRegistration.from_data(terms_of_service_agreed=True, contact=contact)
    client_acme.new_account(reg)

    log("生成站点密钥与 CSR…")
    cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    cert_key_pem = cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    csr_pem = crypto_util.make_csr(cert_key_pem, domains_norm)

    log("创建订单…")
    orderr = client_acme.new_order(csr_pem)
    pairs = _collect_dns01(orderr)

    cleanups: list[Callable[[], None]] = []

    def _run_cleanups() -> None:
        for fn in reversed(cleanups):
            try:
                fn()
            except Exception as ex:
                _log_lines(log, f"[清理DNS] 警告：{ex}")

    answered: list[tuple[messages.ChallengeBody, Any]] = []

    try:
        if dns_provider == "aliyun":
            if not aliyun_access_key_id or not aliyun_access_key_secret:
                raise ValueError("阿里云 AccessKey ID / Secret 不能为空")
            for authz, challb in pairs:
                dom = authz.body.identifier.value
                fqdn = challb.chall.validation_domain_name(dom)
                rr = dns_common.rr_from_challenge_fqdn(fqdn, apex)
                response, validation = challb.response_and_validation(client_acme.net.key)
                val = _txt_value(validation)
                log(f"阿里云 DNS TXT：{fqdn} RR={rr} 值前缀={val[:16]}…")
                rid = dns_aliyun.upsert_txt_record(
                    aliyun_access_key_id,
                    aliyun_access_key_secret,
                    domain_name=apex,
                    rr=rr,
                    value=val,
                )

                def _del_a(rid_: str = rid) -> None:
                    dns_aliyun.delete_record(
                        aliyun_access_key_id,
                        aliyun_access_key_secret,
                        record_id=rid_,
                    )

                cleanups.append(_del_a)
                answered.append((challb, response))

        elif dns_provider == "tencent":
            if not tencent_secret_id or not tencent_secret_key:
                raise ValueError("腾讯云 SecretId / SecretKey 不能为空")
            for authz, challb in pairs:
                dom = authz.body.identifier.value
                fqdn = challb.chall.validation_domain_name(dom)
                rr = dns_common.rr_from_challenge_fqdn(fqdn, apex)
                response, validation = challb.response_and_validation(client_acme.net.key)
                val = _txt_value(validation)
                log(f"腾讯云 DNS TXT：{fqdn} SubDomain={rr} 值前缀={val[:16]}…")
                rid = dns_tencent.upsert_txt_record(
                    tencent_secret_id,
                    tencent_secret_key,
                    domain=apex,
                    subdomain=rr,
                    value=val,
                    record_line=tencent_record_line or "默认",
                )

                def _del_t(r: int = rid) -> None:
                    dns_tencent.delete_record(
                        tencent_secret_id,
                        tencent_secret_key,
                        domain=apex,
                        record_id=r,
                    )

                cleanups.append(_del_t)
                answered.append((challb, response))
        else:
            raise ValueError(f"未知 DNS 提供商：{dns_provider}")

        if propagation_seconds > 0:
            log(f"等待 DNS 传播 {propagation_seconds:.0f} 秒…")
            time.sleep(propagation_seconds)

        log("应答 ACME DNS 校验…")
        for challb, response in answered:
            client_acme.answer_challenge(challb, response)

        log("等待签发…")
        finalized = client_acme.poll_and_finalize(orderr)

        fullchain_pem = finalized.fullchain_pem
        if isinstance(fullchain_pem, bytes):
            chain_bytes = fullchain_pem
        else:
            chain_bytes = fullchain_pem.encode()

        priv_path = output_dir / "privkey.pem"
        fullchain_path = output_dir / "fullchain.pem"
        cert_path = output_dir / "cert.pem"

        priv_path.write_bytes(cert_key_pem)
        fullchain_path.write_bytes(chain_bytes)

        _split_leaf_and_chain(chain_bytes, cert_path)

        log(f"已写入：{priv_path}")
        log(f"已写入：{fullchain_path}")
        log(f"已写入：{cert_path}")

        return {
            "privkey": priv_path,
            "fullchain": fullchain_path,
            "cert": cert_path,
            "account_key": acc_path,
        }

    finally:
        log("清理临时 DNS TXT 记录…")
        _run_cleanups()


def _split_leaf_and_chain(fullchain_bytes: bytes, cert_out: Path) -> None:
    """从 PEM fullchain 中拆出第一张叶子证书写入 cert.pem。"""
    blocks: list[bytes] = []
    cur: list[str] = []
    for line in fullchain_bytes.decode().splitlines():
        if line.startswith("-----BEGIN CERTIFICATE-----"):
            cur = [line]
        elif cur:
            cur.append(line)
            if line.startswith("-----END CERTIFICATE-----"):
                blocks.append("\n".join(cur).encode() + b"\n")
                cur = []
    if not blocks:
        raise ValueError("fullchain PEM 解析失败")
    cert_out.write_bytes(blocks[0])
