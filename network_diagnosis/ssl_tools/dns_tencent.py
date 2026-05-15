"""腾讯云 DNSPod API 3.0：TXT 解析（用于 ACME DNS-01）。"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import requests

_DNSPOD_HOST = "dnspod.tencentcloudapi.com"
_DNSPOD_VER = "2021-03-23"


def _sign_tc3(secret_id: str, secret_key: str, *, payload: bytes, timestamp: int, date_ymd: str) -> dict[str, str]:
    service = "dnspod"
    algorithm = "TC3-HMAC-SHA256"
    canonical_headers = f"content-type:application/json; charset=utf-8\nhost:{_DNSPOD_HOST}\n"
    signed_headers = "content-type;host"
    hashed_payload = hashlib.sha256(payload).hexdigest()
    canonical_request = "\n".join(
        ("POST", "/", "", canonical_headers, signed_headers, hashed_payload),
    )
    credential_scope = f"{date_ymd}/{service}/tc3_request"
    hashed_canonical = hashlib.sha256(canonical_request.encode()).hexdigest()
    string_to_sign = "\n".join((algorithm, str(timestamp), credential_scope, hashed_canonical))

    def _hmac_sha256(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    secret_date = _hmac_sha256(("TC3" + secret_key).encode(), date_ymd)
    secret_service = hmac.new(secret_date, service.encode(), hashlib.sha256).digest()
    secret_signing = hmac.new(secret_service, b"tc3_request", hashlib.sha256).digest()
    signature = hmac.new(secret_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    auth = (
        f"{algorithm} Credential={secret_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return {"Authorization": auth}


def _request(secret_id: str, secret_key: str, action: str, body: dict[str, Any]) -> dict[str, Any]:
    payload = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
    timestamp = int(time.time())
    ts_struct = time.gmtime(timestamp)
    date_ymd = time.strftime("%Y-%m-%d", ts_struct)
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Host": _DNSPOD_HOST,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": _DNSPOD_VER,
        "X-TC-Region": "ap-guangzhou",
    }
    headers.update(_sign_tc3(secret_id, secret_key, payload=payload, timestamp=timestamp, date_ymd=date_ymd))
    r = requests.post(f"https://{_DNSPOD_HOST}/", headers=headers, data=payload, timeout=90)
    r.raise_for_status()
    data = r.json()
    err = data.get("Response", {}).get("Error")
    if err:
        raise RuntimeError(f"腾讯云 DNS API 错误：{err.get('Code')} {err.get('Message')}")
    return data["Response"]


def list_txt_records(secret_id: str, secret_key: str, *, domain: str, subdomain: str) -> list[dict[str, Any]]:
    resp = _request(
        secret_id,
        secret_key,
        "DescribeRecordList",
        {"Domain": domain, "Subdomain": subdomain, "RecordType": "TXT"},
    )
    recs = resp.get("RecordList") or []
    return [x for x in recs if str(x.get("Type", "")).upper() == "TXT"]


def delete_record(secret_id: str, secret_key: str, *, domain: str, record_id: int) -> None:
    _request(secret_id, secret_key, "DeleteRecord", {"Domain": domain, "RecordId": record_id})


def upsert_txt_record(
    secret_id: str,
    secret_key: str,
    *,
    domain: str,
    subdomain: str,
    value: str,
    record_line: str = "默认",
    ttl: int = 600,
) -> int:
    """删除该 Subdomain 下全部 TXT 后新增一条，返回 RecordId。"""
    for row in list_txt_records(secret_id, secret_key, domain=domain, subdomain=subdomain):
        rid = row.get("RecordId")
        if rid is not None:
            delete_record(secret_id, secret_key, domain=domain, record_id=int(rid))
    resp = _request(
        secret_id,
        secret_key,
        "CreateRecord",
        {
            "Domain": domain,
            "SubDomain": subdomain,
            "RecordType": "TXT",
            "RecordLine": record_line,
            "Value": value,
            "TTL": ttl,
        },
    )
    rid = resp.get("RecordId")
    if rid is None:
        raise RuntimeError(f"腾讯云 CreateRecord 响应异常：{resp!r}")
    return int(rid)
