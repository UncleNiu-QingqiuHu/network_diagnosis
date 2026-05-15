"""阿里云 DNS（Alidns）RPC：TXT 记录的增删（用于 ACME DNS-01）。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests

_ALIDNS = "https://alidns.aliyuncs.com/"


def _percent_encode(s: str) -> str:
    return quote(str(s), safe="-_.~")


def _sign(params: dict[str, Any], secret: str) -> str:
    keys = sorted(params.keys())
    qs = "&".join(f"{_percent_encode(k)}={_percent_encode(params[k])}" for k in keys)
    string_to_sign = f"GET&%2F&{_percent_encode(qs)}"
    digest = hmac.new((secret + "&").encode(), string_to_sign.encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def _rpc(access_key_id: str, access_key_secret: str, action: str, **extra: Any) -> dict[str, Any]:
    params: dict[str, Any] = {
        "Format": "JSON",
        "Version": "2015-01-09",
        "AccessKeyId": access_key_id,
        "SignatureMethod": "HMAC-SHA1",
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "SignatureVersion": "1.0",
        "SignatureNonce": str(uuid.uuid4()),
        "Action": action,
        **extra,
    }
    params["Signature"] = _sign(params, access_key_secret)
    r = requests.get(_ALIDNS, params=params, timeout=90)
    r.raise_for_status()
    data = r.json()
    if data.get("Code"):
        raise RuntimeError(f"阿里云 DNS API 错误：{data.get('Code')} {data.get('Message')}")
    return data


def describe_txt_records(access_key_id: str, access_key_secret: str, *, domain_name: str, rr: str) -> list[dict[str, Any]]:
    """列出指定 RR 下的 TXT 解析记录。"""
    page = 1
    page_size = 50
    found: list[dict[str, Any]] = []
    while True:
        data = _rpc(
            access_key_id,
            access_key_secret,
            "DescribeDomainRecords",
            DomainName=domain_name,
            RRKeyWord=rr,
            TypeKeyWord="TXT",
            PageNumber=page,
            PageSize=page_size,
        )
        recs = data.get("DomainRecords", {}).get("Record") or []
        if isinstance(recs, dict):
            recs = [recs]
        for row in recs:
            if str(row.get("RR", "")).lower() == rr.lower() and str(row.get("Type", "")).upper() == "TXT":
                found.append(row)
        total = int(data.get("TotalCount") or 0)
        if page * page_size >= total:
            break
        page += 1
    return found


def delete_record(access_key_id: str, access_key_secret: str, *, record_id: str) -> None:
    _rpc(access_key_id, access_key_secret, "DeleteDomainRecord", RecordId=record_id)


def upsert_txt_record(
    access_key_id: str,
    access_key_secret: str,
    *,
    domain_name: str,
    rr: str,
    value: str,
    ttl: int = 600,
) -> str:
    """删除同 RR 下全部 TXT 后新增一条，返回 RecordId。"""
    for row in describe_txt_records(access_key_id, access_key_secret, domain_name=domain_name, rr=rr):
        rid = row.get("RecordId")
        if rid:
            delete_record(access_key_id, access_key_secret, record_id=str(rid))
    data = _rpc(
        access_key_id,
        access_key_secret,
        "AddDomainRecord",
        DomainName=domain_name,
        RR=rr,
        Type="TXT",
        Value=value,
        TTL=ttl,
    )
    rid = data.get("RecordId")
    if not rid:
        raise RuntimeError(f"阿里云 AddDomainRecord 响应异常：{json.dumps(data, ensure_ascii=False)}")
    return str(rid)
