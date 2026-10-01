"""审计分段完整性原语。

完整性方案固定为“逐段独立定位 + 全链一次性判定”：

* 段内用带密钥的滚动 HMAC 覆盖记录内容与记录顺序；
* 每一段再携带上一段签名封套的 SHA-256，形成跨段链；
* 清单用同一把密钥签名，记录最后一段和每段的封套摘要，用于发现尾段丢失。

生产环境应通过 ``COKE_AUDIT_HMAC_KEY`` 注入 KMS/独立密钥卷中的密钥；未注入
时仅在存储目录生成一把本地随机密钥，适合交付环境和测试，不能防御已拿到该
目录写权限的攻击者。
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import json
import os
from typing import Any

GENESIS_DIGEST = hashlib.sha256(b"").hexdigest()
KEY_ENV = "COKE_AUDIT_HMAC_KEY"
KEY_FILE = ".audit-integrity.key"


def canonical_json(value: Any) -> str:
    """返回跨进程稳定的规范 JSON 文本。"""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def hmac_hex(secret: bytes, message: str) -> str:
    return hmac_module.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()


def envelope_digest(envelope: dict) -> str:
    """计算完整签名封套的链上摘要。"""

    return sha256_hex(canonical_json(envelope).encode("utf-8"))


def sign_envelope(secret: bytes, body: dict) -> dict:
    """对封套正文签名，返回带 ``body_digest`` 和 ``mac`` 的封套。"""

    body_digest = sha256_hex(canonical_json(body).encode("utf-8"))
    mac = hmac_hex(secret, body_digest)
    return {**body, "body_digest": body_digest, "mac": mac}


def open_envelope(secret: bytes, signed: Any) -> tuple[dict | None, list[str]]:
    """验签并拆出封套正文；失败时返回具体问题。"""

    if not isinstance(signed, dict):
        return None, ["envelope_not_object"]
    body = {key: value for key, value in signed.items() if key not in ("body_digest", "mac")}
    expected_digest = signed.get("body_digest")
    actual_digest = sha256_hex(canonical_json(body).encode("utf-8"))
    issues: list[str] = []
    if not isinstance(expected_digest, str) or expected_digest != actual_digest:
        issues.append("body_digest_mismatch")
    expected_mac = signed.get("mac")
    actual_mac = hmac_hex(secret, actual_digest)
    if not isinstance(expected_mac, str) or not hmac_module.compare_digest(expected_mac, actual_mac):
        issues.append("mac_mismatch")
    return body, issues


def next_record_digest(secret: bytes, previous: str, record: Any) -> str:
    """计算段内滚动记录摘要，覆盖记录内容和先后顺序。"""

    return hmac_hex(secret, previous + "\n" + canonical_json(record))


def records_digest(secret: bytes, records: list[Any]) -> str:
    current = GENESIS_DIGEST
    for record in records:
        current = next_record_digest(secret, current, record)
    return current


def load_secret(root: str) -> bytes:
    """从环境变量加载 HMAC 密钥；缺失时生成本地随机密钥文件。"""

    configured = os.environ.get(KEY_ENV)
    if configured:
        if configured.startswith("hex:"):
            try:
                secret = bytes.fromhex(configured[4:])
            except ValueError as error:
                raise ValueError(f"{KEY_ENV} 的 hex 密钥格式非法") from error
        else:
            secret = configured.encode("utf-8")
        if len(secret) < 16:
            raise ValueError(f"{KEY_ENV} 长度不得少于 16 字节")
        return secret

    path = os.path.join(root, KEY_FILE)
    if os.path.isfile(path):
        with open(path, "rb") as handle:
            secret = handle.read()
        if len(secret) < 16:
            raise ValueError(f"审计完整性密钥文件非法: {path}")
        return secret

    secret = os.urandom(32)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, secret)
    finally:
        os.close(descriptor)
    return secret
