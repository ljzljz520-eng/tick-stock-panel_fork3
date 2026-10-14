"""本地信任根与 HMAC-SHA256 签名。

威胁模型说明：沙箱采用"操作者审批 + 本地封存"模型。审批通过后，策略文件
（能力、代码 digest、依赖 digest）由本机信任根密钥 HMAC 签名，防止插件被
悄悄替换、能力被悄悄放大。密钥文件 0600 保存，与插件目录分离：拿到插件
目录写权限但拿不到密钥的攻击者无法签发新策略。

若未来需要"插件作者签名"，可在此模块并列增加公钥（Ed25519）校验，
策略记录格式已为多算法字段预留 ``alg``。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

ALGORITHM = "HS256"


def canonical_json(obj: object) -> bytes:
    """确定性 JSON 编码：键排序、无空白、非 ASCII 不转义。"""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def ensure_trust_key(key_path: Path) -> bytes:
    """读取信任根密钥；不存在则创建（0600）。幂等。"""
    path = Path(key_path)
    if path.exists():
        key = path.read_bytes().strip()
        if len(key) >= 32:
            return key
        raise ValueError(f"信任根密钥强度不足（需 >=32 字节）: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    path.write_bytes(key.hex().encode("ascii") + b"\n")
    os.chmod(path, 0o600)
    return key.hex().encode("ascii")


def sign_payload(payload: dict, key: bytes) -> dict:
    """返回 {alg, sig}，签名对象为 payload 的规范编码。"""
    sig = hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()
    return {"alg": ALGORITHM, "sig": sig}


def verify_payload(payload: dict, alg: str, sig: str, key: bytes) -> bool:
    if alg != ALGORITHM or not isinstance(sig, str):
        return False
    expected = hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)
