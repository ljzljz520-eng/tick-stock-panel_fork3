"""已审批签名策略的存储与校验。

策略记录是激活插件的唯一信任依据：
- 绑定插件目录、清单能力视图、全部代码 digest、依赖 digest、审批时间；
- 整份记录（除 sig 外）由本地信任根 HMAC 签名；
- 激活时重算当前 digest 与记录比对，任何代码/依赖漂移都 fail-closed。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.sandbox.digests import sha256_bytes
from app.sandbox.errors import PolicyError
from app.sandbox.manifest import CapabilityManifest
from app.sandbox.signature import (
    canonical_json,
    ensure_trust_key,
    sign_payload,
    verify_payload,
)


@dataclass(frozen=True)
class PolicyRecord:
    plugin: str
    plugin_dir: str
    record: dict

    @property
    def granted(self) -> dict:
        return self.record["granted"]

    @property
    def code_digests(self) -> dict[str, str]:
        return self.record["code_digests"]

    @property
    def dependency_digests(self) -> dict[str, str]:
        return self.record["dependency_digests"]

    @property
    def approved_at(self) -> str:
        return self.record["approved_at"]


class PolicyStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.policies_dir = self.root / "policies"
        self.key_path = self.root / "trust" / "master.key"

    def approve(
        self,
        manifest: CapabilityManifest,
        plugin_dir: Path,
        code_digests: dict[str, str],
        dependency_digests: dict[str, str],
        *,
        approved_by: str = "local-operator",
    ) -> PolicyRecord:
        """签发并原子写入策略。调用方必须已确认静态检查通过。"""
        key = ensure_trust_key(self.key_path)
        granted = manifest.granted_dict()
        record = {
            "alg": "HS256",
            "plugin": manifest.name,
            "plugin_dir": str(Path(plugin_dir).resolve()),
            "manifest_digest": sha256_bytes(canonical_json(granted)),
            "granted": granted,
            "code_digests": dict(sorted(code_digests.items())),
            "dependency_digests": dict(sorted(dependency_digests.items())),
            "approved_at": datetime.now(UTC).isoformat(),
            "approved_by": approved_by[:64],
        }
        seal = sign_payload(record, key)
        record["alg"] = seal["alg"]
        record["sig"] = seal["sig"]
        self._write_atomic(manifest.name, record)
        return PolicyRecord(manifest.name, record["plugin_dir"], record)

    def load(self, name: str) -> PolicyRecord:
        path = self._path(name)
        if not path.is_file():
            raise PolicyError(f"插件没有已审批策略: {name}")
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise PolicyError(f"策略文件损坏: {name}: {e}") from e
        key = ensure_trust_key(self.key_path)
        sig = record.pop("sig", None)
        alg = record.get("alg")
        if not sig or not verify_payload(record, alg or "", sig, key):
            raise PolicyError(f"策略签名校验失败: {name}")
        record["sig"] = sig
        if record.get("plugin") != name:
            raise PolicyError(f"策略插件名与文件名不一致: {name}")
        return PolicyRecord(name, record.get("plugin_dir", ""), record)

    def exists(self, name: str) -> bool:
        return self._path(name).is_file()

    def _path(self, name: str) -> Path:
        return self.policies_dir / f"{name}.json"

    def _write_atomic(self, name: str, record: dict) -> None:
        self.policies_dir.mkdir(parents=True, exist_ok=True)
        path = self._path(name)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        tmp.chmod(0o600)
        tmp.replace(path)
