"""签名策略：审批落盘、验签、篡改 fail-closed、信任根文件保护。"""
from __future__ import annotations

import json
import os

import pytest

from app.sandbox.digests import code_digests, dependency_digests
from app.sandbox.errors import PolicyError
from app.sandbox.manifest import load_manifest
from app.sandbox.policy import PolicyStore
from app.sandbox.signature import ensure_trust_key, verify_payload


def _approve(tmp_path, make_plugin_fn, root=None, code=None):
    p = make_plugin_fn(
        tmp_path / "plug",
        code or "import json\n\ndef handle(ctx):\n    return {'ok': True}\n",
        imports=["json"],
    )
    m = load_manifest(p)
    store = PolicyStore(root or (tmp_path / "sb"))
    rec = store.approve(
        m, p, code_digests(p), dependency_digests(m.imports)
    )
    return store, rec, p


def test_approve_and_load_roundtrip(tmp_path, make_plugin_fn):
    store, rec, _ = _approve(tmp_path, make_plugin_fn)
    loaded = store.load(rec.plugin)
    assert loaded.granted == rec.granted
    assert loaded.code_digests == rec.code_digests


def test_policy_and_key_files_are_0600(tmp_path, make_plugin_fn):
    root = tmp_path / "sb"
    store, rec, _ = _approve(tmp_path, make_plugin_fn, root=root)
    mode = os.stat(store._path(rec.plugin)).st_mode & 0o777
    assert mode == 0o600
    key_mode = os.stat(root / "trust" / "master.key").st_mode & 0o777
    assert key_mode == 0o600


def test_load_missing_policy_raises(tmp_path):
    with pytest.raises(PolicyError, match="没有已审批策略"):
        PolicyStore(tmp_path).load("ghost")


def test_tampered_policy_fails_verification(tmp_path, make_plugin_fn):
    store, rec, _ = _approve(tmp_path, make_plugin_fn)
    path = store._path(rec.plugin)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["approved_by"] = "forged-operator"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PolicyError, match="签名校验失败"):
        store.load(rec.plugin)


def test_capability_widening_fails_verification(tmp_path, make_plugin_fn):
    store, rec, _ = _approve(tmp_path, make_plugin_fn)
    path = store._path(rec.plugin)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["granted"]["egress"] = ["evil.example"]
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PolicyError):
        store.load(rec.plugin)


def test_wrong_trust_key_rejected(tmp_path, make_plugin_fn):
    root = tmp_path / "sb"
    _, rec, _ = _approve(tmp_path, make_plugin_fn, root=root)
    key = ensure_trust_key(root / "trust" / "master.key")
    other = os.urandom(32).hex().encode("ascii")
    data = json.loads((root / "policies" / f"{rec.plugin}.json").read_text())
    sig = data["sig"]
    payload = {k: v for k, v in data.items() if k != "sig"}
    assert verify_payload(payload, "HS256", sig, key)
    assert not verify_payload(payload, "HS256", sig, other)
    assert not verify_payload(payload, "HS999", sig, key)
