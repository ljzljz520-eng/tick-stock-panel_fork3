"""能力清单解析与边界校验。"""
from __future__ import annotations

import pytest

from app.sandbox.errors import ManifestError
from app.sandbox.manifest import EgressGrant, load_manifest


def _load(tmp_path, yaml_body: str):
    p = tmp_path / "p"
    p.mkdir(exist_ok=True)
    (p / "sandbox-plugin.yaml").write_text(yaml_body, encoding="utf-8")
    return load_manifest(p)


_BASE = """
api_version: 1
name: demo
version: "1.0.0"
entry: "plugin:handle"
imports: [json]
"""


def test_valid_minimal_manifest(tmp_path):
    m = _load(tmp_path, _BASE)
    assert m.name == "demo"
    assert m.imports == ("json",)
    assert m.resources.wall_timeout_s == 60


def test_bad_api_version(tmp_path):
    with pytest.raises(ManifestError, match="api_version"):
        _load(tmp_path, _BASE.replace("api_version: 1", "api_version: 9"))


def test_bad_name(tmp_path):
    with pytest.raises(ManifestError, match="name"):
        _load(tmp_path, _BASE.replace("name: demo", "name: '../evil'"))


def test_bad_semver(tmp_path):
    with pytest.raises(ManifestError, match="semver"):
        _load(tmp_path, _BASE.replace('version: "1.0.0"', 'version: "latest"'))


def test_import_must_be_globally_allowlisted(tmp_path):
    with pytest.raises(ManifestError, match="白名单"):
        _load(tmp_path, _BASE.replace("[json]", "[os]"))
    with pytest.raises(ManifestError, match="白名单"):
        _load(tmp_path, _BASE.replace("[json]", "[httpx]"))


def test_unknown_dataset_rejected(tmp_path):
    body = _BASE + "datasets:\n  secrets_db: {}\n"
    with pytest.raises(ManifestError, match="未知数据集"):
        _load(tmp_path, body)


def test_resource_limits_hard_bounds(tmp_path):
    body = _BASE + "resources:\n  wall_timeout_s: 9999\n"
    with pytest.raises(ManifestError, match="wall_timeout_s"):
        _load(tmp_path, body)


def test_egress_host_validation_and_matching(tmp_path):
    body = _BASE + "egress:\n  - api.example.com\n  - '*.cdn.example.com'\n"
    m = _load(tmp_path, body)
    grants = m.egress
    assert EgressGrant("api.example.com").matches("api.example.com")
    assert not EgressGrant("api.example.com").matches("evil.example.com")
    assert EgressGrant(".cdn.example.com").matches("img.cdn.example.com")
    assert not EgressGrant(".cdn.example.com").matches("cdn.example.com.evil.com")
    assert len(grants) == 2


def test_egress_rejects_bad_host(tmp_path):
    body = _BASE + "egress:\n  - 'not a host'\n"
    with pytest.raises(ManifestError, match="egress"):
        _load(tmp_path, body)


def test_secret_alias_and_env_shape(tmp_path):
    body = _BASE + (
        "secrets:\n"
        "  - alias: token\n"
        "    env: TOKEN_ENV\n"
    )
    m = _load(tmp_path, body)
    assert m.secrets[0].alias == "token"
    bad = _BASE + "secrets:\n  - alias: Token\n    env: token_env\n"
    with pytest.raises(ManifestError):
        _load(tmp_path, bad)


def test_granted_dict_is_canonical(tmp_path):
    body = _BASE + (
        "datasets:\n"
        "  daily: {symbols: ['000001', '600000'], max_rows: 100}\n"
        "egress:\n  - b.example.com\n  - a.example.com\n"
    )
    m = _load(tmp_path, body)
    granted = m.granted_dict()
    assert granted["egress"] == ["a.example.com", "b.example.com"]
    assert granted["datasets"]["daily"]["symbols"] == ["000001", "600000"]
    # 再加载一次，规范化结果必须完全一致（签名稳定性）。
    assert _load(tmp_path, body).granted_dict() == granted


def test_helper_make_plugin_shape(tmp_path, make_plugin_fn):
    p = make_plugin_fn(
        tmp_path / "x",
        "def handle(ctx):\n    return {'ok': True}\n",
        imports=["json"],
        datasets={"daily": "{symbols: ['*'], max_rows: 500}"},
    )
    m = load_manifest(p)
    assert m.datasets["daily"].max_rows == 500
