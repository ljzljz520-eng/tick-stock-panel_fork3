"""AST 静态闸门测试：未授权 import、动态执行、反射逃逸一律拒绝。"""
from __future__ import annotations

import pytest

from app.sandbox.digests import code_digests
from app.sandbox.manifest import load_manifest
from app.sandbox.static_check import check_plugin


def _scan(path):
    m = load_manifest(path)
    report = check_plugin(path, m)
    return m, report


def test_clean_plugin_passes(tmp_path, make_plugin_fn):
    p = make_plugin_fn(
        tmp_path / "ok",
        "import json\n\n"
        "def handle(ctx, x=1):\n"
        "    return {'echo': x, 's': json.dumps({'a': 1})}\n",
        imports=["json"],
    )
    _, report = _scan(p)
    assert report.ok, report.findings


def test_local_helper_module_allowed(tmp_path, make_plugin_fn):
    p = make_plugin_fn(
        tmp_path / "local",
        "from helper import calc\n\n"
        "def handle(ctx):\n    return calc(2)\n",
        imports=["json"],
        extra_files={"helper.py": "def calc(n):\n    return n * 21\n"},
    )
    _, report = _scan(p)
    assert report.ok, report.findings


def test_socket_import_denied(tmp_path, make_plugin_fn):
    p = make_plugin_fn(
        tmp_path / "net",
        "import socket\n\ndef handle(ctx):\n    return 1\n",
        imports=["json"],
    )
    _, report = _scan(p)
    assert not report.ok
    assert any("socket" in f for f in report.findings)


def test_os_and_subprocess_import_denied(tmp_path, make_plugin_fn):
    code = (
        "import os\n"
        "import subprocess\n\n"
        "def handle(ctx):\n"
        "    return os.listdir('.')\n"
    )
    p = make_plugin_fn(tmp_path / "os", code, imports=["json"])
    _, report = _scan(p)
    joined = "\n".join(report.findings)
    assert "os" in joined and "subprocess" in joined


def test_undeclared_third_party_denied(tmp_path, make_plugin_fn):
    # polars 在全局白名单内，但插件没在 manifest 申请 → 拒绝（最小权限）。
    p = make_plugin_fn(
        tmp_path / "undeclared",
        "import polars\n\ndef handle(ctx):\n    return 1\n",
        imports=["json"],
    )
    _, report = _scan(p)
    assert any("polars" in f for f in report.findings)


def test_dynamic_execution_builtins_denied(tmp_path, make_plugin_fn):
    code = (
        "def handle(ctx):\n"
        "    return eval('1 + 1')\n"
    )
    p = make_plugin_fn(tmp_path / "evil", code, imports=["json"])
    _, report = _scan(p)
    assert any("eval" in f for f in report.findings)


def test_open_builtin_denied(tmp_path, make_plugin_fn):
    code = "def handle(ctx):\n    return open('/etc/passwd').read()\n"
    p = make_plugin_fn(tmp_path / "open", code, imports=["json"])
    _, report = _scan(p)
    assert any("open" in f for f in report.findings)


def test_getattr_denied_as_reflection_channel(tmp_path, make_plugin_fn):
    code = (
        "def handle(ctx, x=1):\n"
        "    return getattr(x, '__class__')\n"
    )
    p = make_plugin_fn(tmp_path / "ga", code, imports=["json"])
    _, report = _scan(p)
    assert any("getattr" in f for f in report.findings)


def test_subclasses_escape_chain_denied(tmp_path, make_plugin_fn):
    code = (
        "def handle(ctx):\n"
        "    return ().__class__.__bases__[0].__subclasses__()\n"
    )
    p = make_plugin_fn(tmp_path / "escape", code, imports=["json"])
    _, report = _scan(p)
    joined = "\n".join(report.findings)
    assert "__subclasses__" in joined
    assert "__bases__" in joined


def test_star_import_denied(tmp_path, make_plugin_fn):
    code = "from json import *\n\ndef handle(ctx):\n    return 1\n"
    p = make_plugin_fn(tmp_path / "star", code, imports=["json"])
    _, report = _scan(p)
    assert any("star import" in f for f in report.findings)


def test_missing_entry_callable_denied(tmp_path, make_plugin_fn):
    p = make_plugin_fn(
        tmp_path / "noentry",
        "def other(ctx):\n    return 1\n",
        imports=["json"],
    )
    _, report = _scan(p)
    assert any("entry" in f for f in report.findings)


def test_relative_import_outside_package_denied(tmp_path, make_plugin_fn):
    code = "from .... import secret\n\ndef handle(ctx):\n    return 1\n"
    p = make_plugin_fn(tmp_path / "rel", code, imports=["json"])
    _, report = _scan(p)
    assert not report.ok


def test_native_code_file_rejected(tmp_path, make_plugin_fn):
    p = make_plugin_fn(
        tmp_path / "native",
        "def handle(ctx):\n    return 1\n",
        imports=["json"],
        extra_files={"evil.so": "binary-ish"},
    )
    with pytest.raises(ValueError, match="原生代码"):
        code_digests(p)


def test_symlink_rejected(tmp_path, make_plugin_fn, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside")
    secret = outside / "secret.txt"
    secret.write_text("x")
    p = make_plugin_fn(
        tmp_path / "link",
        "def handle(ctx):\n    return 1\n",
        imports=["json"],
    )
    (p / "link.txt").symlink_to(secret)
    with pytest.raises(ValueError, match="符号链接"):
        code_digests(p)
