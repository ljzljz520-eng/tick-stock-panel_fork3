"""OS 隔离后端测试：环境清洗 + seatbelt profile 的文件/网络/写入强制。

seatbelt 用例直接以受限 profile 运行裸解释器，验证 OS 层独立于
AST 闸门真实生效（AST 被绕过时仍有这一道）。basic 档至少保证环境清洗。
"""
from __future__ import annotations

import subprocess
import sys

import pytest

from app.sandbox import isolate

_seatbelt_only = pytest.mark.skipif(
    isolate.detect_backend() != isolate.BACKEND_SEATBELT,
    reason="仅在 macOS seatbelt 后端测试 OS 强制",
)


def test_clean_env_has_no_operator_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("OPERATOR_SECRET", "do-not-leak")
    env = isolate.build_env(tmp_path / "scratch")
    assert "OPERATOR_SECRET" not in env
    assert env["HOME"].endswith("scratch")
    assert env["TMPDIR"].startswith(str(tmp_path / "scratch"))
    if sys.platform != "win32":
        assert set(env) <= {
            "PATH", "HOME", "TMPDIR", "TZ", "LANG", "LC_ALL", "PYTHONIOENCODING",
        }


def _run_profile(tmp_path, code: str, *, deny_read=None):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir()
    argv = isolate.build_argv(
        isolate.BACKEND_SEATBELT,
        [sys.executable, "-I", "-c", code],
        scratch=scratch,
        plugin_dir=plugin_dir,
        deny_read=deny_read or [],
    )
    return (
        subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=30,
            env=isolate.build_env(scratch),
        ),
        scratch,
    )


@_seatbelt_only
def test_sensitive_file_read_denied_by_os(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    secret = vault / "key.txt"
    secret.write_text("super-secret")
    code = (
        "import sys\n"
        f"target = {str(secret)!r}\n"
        "try:\n"
        "    open(target).read()\n"
        "except OSError:\n"
        "    print('READ_DENIED')\n"
        "    sys.exit(10)\n"
        "sys.exit(11)\n"
    )
    proc, _ = _run_profile(tmp_path, code, deny_read=[vault])
    assert proc.returncode == 10, proc.stderr
    assert "READ_DENIED" in proc.stdout
    assert "super-secret" not in proc.stdout


@_seatbelt_only
def test_network_denied_by_os(tmp_path):
    code = (
        "import socket, sys\n"
        "s = socket.socket()\n"
        "s.settimeout(2)\n"
        "try:\n"
        "    s.connect(('1.1.1.1', 443))\n"
        "except OSError:\n"
        "    print('NET_DENIED')\n"
        "    sys.exit(10)\n"
        "sys.exit(11)\n"
    )
    proc, _ = _run_profile(tmp_path, code)
    assert proc.returncode == 10, proc.stderr
    assert "NET_DENIED" in proc.stdout


@_seatbelt_only
def test_write_outside_scratch_denied(tmp_path):
    target = tmp_path / "outside.txt"
    code = (
        "import sys\n"
        f"target = {str(target)!r}\n"
        "try:\n"
        "    open(target, 'w').write('x')\n"
        "except OSError:\n"
        "    print('WRITE_DENIED')\n"
        "    sys.exit(10)\n"
        "sys.exit(11)\n"
    )
    proc, _ = _run_profile(tmp_path, code)
    assert proc.returncode == 10, proc.stderr
    assert "WRITE_DENIED" in proc.stdout
    assert not target.exists()


@_seatbelt_only
def test_scratch_write_and_plugin_read_allowed(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir()
    (plugin_dir / "data.txt").write_text("payload")
    out = scratch / "out.txt"
    code = (
        f"out = {str(out)!r}\n"
        f"src = {str(plugin_dir / 'data.txt')!r}\n"
        "assert open(src).read() == 'payload'\n"
        "open(out, 'w').write('ok')\n"
    )
    argv = isolate.build_argv(
        isolate.BACKEND_SEATBELT,
        [sys.executable, "-I", "-c", code],
        scratch=scratch, plugin_dir=plugin_dir, deny_read=[],
    )
    proc = subprocess.run(
        argv, capture_output=True, text=True, timeout=30,
        env=isolate.build_env(scratch),
    )
    assert proc.returncode == 0, proc.stderr
    assert out.read_text() == "ok"
