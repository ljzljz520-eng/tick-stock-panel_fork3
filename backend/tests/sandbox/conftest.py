"""沙箱测试公共夹具。"""
from __future__ import annotations

import json
from pathlib import Path

import polars as pl
import pytest

from app.sandbox.audit import AuditLog, verify_chain
from app.sandbox.runtime import SandboxRuntime
from app.sandbox.shm_channel import ShmRegistry


class FakeDataAccess:
    """测试用标准数据口：按标的产出可预测的行情表。"""

    def __init__(self, rows_per_symbol: int = 3):
        self.rows_per_symbol = rows_per_symbol
        self.calls: list[dict] = []

    def query(self, dataset, symbols, start, end, *, limit):
        self.calls.append({
            "dataset": dataset, "symbols": list(symbols),
            "start": start, "end": end, "limit": limit,
        })
        symbols_col: list[str] = []
        close: list[float] = []
        for i, symbol in enumerate(symbols):
            for r in range(self.rows_per_symbol):
                symbols_col.append(symbol)
                close.append(round((i + 1) * 10 + r + 0.25, 2))
        return pl.DataFrame({"symbol": symbols_col, "close": close})


def make_plugin(
    path: Path,
    code: str,
    *,
    name: str = "demo",
    imports: list[str] | None = None,
    datasets: dict | None = None,
    egress: list[str] | None = None,
    secrets: list[dict] | None = None,
    resources: dict | None = None,
    entry: str = "plugin:handle",
    extra_files: dict[str, str] | None = None,
) -> Path:
    lines = [
        "api_version: 1",
        f"name: {name}",
        'version: "1.0.0"',
        f"entry: {entry!r}",
    ]
    if imports is not None:
        lines.append("imports: [" + ", ".join(imports) + "]")
    if datasets:
        lines.append("datasets:")
        for ds, cfg in datasets.items():
            lines.append(f"  {ds}: {cfg}")
    if egress:
        lines.append("egress:")
        lines.extend(f"  - {h}" for h in egress)
    if secrets:
        lines.append("secrets:")
        for s in secrets:
            lines.append(f"  - alias: {s['alias']}")
            lines.append(f"    env: {s['env']}")
    if resources:
        lines.append("resources:")
        for key, value in resources.items():
            lines.append(f"  {key}: {value}")
    path.mkdir(parents=True, exist_ok=True)
    (path / "sandbox-plugin.yaml").write_text("\n".join(lines) + "\n",
                                              encoding="utf-8")
    (path / "plugin.py").write_text(code, encoding="utf-8")
    for rel, content in (extra_files or {}).items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def make_plugin_fn():
    return make_plugin


@pytest.fixture
def fake_data() -> FakeDataAccess:
    return FakeDataAccess()


@pytest.fixture
def runtime(tmp_path, fake_data):
    secret_map = {"TOKEN_ENV": "tok-secret-value"}

    def resolver(alias, env):
        return secret_map.get(env)

    rt = SandboxRuntime(
        tmp_path / "sandbox",
        data_access=fake_data,
        secret_resolver=resolver,
    )
    yield rt
    rt.shutdown()


def _audit_rows(rt: SandboxRuntime) -> list[dict]:
    rows = []
    with rt.audit.path.open(encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    return rows


def _assert_audit_intact(rt: SandboxRuntime) -> None:
    ok, broken = verify_chain(rt.audit.path)
    assert ok, f"审计链在第 {broken} 行断裂"


@pytest.fixture
def audit_rows_fn():
    return _audit_rows


@pytest.fixture
def assert_audit_intact_fn():
    return _assert_audit_intact


@pytest.fixture
def broker_parts(tmp_path):
    root = tmp_path / "sb"
    audit = AuditLog(root / "audit.jsonl")
    shm = ShmRegistry(root / "shm_names")
    yield audit, shm
    shm.release_all()
