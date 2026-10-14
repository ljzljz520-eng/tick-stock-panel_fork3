"""宿主 capability broker 授权矩阵：数据/egress/密钥/SSRF/响应封顶/审计脱敏。"""
from __future__ import annotations

import io
import json
import urllib.request
from multiprocessing import shared_memory

import polars as pl
import pyarrow as pa

from app.sandbox import broker as broker_mod
from app.sandbox.audit import verify_chain
from app.sandbox.broker import CapabilityBroker
from app.sandbox.manifest import load_manifest


def _granted(tmp_path, make_plugin_fn, **kwargs):
    p = make_plugin_fn(
        tmp_path / "p",
        "def handle(ctx):\n    return 1\n",
        **kwargs,
    )
    return load_manifest(p).granted_dict()


def _broker(broker_parts, fake_data, resolver=None):
    audit, shm = broker_parts
    return CapabilityBroker(
        audit, shm,
        data_access=fake_data,
        secret_resolver=resolver or (lambda alias, env: None),
    ), audit, shm


def _open_shm_frame(handle):
    """返回 (frame, remote, view, table)；调用方断言后需先 del frame 再 close。"""
    remote = shared_memory.SharedMemory(name=handle["name"], create=False)
    view = memoryview(remote.buf)[: handle["size"]]
    table = pa.ipc.open_stream(pa.py_buffer(view)).read_all()
    return pl.from_arrow(table), remote, view, table


# --------------------------------------------------------------- data.query

def test_data_query_authorized_zero_copy(tmp_path, make_plugin_fn, broker_parts, fake_data):
    granted = _granted(
        tmp_path, make_plugin_fn,
        imports=["json"],
        datasets={"daily": "{symbols: ['*'], max_rows: 500}"},
    )
    broker, audit, shm = _broker(broker_parts, fake_data)
    resp = broker.handle(
        "demo", granted, 1, "data.query",
        {"dataset": "daily", "symbols": ["000001", "600000"]},
    )
    assert resp["ok"] is True
    df, remote, view, table = _open_shm_frame(resp["shm"])
    assert df.height == 6
    assert df["close"].sum() > 0
    # limit 已下推给数据适配口。
    assert fake_data.calls[-1]["limit"] == 500
    del df, table, view
    remote.close()
    shm.release(resp["shm"]["name"])
    assert verify_chain(audit.path)[0]


def test_data_query_unauthorized_dataset_denied(tmp_path, make_plugin_fn, broker_parts, fake_data):
    granted = _granted(
        tmp_path, make_plugin_fn,
        datasets={"daily": "{symbols: ['*'], max_rows: 100}"},
    )
    broker, _, _ = _broker(broker_parts, fake_data)
    resp = broker.handle(
        "demo", granted, 1, "data.query",
        {"dataset": "financial", "symbols": ["000001"]},
    )
    assert resp["ok"] is False
    assert "未授权数据集" in resp["error"]["message"]


def test_data_query_symbol_outside_grant_denied(tmp_path, make_plugin_fn, broker_parts, fake_data):
    granted = _granted(
        tmp_path, make_plugin_fn,
        datasets={"daily": "{symbols: ['000001'], max_rows: 100}"},
    )
    broker, _, _ = _broker(broker_parts, fake_data)
    resp = broker.handle(
        "demo", granted, 1, "data.query",
        {"dataset": "daily", "symbols": ["600000"]},
    )
    assert resp["ok"] is False
    assert "授权范围" in resp["error"]["message"]


def test_data_query_adapter_over_limit_fails_closed(
    tmp_path, make_plugin_fn, broker_parts,
):
    # 适配口违约返回超限行数：broker 必须复核并拒绝，不得把超量数据下发。
    granted = _granted(
        tmp_path, make_plugin_fn,
        datasets={"daily": "{symbols: ['*'], max_rows: 2}"},
    )

    class GreedySource:
        def query(self, dataset, symbols, start, end, *, limit):
            return pl.DataFrame({"close": [1.0, 2.0, 3.0]})

    broker, _, shm = _broker(broker_parts, GreedySource())
    resp = broker.handle(
        "demo", granted, 1, "data.query",
        {"dataset": "daily", "symbols": ["000001"]},
    )
    assert resp["ok"] is False
    assert "超过授权上限" in resp["error"]["message"]
    # 拒绝时不应留下 shm 段。
    assert shm.live_names() == []


def test_data_query_without_adapter_denied(tmp_path, make_plugin_fn, broker_parts):
    audit, shm = broker_parts
    broker = CapabilityBroker(audit, shm)
    granted = _granted(
        tmp_path, make_plugin_fn,
        datasets={"daily": "{symbols: ['*'], max_rows: 100}"},
    )
    resp = broker.handle(
        "demo", granted, 1, "data.query",
        {"dataset": "daily", "symbols": ["000001"]},
    )
    assert resp["ok"] is False


# ---------------------------------------------------------------- http.fetch

def test_http_requires_https(tmp_path, make_plugin_fn, broker_parts, fake_data):
    granted = _granted(
        tmp_path, make_plugin_fn,
        egress=["api.example.com"],
    )
    broker, _, _ = _broker(broker_parts, fake_data)
    resp = broker.handle(
        "demo", granted, 1, "http.fetch",
        {"url": "http://api.example.com/v1"},
    )
    assert resp["ok"] is False
    assert "HTTPS" in resp["error"]["message"]


def test_http_host_not_in_egress_denied(tmp_path, make_plugin_fn, broker_parts, fake_data):
    granted = _granted(tmp_path, make_plugin_fn, egress=["api.example.com"])
    broker, _, _ = _broker(broker_parts, fake_data)
    resp = broker.handle(
        "demo", granted, 1, "http.fetch",
        {"url": "https://evil.example.org/v1"},
    )
    assert resp["ok"] is False
    assert "白名单" in resp["error"]["message"]


def test_http_ssrf_loopback_and_private_denied(tmp_path, make_plugin_fn, broker_parts, fake_data):
    granted = _granted(
        tmp_path, make_plugin_fn,
        egress=["localhost", "10.0.0.1"],
    )
    broker, _, _ = _broker(broker_parts, fake_data)
    resp = broker.handle(
        "demo", granted, 1, "http.fetch", {"url": "https://localhost/admin"}
    )
    assert resp["ok"] is False
    assert "非公开地址" in resp["error"]["message"]

    resp2 = broker.handle(
        "demo", granted, 1, "http.fetch", {"url": "https://10.0.0.1/admin"}
    )
    assert resp2["ok"] is False
    assert "非公开地址" in resp2["error"]["message"]


def test_http_unauthorized_secret_alias_denied(tmp_path, make_plugin_fn, broker_parts, fake_data):
    granted = _granted(tmp_path, make_plugin_fn, egress=["api.example.com"])
    broker, _, _ = _broker(broker_parts, fake_data)
    resp = broker.handle(
        "demo", granted, 1, "http.fetch",
        {"url": "https://api.example.com/v1",
         "headers": {"Authorization": {"__secret__": "token"}}},
    )
    assert resp["ok"] is False
    assert "未授权密钥别名" in resp["error"]["message"]


def test_http_plaintext_authorization_header_denied(tmp_path, make_plugin_fn, broker_parts, fake_data):
    granted = _granted(tmp_path, make_plugin_fn, egress=["api.example.com"])
    broker, _, _ = _broker(broker_parts, fake_data)
    resp = broker.handle(
        "demo", granted, 1, "http.fetch",
        {"url": "https://api.example.com/v1",
         "headers": {"Authorization": "Bearer abc"}},
    )
    assert resp["ok"] is False
    assert "__secret__" in resp["error"]["message"]


class _FakeResponse:
    def __init__(self, raw: bytes, ctype: str = "application/json", status: int = 200):
        self._bio = io.BytesIO(raw)
        self.status = status
        self.headers = {"Content-Type": ctype}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n=-1):
        return self._bio.read(n)


def test_http_secret_injected_and_audit_redacted(
    tmp_path, make_plugin_fn, broker_parts, fake_data, monkeypatch,
):
    granted = _granted(
        tmp_path, make_plugin_fn,
        egress=["api.example.com"],
        secrets=[{"alias": "token", "env": "TOKEN_ENV"}],
    )
    audit, shm = broker_parts
    broker = CapabilityBroker(
        audit, shm, data_access=fake_data,
        secret_resolver=lambda alias, env: "tok-secret-value",
    )

    captured: dict = {}

    def fake_open(request, timeout=0):
        captured["request"] = request
        return _FakeResponse(b'{"ok": true}')

    class FakeOpener:
        def open(self, request, timeout=0):
            return fake_open(request, timeout)

    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *handlers: FakeOpener()
    )
    monkeypatch.setattr(broker_mod, "_assert_public_address", lambda host: None)

    resp = broker.handle(
        "demo", granted, 1, "http.fetch",
        {"url": "https://api.example.com/v1?q=secret",
         "headers": {"X-Tag": "t", "Authorization": {"__secret__": "token"}},
         "json": {"a": 1}},
    )
    assert resp["ok"] is True, resp
    assert resp["json"] == {"ok": True}
    # 密钥在宿主侧注入，实际随请求发出，但从未进入插件/审计。
    assert captured["request"].get_header("Authorization") == "tok-secret-value"

    text = audit.path.read_text(encoding="utf-8")
    assert "tok-secret-value" not in text
    # query 不进审计。
    assert "q=secret" not in text
    rows = [json.loads(line) for line in text.splitlines()]
    http_event = next(r for r in rows if r["event"] == "broker_http")
    assert http_event["details"]["secrets"] == ["token"]
    assert "Authorization" in http_event["details"]["header_names"]
    assert http_event["details"]["path"] == "/v1"


def test_http_oversized_response_denied(
    tmp_path, make_plugin_fn, broker_parts, fake_data, monkeypatch,
):
    granted = _granted(tmp_path, make_plugin_fn, egress=["big.example.com"])
    audit, shm = broker_parts
    broker = CapabilityBroker(audit, shm, data_access=fake_data)

    class BigOpener:
        def open(self, request, timeout=0):
            return _FakeResponse(b"x" * (5 * 1024 * 1024), ctype="text/plain")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *h: BigOpener())
    monkeypatch.setattr(broker_mod, "_assert_public_address", lambda host: None)
    resp = broker.handle(
        "demo", granted, 1, "http.fetch",
        {"url": "https://big.example.com/blob"},
    )
    assert resp["ok"] is False
    assert "上限" in resp["error"]["message"]


# ---------------------------------------------------------------- log

def test_plugin_warning_log_enters_audit(tmp_path, make_plugin_fn, broker_parts, fake_data):
    granted = _granted(tmp_path, make_plugin_fn)
    broker, audit, _ = _broker(broker_parts, fake_data)
    broker.handle("demo", granted, -1, "log",
                  {"level": "warning", "message": "careful"})
    broker.handle("demo", granted, -1, "log",
                  {"level": "info", "message": "noise"})
    rows = [json.loads(line) for line in audit.path.read_text().splitlines()]
    events = [r["event"] for r in rows]
    assert events.count("plugin_log") == 1
    assert rows[0]["details"]["message"] == "careful"


def test_unknown_broker_method_denied(tmp_path, make_plugin_fn, broker_parts, fake_data):
    granted = _granted(tmp_path, make_plugin_fn)
    broker, _, _ = _broker(broker_parts, fake_data)
    resp = broker.handle("demo", granted, 1, "fs.read", {"path": "/etc/passwd"})
    assert resp["ok"] is False
    assert "未知 broker 方法" in resp["error"]["message"]
