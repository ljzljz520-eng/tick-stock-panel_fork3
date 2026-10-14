"""哈希链审计：append 链校验、篡改断链、重启续链。"""
from __future__ import annotations

import json

from app.sandbox.audit import GENESIS, AuditLog, verify_chain


def test_chain_valid_after_appends(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("a", "p1", x=1)
    log.append("b", "p1", x=2)
    log.append("c", "p2", x=3)
    ok, broken = verify_chain(log.path)
    assert ok and broken is None
    rows = [json.loads(line) for line in log.path.read_text().splitlines()]
    assert [r["seq"] for r in rows] == [1, 2, 3]
    assert rows[0]["prev_hash"] == GENESIS


def test_tampered_entry_breaks_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("a", details={"v": 1})
    log.append("b", details={"v": 2})
    log.append("c", details={"v": 3})
    lines = path.read_text().splitlines()
    row = json.loads(lines[1])
    row["details"] = {"v": 999}
    lines[1] = json.dumps(row)
    path.write_text("\n".join(lines) + "\n")
    ok, broken = verify_chain(path)
    assert not ok
    assert broken == 2


def test_deleted_entry_breaks_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(4):
        log.append(f"e{i}")
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    ok, broken = verify_chain(path)
    assert not ok
    assert broken == 2


def test_chain_continues_across_restart(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).append("a")
    AuditLog(path).append("b")
    log3 = AuditLog(path)
    entry = log3.append("c")
    assert entry["seq"] == 3
    ok, _ = verify_chain(path)
    assert ok


def test_secret_value_in_details_does_not_become_secret_handling(tmp_path):
    # 审计层只负责链接完整性；密钥脱敏由 broker 保证（在 broker 测试中断言）。
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("x", alias="token", header_name="Authorization")
    ok, _ = verify_chain(log.path)
    assert ok
