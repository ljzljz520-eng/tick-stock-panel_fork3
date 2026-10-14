"""追加写、哈希链可校验的沙箱审计日志。

每条记录包含单调序号、UTC 时间、事件名、插件名和详情；
``hash = sha256(prev_hash + 规范化JSON(记录本体))``，删除/重排/篡改任何一行
都会在 :func:`verify_chain` 处断链。

详情中禁止放密钥明文：broker 调用方负责脱敏（headers 只记键名与长度）。
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

from app.sandbox.signature import canonical_json

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = GENESIS
        self._reload_tail()

    def append(self, event: str, plugin: str = "-", **details: object) -> dict:
        with self._lock:
            self._seq += 1
            entry = {
                "seq": self._seq,
                "ts": datetime.now(UTC).isoformat(),
                "event": event,
                "plugin": plugin,
                "details": details,
            }
            digest = hashlib.sha256()
            digest.update(self._prev.encode("ascii"))
            digest.update(b"\n")
            digest.update(canonical_json(entry))
            entry["prev_hash"] = self._prev
            entry["hash"] = digest.hexdigest()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
                f.flush()
            self._prev = entry["hash"]
            return entry

    def _reload_tail(self) -> None:
        if not self.path.is_file():
            return
        last_hash = GENESIS
        seq = 0
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row.get("seq"), int):
                    seq = max(seq, row["seq"])
                if isinstance(row.get("hash"), str):
                    last_hash = row["hash"]
        self._seq = seq
        self._prev = last_hash


def verify_chain(path: Path) -> tuple[bool, int | None]:
    """校验审计链完整性。返回 (是否完好, 首个断链行号)。"""
    prev = GENESIS
    if not Path(path).is_file():
        return True, None
    with Path(path).open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            row = json.loads(line)
            claimed = row.get("hash")
            body = {k: v for k, v in row.items() if k not in ("hash", "prev_hash")}
            digest = hashlib.sha256()
            digest.update(prev.encode("ascii"))
            digest.update(b"\n")
            digest.update(canonical_json(body))
            if digest.hexdigest() != claimed or row.get("prev_hash") != prev:
                return False, lineno
            prev = claimed
    return True, None
