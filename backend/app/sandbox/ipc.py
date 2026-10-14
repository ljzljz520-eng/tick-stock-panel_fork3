"""worker 控制面：8 字节大端长度前缀的 JSON 帧（stdin/stdout）。

数据面（Arrow 批量数据）走共享内存，控制面只传句柄与 JSON 参数，
单帧因此限制为 8 MiB，防止插件用超大 JSON 撑爆宿主读循环。
"""
from __future__ import annotations

import json
import struct
from typing import BinaryIO

_MAX_FRAME = 8 * 1024 * 1024
_PREFIX = struct.Struct(">Q")


def write_frame(fh: BinaryIO, message: dict) -> None:
    payload = json.dumps(message, ensure_ascii=False).encode("utf-8")
    if len(payload) > _MAX_FRAME:
        raise ValueError(f"IPC 帧超出控制面上限: {len(payload)} > {_MAX_FRAME}")
    fh.write(_PREFIX.pack(len(payload)))
    fh.write(payload)
    fh.flush()


def read_frame(fh: BinaryIO) -> dict | None:
    """读取一帧；对端关闭返回 None。"""
    prefix = _read_exact(fh, _PREFIX.size)
    if prefix is None:
        return None
    (length,) = _PREFIX.unpack(prefix)
    if length > _MAX_FRAME:
        raise ValueError(f"对端 IPC 帧超长: {length}")
    payload = _read_exact(fh, length)
    if payload is None:
        raise EOFError("IPC 帧体未读完连接即关闭")
    return json.loads(payload.decode("utf-8"))


def _read_exact(fh: BinaryIO, length: int) -> bytes | None:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = fh.read(remaining)
        if not chunk:
            if not chunks and remaining == length:
                return None
            raise EOFError("IPC 通道意外关闭")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
