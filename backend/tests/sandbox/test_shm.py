"""共享内存注册表：创建/读写/释放，以及崩溃残留段启动清扫。"""
from __future__ import annotations

from multiprocessing import shared_memory

import polars as pl
import pyarrow as pa
import pytest

from app.sandbox.shm_channel import ShmRegistry, encode_arrow


def test_create_write_read_release(tmp_path):
    reg = ShmRegistry(tmp_path / "names")
    handle = reg.create(4096)
    reg.write_payload(handle, b"hello")
    view = reg.read_payload(handle)
    assert bytes(view[:5]) == b"hello"
    del view  # 解除导出，否则 POSIX 段无法 close
    reg.release(handle.name)
    assert reg.live_names() == []
    with pytest.raises(FileNotFoundError):
        shared_memory.SharedMemory(name=handle.name, create=False)


def test_write_beyond_capacity_rejected(tmp_path):
    reg = ShmRegistry(tmp_path / "names")
    handle = reg.create(4)
    with pytest.raises(ValueError, match="容量不足"):
        reg.write_payload(handle, b"too-long")
    reg.release(handle.name)


def test_arrow_roundtrip_via_shm(tmp_path):
    reg = ShmRegistry(tmp_path / "names")
    df = pl.DataFrame({"symbol": ["000001", "600000"], "close": [1.5, 2.5]})
    payload = encode_arrow(df)
    handle = reg.create(len(payload))
    reg.write_payload(handle, payload)

    remote = shared_memory.SharedMemory(name=handle.name, create=False)
    view = memoryview(remote.buf)[: len(payload)]
    table = pa.ipc.open_stream(pa.py_buffer(view)).read_all()
    back = pl.from_arrow(table)
    assert back["close"].sum() == 4.0
    # 释放全部导出指针后才能关闭映射。
    del back, table, view
    remote.close()
    reg.release(handle.name)
    assert reg.live_names() == []


def test_sweep_stale_segments_after_crash(tmp_path):
    reg_file = tmp_path / "names"
    first = ShmRegistry(reg_file)
    handle = first.create(1024)
    name = handle.name
    # 模拟宿主崩溃：不释放直接丢弃注册表（名字仍残留在内核与注册表文件中）。
    del first

    second = ShmRegistry(reg_file)
    removed = second.sweep_stale()
    assert name in removed
    with pytest.raises(FileNotFoundError):
        shared_memory.SharedMemory(name=name, create=False)
    assert second.live_names() == []


def test_release_unknown_name_is_noop(tmp_path):
    reg = ShmRegistry(tmp_path / "names")
    reg.release("tspdeadbeef")
