"""数据面：共享内存 + Arrow IPC。

所有权规则（关键）：
- 所有共享内存段一律由**宿主进程**创建和回收，worker 只用名字打开，
  因此即使 worker 崩溃/被杀，段的释放路径始终在受信侧；
- 每次调用宿主预创建一个"结果槽"（容量=策略 output_mb），worker 只能
  写入该槽，不能自建段、也不能读取其他调用的段名；
- 宿主在运行启动时按注册表清扫上次异常退出残留的段。

输入侧零拷贝：worker mmap 段后由 Arrow IPC 直接构造记录批，
不经过 stdio、不在控制面复制整表。
"""
from __future__ import annotations

import contextlib
import itertools
import os
import threading
from dataclasses import dataclass
from multiprocessing import shared_memory

import pyarrow as pa

_SHM_PREFIX = "tsp"  # 加 posix 自动补的 '/' 与 hex 后远低于 macOS 31 字符限制


@dataclass(frozen=True)
class ShmHandle:
    name: str
    size: int  # 对输入槽=有效载荷字节；对结果槽=容量


def encode_arrow(obj: object) -> bytes:
    """pa.Table 或 polars.DataFrame -> Arrow IPC stream 字节。"""
    if not isinstance(obj, pa.Table):
        import polars as pl

        if not isinstance(obj, pl.DataFrame):
            raise TypeError(f"数据面只接受 Arrow Table/Polars DataFrame: {type(obj)}")
        obj = obj.to_arrow()
    sink = pa.BufferOutputStream()
    with pa.ipc.new_stream(sink, obj.schema) as writer:
        writer.write_table(obj)
    return sink.getvalue().to_pybytes()


class ShmRegistry:
    """宿主侧 shm 段注册表：创建即登记，释放即摘除，启动即清扫。"""

    def __init__(self, registry_file: str | os.PathLike[str]):
        self._file = str(registry_file)
        self._lock = threading.Lock()
        self._counter = itertools.count(1)
        self._live: dict[str, shared_memory.SharedMemory] = {}

    def sweep_stale(self) -> list[str]:
        """清理上一进程残留段（注册表内、当前未持有的全部名字）。"""
        removed: list[str] = []
        with self._lock:
            names: list[str] = []
            if os.path.exists(self._file):
                with open(self._file, encoding="utf-8") as f:
                    names = [line.strip() for line in f if line.strip()]
            for name in names:
                try:
                    stale = shared_memory.SharedMemory(name=name, create=False)
                    stale.close()
                    stale.unlink()
                    removed.append(name)
                except FileNotFoundError:
                    continue
            self._persist_locked()
        return removed

    def create(self, capacity: int) -> ShmHandle:
        with self._lock:
            name = f"{_SHM_PREFIX}{os.getpid():x}{next(self._counter):08x}"
            shm = shared_memory.SharedMemory(name=name, create=True, size=capacity)
            self._live[name] = shm
            self._persist_locked()
            return ShmHandle(name=name, size=capacity)

    def write_payload(self, handle: ShmHandle, payload: bytes) -> ShmHandle:
        """把载荷写入已创建段；返回载荷等大的新句柄。"""
        if len(payload) > handle.size:
            raise ValueError("共享内存段容量不足")
        with self._lock:
            shm = self._live[handle.name]
        shm.buf[: len(payload)] = payload
        return ShmHandle(name=handle.name, size=len(payload))

    def read_payload(self, handle: ShmHandle) -> memoryview:
        with self._lock:
            shm = self._live[handle.name]
        return memoryview(shm.buf)[: handle.size]

    def open_remote_payload(self, handle: ShmHandle) -> memoryview:
        """读取 worker 写进结果槽的内容（槽在宿主注册表内）。"""
        return self.read_payload(handle)

    def release(self, name: str) -> None:
        with self._lock:
            shm = self._live.pop(name, None)
            if shm is None:
                return
            self._persist_locked()
        shm.close()
        with contextlib.suppress(FileNotFoundError):
            shm.unlink()

    def release_all(self) -> None:
        with self._lock:
            names = list(self._live)
        for name in names:
            self.release(name)

    def live_names(self) -> list[str]:
        with self._lock:
            return list(self._live)

    def _persist_locked(self) -> None:
        os.makedirs(os.path.dirname(self._file) or ".", exist_ok=True)
        tmp = self._file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for name in self._live:
                f.write(name + "\n")
        os.replace(tmp, self._file)
