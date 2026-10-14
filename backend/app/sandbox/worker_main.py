"""受限 worker 进程入口（由宿主以 ``python -I <本文件>`` 启动）。

本文件以沙箱目录为 sys.path[0] 运行，刻意只用兄弟模块（ipc / shm_channel /
errors）+ 标准库，不 import 应用包：worker 内不应出现任何宿主业务代码路径。

信任链：
- 进程外：OS 隔离后端（seatbelt/bwrap/basic）+ rlimits + env 清洗；
- 进程内：插件源码以受限 ``__builtins__`` 执行，动态 import 受白名单守卫，
  文件/动态执行/反射内置名全部摘除；第三方库（polars/pyarrow 等）按审批
  digest 固化，以完整内置执行（它们是受信依赖，不是插件代码）。
"""
from __future__ import annotations

import builtins
import contextlib
import io
import itertools
import json
import os
import sys
import traceback
import types
from multiprocessing import shared_memory
from pathlib import Path

import errors
import ipc
import shm_channel

# 在任何受限化之前固定引导期需要的真函数。
_real_compile = compile
_real_exec = exec
_real_import = builtins.__import__

RAW_IN = sys.stdin.buffer
RAW_OUT = sys.stdout.buffer

# 插件可使用的内置名白名单（显式枚举，默认拒绝其余一切）。
_BUILTIN_ALLOWLIST = {
    "abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes",
    "chr", "complex", "dict", "divmod", "enumerate", "filter", "float",
    "format", "frozenset", "hash", "hex", "int", "isinstance", "issubclass",
    "iter", "len", "list", "map", "max", "min", "next", "oct", "ord", "pow",
    "print", "range", "repr", "reversed", "round", "set", "slice", "sorted",
    "str", "sum", "tuple", "type", "zip", "object", "property",
    "staticmethod", "classmethod", "super", "__build_class__",
    "NotImplemented", "Ellipsis",
    # 插件需要能抛出/捕获的异常类型。
    "BaseException", "Exception", "ArithmeticError", "AssertionError",
    "AttributeError", "FloatingPointError", "IndexError", "KeyError",
    "LookupError", "NameError", "NotImplementedError", "OSError",
    "OverflowError", "RecursionError", "RuntimeError", "StopIteration",
    "TypeError", "ValueError", "ZeroDivisionError", "UnicodeError",
    "UnicodeDecodeError", "UnicodeEncodeError", "TimeoutError",
    "ConnectionError", "json",
}


class _LogStream(io.TextIOBase):
    """sys.stdout/stderr 替身：插件 print 与未捕获输出变成 log 帧，绝不污染帧通道。"""

    def __init__(self, level: str, send):
        self._level = level
        self._send = send
        self._buf = ""

    def writable(self) -> bool:
        return True

    def write(self, text: object) -> int:
        if not isinstance(text, str):
            text = str(text)
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                self._send_log(line)
        return len(text)

    def flush(self) -> None:
        if self._buf.strip():
            self._send_log(self._buf)
        self._buf = ""

    def _send_log(self, line: str) -> None:
        try:
            self._send({"type": "log", "level": self._level,
                        "message": line[:2000]})
        except (BrokenPipeError, OSError):
            os._exit(2)


class PluginContext:
    """插件每个调用收到的唯一能力句柄。"""

    def __init__(self, granted: dict, result_slot: dict):
        self._granted = granted
        self._result_slot = result_slot
        # 输入 shm 映射在调用期保持打开（polars 零拷贝引用其缓冲），
        # 由 _execute_call 在调用结束后统一关闭；宿主负责 unlink。
        self._shm_handles: list[shared_memory.SharedMemory] = []
        self.data = _DataClient(self)
        self.http = _HttpClient(self)
        self.log = _LogClient(self)

    # 由主循环注入。
    _broker = None

    def broker_call(self, method: str, params: dict) -> dict:
        return self._broker(method, params)


class _DataClient:
    def __init__(self, ctx: PluginContext):
        self._ctx = ctx

    def query(
        self,
        dataset: str,
        symbols: list[str],
        start: str | None = None,
        end: str | None = None,
    ):
        """返回 polars.DataFrame。

        Arrow 记录批次零拷贝映射自 shm；映射关闭前必须先由 polars 物化为
        插件自有内存，否则 Arrow 缓冲区仍导出指针会导致 close 失败。
        """
        import polars as pl
        import pyarrow as pa

        resp = self._ctx.broker_call("data.query", {
            "dataset": dataset, "symbols": list(symbols),
            "start": start, "end": end,
        })
        handle = resp["shm"]
        shm = shared_memory.SharedMemory(name=handle["name"], create=False)
        view = memoryview(shm.buf)[: handle["size"]]
        table = pa.ipc.open_stream(pa.py_buffer(view)).read_all()
        frame = pl.from_arrow(table)
        self._ctx._shm_handles.append(shm)
        return frame


class _HttpClient:
    def __init__(self, ctx: PluginContext):
        self._ctx = ctx

    def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict | None = None,
        json: object = None,
    ) -> dict:
        params: dict = {"url": url, "method": method}
        if headers is not None:
            params["headers"] = headers
        if json is not None:
            params["json"] = json
        return self._ctx.broker_call("http.fetch", params)


class _LogClient:
    _LEVELS = ("debug", "info", "warning", "error")

    def __init__(self, ctx: PluginContext):
        self._ctx = ctx

    def _emit(self, level: str, message: str) -> None:
        self._ctx.broker_call("log", {"level": level, "message": str(message)})

    def debug(self, message: str) -> None:
        self._emit("debug", message)

    def info(self, message: str) -> None:
        self._emit("info", message)

    def warning(self, message: str) -> None:
        self._emit("warning", message)

    def error(self, message: str) -> None:
        self._emit("error", message)


# ============================================================
# 受限执行环境
# ============================================================

class RestrictedEnvironment:
    def __init__(self, plugin_dir: Path, granted: dict):
        self.dir = plugin_dir.resolve()
        self.allowed_imports = set(granted.get("imports", []))
        self.modules: dict[str, types.ModuleType] = {}
        self.builtins = self._build_builtins()

    def _build_builtins(self) -> dict:
        allowed = {
            name: getattr(builtins, name)
            for name in _BUILTIN_ALLOWLIST
            if hasattr(builtins, name)
        }
        allowed["__import__"] = self.guarded_import
        allowed["json"] = json
        return allowed

    def guarded_import(self, name, g_globals=None, g_locals=None,
                       fromlist=(), level=0):
        g_globals = g_globals or {}
        if level:
            return self._import_relative(name, g_globals, fromlist, level)
        top = str(name).split(".", 1)[0]
        if top in self.allowed_imports:
            return _real_import(name, g_globals, g_locals, fromlist, 0)
        if self._local_candidate(tuple(str(name).split("."))):
            return self._import_local(name, fromlist)
        raise ImportError(
            f"沙箱拒绝 import {name!r}：未在签名策略授权的白名单内"
        )

    def _import_relative(self, name, g_globals, fromlist, level):
        package = str(g_globals.get("__package__") or "")
        parts = [p for p in package.split(".") if p]
        if level - 1 > len(parts):
            raise ImportError("相对导入越出插件包")
        base = parts[: len(parts) - (level - 1)] if level > 1 else parts
        target = tuple(base + str(name).split(".")) if str(name) else tuple(base)
        if not target or not self._local_candidate(target):
            raise ImportError(f"相对导入目标不在插件目录: {'.'.join(target)}")
        module = self.load_local(".".join(target))
        return self._bind_fromlist(module, target, fromlist)

    def _import_local(self, name: str, fromlist) -> types.ModuleType:
        module = self.load_local(name)
        return self._bind_fromlist(module, tuple(name.split(".")), fromlist)

    def _bind_fromlist(
        self, module: types.ModuleType, parts: tuple[str, ...], fromlist
    ) -> types.ModuleType:
        if not fromlist:
            return module
        for item in fromlist:
            if item == "*":
                raise ImportError("worker 禁止 star import")
            if hasattr(module, item):
                continue
            sub_parts = (*parts, item)
            if self._local_candidate(sub_parts):
                sub = self.load_local(".".join(sub_parts))
                setattr(module, item, sub)
        return module

    def _local_candidate(self, parts: tuple[str, ...]) -> Path | None:
        base = self.dir.joinpath(*parts)
        init = base / "__init__.py"
        module = base.with_suffix(".py")
        if init.is_file():
            return init
        if module.is_file():
            return module
        return None

    def load_local(self, fullname: str) -> types.ModuleType:
        if fullname in self.modules:
            return self.modules[fullname]
        parts = tuple(fullname.split("."))
        path = self._local_candidate(parts)
        if path is None:
            raise ImportError(f"插件本地模块不存在: {fullname}")
        # 防穿越：路径必须严格位于插件目录内。
        if not str(path.resolve()).startswith(str(self.dir) + os.sep):
            raise ImportError(f"模块路径越界: {fullname}")

        is_package = path.name == "__init__.py"
        module = types.ModuleType(fullname)
        module.__file__ = str(path)
        module.__loader__ = None
        if is_package:
            module.__package__ = fullname
            module.__path__ = [str(path.parent)]
        else:
            module.__package__ = ".".join(parts[:-1])
        module.__builtins__ = self.builtins  # type: ignore[attr-defined]
        self.modules[fullname] = module  # 先登记，防循环导入重入
        # 父包属性挂载。
        if len(parts) > 1:
            parent = self.load_local(".".join(parts[:-1]))
            setattr(parent, parts[-1], module)

        source = path.read_text(encoding="utf-8")
        code = _real_compile(source, str(path), "exec")
        _real_exec(code, module.__dict__)
        return module


# ============================================================
# 主循环
# ============================================================

def main() -> int:
    def send(message: dict) -> None:
        ipc.write_frame(RAW_OUT, message)

    log_stream_out = _LogStream("info", send)
    log_stream_err = _LogStream("error", send)
    sys.stdout = log_stream_out  # type: ignore[assignment]
    sys.stderr = log_stream_err  # type: ignore[assignment]

    try:
        hello = ipc.read_frame(RAW_IN)
    except (EOFError, ValueError):
        return 0
    if not hello or hello.get("type") != "hello":
        return 2

    granted = hello.get("granted") or {}
    try:
        plugin_dir = Path(hello["dir"])
        entry_ref = hello["entry"]
        env = RestrictedEnvironment(plugin_dir, granted)
        module_name, callable_name = entry_ref.split(":", 1)
        module = env.load_local(module_name)
        fn = module.__dict__.get(callable_name)
        if not callable(fn):
            raise TypeError(f"entry 不可调用: {entry_ref}")
    except Exception as e:  # noqa: BLE001
        send({"type": "ready", "ok": False,
              "error": {"type": type(e).__name__, "message": str(e)}})
        return 2

    send({"type": "ready", "ok": True})

    while True:
        try:
            frame = ipc.read_frame(RAW_IN)
        except (EOFError, ValueError):
            return 0
        if frame is None:
            return 0
        if frame.get("type") == "shutdown":
            return 0
        if frame.get("type") != "call":
            continue
        if _execute_call(frame, send, granted, fn):
            return 0


def _execute_call(frame: dict, send, granted: dict, fn) -> bool:
    """执行单次调用。返回 True 表示 worker 应退出（SystemExit）。"""
    call_id = frame.get("id")
    kwargs = frame.get("kwargs") or {}
    result_slot = frame.get("result_slot") or {}
    ctx = PluginContext(granted, result_slot)
    counter = itertools.count(1)
    ctx._broker = _make_broker_call(send, counter)  # type: ignore[attr-defined]

    try:
        try:
            result = fn(ctx, **kwargs)
            _send_result(send, call_id, result, result_slot, granted)
        except SystemExit:
            return True
        except BaseException as e:  # noqa: BLE001 - 任何插件异常都不得杀通道
            send({
                "type": "error", "id": call_id,
                "error": {
                    "type": type(e).__name__,
                    "message": str(e)[:1000],
                    "trace": traceback.format_exc(limit=5)[-1500:],
                },
            })
        return False
    finally:
        # 调用结束：插件局部 frame 已随栈帧释放，关闭输入映射。
        # 若插件把零拷贝 frame 藏进了模块级全局（仍计入其 RSS 配额），
        # BufferError 时延后到 worker 退出回收，宿主侧 unlink 不受影响。
        for shm in ctx._shm_handles:
            with contextlib.suppress(BufferError):
                shm.close()
        ctx._shm_handles.clear()


def _make_broker_call(send, counter):
    def broker_call(method: str, params: dict) -> dict:
        req_id = next(counter)
        send({"type": "broker_request", "id": req_id,
              "method": method, "params": params})
        while True:
            resp = ipc.read_frame(RAW_IN)
            if not resp or resp.get("type") != "broker_response" \
                    or resp.get("id") != req_id:
                raise RuntimeError("broker 响应帧错位")
            body = resp.get("body") or {}
            if not body.get("ok"):
                err = body.get("error") or {}
                cls = getattr(errors, err.get("type", "SandboxError"),
                              errors.SandboxError)
                raise cls(str(err.get("message", "broker 拒绝")))
            return body

    return broker_call


def _send_result(send, call_id, result, result_slot: dict, granted: dict) -> None:
    # polars DataFrame -> 预分配结果槽（零自建 shm）。
    try:
        import polars as pl
    except ImportError:
        pl = None  # type: ignore[assignment]

    if pl is not None and isinstance(result, pl.DataFrame):
        payload = shm_channel.encode_arrow(result)
        capacity = int(result_slot.get("size", 0))
        if len(payload) > capacity:
            raise MemoryError(
                f"结果数据 {len(payload)} 字节超过 output_mb 容量 {capacity}"
            )
        shm = shared_memory.SharedMemory(
            name=result_slot["name"], create=False
        )
        try:
            shm.buf[: len(payload)] = payload
        finally:
            shm.close()
        send({"type": "result_shm", "id": call_id, "size": len(payload)})
        return

    try:
        encoded = json.dumps(result, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise TypeError(f"返回值不是 JSON 可序列化对象: {type(result).__name__}") from e
    cap = int(granted.get("resources", {}).get("output_mb", 16)) * 1024 * 1024
    if len(encoded) > cap:
        raise MemoryError(f"JSON 结果 {len(encoded)} 字节超过 output_mb 容量 {cap}")
    send({"type": "result", "id": call_id, "result": json.loads(encoded)})


if __name__ == "__main__":
    sys.exit(main())
