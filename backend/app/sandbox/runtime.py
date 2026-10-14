"""沙箱宿主运行时：scan → approve → activate → call 的唯一编排入口。

生命周期：

- ``scan``    纯读：解析清单 + AST 静态检查 + 代码/依赖 digest，不产生副作用；
- ``approve`` 静态门通过后签发 HMAC 策略落盘，digest 与能力写审计；
- ``activate`` 重算 digest 与签名策略比对（漂移即拒绝），启动受限 worker，
              能力/隔离档位/pid 写审计；
- ``call``    经窄 IPC 调用，wall timeout / RSS 超限 / 崩溃只回收该 worker
              进程组，异常只传导到这一次调用，下次调用惰性重启。
"""
from __future__ import annotations

import contextlib
import itertools
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import psutil

from app.sandbox import ipc, isolate
from app.sandbox.audit import AuditLog
from app.sandbox.broker import CapabilityBroker, DataAccess, SecretResolver
from app.sandbox.digests import code_digests, dependency_digests
from app.sandbox.errors import (
    ActivationDenied,
    WorkerCallError,
    WorkerCrashed,
    WorkerTimeout,
)
from app.sandbox.manifest import CapabilityManifest, load_manifest
from app.sandbox.policy import PolicyRecord, PolicyStore
from app.sandbox.shm_channel import ShmRegistry
from app.sandbox.static_check import StaticReport, check_plugin

logger = logging.getLogger(__name__)

_READY_TIMEOUT_S = 15
_START_KILL_GRACE_S = 2


@dataclass(frozen=True)
class ScanResult:
    plugin_dir: Path
    manifest: CapabilityManifest
    static: StaticReport
    code_digests: dict[str, str]
    dependency_digests: dict[str, str]

    @property
    def approvable(self) -> bool:
        return self.static.ok


class SandboxRuntime:
    def __init__(
        self,
        root: Path | None = None,
        *,
        data_access: DataAccess | None = None,
        secret_resolver: SecretResolver | None = None,
        deny_read: list[Path] | None = None,
    ):
        if root is None:
            from app.config import settings

            root = settings.data_dir / "sandbox"
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.audit = AuditLog(self.root / "audit.jsonl")
        self.policies = PolicyStore(self.root)
        self.shm = ShmRegistry(self.root / "shm_names")
        self.broker = CapabilityBroker(
            self.audit,
            self.shm,
            data_access=data_access,
            secret_resolver=secret_resolver or _env_secret_resolver,
        )
        self._extra_deny = [Path(p) for p in (deny_read or [])]
        self._workers: dict[str, ActiveWorker] = {}
        self._wlock = threading.Lock()
        stale = self.shm.sweep_stale()
        if stale:
            self.audit.append("shm_swept", count=len(stale))

    # ---------------------------------------------------------- scan/approve

    def scan(self, plugin_dir: Path | str) -> ScanResult:
        plugin_dir = Path(plugin_dir).resolve()
        manifest = load_manifest(plugin_dir)
        static = check_plugin(plugin_dir, manifest)
        digests = code_digests(plugin_dir)
        deps = dependency_digests(manifest.imports)
        return ScanResult(
            plugin_dir=plugin_dir,
            manifest=manifest,
            static=static,
            code_digests=digests,
            dependency_digests=deps,
        )

    def approve(self, plugin_dir: Path | str) -> PolicyRecord:
        result = self.scan(plugin_dir)
        if not result.approvable:
            self.audit.append(
                "policy_approve_rejected",
                result.manifest.name,
                findings=list(result.static.findings),
            )
            raise ActivationDenied(
                f"静态检查未通过，拒绝审批: {'; '.join(result.static.findings)}"
            )
        record = self.policies.approve(
            result.manifest,
            result.plugin_dir,
            result.code_digests,
            result.dependency_digests,
        )
        granted = record.granted
        self.audit.append(
            "policy_approved",
            result.manifest.name,
            manifest_digest=record.record["manifest_digest"],
            datasets=sorted(granted["datasets"]),
            egress=list(granted["egress"]),
            secret_aliases=[s["alias"] for s in granted["secrets"]],
            resources=dict(granted["resources"]),
            code_digests=record.code_digests,
            dependency_digests=record.dependency_digests,
            code_files=len(record.code_digests),
        )
        return record

    # ---------------------------------------------------------- activation

    def activate(self, name: str) -> ActiveWorker:
        with self._wlock:
            existing = self._workers.get(name)
            if existing is not None and existing.alive:
                return existing
            record = self.policies.load(name)
            plugin_dir = self._verify_record(name, record)
            worker = ActiveWorker(
                name=name,
                plugin_dir=plugin_dir,
                granted=record.granted,
                runtime=self,
                record=record,
            )
            worker.start()
            self._workers[name] = worker
            return worker

    def _verify_record(self, name: str, record: PolicyRecord) -> Path:
        plugin_dir = Path(record.plugin_dir)
        if not plugin_dir.is_dir():
            raise ActivationDenied(f"插件目录已不存在: {plugin_dir}")
        current_code = code_digests(plugin_dir)
        if current_code != record.code_digests:
            self.audit.append(
                "activation_denied", name, reason="code_digest_mismatch",
                expected=len(record.code_digests), actual=len(current_code),
            )
            raise ActivationDenied("插件代码 digest 与审批策略不一致（代码已变更）")
        current_deps = dependency_digests(
            tuple(sorted(record.granted.get("imports", [])))
        )
        if current_deps != record.dependency_digests:
            self.audit.append(
                "activation_denied", name, reason="dependency_digest_mismatch",
            )
            raise ActivationDenied("依赖 digest 与审批策略不一致（依赖已变更）")
        return plugin_dir

    def deactivate(self, name: str) -> None:
        with self._wlock:
            worker = self._workers.pop(name, None)
        if worker is not None:
            worker.close()

    def shutdown(self) -> None:
        with self._wlock:
            workers = list(self._workers.values())
            self._workers.clear()
        for worker in workers:
            worker.close()
        self.shm.release_all()

    # ---------------------------------------------------------------- call

    def call(self, name: str, **kwargs: object) -> object:
        worker = self.activate(name)
        # 每次调用前重算 digest：即使 worker 已存活，也要防"激活后篡改磁盘上
        # 的插件文件/替换依赖"（本地模块支持调用中延迟 import）。漂移即收
        # 回 worker 并拒绝本次调用。
        try:
            self._verify_record(name, worker.record)
        except ActivationDenied:
            self.deactivate(name)
            raise
        try:
            return worker.call(kwargs)
        except (WorkerCrashed, WorkerTimeout):
            with self._wlock:
                if self._workers.get(name) is worker:
                    self._workers.pop(name, None)
            raise

    def deny_read_paths(self, plugin_dir: Path) -> list[Path]:
        """生效的敏感读拒绝路径：默认数据目录 + 调用方附加，自动豁免解释器/
        worker 自身/插件目录，否则 profile 会把执行所需代码一起拒掉。"""
        from app.config import settings

        candidates = [settings.data_dir, *self._extra_deny]
        worker_file = Path(__file__).resolve()
        prefixes = [
            Path(sys.executable).resolve(),
            worker_file,
            Path(plugin_dir).resolve(),
        ]
        out: list[Path] = []
        for path in candidates:
            resolved = Path(path).resolve()
            if any(_is_prefix(resolved, p) for p in prefixes):
                continue
            out.append(resolved)
        return out

    def scratch_for(self, name: str) -> Path:
        return self.root / "scratch" / name


def _env_secret_resolver(alias: str, env: str) -> str | None:
    return os.environ.get(env)


def _is_prefix(path: Path, prefix: Path) -> bool:
    try:
        path.relative_to(prefix)
        return True
    except ValueError:
        return False


# ============================================================
# 单个活跃 worker
# ============================================================

class ActiveWorker:
    def __init__(
        self,
        *,
        name: str,
        plugin_dir: Path,
        granted: dict,
        runtime: SandboxRuntime,
        record: PolicyRecord,
    ):
        self.name = name
        self.plugin_dir = plugin_dir
        self.granted = granted
        self.record = record
        self.resources = granted.get("resources", {})
        self.rt = runtime
        self.backend = isolate.detect_backend()
        self.proc: subprocess.Popen | None = None
        self.alive = False
        self._wlock = threading.Lock()  # 写 stdin 串行
        self._call_lock = threading.Lock()
        self._ready = threading.Event()
        self._ready_box: dict = {}
        self._pending: dict[int, _PendingCall] = {}
        self._pending_lock = threading.Lock()
        self._seq = itertools.count(1)
        self._threads: list[threading.Thread] = []
        self._result_slot_name: str | None = None
        self._result_cap = (
            int(self.resources.get("output_mb", 16)) * 1024 * 1024
        )
        self._input_handles: set[str] = set()
        self._death_reason = ""
        self._stderr_tail = ""

    # ------------------------------------------------------------- startup

    def start(self) -> None:
        scratch = self.rt.scratch_for(self.name)
        if scratch.exists():
            shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True, exist_ok=True)

        # -I 在 3.11+ 隐含 -P（不把脚本目录放入 sys.path），因此用受控
        # -c 引导：唯一显式插入的路径是沙箱包目录，插件目录不进 sys.path。
        sandbox_dir = str(Path(__file__).with_name("worker_main.py").parent.resolve())
        bootstrap = (
            "import sys;"
            f"sys.path.insert(0,{sandbox_dir!r});"
            "import worker_main;sys.exit(worker_main.main())"
        )
        argv = [sys.executable, "-I", "-c", bootstrap]
        deny_read = self.rt.deny_read_paths(self.plugin_dir)
        argv = isolate.build_argv(
            self.backend, argv,
            scratch=scratch, plugin_dir=self.plugin_dir, deny_read=deny_read,
        )
        env = isolate.build_env(scratch)
        preexec = isolate.make_preexec(
            int(self.resources.get("cpu_seconds", 30)),
            int(self.resources.get("memory_mb", 512)),
            int(self.resources.get("output_mb", 16)),
            self.backend,
        )
        self.rt.audit.append(
            "activation_started", self.name,
            backend=self.backend, env_keys=sorted(env),
            deny_read=[str(p) for p in deny_read],
        )
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(scratch),
            env=env,
            close_fds=True,
            preexec_fn=preexec,
        )
        self.alive = True
        self._start_threads()

        # 结果槽在 worker 整个生命周期复用（调用串行）。
        slot = self.rt.shm.create(self._result_cap)
        self._result_slot_name = slot.name

        with self._wlock:
            ipc.write_frame(self.proc.stdin, {
                "type": "hello",
                "dir": str(self.plugin_dir),
                "entry": self.granted["entry"],
                "granted": self.granted,
            })
        if not self._ready.wait(_READY_TIMEOUT_S):
            self._kill("ready 超时")
            raise ActivationDenied(f"worker 启动超时（{_READY_TIMEOUT_S}s）")
        if not self._ready_box.get("ok"):
            err = self._ready_box.get("error") or {}
            self.alive = False
            self.rt.audit.append(
                "activation_denied", self.name, reason="worker_ready_failed",
                error=err,
            )
            raise ActivationDenied(f"worker 加载失败: {err.get('message')}")
        self.rt.audit.append(
            "activation_allowed", self.name,
            backend=self.backend, pid=self.proc.pid,
            resources=dict(self.resources),
            scratch=str(scratch),
        )

    def _start_threads(self) -> None:
        reader = threading.Thread(
            target=self._reader_loop, name=f"sb-{self.name}-read", daemon=True,
        )
        stderr = threading.Thread(
            target=self._stderr_loop, name=f"sb-{self.name}-err", daemon=True,
        )
        watchdog = threading.Thread(
            target=self._watchdog_loop, name=f"sb-{self.name}-watch", daemon=True,
        )
        self._threads = [reader, stderr, watchdog]
        for t in self._threads:
            t.start()

    # --------------------------------------------------------------- call

    def call(self, kwargs: dict) -> object:
        if not self._call_lock.acquire(blocking=False):
            raise WorkerCallError("同一 worker 的调用必须串行")
        try:
            if not self.alive:
                raise WorkerCrashed(f"worker 已退出: {self._death_reason or 'unknown'}")
            call_id = next(self._seq)
            pending = _PendingCall(call_id)
            with self._pending_lock:
                self._pending[call_id] = pending
                self._input_handles.clear()
            timeout_s = int(self.resources.get("wall_timeout_s", 60))
            t0 = time.perf_counter()
            try:
                with self._wlock:
                    ipc.write_frame(self.proc.stdin, {
                        "type": "call",
                        "id": call_id,
                        "kwargs": kwargs,
                        "result_slot": {
                            "name": self._result_slot_name,
                            "size": self._result_cap,
                        },
                    })
            except (BrokenPipeError, OSError) as e:
                self._on_process_dead(f"写入通道断裂: {e}")
            self.rt.audit.append(
                "call_started", self.name, call_id=call_id,
                arg_keys=sorted(kwargs.keys()),
            )

            if not pending.event.wait(timeout_s):
                self._kill(f"wall timeout {timeout_s}s")
                self.rt.audit.append(
                    "call_timeout", self.name, call_id=call_id,
                    timeout_s=timeout_s,
                )
                raise WorkerTimeout(f"插件调用超过 {timeout_s}s，worker 已回收")
            self._release_inputs()
            elapsed = (time.perf_counter() - t0) * 1000
            if pending.error is not None:
                self.rt.audit.append(
                    "call_error", self.name, call_id=call_id,
                    error=pending.error.get("type"), ms=round(elapsed, 1),
                )
                raise WorkerCallError(
                    f"{pending.error.get('type')}: {pending.error.get('message')}"
                )
            if pending.crashed:
                self.rt.audit.append(
                    "call_crash", self.name, call_id=call_id,
                    reason=self._death_reason,
                    stderr_tail=self._stderr_tail[-400:],
                    ms=round(elapsed, 1),
                )
                raise WorkerCrashed(
                    f"worker 崩溃（{self._death_reason}），仅本任务失败，"
                    f"进程组已回收"
                )
            kind, value = pending.result
            self.rt.audit.append(
                "call_finished", self.name, call_id=call_id,
                result=kind, ms=round(elapsed, 1),
            )
            return value
        finally:
            self._call_lock.release()

    # ------------------------------------------------------------- threads

    def _reader_loop(self) -> None:
        assert self.proc is not None
        stdout = self.proc.stdout
        while True:
            try:
                frame = ipc.read_frame(stdout)
            except (EOFError, ValueError, OSError):
                self._on_process_dead("stdout 通道关闭")
                return
            if frame is None:
                self._on_process_dead("stdout EOF")
                return
            try:
                self._dispatch(frame)
            except Exception as e:  # noqa: BLE001
                logger.warning("sandbox 帧分发异常: %s", e)

    def _dispatch(self, frame: dict) -> None:
        ftype = frame.get("type")
        if ftype == "ready":
            self._ready_box.update(frame)
            self._ready.set()
            return
        if ftype == "log":
            self.rt.broker.handle(
                self.name, self.granted, -1, "log", {
                    "level": frame.get("level"),
                    "message": frame.get("message"),
                },
            )
            return
        if ftype == "broker_request":
            body = self.rt.broker.handle(
                self.name, self.granted,
                int(frame.get("id", 0)),
                str(frame.get("method")),
                frame.get("params") or {},
            )
            shm = (body.get("shm") if body.get("ok") else None)
            if shm:
                with self._pending_lock:
                    self._input_handles.add(shm["name"])
            with self._wlock:
                ipc.write_frame(self.proc.stdin, {
                    "type": "broker_response",
                    "id": frame.get("id"),
                    "body": body,
                })
            return
        call_id = frame.get("id")
        with self._pending_lock:
            pending = self._pending.get(call_id)
        if pending is None:
            return
        if ftype == "result":
            pending.resolve(("json", frame.get("result")))
        elif ftype == "result_shm":
            value = self._read_result_slot(int(frame["size"]))
            pending.resolve(("arrow", value))
        elif ftype == "error":
            pending.error = frame.get("error") or {}
            pending.event.set()

    def _read_result_slot(self, size: int):
        import polars as pl
        import pyarrow as pa

        view = self.rt.shm.read_payload(
            _Handle(self._result_slot_name, size)
        )
        # 结果槽跨调用复用：必须先拷贝出段，否则上次调用返回的零拷贝 frame
        # 会在下次调用时被 worker 原地覆写。段内传输仍是零拷贝，这里仅复制一次。
        raw = bytes(view)
        table = pa.ipc.open_stream(pa.BufferReader(raw)).read_all()
        return pl.from_arrow(table)

    def _stderr_loop(self) -> None:
        assert self.proc is not None
        tail: list[str] = []
        while True:
            line = self.proc.stderr.readline()
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip()
            if text:
                logger.debug("sandbox[%s] stderr: %s", self.name, text[:300])
                tail.append(text)
                self._stderr_tail = "\n".join(tail[-10:])[-800:]

    def _watchdog_loop(self) -> None:
        """RSS 看门狗：跨平台内存上限的主执行机制（Linux 另有 RLIMIT_AS）。"""
        limit_bytes = int(self.resources.get("memory_mb", 512)) * 1024 * 1024
        strikes = 0
        while self.alive:
            time.sleep(0.25)
            if self.proc is None or self.proc.poll() is not None:
                return
            try:
                parent = psutil.Process(self.proc.pid)
                rss = parent.memory_info().rss
                for child in parent.children(recursive=True):
                    rss += child.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return
            if rss > limit_bytes:
                strikes += 1
                if strikes >= 2:
                    self.rt.audit.append(
                        "call_memory_kill", self.name,
                        rss_mb=round(rss / 1024 / 1024, 1),
                        limit_mb=round(limit_bytes / 1024 / 1024, 1),
                    )
                    self._kill(f"RSS {rss // 1024 // 1024}MB 超限")
                    return
            else:
                strikes = 0

    # ------------------------------------------------------------ teardown

    def _release_inputs(self) -> None:
        with self._pending_lock:
            names = list(self._input_handles)
            self._input_handles.clear()
        for name in names:
            self.rt.shm.release(name)

    def _on_process_dead(self, reason: str) -> None:
        if not self.alive:
            return
        self.alive = False
        self._death_reason = reason
        code = self.proc.wait() if self.proc else -1
        if self._result_slot_name:
            self.rt.shm.release(self._result_slot_name)
            self._result_slot_name = None
        self._release_inputs()
        with self._pending_lock:
            pending = list(self._pending.values())
            self._pending.clear()
        for p in pending:
            p.crashed = True
            p.event.set()
        self.rt.audit.append(
            "worker_exited", self.name, returncode=code, reason=reason,
        )

    def _kill(self, reason: str) -> None:
        if self.proc is None:
            return
        pid = self.proc.pid
        try:
            if os.name == "posix":
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                try:
                    self.proc.wait(timeout=_START_KILL_GRACE_S)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(os.getpgid(pid), signal.SIGKILL)
                    self.proc.wait(timeout=_START_KILL_GRACE_S)
            else:
                self.proc.kill()
                self.proc.wait(timeout=_START_KILL_GRACE_S)
        except (ProcessLookupError, OSError):
            pass
        self._on_process_dead(reason)

    def close(self) -> None:
        if self.alive and self.proc is not None and self.proc.poll() is None:
            try:
                with self._wlock:
                    ipc.write_frame(self.proc.stdin, {"type": "shutdown"})
                self.proc.wait(timeout=3)
            except Exception:  # noqa: BLE001
                self._kill("关闭")
                return
        self._on_process_dead("正常关闭")


class _PendingCall:
    __slots__ = ("crashed", "error", "event", "id", "result")

    def __init__(self, call_id: int):
        self.id = call_id
        self.event = threading.Event()
        self.result: tuple[str, object] | None = None
        self.error: dict | None = None
        self.crashed = False

    def resolve(self, value: tuple[str, object]) -> None:
        self.result = value
        self.event.set()


class _Handle:
    """适配 ShmRegistry.read_payload 的最小句柄。"""

    __slots__ = ("name", "size")

    def __init__(self, name: str, size: int):
        self.name = name
        self.size = size
