"""端到端：scan→approve→activate→call，含超时/崩溃/内存/漂移/数据面全链路。

这些用例在真实 seatbelt 受限 worker 进程中运行插件，是"纵深防御"的集成验证。
"""
from __future__ import annotations

import os
import time

import polars as pl
import psutil
import pytest

from app.sandbox.errors import (
    ActivationDenied,
    PolicyError,
    WorkerCallError,
    WorkerCrashed,
    WorkerTimeout,
)

_BASIC_CODE = (
    "import json\n\n"
    "def handle(ctx, x=1):\n"
    "    return {'echo': x, 'enc': json.dumps({'x': x})}\n"
)

_DATA_CODE = (
    "def handle(ctx, symbols):\n"
    "    df = ctx.data.query('daily', symbols=symbols)\n"
    "    grouped = df.group_by('symbol').len()\n"
    "    return {\n"
    "        'rows': df.height,\n"
    "        'sum': float(df['close'].sum()),\n"
    "        'symbols': sorted(grouped['symbol'].to_list()),\n"
    "    }\n"
)

_FRAME_CODE = (
    "import polars as pl\n\n"
    "def handle(ctx, n=10):\n"
    "    return pl.DataFrame({\n"
    "        'a': [i for i in range(n)],\n"
    "        'b': [i * 0.5 for i in range(n)],\n"
    "    })\n"
)


def _wait_pid_gone(pid: int, timeout_s: float = 5.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if not psutil.pid_exists(pid):
            return True
        time.sleep(0.05)
    return not psutil.pid_exists(pid)


# ----------------------------------------------------------- 基础调用与数据面

def test_basic_json_call(tmp_path, runtime, make_plugin_fn, audit_rows_fn):
    p = make_plugin_fn(tmp_path / "basicp", _BASIC_CODE, name="basicp",
                       imports=["json"])
    record = runtime.approve(p)
    assert runtime.call("basicp", x=42) == {"echo": 42, "enc": '{"x": 42}'}

    rows = audit_rows_fn(runtime)
    events = [r["event"] for r in rows]
    assert "policy_approved" in events
    assert "activation_allowed" in events
    assert "call_finished" in events

    # 批准策略的代码/依赖 digest 必须完整写入审计。
    approved = next(r for r in rows if r["event"] == "policy_approved")
    assert approved["details"]["code_digests"] == record.code_digests
    assert approved["details"]["dependency_digests"] == record.dependency_digests

    # 激活事件必须记录实际运行能力（隔离档位、资源上限）。
    allowed = next(r for r in rows if r["event"] == "activation_allowed")
    assert allowed["details"]["backend"] in {"seatbelt", "bwrap", "basic"}
    assert allowed["details"]["resources"]["wall_timeout_s"] == 60
    assert allowed["details"]["pid"] > 0


def test_data_query_through_worker(tmp_path, runtime, make_plugin_fn):
    p = make_plugin_fn(
        tmp_path / "datap", _DATA_CODE, name="datap",
        imports=["polars"],
        datasets={"daily": "{symbols: ['*'], max_rows: 500}"},
    )
    runtime.approve(p)
    result = runtime.call("datap", symbols=["000001", "600000"])
    assert result["rows"] == 6
    assert result["symbols"] == ["000001", "600000"]
    # fake 数据：第 i 组 close=(i+1)*10+r+0.25：
    # 000001=10.25/11.25/12.25，600000=20.25/21.25/22.25。
    assert result["sum"] == pytest.approx(
        10.25 + 11.25 + 12.25 + 20.25 + 21.25 + 22.25
    )


def test_dataframe_result_via_shm_slot_is_stable_across_calls(
    tmp_path, runtime, make_plugin_fn,
):
    p = make_plugin_fn(tmp_path / "framep", _FRAME_CODE, name="framep",
                       imports=["polars"])
    runtime.approve(p)
    f1 = runtime.call("framep", n=4)
    f2 = runtime.call("framep", n=6)
    assert isinstance(f1, pl.DataFrame)
    # 结果槽跨调用复用：宿主已拷贝出槽，首帧不能被第二次调用覆写。
    assert f1["a"].to_list() == [0, 1, 2, 3]
    assert f2["a"].to_list() == [0, 1, 2, 3, 4, 5]
    assert f1["b"].to_list() == [0.0, 0.5, 1.0, 1.5]


def test_input_shm_released_after_call(tmp_path, runtime, make_plugin_fn):
    p = make_plugin_fn(
        tmp_path / "datap2", _DATA_CODE, name="datap2",
        imports=["polars"],
        datasets={"daily": "{symbols: ['*'], max_rows: 100}"},
    )
    runtime.approve(p)
    runtime.call("datap2", symbols=["000001"])
    # 活跃期只剩复用的结果槽；输入段调用结束即释放。
    assert len(runtime.shm.live_names()) == 1
    runtime.shutdown()
    assert runtime.shm.live_names() == []


def test_output_over_capacity_rejected(tmp_path, runtime, make_plugin_fn):
    code = (
        "import polars as pl\n\n"
        "def handle(ctx):\n"
        "    n = 200000\n"
        "    return pl.DataFrame({\n"
        "        'a': [i for i in range(n)],\n"
        "        'b': [float(i) for i in range(n)],\n"
        "    })\n"
    )
    p = make_plugin_fn(
        tmp_path / "bigp", code, name="bigp",
        imports=["polars"],
        resources={"output_mb": 1},
    )
    runtime.approve(p)
    with pytest.raises(WorkerCallError, match="output_mb"):
        runtime.call("bigp")


# ----------------------------------------------------- 插件异常不杀通道

def test_plugin_exception_does_not_kill_worker(tmp_path, runtime, make_plugin_fn):
    code = (
        "def handle(ctx, fail=False):\n"
        "    if fail:\n"
        "        raise ValueError('boom-detail')\n"
        "    return {'ok': True}\n"
    )
    p = make_plugin_fn(tmp_path / "errorp", code, name="errorp")
    runtime.approve(p)
    with pytest.raises(WorkerCallError, match="boom-detail"):
        runtime.call("errorp", fail=True)
    # 插件异常只以错误帧回传，不杀通道：同一 worker 第二次调用直接成功。
    assert runtime.call("errorp") == {"ok": True}
    assert runtime._workers["errorp"].alive


def test_plugin_log_and_print_frames(tmp_path, runtime, make_plugin_fn, audit_rows_fn):
    code = (
        "def handle(ctx):\n"
        "    ctx.log.warning('plugin-careful')\n"
        "    print('printed-line')\n"
        "    return {'logged': True}\n"
    )
    p = make_plugin_fn(tmp_path / "logp", code, name="logp")
    runtime.approve(p)
    assert runtime.call("logp") == {"logged": True}
    rows = audit_rows_fn(runtime)
    warned = [r for r in rows if r["event"] == "plugin_log"]
    assert any(r["details"]["message"] == "plugin-careful" for r in warned)


# ------------------------------------------------------- broker 端到端拒绝

def test_unauthorized_egress_denied_through_worker(tmp_path, runtime, make_plugin_fn):
    code = (
        "def handle(ctx, do_fetch=False):\n"
        "    if do_fetch:\n"
        "        return ctx.http.fetch('https://evil.example.com/x')\n"
        "    return {'ok': True}\n"
    )
    p = make_plugin_fn(tmp_path / "httpp", code, name="httpp")
    runtime.approve(p)
    with pytest.raises(WorkerCallError, match="白名单"):
        runtime.call("httpp", do_fetch=True)
    # broker 拒绝是错误回传，不是崩溃：worker 继续可用。
    assert runtime.call("httpp") == {"ok": True}


def test_unauthorized_dataset_denied_through_worker(tmp_path, runtime, make_plugin_fn):
    code = (
        "def handle(ctx):\n"
        "    df = ctx.data.query('financial', symbols=['000001'])\n"
        "    return df.height\n"
    )
    p = make_plugin_fn(tmp_path / "dendp", code, name="dendp")
    runtime.approve(p)
    with pytest.raises(WorkerCallError, match="未授权数据集"):
        runtime.call("dendp")


# ------------------------------------------------------ 超时、崩溃、内存

def test_wall_timeout_kills_process_group_and_restarts(
    tmp_path, runtime, make_plugin_fn, audit_rows_fn,
):
    code = (
        "def handle(ctx, spin=False):\n"
        "    if spin:\n"
        "        while True:\n"
        "            pass\n"
        "    return {'recovered': True}\n"
    )
    p = make_plugin_fn(
        tmp_path / "slowp", code, name="slowp",
        resources={"wall_timeout_s": 2},
    )
    runtime.approve(p)
    worker = runtime.activate("slowp")
    pid = worker.proc.pid
    with pytest.raises(WorkerTimeout):
        runtime.call("slowp", spin=True)
    assert _wait_pid_gone(pid), "超时后 worker 进程未被回收"
    assert runtime.shm.live_names() == []
    # 下次调用惰性重启并成功。
    assert runtime.call("slowp") == {"recovered": True}
    events = [r["event"] for r in audit_rows_fn(runtime)]
    assert "call_timeout" in events


def test_worker_crash_only_fails_that_task(tmp_path, runtime, make_plugin_fn):
    # 插件拿不到 SystemExit/os._exit（受限 builtins）；这里让 worker 在
    # 调用进行中被宿主侧 SIGKILL，模拟段错误/OOM killer 等真实崩溃。
    import threading

    code = (
        "import time\n\n"
        "def handle(ctx, wait=0):\n"
        "    if wait:\n"
        "        time.sleep(wait)\n"
        "    return {'alive': True}\n"
    )
    p = make_plugin_fn(tmp_path / "crashp", code, name="crashp",
                       imports=["time"])
    runtime.approve(p)
    worker = runtime.activate("crashp")
    timer = threading.Timer(0.5, lambda: worker.proc.kill())
    timer.start()
    with pytest.raises(WorkerCrashed):
        runtime.call("crashp", wait=10)
    timer.join()
    assert runtime.shm.live_names() == []
    # 宿主存活，下次调用惰性重启成功。
    assert runtime.call("crashp") == {"alive": True}


def test_rss_watchdog_kills_worker_and_restarts(
    tmp_path, runtime, make_plugin_fn, audit_rows_fn,
):
    code = (
        "def handle(ctx, alloc=False):\n"
        "    if not alloc:\n"
        "        return {'ok': True}\n"
        "    size = 400 * 1024 * 1024\n"
        "    buf = bytearray(size)\n"
        "    tick = 0\n"
        "    while True:\n"
        "        i = tick % 4096\n"
        "        while i < size:\n"
        "            buf[i] = (tick + i) & 0xFF\n"
        "            i += 4096\n"
        "        tick += 1\n"
    )
    p = make_plugin_fn(
        tmp_path / "memp", code, name="memp",
        resources={"memory_mb": 192, "wall_timeout_s": 30},
    )
    runtime.approve(p)
    with pytest.raises(WorkerCrashed):
        runtime.call("memp", alloc=True)
    assert runtime.call("memp") == {"ok": True}
    events = [r["event"] for r in audit_rows_fn(runtime)]
    assert "call_memory_kill" in events


# ------------------------------------------------------ 策略漂移与无策略

def test_code_drift_after_approval_fails_closed(tmp_path, runtime, make_plugin_fn):
    p = make_plugin_fn(tmp_path / "driftp", _BASIC_CODE, name="driftp",
                       imports=["json"])
    runtime.approve(p)
    assert runtime.call("driftp", x=1)["echo"] == 1
    (p / "plugin.py").write_text(
        _BASIC_CODE + "# post-approval modification\n", encoding="utf-8"
    )
    with pytest.raises(ActivationDenied, match="digest"):
        runtime.call("driftp")


def test_call_without_approved_policy_denied(tmp_path, runtime, make_plugin_fn):
    make_plugin_fn(tmp_path / "ghostp", _BASIC_CODE, name="ghostp",
                   imports=["json"])
    with pytest.raises(PolicyError):
        runtime.call("ghostp")
    assert not (runtime.root / "policies" / "ghostp.json").exists()


def test_static_failure_blocks_approval(tmp_path, runtime, make_plugin_fn, audit_rows_fn):
    code = "import os\n\ndef handle(ctx):\n    return os.listdir('.')\n"
    p = make_plugin_fn(tmp_path / "badvp", code, name="badvp", imports=["json"])
    with pytest.raises(ActivationDenied):
        runtime.approve(p)
    assert not (runtime.root / "policies" / "badvp.json").exists()
    events = [r["event"] for r in audit_rows_fn(runtime)]
    assert "policy_approve_rejected" in events


def test_secret_not_present_in_worker_env(
    tmp_path, runtime, make_plugin_fn, audit_rows_fn, monkeypatch,
):
    monkeypatch.setenv("OPERATOR_SECRET_VALUE", "must-not-leak")
    p = make_plugin_fn(tmp_path / "envp", _BASIC_CODE, name="envp",
                       imports=["json"])
    runtime.approve(p)
    runtime.call("envp")
    rows = audit_rows_fn(runtime)
    started = next(r for r in rows if r["event"] == "activation_started")
    env_keys = started["details"]["env_keys"]
    assert "OPERATOR_SECRET_VALUE" not in env_keys
    text = runtime.audit.path.read_text(encoding="utf-8")
    assert "must-not-leak" not in text


def test_audit_chain_intact_after_full_session(
    tmp_path, runtime, make_plugin_fn, assert_audit_intact_fn,
):
    p = make_plugin_fn(tmp_path / "chainp", _BASIC_CODE, name="chainp",
                       imports=["json"])
    runtime.approve(p)
    runtime.call("chainp", x=1)
    runtime.call("chainp", x=2)
    runtime.deactivate("chainp")
    assert_audit_intact_fn(runtime)


def test_policy_and_key_file_permissions(tmp_path, runtime, make_plugin_fn):
    p = make_plugin_fn(tmp_path / "modep", _BASIC_CODE, name="modep",
                       imports=["json"])
    runtime.approve(p)
    policy_mode = os.stat(
        runtime.root / "policies" / "modep.json"
    ).st_mode & 0o777
    key_mode = os.stat(runtime.root / "trust" / "master.key").st_mode & 0o777
    assert policy_mode == 0o600
    assert key_mode == 0o600
