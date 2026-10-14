"""OS 级隔离后端与资源限额。

三档后端，按宿主能力自动选择，选择结果写入审计：

- ``seatbelt``（macOS）：sandbox-exec 配置式 profile。默认拒绝，
  文件可读但敏感目录显式拒绝，写仅限私有 scratch，网络全拒；
- ``bwrap``（Linux）：bubblewrap 只读绑定解释器/插件、私有 scratch、
  ``--unshare-net`` 关网络命名空间；
- ``basic``（兜底，含 Windows）：env 清洗 + cwd=scratch + POSIX rlimits。
  basic 档的文件/网络隔离依赖 AST 静态门与 worker 运行时 import 守卫，
  审计会明确标注档位（生产 Linux 建议安装 bubblewrap）。

所有档位共用：独立进程组（超时整组回收）、RLIMIT_CPU/FSIZE/NOFILE/CORE、
宿主侧 RSS 看门狗（见 runtime）。RLIMIT_AS 只在 Linux 设置——macOS 的
虚拟地址预留语义会让大型原生库在启动期即触发误杀，macOS 内存以 RSS
实测值兜底。
"""
from __future__ import annotations

import contextlib
import os
import resource
import shutil
import sys
from pathlib import Path

BACKEND_SEATBELT = "seatbelt"
BACKEND_BWRAP = "bwrap"
BACKEND_BASIC = "basic"


def detect_backend() -> str:
    if sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file():
        return BACKEND_SEATBELT
    if shutil.which("bwrap"):
        return BACKEND_BWRAP
    return BACKEND_BASIC


def build_env(scratch: Path) -> dict[str]:
    """清洗后的最小环境：无密钥、无 HOME 泄露、TMP 指向私有 scratch。"""
    scratch = Path(scratch)
    (scratch / "tmp").mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": str(scratch),
        "TMPDIR": str(scratch / "tmp") + os.sep,
        "TZ": "UTC",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONIOENCODING": "utf-8",
    }
    if sys.platform == "win32":
        for key in ("SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC", "TEMP", "TMP"):
            if key in os.environ:
                env[key] = os.environ[key]
    return env


def build_argv(
    backend: str,
    worker_argv: list[str],
    *,
    scratch: Path,
    plugin_dir: Path,
    deny_read: list[Path],
) -> list[str]:
    if backend == BACKEND_SEATBELT:
        profile = seatbelt_profile(scratch, plugin_dir, deny_read)
        return ["/usr/bin/sandbox-exec", "-p", profile, *worker_argv]
    if backend == BACKEND_BWRAP:
        return bwrap_argv(worker_argv, scratch=scratch, plugin_dir=plugin_dir)
    return list(worker_argv)


def seatbelt_profile(scratch: Path, plugin_dir: Path, deny_read: list[Path]) -> str:
    scratch_s = _scheme_escape(str(Path(scratch).resolve()))
    plugin_s = _scheme_escape(str(Path(plugin_dir).resolve()))
    denies = "".join(
        f'(deny file-read* (subpath "{_scheme_escape(str(Path(p).resolve()))}"))'
        for p in deny_read
    )
    # 已在本机用 venv Python + pyarrow + polars 实测：
    # 网络拒绝、敏感路径读拒绝、scratch 外写拒绝均生效。
    return (
        "(version 1)"
        "(deny default)"
        "(allow process-fork)(allow process-exec)"
        "(allow signal (target self))"
        "(allow sysctl*)"
        "(allow file-read*)"
        f'{denies}'
        f'(allow file-write* (subpath "{scratch_s}"))'
        "(allow ipc*)"
        "(allow mach*)"
        "(deny network*)"
        f'(allow file-read* (subpath "{plugin_s}"))'
    )


def bwrap_argv(
    worker_argv: list[str], *, scratch: Path, plugin_dir: Path
) -> list[str]:
    args = [
        "bwrap",
        "--unshare-net", "--unshare-ipc", "--unshare-uts",
        "--unshare-cgroup-try",
        "--new-session", "--die-with-parent",
        "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp",
    ]
    # 解释器与系统库只读绑定（存在才绑）。
    roots = [
        "/usr", "/lib", "/lib64", "/opt",
        sys.prefix, sys.base_prefix,
        str(Path(sys.executable).resolve().parent.parent),
    ]
    seen: set[str] = set()
    for root in roots:
        root = str(Path(root).resolve())
        if root in seen or root == "/" or not Path(root).exists():
            continue
        seen.add(root)
        args += ["--ro-bind-try", root, root]
    # 插件代码只读绑定；scratch 可写。
    plugin = str(Path(plugin_dir).resolve())
    args += ["--ro-bind-try", plugin, plugin]
    scratch_s = str(Path(scratch).resolve())
    args += ["--bind", scratch_s, scratch_s]
    return [*args, *worker_argv]


def make_preexec(cpu_seconds: int, memory_mb: int, output_mb: int, backend: str):
    if os.name != "posix":
        return None

    def _apply() -> None:
        os.setsid()
        _set_limit(resource.RLIMIT_CORE, (0, 0))
        _set_limit(resource.RLIMIT_NOFILE, (64, 64))
        _set_limit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        fsize = max(output_mb, 1) * 4 * 1024 * 1024
        _set_limit(resource.RLIMIT_FSIZE, (fsize, fsize))
        # 仅 Linux：虚拟地址空间硬上限；macOS 由 RSS 看门狗限制内存。
        if sys.platform.startswith("linux"):
            mem = memory_mb * 1024 * 1024
            _set_limit(resource.RLIMIT_AS, (mem, mem))

    return _apply


def _set_limit(which: int, value: tuple[int, int]) -> None:
    # 容器/平台不允许收紧某条限额时不应阻止其余隔离生效。
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(which, value)


def _scheme_escape(path: str) -> str:
    return path.replace("\\", "\\\\").replace('"', '\\"')
