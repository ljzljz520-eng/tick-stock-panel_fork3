"""代码与依赖 digest 计算。

- 代码 digest：对插件目录下每个常规文件（相对路径 + 内容）计算 sha256，
  结果与相对路径绑定，避免"内容相同但换位置"被混过。
- 依赖 digest：对清单申请的每个第三方顶层模块，定位其安装分发，
  用 pip 的 RECORD 清单（内含每个文件的哈希）内容再哈希作为指纹；
  RECORD 缺失时回退哈希包目录。标准库依赖按解释器版本固化。
"""
from __future__ import annotations

import hashlib
import importlib.metadata as impmd
import importlib.util as imputil
import sys
from pathlib import Path

# 允许随插件分发的文本类型；任何原生可加载文件直接拒绝（可绕过解释器层限制）。
_NATIVE_SUFFIXES = {".so", ".pyd", ".dll", ".dylib"}
_SKIP_DIRS = {"__pycache__", ".git", "node_modules"}
_SKIP_FILES = {".DS_Store"}


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def code_digests(plugin_dir: Path) -> dict[str, str]:
    """返回 {相对路径: digest}。

    拒绝符号链接、越界硬连接场景（relpath 逃逸）和原生代码文件。
    """
    root = Path(plugin_dir).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"插件目录不存在: {root}")
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"插件目录不允许符号链接: {rel}")
        if not path.is_file():
            continue
        if path.name in _SKIP_FILES:
            continue
        if path.suffix.lower() in _NATIVE_SUFFIXES:
            raise ValueError(f"插件不允许携带原生代码文件: {rel}")
        data = path.read_bytes()
        h = hashlib.sha256()
        h.update(str(rel).encode("utf-8"))
        h.update(b"\0")
        h.update(data)
        out[rel.as_posix()] = "sha256:" + h.hexdigest()
    return out


def dependency_digests(imports: tuple[str, ...] | list[str]) -> dict[str, str]:
    """返回 {顶层模块: 依赖指纹}，覆盖第三方模块与标准库模块。

    指纹绑定解释器版本 / 分发版本与 RECORD 内容；激活时重算，任何升级或
    替换都会导致 digest 漂移并 fail-closed。
    """
    out: dict[str, str] = {}
    for top in sorted(imports):
        if imputil.find_spec(top) is None:
            raise ValueError(f"依赖在当前解释器中不可用: {top}")
        out[top] = _external_fingerprint(top) if _is_external(top) else _stdlib_fingerprint(top)
    return out


def _is_external(top: str) -> bool:
    from app.sandbox.manifest import ALLOWED_EXTERNAL

    return top in ALLOWED_EXTERNAL


def _stdlib_fingerprint(top: str) -> str:
    spec = imputil.find_spec(top)
    origin = spec.origin if spec else None
    h = hashlib.sha256()
    h.update(f"stdlib:{top}:{sys.version_info[:3]}".encode())
    h.update(b"\0")
    h.update((origin or "").encode())
    return "sha256:" + h.hexdigest()


def _external_fingerprint(top: str) -> str:
    dist = _distribution_for(top)
    h = hashlib.sha256()
    h.update(f"dist:{top}:{sys.implementation.cache_tag}".encode())
    h.update(b"\0")
    if dist is not None:
        record = dist.read_text("RECORD")
        if record is not None:
            h.update(f"{dist.metadata['Name']}=={dist.version}".encode())
            h.update(b"\0")
            h.update(record.encode("utf-8", "replace"))
            return "sha256:" + h.hexdigest()
    # 回退：哈希包目录全部文件（RECORD 缺失，如开发态安装）。
    spec = imputil.find_spec(top)
    origin = Path(spec.origin).resolve() if spec and spec.origin else None
    if origin is None:
        raise ValueError(f"无法定位依赖路径: {top}")
    if origin.name == "__init__.py":
        # 包：递归哈希目录内全部非原生文件。
        pkg_dir = origin.parent
        h.update(pkg_dir.name.encode())
        for f in sorted(pkg_dir.rglob("*")):
            if f.is_file() and f.suffix.lower() not in _NATIVE_SUFFIXES:
                h.update(f.relative_to(pkg_dir).as_posix().encode())
                h.update(b"\0")
                h.update(f.read_bytes())
    else:
        # 单文件模块。
        h.update(origin.name.encode())
        h.update(origin.read_bytes())
    return "sha256:" + h.hexdigest()


def _distribution_for(top: str) -> impmd.Distribution | None:
    # 优先按 top_level 映射定位；找不到时退回名称匹配。
    try:
        dists = impmd.packages_distributions()
    except Exception:  # noqa: BLE001 - 旧版本/异常环境退回名称查找
        dists = {}
    names = dists.get(top) or ([top] if impmd.distribution(top) else [])
    for name in names:
        try:
            return impmd.distribution(name)
        except impmd.PackageNotFoundError:
            continue
    return None
