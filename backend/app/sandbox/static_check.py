"""静态检查：AST 级别的最小权限分析。

静态检查不替代 OS 隔离，而是"策略生成前置门"：
- import 白名单：只有清单申请且在全局白名单内的模块、或插件目录内本地模块可导入；
- 禁止解释器逃逸/反射链相关语法形态（eval/exec/compile/open、__subclasses__ 等）；
- 禁止 * import（无法静态审计实际引用名）。

工作端还会在运行时再装一道 import 守卫 + 受限 builtins（见 worker_main.py），
形成静态 + 动态双闸门。
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from app.sandbox.manifest import CapabilityManifest

# 禁止以任何形式（不止调用点）引用的内置名：文件访问、动态执行、
# 全名字典反射、字符串属性访问（绕过属性黑名单的常用通道）。
FORBIDDEN_NAMES: frozenset[str] = frozenset({
    "eval", "exec", "compile", "open", "input", "breakpoint",
    "globals", "locals", "vars", "dir",
    "getattr", "setattr", "delattr", "hasattr",
    "memoryview", "__import__", "__builtins__",
})

# 禁止的属性名：对象图逃逸链（__class__.__subclasses__ 等）与帧/代码对象访问。
FORBIDDEN_ATTRS: frozenset[str] = frozenset({
    "__globals__", "__subclasses__", "__bases__", "__mro__",
    "__reduce__", "__reduce_ex__", "__getattribute__",
    "__code__", "__func__", "func_globals",
    "f_globals", "f_locals", "gi_frame", "cr_frame", "gi_code",
})


@dataclass(frozen=True)
class StaticReport:
    findings: tuple[str, ...]
    checked_files: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.findings


def check_plugin(plugin_dir: Path, manifest: CapabilityManifest) -> StaticReport:
    root = Path(plugin_dir).resolve()
    py_files = sorted(
        p for p in root.rglob("*.py")
        if "__pycache__" not in p.relative_to(root).parts
    )
    findings: list[str] = []
    checked: list[str] = []
    allowed = set(manifest.imports)
    for path in py_files:
        rel = path.relative_to(root).as_posix()
        checked.append(rel)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        except SyntaxError as e:
            findings.append(f"{rel}:{e.lineno}: 语法错误: {e.msg}")
            continue
        findings.extend(_check_tree(tree, root, rel, allowed))

    findings.extend(_check_entry(root, manifest))
    return StaticReport(tuple(findings), tuple(checked))


def _check_tree(tree: ast.AST, root: Path, rel: str, allowed: set[str]) -> list[str]:
    findings: list[str] = []
    # rel 形如 "pkg/sub/m.py" 或 "pkg/__init__.py"；去掉文件名后即为逻辑包路径。
    package_parts = tuple(rel.split("/")[:-1])

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                reason = _import_reason(alias.name, 0, root, package_parts, allowed)
                if reason:
                    findings.append(f"{rel}:{node.lineno}: {reason}")
        elif isinstance(node, ast.ImportFrom):
            if any(a.name == "*" for a in node.names):
                findings.append(f"{rel}:{node.lineno}: 禁止 star import")
                continue
            reason = _import_reason(
                node.module or "", node.level or 0, root, package_parts, allowed
            )
            if reason:
                findings.append(f"{rel}:{node.lineno}: {reason}")
        elif isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRS:
            findings.append(
                f"{rel}:{node.lineno}: 禁止访问反射/帧属性 .{node.attr}"
            )
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            findings.append(f"{rel}:{node.lineno}: 禁止使用内置名 {node.id!r}")
    return findings


def _import_reason(
    module: str,
    level: int,
    root: Path,
    package_parts: tuple[str, ...],
    allowed: set[str],
) -> str | None:
    """返回拒绝原因；None 表示放行（本地模块或白名单模块）。"""
    if level > 0:
        # 相对导入：按导入方所在包解析，解析结果必须落在插件目录内。
        if level - 1 > len(package_parts):
            return "相对导入越出插件包"
        base = package_parts[: len(package_parts) - (level - 1)]
        parts = tuple(module.split(".")) if module else ()
        target = (*base, *parts)
        if not target:
            return "非法相对导入"
        if not _is_local_module(root, target):
            return f"相对导入目标不在插件目录内: {'.'.join(target)}"
        return None

    if not module:
        return "非法导入"
    parts = tuple(module.split("."))
    # 本地模块优先（插件可用同名文件遮蔽标准库，遮蔽的仍是被审计代码）。
    if _is_local_module(root, parts):
        return None
    if parts[0] in allowed:
        return None
    return (
        f"未授权 import: {module!r}（未在 manifest.imports 申请，"
        f"或属于文件/进程/网络/反射类全局禁用模块）"
    )


def _is_local_module(root: Path, parts: tuple[str, ...]) -> bool:
    if not parts:
        return False
    base = root.joinpath(*parts)
    return (base.with_suffix(".py").is_file()
            or (base / "__init__.py").is_file())


def _check_entry(root: Path, manifest: CapabilityManifest) -> list[str]:
    module_name, callable_name = manifest.entry.split(":", 1)
    parts = tuple(module_name.split("."))
    module_path = root.joinpath(*parts).with_suffix(".py")
    package_init = root.joinpath(*parts) / "__init__.py"
    if not module_path.is_file() and not package_init.is_file():
        return [f"entry 模块不存在: {module_name}"]
    path = module_path if module_path.is_file() else package_init
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError as e:
        return [f"entry 模块语法错误: {e.msg}"]
    # worker 只支持同步 entry（不引入事件循环/kqueue 额外系统调用面）。
    defined = {
        n.name
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.ClassDef))
    }
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            defined.update(
                t.id for t in n.targets if isinstance(t, ast.Name)
            )
    if callable_name not in defined:
        return [f"entry 未在模块顶层定义可调用对象: {manifest.entry}"]
    return []
