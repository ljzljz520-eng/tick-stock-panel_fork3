"""插件能力清单（sandbox-plugin.yaml）模型与校验。

清单是插件"申请"的能力；真正生效的能力以审批后签名策略（policy.py）为准。
清单本身不要求可信——激活时只信任签名策略，且策略中的代码 digest 必须与
插件目录现状一致。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from app.sandbox.errors import ManifestError

SANDBOX_API_VERSION = 1
MANIFEST_FILENAME = "sandbox-plugin.yaml"

# 插件允许 import 的标准库模块（白名单制）。文件/进程/网络相关的 os/sys/socket/
# subprocess/ctypes/threading/multiprocessing/pickle/marshal 等一律不在表内。
ALLOWED_STDLIB: frozenset[str] = frozenset({
    "json", "math", "cmath", "statistics", "decimal", "fractions", "numbers",
    "datetime", "zoneinfo", "time", "random", "secrets", "hashlib", "hmac",
    "base64", "itertools", "functools", "collections", "operator", "enum",
    "typing", "dataclasses", "re", "string", "textwrap", "unicodedata",
    "csv", "io", "array", "bisect", "heapq", "uuid", "pprint", "copy",
})

# 插件允许 import 的第三方顶层模块（已安装、其 digest 在审批时固化）。
# 网络客户端（httpx/requests/urllib）不在其中：外联只能走 broker。
ALLOWED_EXTERNAL: frozenset[str] = frozenset({
    "polars", "pyarrow", "numpy", "pandas",
})

_NAME_RE = re.compile(r"^[a-z0-9_]{2,40}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)"
                      r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.IGNORECASE)
_ENTRY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*"
                       r":[A-Za-z_][A-Za-z0-9_]*$")

# 资源上下限（审批侧硬边界，防止清单申请无限额度）。
_LIMITS = {
    "cpu_seconds": (1, 300),
    "memory_mb": (128, 4096),
    "wall_timeout_s": (1, 600),
    "output_mb": (1, 256),
}
_DEFAULT_LIMITS = {
    "cpu_seconds": 30,
    "memory_mb": 512,
    "wall_timeout_s": 60,
    "output_mb": 16,
}


@dataclass(frozen=True)
class DatasetGrant:
    """对一个标准化数据集的读取授权。

    symbols 为 ``["*"]`` 表示全标的；否则只能命中显式列出的代码。
    max_rows 是单次查询硬上限（broker 下推 limit 并复核返回行数）。
    """

    name: str
    symbols: tuple[str, ...] = ("*",)
    max_rows: int = 200_000

    def allows_symbol(self, symbol: str) -> bool:
        if "*" in self.symbols:
            return True
        return symbol in self.symbols

    def to_dict(self) -> dict:
        return {"symbols": list(self.symbols), "max_rows": self.max_rows}


@dataclass(frozen=True)
class EgressGrant:
    """外网出站授权：仅 HTTPS，精确主机名或 ``.example.com`` 形式的子域后缀。"""

    host: str

    def matches(self, host: str) -> bool:
        h = host.lower().strip()
        if self.host.startswith("."):
            return h == self.host[1:] or h.endswith(self.host)
        return h == self.host


@dataclass(frozen=True)
class SecretRef:
    """密钥引用：插件只能用别名，宿主代发请求时解析真实值。"""

    alias: str
    env: str


@dataclass(frozen=True)
class ResourceLimits:
    cpu_seconds: int = 30
    memory_mb: int = 512
    wall_timeout_s: int = 60
    output_mb: int = 16

    def to_dict(self) -> dict:
        return {
            "cpu_seconds": self.cpu_seconds,
            "memory_mb": self.memory_mb,
            "wall_timeout_s": self.wall_timeout_s,
            "output_mb": self.output_mb,
        }


@dataclass(frozen=True)
class CapabilityManifest:
    name: str
    version: str
    entry: str
    imports: tuple[str, ...]
    datasets: dict[str, DatasetGrant] = field(default_factory=dict)
    egress: tuple[EgressGrant, ...] = ()
    secrets: tuple[SecretRef, ...] = ()
    resources: ResourceLimits = ResourceLimits()
    description: str = ""

    def granted_dict(self) -> dict:
        """规范化为签名/IPC 使用的纯 JSON 能力视图。"""
        return {
            "name": self.name,
            "version": self.version,
            "entry": self.entry,
            "imports": sorted(self.imports),
            "datasets": {
                k: v.to_dict() for k, v in sorted(self.datasets.items())
            },
            "egress": [e.host for e in sorted(self.egress, key=lambda x: x.host)],
            "secrets": [
                {"alias": s.alias, "env": s.env}
                for s in sorted(self.secrets, key=lambda x: x.alias)
            ],
            "resources": self.resources.to_dict(),
        }


def load_manifest(plugin_dir: Path) -> CapabilityManifest:
    path = Path(plugin_dir) / MANIFEST_FILENAME
    if not path.is_file():
        raise ManifestError(f"缺少清单文件: {MANIFEST_FILENAME}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ManifestError(f"清单 YAML 解析失败: {e}") from e
    if not isinstance(raw, dict):
        raise ManifestError("清单必须是 YAML mapping")
    return manifest_from_dict(raw)


def manifest_from_dict(raw: dict) -> CapabilityManifest:
    api = raw.get("api_version")
    if api != SANDBOX_API_VERSION:
        raise ManifestError(
            f"api_version 必须为 {SANDBOX_API_VERSION}，得到 {api!r}"
        )

    name = str(raw.get("name") or "").strip()
    if not _NAME_RE.match(name):
        raise ManifestError(f"非法插件 name: {name!r}（2-40 位小写字母数字下划线）")

    version = str(raw.get("version") or "").strip()
    if not re.match(r"^\d+\.\d+\.\d+$", version):
        raise ManifestError(f"version 必须为 semver X.Y.Z: {version!r}")

    entry = str(raw.get("entry") or "").strip()
    if not _ENTRY_RE.match(entry):
        raise ManifestError(f"entry 必须形如 module:callable: {entry!r}")

    imports = _parse_imports(raw.get("imports"))
    datasets = _parse_datasets(raw.get("datasets"))
    egress = _parse_egress(raw.get("egress"))
    secrets = _parse_secrets(raw.get("secrets"))
    resources = _parse_resources(raw.get("resources"))

    # entry 的顶层模块必须在 import 白名单内（或为插件本地模块，静态阶段复核）。
    return CapabilityManifest(
        name=name,
        version=version,
        entry=entry,
        imports=imports,
        datasets=datasets,
        egress=egress,
        secrets=secrets,
        resources=resources,
        description=str(raw.get("description") or "")[:200],
    )


def _parse_imports(raw: object) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise ManifestError("imports 必须是字符串列表")
    out: set[str] = set()
    for item in raw:
        top = str(item).strip().split(".", 1)[0]
        if top not in ALLOWED_STDLIB and top not in ALLOWED_EXTERNAL:
            raise ManifestError(
                f"import 不在全局白名单: {item!r}（第三方/系统模块一律拒绝，"
                f"外联与文件能力只能通过 broker）"
            )
        out.add(top)
    return tuple(sorted(out))


def _parse_datasets(raw: object) -> dict[str, DatasetGrant]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ManifestError("datasets 必须是 mapping")
    known = {"daily", "adj_factor", "minute", "full_minute", "realtime",
             "depth5", "financial"}
    out: dict[str, DatasetGrant] = {}
    for key, cfg in raw.items():
        if not isinstance(key, str) or key not in known:
            raise ManifestError(f"未知数据集: {key!r}（沙箱只授权既有标准数据集）")
        cfg = cfg if isinstance(cfg, dict) else {}
        symbols_raw = cfg.get("symbols", ["*"])
        if symbols_raw == "*":
            symbols_raw = ["*"]
        if not isinstance(symbols_raw, list) or not all(
            isinstance(s, str) and s for s in symbols_raw
        ):
            raise ManifestError(f"{key}.symbols 必须是代码列表或 ['*']")
        if not symbols_raw:
            raise ManifestError(f"{key}.symbols 不能为空")
        try:
            max_rows = int(cfg.get("max_rows", 200_000))
        except (TypeError, ValueError) as e:
            raise ManifestError(f"{key}.max_rows 必须是整数") from e
        if not 1 <= max_rows <= 2_000_000:
            raise ManifestError(f"{key}.max_rows 超出 1..2_000_000")
        out[key] = DatasetGrant(
            name=key,
            symbols=tuple(sorted(symbols_raw)),
            max_rows=max_rows,
        )
    return out


def _parse_egress(raw: object) -> tuple[EgressGrant, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ManifestError("egress 必须是主机名列表")
    hosts: list[str] = []
    for item in raw:
        host = str(item or "").strip().lower()
        if host.startswith("*."):
            host = host[1:]  # *.example.com -> .example.com 后缀授权
        check = host[1:] if host.startswith(".") else host
        if not _HOST_RE.match(check):
            raise ManifestError(f"非法 egress 主机名: {item!r}")
        hosts.append(host)
    if len(set(hosts)) != len(hosts):
        raise ManifestError("egress 主机名重复")
    return tuple(EgressGrant(h) for h in hosts)


def _parse_secrets(raw: object) -> tuple[SecretRef, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ManifestError("secrets 必须是列表")
    out: list[SecretRef] = []
    seen_alias: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ManifestError("secrets 项必须是 {alias, env}")
        alias = str(item.get("alias") or "").strip()
        env = str(item.get("env") or "").strip()
        if not re.match(r"^[a-z][a-z0-9_]{1,40}$", alias):
            raise ManifestError(f"非法 secret alias: {alias!r}")
        if not re.match(r"^[A-Z][A-Z0-9_]{1,60}$", env):
            raise ManifestError(f"secret env 必须为大写下划线名: {env!r}")
        if alias in seen_alias:
            raise ManifestError(f"secret alias 重复: {alias}")
        seen_alias.add(alias)
        out.append(SecretRef(alias=alias, env=env))
    return tuple(out)


def _parse_resources(raw: object) -> ResourceLimits:
    cfg = dict(_DEFAULT_LIMITS)
    if raw is not None:
        if not isinstance(raw, dict):
            raise ManifestError("resources 必须是 mapping")
        for key, (lo, hi) in _LIMITS.items():
            if key not in raw:
                continue
            try:
                value = int(raw[key])
            except (TypeError, ValueError) as e:
                raise ManifestError(f"resources.{key} 必须是整数") from e
            if not lo <= value <= hi:
                raise ManifestError(
                    f"resources.{key}={value} 超出硬边界 {lo}..{hi}"
                )
            cfg[key] = value
    return ResourceLimits(**cfg)
