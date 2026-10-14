"""宿主侧 Capability Broker：worker 访问外界的唯一中介。

三类能力，全部默认拒绝、逐条授权、逐条审计：

- ``data.query``  按签名策略中的数据集/标的/行数授权，经注入的 DataAccess
                  取数，结果经共享内存零拷贝回传（审计只记元信息，不记数据）；
- ``http.fetch``  仅 HTTPS、主机名白名单、禁私网/环回地址、禁重定向、
                  响应大小封顶；密钥以别名引用，宿主解析注入，永不下发 worker；
- ``log``         插件结构化日志，warning/error 进审计链。
"""
from __future__ import annotations

import ipaddress
import json
import logging
import socket
import urllib.request
from collections.abc import Callable
from typing import Any, Protocol

import pyarrow as pa

from app.sandbox.audit import AuditLog
from app.sandbox.errors import BrokerDenied
from app.sandbox.shm_channel import ShmRegistry, encode_arrow

logger = logging.getLogger(__name__)

_MAX_SYMBOLS_PER_CALL = 500
# 小于 IPC 控制面 8MiB 帧上限，给 JSON 信封留余量。
_HTTP_MAX_BYTES = 4 * 1024 * 1024
_HTTP_TIMEOUT_S = 20
_HTTP_METHODS = {"GET", "POST"}
_SECRET_MARK = "__secret__"


class DataAccess(Protocol):
    """宿主注入的标准数据访问口（由仓储层适配，沙箱不直连任何数据源）。"""

    def query(
        self,
        dataset: str,
        symbols: list[str],
        start: str | None,
        end: str | None,
        *,
        limit: int,
    ) -> pa.Table: ...


SecretResolver = Callable[[str, str], str | None]


def default_secret_resolver(alias: str, env: str) -> str | None:
    import os

    return os.environ.get(env)


class CapabilityBroker:
    def __init__(
        self,
        audit: AuditLog,
        shm: ShmRegistry,
        *,
        data_access: DataAccess | None = None,
        secret_resolver: SecretResolver = default_secret_resolver,
    ):
        self._audit = audit
        self._shm = shm
        self._data_access = data_access
        self._resolve_secret = secret_resolver

    def handle(
        self, plugin: str, granted: dict, req_id: int, method: str, params: dict
    ) -> dict:
        """处理一个 worker broker 请求，返回响应帧 body。任何异常都收敛为错误帧。"""
        try:
            if method == "data.query":
                return {"ok": True, **self._data_query(plugin, granted, params)}
            if method == "http.fetch":
                return {"ok": True, **self._http_fetch(plugin, granted, params)}
            if method == "log":
                return {"ok": True, **self._plugin_log(plugin, params)}
            raise BrokerDenied(f"未知 broker 方法: {method}")
        except BrokerDenied as e:
            self._audit.append(
                "broker_denied", plugin, method=method, reason=str(e), req_id=req_id
            )
            return {"ok": False, "error": {"type": "BrokerDenied", "message": str(e)}}
        except Exception as e:  # noqa: BLE001 - 失败不得炸宿主读线程
            logger.warning("sandbox broker %s 失败: %s", method, e)
            self._audit.append(
                "broker_error", plugin, method=method,
                error=type(e).__name__, req_id=req_id,
            )
            return {"ok": False, "error": {"type": type(e).__name__, "message": str(e)}}

    # ---------------------------------------------------------------- data

    def _data_query(self, plugin: str, granted: dict, params: dict) -> dict:
        dataset = str(params.get("dataset") or "")
        grants = granted.get("datasets", {})
        if dataset not in grants:
            raise BrokerDenied(f"未授权数据集: {dataset!r}")
        grant = grants[dataset]

        symbols = params.get("symbols") or []
        if not isinstance(symbols, list) or not symbols:
            raise BrokerDenied("symbols 必须是非空列表")
        if len(symbols) > _MAX_SYMBOLS_PER_CALL:
            raise BrokerDenied(f"单次查询标的数超过 {_MAX_SYMBOLS_PER_CALL}")
        allowed = set(grant.get("symbols", ["*"]))
        if "*" not in allowed:
            bad = [s for s in symbols if s not in allowed]
            if bad:
                raise BrokerDenied(f"标的不在授权范围内: {bad[:5]}{'...' if len(bad)>5 else ''}")
        start = _opt_str(params.get("start"))
        end = _opt_str(params.get("end"))
        limit = int(grant.get("max_rows", 200_000))

        if self._data_access is None:
            raise BrokerDenied("宿主未提供数据访问口，data.query 不可用")

        table = self._data_access.query(
            dataset, [str(s) for s in symbols], start, end, limit=limit
        )
        if not isinstance(table, pa.Table):
            table = table.to_arrow()
        if table.num_rows > limit:
            # 适配口必须遵守 limit；返回超限说明适配口违约，fail-closed 不放行。
            raise BrokerDenied(
                f"数据适配口返回 {table.num_rows} 行，超过授权上限 {limit}"
            )

        payload = encode_arrow(table)
        handle = self._shm.create(len(payload))
        self._shm.write_payload(handle, payload)
        self._audit.append(
            "broker_data", plugin, dataset=dataset,
            symbols=len(symbols), start=start, end=end,
            rows=table.num_rows, bytes=len(payload), shm=handle.name,
        )
        return {"shm": {"name": handle.name, "size": len(payload)}, "rows": table.num_rows}

    # ---------------------------------------------------------------- http

    def _http_fetch(self, plugin: str, granted: dict, params: dict) -> dict:
        url = str(params.get("url") or "")
        method = str(params.get("method") or "GET").upper()
        if method not in _HTTP_METHODS:
            raise BrokerDenied(f"HTTP 方法不允许: {method}")
        host, path = _parse_https_host_path(url, granted.get("egress", []))

        headers = _validate_headers(params.get("headers"))
        secret_aliases: list[str] = []
        for key, value in list(headers.items()):
            if isinstance(value, dict) and _SECRET_MARK in value:
                alias = str(value[_SECRET_MARK])
                allowed_alias = {
                    s["alias"] for s in granted.get("secrets", [])
                }
                if alias not in allowed_alias:
                    raise BrokerDenied(f"未授权密钥别名: {alias!r}")
                env = next(
                    (s["env"] for s in granted.get("secrets", [])
                     if s["alias"] == alias),
                    "",
                )
                secret = self._resolve_secret(alias, env)
                if secret is None:
                    raise BrokerDenied(f"密钥不可用: {alias!r}")
                headers[key] = str(secret)
                secret_aliases.append(alias)

        _assert_public_address(host)

        body = None
        if "json" in params and params["json"] is not None:
            body = json.dumps(params["json"], ensure_ascii=False).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")

        request = urllib.request.Request(
            url, data=body, headers=headers, method=method
        )
        opener = urllib.request.build_opener(_NoRedirects, urllib.request.HTTPSHandler())
        try:
            with opener.open(request, timeout=_HTTP_TIMEOUT_S) as resp:
                raw = _read_capped(resp, _HTTP_MAX_BYTES)
                status = resp.status
                ctype = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            # HTTP 错误状态仍然是"外联成功"的一种，原样返回给插件处理。
            raw = _read_capped(e, _HTTP_MAX_BYTES)
            status = e.code
            ctype = e.headers.get("Content-Type", "") if e.headers else ""

        result: dict[str] = {"status": status, "bytes": len(raw)}
        text = raw.decode("utf-8", "replace")
        if "json" in ctype:
            try:
                result["json"] = json.loads(text)
            except json.JSONDecodeError:
                result["text"] = text
        else:
            result["text"] = text
        self._audit.append(
            "broker_http", plugin, method=method, host=host, path=path,
            status=status, bytes=len(raw),
            secrets=secret_aliases, header_names=sorted(headers),
        )
        return result

    # ---------------------------------------------------------------- log

    def _plugin_log(self, plugin: str, params: dict) -> dict:
        level = str(params.get("level") or "info").lower()
        message = str(params.get("message") or "")[:2000]
        if level not in {"debug", "info", "warning", "error"}:
            level = "info"
        logging.getLogger(f"app.sandbox.plugin.{plugin}").log(
            {"debug": logging.DEBUG, "info": logging.INFO,
             "warning": logging.WARNING, "error": logging.ERROR}[level],
            message,
        )
        if level in {"warning", "error"}:
            self._audit.append("plugin_log", plugin, level=level, message=message)
        return {}


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _validate_headers(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise BrokerDenied("headers 必须是 mapping")
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key.strip():
            raise BrokerDenied("非法 header 名")
        if isinstance(value, dict):
            if set(value.keys()) != {_SECRET_MARK}:
                raise BrokerDenied("header 值只能是字符串或 {__secret__: alias}")
            out[key] = value
        elif isinstance(value, str):
            out[key] = value
        else:
            raise BrokerDenied(f"header {key!r} 值类型非法")
    # 禁止插件自行伪造内部转发/鉴权头。
    for forbidden in ("Authorization",):
        if forbidden in out and not isinstance(out[forbidden], dict):
            raise BrokerDenied("凭据必须通过 __secret__ 别名注入")
    return out


def _parse_https_host_path(url: str, egress: list[str]) -> tuple[str, str]:
    if "://" not in url:
        raise BrokerDenied("URL 必须包含 scheme")
    scheme, _, rest = url.partition("://")
    if scheme.lower() != "https":
        raise BrokerDenied("只允许 HTTPS 外联")
    host_part, _, path_part = rest.partition("/")
    host = host_part.rpartition("@")[-1]  # 防 userinfo 绕过
    host_no_port = host.split(":", 1)[0].lower()
    if not any(_egress_match(pattern, host_no_port) for pattern in egress):
        raise BrokerDenied(f"目标主机不在 egress 白名单: {host_no_port}")
    # 审计不保留 query（可能含敏感参数）。
    return host_no_port, "/" + path_part.split("?", 1)[0]


def _egress_match(pattern: str, host: str) -> bool:
    if pattern.startswith("."):
        return host == pattern[1:] or host.endswith(pattern)
    return host == pattern


def _assert_public_address(host: str) -> None:
    """DNS 解析后拒绝环回/私网/链路本地/保留地址，防 SSRF 打内网。"""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise BrokerDenied(f"DNS 解析失败: {host}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise BrokerDenied(f"目标解析到非公开地址，已拒绝: {ip}")


def _read_capped(response: Any, cap: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise BrokerDenied(f"响应体超过 {cap} 字节上限")
        chunks.append(chunk)
    return b"".join(chunks)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any):  # type: ignore[override]
        raise BrokerDenied("禁止 HTTP 重定向（可能绕过主机白名单）")
