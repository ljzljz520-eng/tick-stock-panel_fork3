"""不可信插件沙箱执行子系统。

执行边界（host = 受信后端, worker = 受限子进程）:

    插件目录 --scan--> 静态检查(AST) + 代码/依赖 digest
        --approve--> 能力裁剪 + HMAC 签名策略落盘 + 审计
        --activate--> 校验签名与 digest 未漂移 -> 启动受限 worker(OS 隔离 + rlimits)
        --call--> 窄 IPC(帧 JSON + shm Arrow 零拷贝)
                   worker 只经 capability broker 取数据 / 发外网请求

设计原则:
- 默认拒绝: 未在签名策略中授予的能力一律 fail-closed。
- 密钥不进 worker: 外网请求由宿主代发, secret 仅以别名引用。
- 数据零拷贝: 批量数据经共享内存 Arrow IPC mmap 传递, IPC 控制面只走 JSON。
- 故障域隔离: 单次调用超时/内存越界/崩溃只杀 worker 进程组, 不影响主进程,
  下次调用惰性重启新 worker。

公开入口见 :class:`app.sandbox.runtime.SandboxRuntime`。
"""
from __future__ import annotations

from app.sandbox.errors import (
    ActivationDenied,
    BrokerDenied,
    ManifestError,
    PolicyError,
    SandboxError,
    StaticCheckError,
    WorkerCallError,
    WorkerCrashed,
    WorkerTimeout,
)
from app.sandbox.manifest import (
    ALLOWED_EXTERNAL,
    ALLOWED_STDLIB,
    MANIFEST_FILENAME,
    SANDBOX_API_VERSION,
    CapabilityManifest,
    DatasetGrant,
    EgressGrant,
    ResourceLimits,
    SecretRef,
    load_manifest,
)
from app.sandbox.runtime import SandboxRuntime, ScanResult

__all__ = [
    "ALLOWED_EXTERNAL",
    "ALLOWED_STDLIB",
    "MANIFEST_FILENAME",
    "SANDBOX_API_VERSION",
    "ActivationDenied",
    "BrokerDenied",
    "CapabilityManifest",
    "DatasetGrant",
    "EgressGrant",
    "ManifestError",
    "PolicyError",
    "ResourceLimits",
    "SandboxError",
    "SandboxRuntime",
    "ScanResult",
    "SecretRef",
    "StaticCheckError",
    "WorkerCallError",
    "WorkerCrashed",
    "WorkerTimeout",
    "load_manifest",
]
