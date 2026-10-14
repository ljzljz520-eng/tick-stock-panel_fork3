"""沙箱子系统异常类型。"""
from __future__ import annotations


class SandboxError(Exception):
    """沙箱相关错误基类。"""


class ManifestError(SandboxError):
    """插件能力清单缺失、格式非法或能力越权。"""


class StaticCheckError(SandboxError):
    """静态检查发现禁止的 import / 调用 / 属性或原生代码文件。"""

    def __init__(self, findings: list[str]):
        self.findings = findings
        super().__init__("; ".join(findings))


class PolicyError(SandboxError):
    """策略文件缺失、签名错误或字段非法。"""


class ActivationDenied(SandboxError):  # noqa: N818 - 领域语义为"拒绝"而非错误后缀
    """激活被拒绝：策略签名失效、代码/依赖 digest 漂移或能力不一致。"""


class BrokerDenied(SandboxError):  # noqa: N818 - 同上，拒绝语义
    """Capability broker 拒绝本次请求（未授权数据集/标的/域名/密钥别名）。"""


class WorkerCallError(SandboxError):
    """Worker 内插件执行抛出的异常（已隔离，不影响宿主与其他插件）。"""


class WorkerTimeout(SandboxError):  # noqa: N818 - 超时事件类型
    """调用超过 wall timeout，worker 进程组已被回收。"""


class WorkerCrashed(SandboxError):  # noqa: N818 - 崩溃事件类型
    """Worker 非零退出/通道断裂；进程已回收，仅影响该任务。"""
