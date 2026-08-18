"""异常层次（完整实现，不是 stub）。

对应 SPEC §5 的 fail-closed 表格。每种异常对应表里的一行处置方式：

    异常                行为                              模型看到什么
    ─────────────────────────────────────────────────────────────────────────
    ConfigError         拒绝启动，非零退出（exit 2）      进程根本起不来
    DetectorError       deny 当前这条消息，继续转发       isError:true + "detector failure"
    AuditUnavailable    deny，且**停止转发后续 tools/call**  isError:true + "audit unavailable"
    UpstreamCrash       记审计后整体退出（exit 3）        server 断开

统一约定：
- 每个异常都带一个 :attr:`model_text` —— **给模型看的那句话**，proxy 会把它塞进
  ``result.content[0].text``。默认值已按 SPEC 写好，一般不用自己传。
- 每个异常都带 :attr:`exit_code`，只有需要退出进程的场景才用。
- 异常栈**只进 guard.log**，绝不进 stdout，也绝不塞给模型（SPEC §5）。
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from mcp_guarder.types import (
    EXIT_AUDIT_UNAVAILABLE,
    EXIT_CONFIG_ERROR,
    EXIT_GENERIC_ERROR,
    EXIT_UPSTREAM_CRASH,
    DetectorName,
)


class GuarderError(Exception):
    """所有 mcp-guarder 自有异常的基类。

    :param message: 给开发者/运维看的详细信息，进 guard.log 和 stderr。
    :param model_text: 给模型看的一句话；不传就用类级别的 ``default_model_text``。
    """

    #: 需要退出进程时用的退出码。
    exit_code: int = EXIT_GENERIC_ERROR
    #: 未显式传 model_text 时的兜底文案。
    default_model_text: str = "mcp-guarder: internal error"

    def __init__(self, message: str, *, model_text: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self._model_text = model_text

    @property
    def model_text(self) -> str:
        """塞进 ``result.content[0].text`` 的那句话。绝不包含异常栈或内部路径。"""
        return self._model_text or self.default_model_text

    def __str__(self) -> str:  # pragma: no cover - 纯格式化
        return self.message


class ConfigError(GuarderError):
    """配置解析失败 / 出现未知字段 / 启动期冲突检查不过 → **拒绝启动**。

    SPEC §5：「配置解析失败 / 出现未知字段 → 拒绝启动，非零退出」，
    「启动时静态检查发现同 tool 重复定义就拒绝启动并打印冲突 rule id」。

    :param problems: 逐条列出的问题（例如多个未知字段、多组冲突 rule id），
        CLI 会把它们一行一条打到 stderr，方便用户一次改完。
    :param path: 出问题的配置文件路径。
    :param field_path: 出问题的字段路径，例如 ``policy.rules[2].when[0]``。
    """

    exit_code = EXIT_CONFIG_ERROR
    default_model_text = "mcp-guarder: refused to start (config error)"

    def __init__(
        self,
        message: str,
        *,
        problems: Sequence[str] = (),
        path: Path | None = None,
        field_path: str | None = None,
        model_text: str | None = None,
    ) -> None:
        super().__init__(message, model_text=model_text)
        self.problems: tuple[str, ...] = tuple(problems)
        self.path = path
        self.field_path = field_path

    def format_report(self) -> str:
        """给 stderr 用的多行报告：一行摘要 + 每条问题一行。"""
        head = f"[mcp-guarder] config error: {self.message}"
        if self.path is not None:
            head += f" (file={self.path})"
        if self.field_path is not None:
            head += f" (field={self.field_path})"
        lines = [head]
        lines.extend(f"  - {p}" for p in self.problems)
        return "\n".join(lines)


class DetectorError(GuarderError):
    """检测器（指纹 / 静态检查 / 脱敏 / 权限门）自己抛异常 → **deny 当前这条消息**。

    SPEC §5：「检测器抛异常 → deny 当前这条消息；``isError:true``，
    text 写 ``detector failure``；异常栈只进 guard.log」。

    四个检测器的入口函数**必须自己把内部异常包成 DetectorError 再抛**
    （用 :meth:`wrap`），proxy 只认这一种，统一按 fail-closed 处置。
    """

    default_model_text = "mcp-guarder: detector failure"

    def __init__(
        self,
        message: str,
        *,
        detector: DetectorName,
        cause: BaseException | None = None,
        model_text: str | None = None,
    ) -> None:
        super().__init__(message, model_text=model_text)
        self.detector = detector
        self.cause = cause

    @property
    def model_text(self) -> str:
        """例如 ``mcp-guarder: detector failure (static_checks)``。不含任何栈信息。"""
        return self._model_text or f"{self.default_model_text} ({self.detector})"

    @classmethod
    def wrap(cls, detector: DetectorName, exc: BaseException) -> DetectorError:
        """把任意内部异常包成 DetectorError。检测器入口的 ``except`` 里统一这么写::

            try:
                ...
            except DetectorError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise DetectorError.wrap(DetectorName.STATIC_CHECKS, exc) from exc
        """
        return cls(
            f"{detector} raised {type(exc).__name__}: {exc}",
            detector=detector,
            cause=exc,
        )


class AuditUnavailable(GuarderError):
    """审计写盘失败（磁盘满 / 权限 / 目录没了）→ **deny 且停止转发后续 tools/call**。

    SPEC §5：「审计写盘失败 → deny，且停止转发后续 ``tools/call``；
    ``isError:true``，text 写 ``audit unavailable``」。

    注意语义：**不是整体退出**，而是把网关切到「降级模式」——
    非 ``tools/call`` 的报文继续原样转发（否则连 initialize 都断了，客户端体验极差），
    但任何 ``tools/call`` 一律返 isError。这个状态由 ``audit.AuditLogger.degraded``
    标记，proxy 每条 tools/call 前都要查。
    """

    exit_code = EXIT_AUDIT_UNAVAILABLE
    default_model_text = "mcp-guarder: audit unavailable"

    def __init__(
        self,
        message: str,
        *,
        path: Path | None = None,
        cause: BaseException | None = None,
        model_text: str | None = None,
    ) -> None:
        super().__init__(message, model_text=model_text)
        self.path = path
        self.cause = cause


class UpstreamCrash(GuarderError):
    """上游子进程崩溃，或它的 stdout 出现非 JSON 行 → **记审计后整体退出**。

    SPEC §5：「上游崩溃，或 stdout 出现非 JSON 行 → 记审计后整体退出；
    server 断开，不会拿到半截数据」。对应 ``defaults.on_upstream_crash: fail``。
    """

    exit_code = EXIT_UPSTREAM_CRASH
    default_model_text = "mcp-guarder: upstream server crashed"

    def __init__(
        self,
        message: str,
        *,
        returncode: int | None = None,
        signal_number: int | None = None,
        cause: BaseException | None = None,
        model_text: str | None = None,
    ) -> None:
        super().__init__(message, model_text=model_text)
        self.returncode = returncode
        self.signal_number = signal_number
        self.cause = cause

    @classmethod
    def exited(cls, returncode: int) -> UpstreamCrash:
        """子进程退出（含被信号杀掉，returncode 为负）。"""
        signal_number = -returncode if returncode < 0 else None
        return cls(
            f"upstream exited with returncode={returncode}",
            returncode=returncode,
            signal_number=signal_number,
        )

    @classmethod
    def non_json_line(cls, line: bytes, *, limit: int = 200) -> UpstreamCrash:
        """上游 stdout 吐了非 JSON 行。

        摘要只截前 ``limit`` 字节且做 repr 转义，避免把上游的垃圾原样再传播一遍。
        """
        preview = repr(line[:limit])
        return cls(f"upstream emitted a non-JSON line on stdout: {preview}")


__all__ = [
    "GuarderError",
    "ConfigError",
    "DetectorError",
    "AuditUnavailable",
    "UpstreamCrash",
]
