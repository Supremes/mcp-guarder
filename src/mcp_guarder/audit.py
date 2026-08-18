"""JSONL 审计 + 人看的 guard.log（SPEC §4 audit 段 / §6 记录格式 / §5 写盘失败语义）。

两个组件：
- :class:`AuditLogger`：一行一个事件写 ``~/.mcp-guarder/audit/{server}-{date}.jsonl``。
  **写失败一律抛 :class:`~mcp_guarder.errors.AuditUnavailable`**，proxy 靠这个异常
  切换到降级模式：deny 且停止转发后续 ``tools/call``（SPEC §5 第五行）。
- :class:`GuardLog`：人看的日志（rug pull 告警、静态规则命中、ask 降级提示、异常栈）。
  **它绝不能写 stdout**，只写文件 + 可选 stderr（SPEC 铁律：stdout 只有协议报文）。

外加 CLI ``audit tail`` / ``audit grep`` 要用的只读工具函数。

依赖方向：types / errors / config / fingerprint（借它的 canonical_json + digest）。
**不 import proxy。**
"""

from __future__ import annotations

import io  # noqa: F401  （文件句柄类型标注/实现用）
import json
import os
import re
import secrets
import shlex
import sys
import threading
import time
import traceback
from collections.abc import Iterator, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_guarder.config import expand_path
from mcp_guarder.errors import AuditUnavailable, GuarderError
from mcp_guarder.fingerprint import canonical_json, digest_value, tool_preview
from mcp_guarder.types import (
    GUARD_VERSION,
    METHOD_TOOLS_CALL,
    METHOD_TOOLS_LIST,
    AuditConfig,
    AuditRecord,
    Decision,
    DecisionBy,
    DetectorOutcome,
    Direction,
    FsyncMode,
    JsonObj,
    JsonValue,
    LatencyMs,
    RecordMode,
    RedactionCount,
    UpstreamInfo,
)

#: guard.log 每行的前缀，SPEC §8 的验收命令按这个 grep。
LOG_PREFIX = "[mcp-guarder]"

#: ``fsync: interval`` 模式下两次 fsync 的最小间隔（秒）。
FSYNC_INTERVAL_SECONDS = 5.0

#: payload 超过 ``max_bytes`` 时，退化预览里 ``_head`` 最多保留多少个字符。
TRUNCATED_HEAD_MAX_CHARS = 256

#: ``tail -f`` 的轮询间隔（秒）。不引第三方 watch 库（SPEC：运行时依赖只有 pyyaml）。
FOLLOW_POLL_SECONDS = 0.5

#: Crockford base32 字母表（去掉 I/L/O/U，只剩 ``[0-9A-HJKMNP-TV-Z]``）。
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

#: audit_id 的两段长度：10 字符毫秒时间戳 + 6 字符随机后缀。
_ID_TIME_CHARS = 10
_ID_RANDOM_CHARS = 6
_ID_RANDOM_MAX = 32**_ID_RANDOM_CHARS - 1


# ────────────────────────────────────────────────────────────────────────────
# 时间与 id
# ────────────────────────────────────────────────────────────────────────────


def utc_now_iso(now: datetime | None = None) -> str:
    """返回 SPEC §6 那种时间戳：``2026-08-17T10:32:41.518Z``（UTC、毫秒、Z 结尾）。

    传进来的 naive datetime 一律当成 UTC；aware 的先转 UTC。
    """
    dt = datetime.now(timezone.utc) if now is None else now
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{dt.microsecond // 1000:03d}Z"


def _crockford(value: int, width: int) -> str:
    """把非负整数编码成定长 Crockford base32（高位补 0）。"""
    if value < 0:
        value = 0
    out: list[str] = []
    for _ in range(width):
        out.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(out))


_ID_LOCK = threading.Lock()
_ID_LAST_MS = -1
_ID_LAST_RANDOM = -1


def new_audit_id(now: datetime | None = None) -> str:
    """生成 ``audit_id``：ULID 风格的 Crockford base32 短 id（如 ``01J8Z9Q3K7``）。

    要求：同一进程内单调递增、跨进程基本不撞、只含 ``[0-9A-HJKMNP-TV-Z]``。
    不引第三方库（运行时依赖只有 pyyaml），用 ``time_ns`` + ``secrets`` 自己拼。

    形态是 10 字符毫秒时间戳 + 6 字符随机后缀（共 16 字符）：
    - 时间戳在高位 → 字典序 == 时间序，``sort`` 审计文件就是按时间排。
    - 同一毫秒内多条记录靠后缀 +1 保证严格递增（proxy 是多线程的，这里上锁）。

    显式传 ``now`` 时只用它算时间戳前缀，**不参与进程内的单调状态**
    （否则测试里塞一个过去的时间会把后续真实 id 一起拽回去）。
    """
    if now is not None:
        dt = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
        ms = int(dt.timestamp() * 1000)
        return _crockford(ms, _ID_TIME_CHARS) + _crockford(
            secrets.randbelow(_ID_RANDOM_MAX), _ID_RANDOM_CHARS
        )

    global _ID_LAST_MS, _ID_LAST_RANDOM
    ms = time.time_ns() // 1_000_000
    with _ID_LOCK:
        if ms < _ID_LAST_MS:
            # 时钟回拨也不许让 id 倒退。
            ms = _ID_LAST_MS
        if ms == _ID_LAST_MS:
            suffix = _ID_LAST_RANDOM + 1
            if suffix > _ID_RANDOM_MAX:
                ms += 1
                suffix = secrets.randbelow(_ID_RANDOM_MAX // 2)
        else:
            # 只取一半空间，给同毫秒内的自增留出余量。
            suffix = secrets.randbelow(_ID_RANDOM_MAX // 2)
        _ID_LAST_MS, _ID_LAST_RANDOM = ms, suffix
    return _crockford(ms, _ID_TIME_CHARS) + _crockford(suffix, _ID_RANDOM_CHARS)


def _local_date(now: datetime | None = None) -> str:
    """本地日期 ``YYYY-MM-DD``，和 shell 的 ``date +%F`` 对齐。"""
    dt = datetime.now() if now is None else now
    if dt.tzinfo is not None:
        dt = dt.astimezone()
    return dt.strftime("%Y-%m-%d")


def resolve_audit_path(config: AuditConfig, server: str, now: datetime | None = None) -> Path:
    """把 ``audit.path`` 模板里的 ``{server}`` / ``{date}`` 填上，展开 ``~`` 后返回绝对路径。

    ``{date}`` 用 UTC 的 ``YYYY-MM-DD``。注意 SPEC §8 的验收命令是
    ``~/.mcp-guarder/audit/demo-$(date +%F).jsonl``（本地日期）—— 用 UTC 会在跨时区
    的深夜对不上，所以这里**用本地日期**，和 ``date +%F`` 一致；记录里的 ``ts`` 仍是 UTC。

    只认 ``{server}`` / ``{date}`` 两个占位符，用 :meth:`str.replace` 而不是
    :meth:`str.format` —— 路径里出现别的花括号不该让我们炸掉。
    """
    rendered = config.path.replace("{server}", server).replace("{date}", _local_date(now))
    return expand_path(rendered)


# ────────────────────────────────────────────────────────────────────────────
# payload 处理
# ────────────────────────────────────────────────────────────────────────────


def build_payload_preview(
    payload: JsonValue,
    *,
    max_bytes: int,
) -> tuple[JsonValue, bool, str]:
    """把（**已脱敏的**）payload 压成审计里的 ``payload_preview``。

    :return: ``(preview, truncated, digest)``
        - ``preview``：canonical_json 后不超过 ``max_bytes`` 的对象；超了就截断
          （截断策略：先整体序列化判断长度，超了就退化成
          ``{"_truncated": true, "_bytes": <n>, "_head": "<前若干字符>"}``）。
        - ``truncated``：是否发生了截断，对应记录里的 ``truncated`` 字段。
        - ``digest``：对**全量**内容算的 ``blake2b:<hex>``（SPEC §4「超出截断，另记全量摘要」），
          用 :func:`~mcp_guarder.fingerprint.digest_value`。

    **铁律**：传进来的必须已经是脱敏后的内容（``payload.store_redacted_only: true``）。
    这个函数不做脱敏，也不检查 —— 调用方（proxy）负责先脱敏再记账。
    """
    digest = digest_value(payload)
    data = canonical_json(payload)
    size = len(data)
    if size <= max_bytes:
        return payload, False, digest

    head_chars = max(0, min(int(max_bytes), TRUNCATED_HEAD_MAX_CHARS))
    # 只解码够用的前缀：UTF-8 一个字符最多 4 字节，多切一点再按字符截。
    head = data[: head_chars * 4].decode("utf-8", errors="replace")[:head_chars]
    preview: JsonValue = {"_truncated": True, "_bytes": size, "_head": head}
    return preview, True, digest


def record_mode_for(config: AuditConfig, event: str) -> RecordMode:
    """按 ``audit.record`` 决定某个 event 记多细：
    ``tools/list`` / ``tools/call`` 各自取配置，其余走 ``other_methods``。"""
    if event == METHOD_TOOLS_LIST:
        return config.record.tools_list
    if event == METHOD_TOOLS_CALL:
        return config.record.tools_call
    return config.record.other_methods


def _tools_for_preview(payload: JsonValue) -> list[JsonObj] | None:
    """从 ``tools/list`` 的 payload 里掏出 tool 列表；形态对不上返回 None。

    容忍三种形态（proxy 传整条响应、传 result、直接传列表）：
    ``{"result": {"tools": [...]}}`` / ``{"tools": [...]}`` / ``[{...}, ...]``。
    """
    candidate: Any = payload
    if isinstance(candidate, dict):
        if isinstance(candidate.get("result"), dict):
            candidate = candidate["result"]
        if isinstance(candidate, dict):
            candidate = candidate.get("tools")
    if not isinstance(candidate, list) or not candidate:
        return None
    if not all(isinstance(item, dict) and "name" in item for item in candidate):
        return None
    return list(candidate)


def _json_default(obj: Any) -> Any:
    """json.dumps 的兜底：不认识的对象一律转字符串，**绝不让 TypeError 冒到主干**。"""
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("utf-8", errors="replace")
    if isinstance(obj, (set, frozenset)):
        return sorted(str(x) for x in obj)
    if isinstance(obj, Path):
        return str(obj)
    return str(obj)


#: :func:`_json_safe` 的递归深度上限，防自引用结构把栈打爆。
_JSON_SAFE_MAX_DEPTH = 64


def _json_safe(value: Any, depth: int = 0) -> JsonValue:
    """把任意对象洗成纯 JSON 值。**只在快路径已经抛过异常时才走**（递归有代价）。

    正常情况下 payload 来自 ``json.loads``，本来就是干净的；这里只是给
    「proxy 塞了个非 JSON 对象进来」兜底，保证记账不会把转发主干带崩。
    """
    if depth > _JSON_SAFE_MAX_DEPTH:
        return "<max depth exceeded>"
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {
            (k if isinstance(k, str) else str(k)): _json_safe(v, depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(v, depth + 1) for v in value]
    return _json_default(value)


# ────────────────────────────────────────────────────────────────────────────
# 审计写入
# ────────────────────────────────────────────────────────────────────────────


class AuditLogger:
    """JSONL 审计写入器。

    生命周期由 proxy 持有：启动时 :meth:`open`，退出时 :meth:`close`。
    **只有它能决定网关是否进入降级模式**（:attr:`degraded`）。

    线程安全：proxy 有两条泵（client→upstream / upstream→client）并发写同一个文件，
    :meth:`write` 全程持锁，保证 JSONL 不会被交错撕成半行。
    """

    def __init__(
        self,
        config: AuditConfig,
        *,
        server: str,
        upstream: UpstreamInfo,
        log: GuardLog | None = None,
    ) -> None:
        """记配置，**不建文件**（建文件放 :meth:`open`）。"""
        self._config = config
        self._server = server
        self._upstream = upstream
        self._log = log
        self._lock = threading.Lock()
        self._fh: io.TextIOWrapper | None = None
        self._path: Path = resolve_audit_path(config, server)
        self._date: str = _local_date()
        self._degraded = False
        self._degraded_logged = False
        self._last_fsync = time.monotonic()
        self._closed = False

    # ── 状态 ────────────────────────────────────────────────────────────────

    @property
    def degraded(self) -> bool:
        """一旦写盘失败过就永久为 True。

        proxy 每条 ``tools/call`` 前必须查这个标志：为 True 就直接返
        ``isError:true`` + ``audit unavailable``，不再转发给上游（SPEC §5 第五行）。
        非 tools/* 的报文照常透传，别把 initialize 也掐了。
        """
        return self._degraded

    @property
    def path(self) -> Path:
        """当前正在写的文件路径（跨天会变，每次写入前重新 :func:`resolve_audit_path`）。"""
        return self._path

    def set_upstream(self, upstream: UpstreamInfo) -> None:
        """补写 ``upstream``（SPEC §6 的 ``{"pid":..., "cmd":[...]}``）。

        为什么需要它：``pid`` 只有 :meth:`Proxy._spawn_upstream <mcp_guarder.proxy.Proxy._spawn_upstream>`
        起完子进程才知道，而 AuditLogger 必须在起子进程**之前**就 open（open 失败要 exit 4）。
        所以构造时先只带 ``cmd``，拿到 pid 之后再补一次。
        """
        with self._lock:
            self._upstream = upstream

    # ── 打开 / 关闭 ─────────────────────────────────────────────────────────

    def open(self) -> None:
        """建目录、以 append + line-buffered 方式开文件。

        开不了（权限/磁盘）→ 抛 :class:`~mcp_guarder.errors.AuditUnavailable`。
        proxy 在启动阶段拿到它应该**直接退出**（审计都起不来就别代理了），
        运行期拿到才是切降级模式。
        """
        with self._lock:
            if self._fh is not None:
                return
            self._closed = False
            self._open_locked(resolve_audit_path(self._config, self._server))

    def _open_locked(self, path: Path) -> None:
        """真正开文件。调用方必须已持锁。失败置 degraded 并抛 AuditUnavailable。"""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # 行缓冲的文本句柄：写完一行就落到 OS，fsync 由 _flush_locked 按配置决定。
            fh = open(path, "a", encoding="utf-8", buffering=1, newline="\n")
        except OSError as exc:
            self._mark_degraded_locked(f"cannot open audit file {path}: {exc}")
            raise AuditUnavailable(
                f"cannot open audit file {path}: {exc}", path=path, cause=exc
            ) from exc
        self._fh = fh
        self._path = path
        self._date = _local_date()
        self._last_fsync = time.monotonic()

    def close(self) -> None:
        """flush + fsync + 关句柄。幂等。"""
        with self._lock:
            self._closed = True
            fh, self._fh = self._fh, None
            if fh is None:
                return
            try:
                fh.flush()
                os.fsync(fh.fileno())
            except (OSError, ValueError):
                pass  # 关闭阶段的 IO 失败没有补救余地，吞掉
            try:
                fh.close()
            except OSError:
                pass

    # ── 写入 ────────────────────────────────────────────────────────────────

    def write(self, record: AuditRecord) -> None:
        """写一行 JSONL。

        - 序列化：``json.dumps(record.to_dict(), ensure_ascii=False)`` + ``"\\n"``。
          非 ASCII 保留原样，别把中文转成 ``\\uXXXX`` 让人没法看。
        - 不可序列化的对象一律先转成字符串，**绝不能让 TypeError 冒到转发主干**。
        - ``fsync: every_record`` → 每条 ``flush()`` + ``os.fsync()``；
          ``interval`` → 攒够间隔再 fsync；``never`` → 只 flush。
        - 跨天了就滚到新文件（重新 resolve 路径并换句柄）。

        :raises AuditUnavailable: 任何 IO 失败。抛之前先把 :attr:`degraded` 置 True，
            并往 guard.log 记一次（只记一次，别刷屏）。
        """
        line = self._serialize(record)
        with self._lock:
            today = _local_date()
            if self._fh is None or today != self._date:
                # 首次写（proxy 忘了 open）或跨天滚动。
                self._roll_locked(resolve_audit_path(self._config, self._server))
            fh = self._fh
            if fh is None:  # 理论上不可达：_roll_locked 要么成功要么抛
                self._mark_degraded_locked(f"audit file handle is gone: {self._path}")
                raise AuditUnavailable(
                    f"audit file handle is gone: {self._path}", path=self._path
                )
            try:
                fh.write(line)
                self._flush_locked(fh)
            except (OSError, ValueError) as exc:
                self._mark_degraded_locked(f"audit write failed on {self._path}: {exc}")
                raise AuditUnavailable(
                    f"audit write failed on {self._path}: {exc}",
                    path=self._path,
                    cause=exc,
                ) from exc

    def _serialize(self, record: AuditRecord) -> str:
        """AuditRecord → 一行 JSON 文本（带换行）。绝不抛序列化异常。"""
        data = record.to_dict()
        try:
            return json.dumps(data, ensure_ascii=False, default=_json_default) + "\n"
        except (TypeError, ValueError):
            # 循环引用之类的极端情况：把 payload_preview 降级成 repr 再来一次。
            data["payload_preview"] = repr(data.get("payload_preview"))
            try:
                return json.dumps(data, ensure_ascii=False, default=_json_default) + "\n"
            except (TypeError, ValueError) as exc:
                with self._lock:
                    self._mark_degraded_locked(f"audit record is not serializable: {exc}")
                raise AuditUnavailable(
                    f"audit record is not serializable: {exc}", path=self._path, cause=exc
                ) from exc

    def _roll_locked(self, path: Path) -> None:
        """换到新文件（跨天滚动）。调用方必须已持锁。"""
        fh, self._fh = self._fh, None
        if fh is not None:
            try:
                fh.flush()
                os.fsync(fh.fileno())
            except (OSError, ValueError):
                pass
            try:
                fh.close()
            except OSError:
                pass
        self._open_locked(path)

    def _flush_locked(self, fh: io.TextIOWrapper) -> None:
        """按 ``audit.fsync`` 落盘。调用方必须已持锁。"""
        fh.flush()
        mode = self._config.fsync
        if mode is FsyncMode.NEVER:
            return
        if mode is FsyncMode.INTERVAL:
            now = time.monotonic()
            if now - self._last_fsync < FSYNC_INTERVAL_SECONDS:
                return
            self._last_fsync = now
        else:  # EVERY_RECORD
            self._last_fsync = time.monotonic()
        os.fsync(fh.fileno())

    def _mark_degraded_locked(self, message: str) -> None:
        """置降级标志并往 guard.log 记一次（只记一次，别刷屏）。"""
        self._degraded = True
        if self._degraded_logged:
            return
        self._degraded_logged = True
        if self._log is not None:
            self._log.error(f"AUDIT UNAVAILABLE {message} (denying further tools/call)")

    # ── 组装记录 ────────────────────────────────────────────────────────────

    def build_record(
        self,
        *,
        event: str,
        direction: Direction,
        decision: Decision,
        decision_by: DecisionBy,
        rpc_id: int | str | None = None,
        tool: str | None = None,
        tool_use_id: str | None = None,
        rule_id: str | None = None,
        reason: str | None = None,
        detectors: Sequence[DetectorOutcome] = (),
        redactions_outbound: Sequence[RedactionCount] = (),
        redactions_inbound: Sequence[RedactionCount] = (),
        payload: JsonValue = None,
        latency_ms: LatencyMs | None = None,
        audit_id: str | None = None,
    ) -> AuditRecord:
        """组装一条 :class:`~mcp_guarder.types.AuditRecord`。

        自动补齐 ``ts`` / ``audit_id`` / ``guard_version`` / ``server`` / ``upstream``，
        并按 :func:`record_mode_for` 决定要不要算 ``payload_preview``
        （``metadata_only`` 时 preview 为 None、digest 仍然算，这样事后还能对账）。

        ``event == "tools/list"`` 时 preview 只留 ``{name, desc_digest, schema_digest}``
        列表，全文不进审计（SPEC §6；全文由 fingerprint 的快照负责，供 ``diff`` 用）。

        :param payload: **必须是脱敏之后的内容**。
        :param audit_id: 允许调用方预先分配 —— deny 响应的文案里要带 ``event={audit_id}``，
            所以 proxy 得先拿到 id 才能拼文案，再用同一个 id 落审计。
        """
        payload_digest: str | None = None
        preview: JsonValue = None
        truncated = False

        if payload is not None:
            try:
                payload_digest, preview, truncated = self._summarize(event, payload)
            except (TypeError, ValueError):
                # payload 里混了非 JSON 对象（proxy 传错了）。洗一遍再来，
                # 记账绝不能把转发主干带崩。
                payload_digest, preview, truncated = self._summarize(
                    event, _json_safe(payload)
                )

        return AuditRecord(
            ts=utc_now_iso(),
            audit_id=audit_id or new_audit_id(),
            server=self._server,
            event=event,
            direction=direction,
            decision=decision,
            decision_by=decision_by,
            guard_version=GUARD_VERSION,
            rpc_id=rpc_id,
            tool=tool,
            tool_use_id=tool_use_id,
            rule_id=rule_id,
            reason=reason,
            detectors=tuple(detectors),
            redactions_outbound=tuple(redactions_outbound),
            redactions_inbound=tuple(redactions_inbound),
            payload_digest=payload_digest,
            payload_preview=preview,
            truncated=truncated,
            latency_ms=latency_ms or LatencyMs(),
            upstream=self._upstream,
        )

    def _summarize(self, event: str, payload: JsonValue) -> tuple[str, JsonValue, bool]:
        """算 ``(payload_digest, payload_preview, truncated)``。

        - 摘要永远对**全量原始 payload** 求值，和 preview 是否被压缩/截断无关。
        - ``metadata_only`` 只算摘要，preview 留 None。
        - ``tools/list`` 的 preview 收敛成 ``{name, desc_digest, schema_digest}`` 列表。
        """
        digest = digest_value(payload)
        if record_mode_for(self._config, event) is not RecordMode.FULL:
            return digest, None, False

        shaped: JsonValue = payload
        if event == METHOD_TOOLS_LIST:
            tools = _tools_for_preview(payload)
            if tools is not None:
                shaped = [tool_preview(t).to_dict() for t in tools]
        preview, truncated, _ = build_payload_preview(
            shaped, max_bytes=self._config.payload.max_bytes
        )
        return digest, preview, truncated


# ────────────────────────────────────────────────────────────────────────────
# guard.log
# ────────────────────────────────────────────────────────────────────────────


class GuardLog:
    """人看的日志。写文件 + 可选写 stderr。**任何情况下都不碰 stdout。**

    自身 IO 失败必须吞掉（最多降级成只写 stderr）—— 日志写不了不能反过来搞挂网关。

    行格式：``<ts> [mcp-guarder] <message>``（info）/ ``<ts> [mcp-guarder] WARN <message>``。
    info 不带 level 词，是为了让 SPEC §8 那条 ``[mcp-guarder] RUG PULL demo/echo …``
    的验收 grep 原样成立。
    """

    def __init__(self, path: Path, *, also_stderr: bool = True) -> None:
        self._path = Path(path)
        self._also_stderr = also_stderr
        self._fh: io.TextIOWrapper | None = None
        self._opened = False  # 只尝试开一次，开不了就一直只写 stderr
        self._closed = False
        self._lock = threading.Lock()

    # ── 内部 ────────────────────────────────────────────────────────────────

    def _ensure_open(self) -> io.TextIOWrapper | None:
        """懒打开。失败就返回 None（降级成只写 stderr），**绝不抛**。"""
        if self._fh is not None or self._opened or self._closed:
            return self._fh
        self._opened = True
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self._path, "a", encoding="utf-8", buffering=1, newline="\n")
        except OSError:
            self._fh = None
        return self._fh

    def _emit(self, message: str, *, level: str = "", force_stderr: bool = False) -> None:
        """写一行。stdout 一个字节都不碰。"""
        head = f"{utc_now_iso()} {LOG_PREFIX}"
        line = f"{head} {level} {message}\n" if level else f"{head} {message}\n"
        with self._lock:
            fh = self._ensure_open()
            if fh is not None:
                try:
                    fh.write(line)
                except (OSError, ValueError):
                    pass  # 日志写不了不能反过来搞挂网关
            if self._also_stderr or force_stderr:
                try:
                    sys.stderr.write(line)
                    sys.stderr.flush()
                except (OSError, ValueError):
                    pass

    # ── 公开接口 ────────────────────────────────────────────────────────────

    def info(self, message: str) -> None:
        """一行 ``[mcp-guarder] <message>``，带时间戳前缀。"""
        self._emit(message)

    def warn(self, message: str) -> None:
        self._emit(message, level="WARN")

    def error(self, message: str) -> None:
        self._emit(message, level="ERROR")

    def exception(self, message: str, exc: BaseException) -> None:
        """记 message + 完整 traceback。**异常栈只进这里**（SPEC §5）。"""
        self._emit(message, level="ERROR")
        try:
            stack = "".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            ).rstrip()
        except Exception:  # noqa: BLE001 - 格式化栈也失败就退化成 repr
            stack = repr(exc)
        with self._lock:
            fh = self._ensure_open()
            if fh is None:
                return
            try:
                # 栈只落文件，不进 stderr，更不可能进 stdout。
                fh.write(stack + "\n")
            except (OSError, ValueError):
                pass

    def banner(self, *, server: str, command: Sequence[str], config_path: Path | None) -> None:
        """启动横幅：把完整命令行打到 stderr + guard.log（SPEC §2 T8 的缓解措施）。"""
        parts = [
            f"start v{GUARD_VERSION}",
            f"server={server}",
            f"pid={os.getpid()}",
            f"config={config_path if config_path is not None else '-'}",
            f"command={shlex.join(str(c) for c in command)}",
        ]
        self._emit(" ".join(parts), force_stderr=True)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            fh, self._fh = self._fh, None
            if fh is None:
                return
            try:
                fh.flush()
            except (OSError, ValueError):
                pass
            try:
                fh.close()
            except OSError:
                pass


# ────────────────────────────────────────────────────────────────────────────
# 只读工具（CLI audit tail / grep 用）
# ────────────────────────────────────────────────────────────────────────────


def _eprint(message: str) -> None:
    """只读工具的提示走 stderr。stdout 留给 CLI 的正经输出。"""
    print(f"{LOG_PREFIX} {message}", file=sys.stderr)


def audit_files_for(config: AuditConfig, server: str) -> tuple[Path, ...]:
    """把 ``audit.path`` 模板的 ``{date}`` 换成通配，列出该 server 的所有审计文件，按名字排序。"""
    pattern_path = expand_path(
        config.path.replace("{server}", server).replace("{date}", "*")
    )
    parent = pattern_path.parent
    if not parent.is_dir():
        return ()
    try:
        return tuple(sorted(p for p in parent.glob(pattern_path.name) if p.is_file()))
    except OSError as exc:
        _eprint(f"cannot list audit files under {parent}: {exc}")
        return ()


def _parse_line(line: str, path: Path, lineno: int) -> JsonObj | None:
    """解析一行 JSONL；坏行返回 None 并在 stderr 提示。"""
    try:
        record = json.loads(line)
    except ValueError as exc:
        _eprint(f"skipping malformed line {path}:{lineno}: {exc}")
        return None
    if not isinstance(record, dict):
        _eprint(f"skipping non-object line {path}:{lineno}")
        return None
    return record


def iter_records(path: Path) -> Iterator[JsonObj]:
    """逐行读 JSONL。坏行（半截 JSON）跳过并在 stderr 提示，不要整个命令炸掉。"""
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        _eprint(f"cannot read {path}: {exc}")
        return
    with fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            record = _parse_line(line, path, lineno)
            if record is not None:
                yield record


def tail_records(paths: Sequence[Path], count: int, *, follow: bool = False) -> Iterator[JsonObj]:
    """``mcp-guarder audit tail -n <count> [-f]``。follow 用轮询实现，别引第三方 watch 库。"""
    # 先记位置再读内容：反过来的话，「读完 → stat」这个窗口里追加的行会被永久漏掉。
    # 这个顺序最坏只会把同一行重放一次，漏行是不能接受的。
    offsets: dict[Path, int] = {}
    collected: list[JsonObj] = []
    for path in paths:
        try:
            offsets[path] = path.stat().st_size
        except OSError:
            offsets[path] = 0
        collected.extend(iter_records(path))
    if count > 0:
        yield from collected[-count:]

    if not follow:
        return

    while True:
        time.sleep(FOLLOW_POLL_SECONDS)
        for path in paths:
            try:
                size = path.stat().st_size
            except OSError:
                continue
            start = offsets.get(path, 0)
            if size < start:
                start = 0  # 文件被截断/换过了，从头读
            if size <= start:
                continue
            yield from _read_new_lines(path, start, offsets)


def _read_new_lines(path: Path, start: int, offsets: dict[Path, int]) -> Iterator[JsonObj]:
    """从 ``start`` 读到文件末尾，只 yield **完整**的行；半截行留到下一轮。"""
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return
    with fh:
        try:
            fh.seek(start)
        except OSError:
            return
        pos = start
        while True:
            # 用 readline 而不是 for-in：文本句柄一边迭代一边 tell() 会直接报错。
            raw = fh.readline()
            if not raw:
                break
            if not raw.endswith("\n"):
                break  # 写了一半的行，别急着解析
            pos = fh.tell()
            line = raw.strip()
            if not line:
                continue
            record = _parse_line(line, path, -1)
            if record is not None:
                yield record
        offsets[path] = pos


def grep_records(paths: Sequence[Path], pattern: str) -> Iterator[JsonObj]:
    """``mcp-guarder audit grep <pattern>``：正则匹配整行原文，命中就 yield 解析后的记录。"""
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        raise GuarderError(f"invalid grep pattern {pattern!r}: {exc}") from exc

    for path in paths:
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
        except OSError as exc:
            _eprint(f"cannot read {path}: {exc}")
            continue
        with fh:
            for lineno, raw in enumerate(fh, start=1):
                line = raw.strip()
                if not line or regex.search(line) is None:
                    continue
                record = _parse_line(line, path, lineno)
                if record is not None:
                    yield record


def format_record(record: JsonObj, *, verbose: bool = False) -> str:
    """把一条记录渲染成人看的一行（tail/grep 的默认输出）。

    简洁形态：``<ts> <event> <tool> <decision>/<decision_by> rule=<rule_id> <reason>``；
    ``verbose`` 时直接 ``json.dumps(indent=2)``。
    """
    if verbose:
        return json.dumps(record, ensure_ascii=False, indent=2, default=_json_default)

    parts = [
        str(record.get("ts", "-")),
        str(record.get("event", "-")),
        str(record.get("tool") or "-"),
        f"{record.get('decision', '-')}/{record.get('decision_by', '-')}",
    ]
    rule_id = record.get("rule_id")
    if rule_id:
        parts.append(f"rule={rule_id}")
    reason = record.get("reason")
    if reason:
        parts.append(str(reason))
    return " ".join(parts)


__all__ = [
    "LOG_PREFIX",
    "FSYNC_INTERVAL_SECONDS",
    "TRUNCATED_HEAD_MAX_CHARS",
    "FOLLOW_POLL_SECONDS",
    "utc_now_iso",
    "new_audit_id",
    "resolve_audit_path",
    "build_payload_preview",
    "record_mode_for",
    "AuditLogger",
    "GuardLog",
    "audit_files_for",
    "iter_records",
    "tail_records",
    "grep_records",
    "format_record",
]
