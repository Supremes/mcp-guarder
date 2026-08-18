"""TOFU 指纹：首见记账，之后任何字段变化都是 rug pull（SPEC §2 T2 / §4 / §7 M1）。

职责：
1. 对 ``tools/list`` 响应里的每个 tool，按 ``inspect.fingerprint.fields``
   （默认 ``name/title/description/inputSchema``）拼 canonical_json 后算 blake2b。
2. 和 sqlite 里的历史指纹比：首见 → ``allow_and_record``；变了 → ``deny_and_alert``
   （该 tool 从响应里剥离，一个都不剩就返空列表，SPEC §5 第六行）。
3. 存全文快照到 ``<snapshot_dir>/<server>/<digest>.json``，供 ``mcp-guarder diff`` 用（SPEC §6）。

本模块顺带提供全包共用的 canonical_json / digest 工具 —— audit 算 ``payload_digest``
也从这里取，**不要各写一份**（两处算法不一致会让 diff 和审计对不上）。

依赖方向：types / errors / config / 标准库（sqlite3、hashlib）。**不 import proxy / audit。**
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from mcp_guarder.errors import DetectorError
from mcp_guarder.types import (
    DIGEST_ALGO,
    DIGEST_SIZE,
    DetectorName,
    FingerprintConfig,
    FingerprintReport,
    FingerprintStatus,
    JsonObj,
    JsonValue,
    ToolDigestPreview,
    ToolFingerprint,
    ToolFingerprintResult,
)

#: sqlite 建表语句。表结构一旦定下就只增列不改列名（和审计字段一个原则）。
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tool_fingerprints (
    server         TEXT NOT NULL,
    tool           TEXT NOT NULL,
    digest         TEXT NOT NULL,
    fields         TEXT NOT NULL,
    first_seen_ts  TEXT NOT NULL,
    last_seen_ts   TEXT NOT NULL,
    snapshot_path  TEXT,
    PRIMARY KEY (server, tool)
);
"""

#: 摘要字符串的分隔符，形如 ``blake2b:<hex>``。
_DIGEST_SEP = ":"

#: guard.log 里只显示摘要前几位（SPEC §7 M1-4 的 ``4f2a…``）。
_SHORT_DIGEST_CHARS = 8

#: 文件名里允许出现的字符，其余一律换成 ``_``（server 名来自配置，别让它穿越目录）。
_SAFE_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)

#: sqlite 跨进程锁等待时间（ms）。proxy 在写、CLI 的 trust 可能同时在删。
_BUSY_TIMEOUT_MS = 5000


# ────────────────────────────────────────────────────────────────────────────
# 摘要工具（全包共用）
# ────────────────────────────────────────────────────────────────────────────


def canonical_json(value: JsonValue) -> bytes:
    """把任意 JSON 值序列化成**稳定字节**：key 排序、无多余空格、``ensure_ascii=False``。

    只用来算摘要，**绝不用它来生成要转发出去的报文**（转发必须字节级原样，见
    :class:`~mcp_guarder.types.OutgoingLine`）。
    """
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest_value(value: JsonValue) -> str:
    """对任意 JSON 值算摘要，返回 ``"blake2b:<hex>"``。

    长度取 :data:`~mcp_guarder.types.DIGEST_SIZE`。日志里习惯只显示前 8 位
    （见 :func:`short_digest`）。
    """
    return digest_bytes(canonical_json(value))


def digest_bytes(data: bytes) -> str:
    """对原始字节算摘要，返回 ``"blake2b:<hex>"``。audit 的 ``payload_digest`` 用这个。"""
    hexdigest = hashlib.blake2b(data, digest_size=DIGEST_SIZE).hexdigest()
    return f"{DIGEST_ALGO}{_DIGEST_SEP}{hexdigest}"


def short_digest(digest: str) -> str:
    """取摘要前 8 位 hex，用于 guard.log 那行 ``RUG PULL demo/echo 4f2a… -> 9b71…``。

    传进来带不带 ``blake2b:`` 前缀都行；比 8 位还短就原样返回。
    """
    hexpart = digest.rsplit(_DIGEST_SEP, 1)[-1] if _DIGEST_SEP in digest else digest
    return hexpart[:_SHORT_DIGEST_CHARS]


def tool_digest(tool: JsonObj, fields: Sequence[str]) -> str:
    """按配置的字段子集算某个 tool 的指纹。

    做法：从 tool 对象里**按 fields 顺序**取出存在的字段，组成一个有序 dict，
    再 :func:`canonical_json` + blake2b。字段缺失就跳过（不要用 None 占位，
    否则「加上一个 title」和「title 是 null」会撞成同一指纹）。

    canonical_json 会递归排序 key，所以上游把 ``inputSchema`` 里字段顺序换个个儿
    **不会**误报成 rug pull —— 只有内容真的变了才变。
    """
    if not isinstance(tool, dict):
        raise TypeError(f"tool must be a JSON object, got {type(tool).__name__}")
    subset: dict[str, JsonValue] = {}
    for name in fields:
        if name in tool:
            subset[name] = tool[name]
    return digest_value(subset)


def tool_preview(tool: JsonObj) -> ToolDigestPreview:
    """算 SPEC §6 里 ``tools/list`` 的 ``payload_preview`` 项：
    ``{name, desc_digest, schema_digest}``。"""
    raw_name = tool.get("name")
    name = raw_name if isinstance(raw_name, str) else ""
    return ToolDigestPreview(
        name=name,
        desc_digest=digest_value(tool.get("description")),
        schema_digest=digest_value(tool.get("inputSchema")),
    )


# ────────────────────────────────────────────────────────────────────────────
# 指纹库
# ────────────────────────────────────────────────────────────────────────────


class FingerprintStore:
    """sqlite 指纹库。线程安全由调用方保证（proxy 只在一个线程里碰它）。

    连接用 ``check_same_thread=False`` + 一把内部锁，因为 proxy 的上下行是两个线程，
    只有 server→client 线程会写，但 CLI 的 ``trust`` 是另一个进程 —— 靠 sqlite 自己的
    文件锁兜住（``PRAGMA busy_timeout`` 给它等的耐心）。

    异常约定：:meth:`open` 让底层异常原样冒出去（启动期由 proxy 转成 ConfigError）；
    其余读写方法把 sqlite/OS 异常包成
    :class:`~mcp_guarder.errors.DetectorError`，运行期调用方只需要认这一种。
    """

    def __init__(self, path: Path) -> None:
        """记下路径，**不在这里连库**（连库放 :meth:`open`，方便测试）。"""
        self.path = Path(path)
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.RLock()

    # —— 生命周期 ————————————————————————————————————————————————

    def open(self) -> None:
        """建目录、连库、建表。目录不可写 → 让异常冒出去，由 proxy 转成 ConfigError（启动期）。

        幂等：已经开着就什么都不做，重复初始化不炸（``CREATE TABLE IF NOT EXISTS``）。
        """
        with self._lock:
            if self._conn is not None:
                return
            parent = self.path.parent
            if str(parent):
                parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                str(self.path),
                check_same_thread=False,
                isolation_level=None,  # autocommit，每条语句立即落盘
            )
            try:
                conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
                conn.executescript(SCHEMA_SQL)
            except BaseException:
                conn.close()
                raise
            self._conn = conn

    def close(self) -> None:
        """关连接。幂等。"""
        with self._lock:
            conn, self._conn = self._conn, None
            if conn is not None:
                conn.close()

    def __enter__(self) -> FingerprintStore:
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # —— 查询 ——————————————————————————————————————————————————

    def get(self, server: str, tool: str) -> ToolFingerprint | None:
        """查一条指纹；没有就 None（= 首见）。"""
        with self._lock, _wrapped("get"):
            row = self._require_conn().execute(
                "SELECT server, tool, digest, fields, first_seen_ts, last_seen_ts, snapshot_path"
                " FROM tool_fingerprints WHERE server = ? AND tool = ?",
                (server, tool),
            ).fetchone()
        return _row_to_fingerprint(row) if row is not None else None

    def list_tools(self, server: str) -> tuple[ToolFingerprint, ...]:
        """列出某个 server 下所有已记账的 tool，按 tool 名排序。CLI ``trust``/``diff`` 用。"""
        with self._lock, _wrapped("list_tools"):
            rows = self._require_conn().execute(
                "SELECT server, tool, digest, fields, first_seen_ts, last_seen_ts, snapshot_path"
                " FROM tool_fingerprints WHERE server = ? ORDER BY tool",
                (server,),
            ).fetchall()
        return tuple(_row_to_fingerprint(row) for row in rows)

    # —— 写入 ——————————————————————————————————————————————————

    def upsert(self, fp: ToolFingerprint) -> None:
        """写入或更新一条指纹。首见时 ``first_seen_ts == last_seen_ts``。"""
        with self._lock, _wrapped("upsert"):
            self._require_conn().execute(
                "INSERT INTO tool_fingerprints"
                " (server, tool, digest, fields, first_seen_ts, last_seen_ts, snapshot_path)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(server, tool) DO UPDATE SET"
                "   digest = excluded.digest,"
                "   fields = excluded.fields,"
                "   last_seen_ts = excluded.last_seen_ts,"
                "   snapshot_path = excluded.snapshot_path",
                (
                    fp.server,
                    fp.tool,
                    fp.digest,
                    json.dumps(list(fp.fields), ensure_ascii=False),
                    fp.first_seen_ts,
                    fp.last_seen_ts,
                    fp.snapshot_path,
                ),
            )

    def touch(self, server: str, tool: str, ts: str) -> None:
        """指纹没变时只更新 ``last_seen_ts``，别动 digest 和 first_seen_ts。"""
        with self._lock, _wrapped("touch"):
            self._require_conn().execute(
                "UPDATE tool_fingerprints SET last_seen_ts = ? WHERE server = ? AND tool = ?",
                (ts, server, tool),
            )

    def delete(self, server: str, tool: str | None = None) -> int:
        """删指纹，返回删掉的行数。

        ``mcp-guarder trust <server> [tool]`` 用它：不传 tool 就清整个 server ——
        下一次 ``tools/list`` 会重新走 TOFU 首见流程，等于"接受新指纹"
        （SPEC §7 M3：不然 server 正常升级后只能手删 sqlite）。
        """
        with self._lock, _wrapped("delete"):
            conn = self._require_conn()
            if tool is None:
                cur = conn.execute("DELETE FROM tool_fingerprints WHERE server = ?", (server,))
            else:
                cur = conn.execute(
                    "DELETE FROM tool_fingerprints WHERE server = ? AND tool = ?",
                    (server, tool),
                )
            return int(cur.rowcount or 0)

    # —— 内部 ——————————————————————————————————————————————————

    def _require_conn(self) -> sqlite3.Connection:
        """取连接；没 open 过就是调用方的 bug，抛出去让 :func:`_wrapped` 包成 DetectorError。"""
        if self._conn is None:
            raise RuntimeError(f"FingerprintStore is not open (path={self.path})")
        return self._conn


class _wrapped:
    """上下文管理器：把里面抛的任何异常包成 DetectorError(fingerprint)。

    :class:`~mcp_guarder.errors.DetectorError` 本身原样放行，不套娃。
    """

    __slots__ = ("_op",)

    def __init__(self, op: str) -> None:
        self._op = op

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: object) -> bool:
        if exc is None or isinstance(exc, DetectorError):
            return False
        if not isinstance(exc, Exception):  # KeyboardInterrupt / SystemExit 不拦
            return False
        raise DetectorError.wrap(DetectorName.FINGERPRINT, exc) from exc


def _row_to_fingerprint(row: tuple) -> ToolFingerprint:
    """sqlite 行 → :class:`~mcp_guarder.types.ToolFingerprint`。"""
    server, tool, digest, fields_json, first_seen_ts, last_seen_ts, snapshot_path = row
    try:
        fields = tuple(json.loads(fields_json))
    except (TypeError, ValueError):
        # 老库或被手改过：退化成逗号分隔，别因为一个元数据字段就让整条链路挂掉
        fields = tuple(p for p in str(fields_json).split(",") if p)
    return ToolFingerprint(
        server=server,
        tool=tool,
        digest=digest,
        fields=fields,
        first_seen_ts=first_seen_ts,
        last_seen_ts=last_seen_ts,
        snapshot_path=snapshot_path,
    )


# ────────────────────────────────────────────────────────────────────────────
# 快照（供 mcp-guarder diff）
# ────────────────────────────────────────────────────────────────────────────


def save_tool_snapshot(snapshot_dir: Path, server: str, tool: JsonObj, digest: str) -> Path:
    """把 tool 全文写到 ``<snapshot_dir>/<server>/<digest_hex>.json``（SPEC §6）。

    - 文件已存在就不重写（同 digest 内容必然相同）。
    - 内容用 :func:`canonical_json`，方便 diff 出稳定结果。
    - **快照里存的是原始描述（含投毒文本）**，这是取证材料；它不进模型上下文，
      所以不脱敏。但 ANSI 之类的控制字符照原样存，CLI 显示时才做可见化转义。
    - 写失败不算致命：本函数照常抛 OSError，由 :func:`inspect_tools` 吞掉并继续
      （别因为快照写不了就拒服务）。
    """
    path = snapshot_path_for(snapshot_dir, server, digest)
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(canonical_json(tool))
    tmp.replace(path)  # 原子落盘，别让 diff 读到半截文件
    return path


def load_tool_snapshot(snapshot_dir: Path, server: str, digest: str) -> JsonObj | None:
    """按 digest 读回快照；没有返回 None。"""
    path = snapshot_path_for(snapshot_dir, server, digest)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    return json.loads(data.decode("utf-8"))


def snapshot_path_for(snapshot_dir: Path, server: str, digest: str) -> Path:
    """算快照文件路径（digest 里的 ``blake2b:`` 前缀要去掉，不能进文件名）。"""
    hexpart = digest.rsplit(_DIGEST_SEP, 1)[-1] if _DIGEST_SEP in digest else digest
    return Path(snapshot_dir) / _safe_component(server) / f"{_safe_component(hexpart)}.json"


def _safe_component(name: str) -> str:
    """把任意字符串压成安全的单级文件名：非白名单字符换 ``_``，空串换 ``_``。

    server 名来自配置文件，理论上可信，但让它带上 ``../`` 就能写到别处 —— 不给这个机会。
    """
    safe = "".join(ch if ch in _SAFE_NAME_CHARS else "_" for ch in name)
    if not safe or set(safe) <= {"."}:
        return "_"
    return safe


# ────────────────────────────────────────────────────────────────────────────
# 检测器入口
# ────────────────────────────────────────────────────────────────────────────


def inspect_tools(
    tools: Sequence[JsonObj],
    *,
    config: FingerprintConfig,
    store: FingerprintStore,
    server: str,
    snapshot_dir: Path | None = None,
    now: str | None = None,
) -> FingerprintReport:
    """检测器统一入口：对一批 tool 做 TOFU 比对并记账。

    行为（SPEC §4 ``on_first_seen: allow_and_record`` / ``on_change: deny_and_alert``）：
    - ``config.enabled`` 为 False → 直接返回 ``FingerprintReport(skipped=True)``，不碰库。
    - 库里没有 → ``FIRST_SEEN``，写入指纹 + 快照，放行。
    - digest 相同 → ``UNCHANGED``，只 touch ``last_seen_ts``。
    - digest 不同 → ``CHANGED``，**先写快照（留证据）但不更新指纹**（不更新才能反复检出，
      也才能让 ``mcp-guarder diff`` 对比"已信任的"和"现在的"），由 proxy 剥离该 tool
      并往 guard.log 打 ``RUG PULL <server>/<tool> <old8>… -> <new8>…``。

    :param now: ISO8601 时间戳；不传就取当前 UTC（测试注入用）。
    :raises DetectorError: 任何内部异常（sqlite 挂了、tool 不是 dict、tool 没名字）都包成
        :meth:`DetectorError.wrap(DetectorName.FINGERPRINT, exc) <mcp_guarder.errors.DetectorError.wrap>`
        再抛，proxy 统一按 fail-closed（deny 当前消息）处置。
    """
    if not config.enabled:
        return FingerprintReport(skipped=True)

    try:
        ts = now or _utc_now_iso()
        fields = tuple(config.fields)
        results: list[ToolFingerprintResult] = []

        for tool in tools:
            if not isinstance(tool, dict):
                raise TypeError(f"tools[] entry must be a JSON object, got {type(tool).__name__}")
            name = tool.get("name")
            if not isinstance(name, str) or not name:
                # 没名字的 tool 无法记账 → fail-closed，让 proxy deny 掉这条 tools/list
                raise ValueError(f"tool has no usable 'name' field: {canonical_json(tool)[:120]!r}")

            new_digest = tool_digest(tool, fields)
            old = store.get(server, name)

            if old is None:
                # TOFU 首见：记账 + 存快照 + 放行
                snapshot = _try_save_snapshot(snapshot_dir, server, tool, new_digest)
                store.upsert(
                    ToolFingerprint(
                        server=server,
                        tool=name,
                        digest=new_digest,
                        fields=fields,
                        first_seen_ts=ts,
                        last_seen_ts=ts,
                        snapshot_path=str(snapshot) if snapshot is not None else None,
                    )
                )
                status = FingerprintStatus.FIRST_SEEN
            elif old.digest == new_digest:
                store.touch(server, name, ts)
                status = FingerprintStatus.UNCHANGED
            else:
                # rug pull：只留证据，**绝不 upsert**——不然第二次 tools/list 就检不出来了，
                # 而且 diff 也失去了「已信任版本」这个参照。接受新指纹只能靠 mcp-guarder trust。
                _try_save_snapshot(snapshot_dir, server, tool, new_digest)
                status = FingerprintStatus.CHANGED

            results.append(
                ToolFingerprintResult(
                    tool=name,
                    status=status,
                    new_digest=new_digest,
                    old_digest=old.digest if old is not None else None,
                )
            )

        return FingerprintReport(results=tuple(results))
    except DetectorError:
        raise
    except Exception as exc:  # noqa: BLE001 —— 检测器入口统一包成 DetectorError
        raise DetectorError.wrap(DetectorName.FINGERPRINT, exc) from exc


def _try_save_snapshot(
    snapshot_dir: Path | None, server: str, tool: JsonObj, digest: str
) -> Path | None:
    """写快照，失败只当没写成（返回 None），**不影响指纹判定**。

    快照是取证材料不是安全依据 —— 磁盘满了也不该因此拒服务（见
    :func:`save_tool_snapshot` 的 docstring）。
    """
    if snapshot_dir is None:
        return None
    try:
        return save_tool_snapshot(Path(snapshot_dir), server, tool, digest)
    except OSError:
        return None


def rug_pull_log_line(server: str, tool: str, old_digest: str, new_digest: str) -> str:
    """拼 SPEC §7 M1-4 / §8 要求的那行 guard.log 文本::

        RUG PULL demo/echo 4f2a… -> 9b71…

    静态检查也命中时由 proxy 在后面追加 ``  static_checks: <rule_id,...>``。
    """
    return (
        f"RUG PULL {server}/{tool} "
        f"{short_digest(old_digest)}… -> {short_digest(new_digest)}…"
    )


def _utc_now_iso() -> str:
    """``2026-08-17T10:32:41.518Z``。

    和 ``audit.utc_now_iso()`` 同格式，但**不能 import audit**（audit 依赖本模块，
    反向 import 就成环了），所以这里自己算一份。
    """
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


__all__ = [
    "SCHEMA_SQL",
    "canonical_json",
    "digest_value",
    "digest_bytes",
    "short_digest",
    "tool_digest",
    "tool_preview",
    "FingerprintStore",
    "save_tool_snapshot",
    "load_tool_snapshot",
    "snapshot_path_for",
    "inspect_tools",
    "rug_pull_log_line",
]
