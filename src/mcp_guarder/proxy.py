"""转发主干（SPEC §3 架构图 / §5 fail-closed / §7 M1 验收）。

    Claude Code --stdin--> [① 按行读 ② id→method 记账 ③ 出站脱敏 ④ 权限门] --stdin--> 真 server
                <-stdout-- [⑧ 序列化回写 ⑦ 回流脱敏 ⑥ 投毒检测 ⑤ 按行读] <-stdout--

主干原则：**字节级保守转发**。只有 ``tools/list`` 和 ``tools/call`` 会被深加工，
其余一切 method（``initialize``、``notifications/*``、``resources/*``、``prompts/*``、``ping``，
以及反向的 ``roots/list`` / ``sampling/createMessage`` / ``elicitation/create``）
一律 ``json.loads`` → 记账 → **回写原始行字节**。不认识的字段 100% 原样保留。

八条铁律在本模块的落点：
1. **stdout 洁净**：只有 :meth:`Proxy._write_client` 能碰 stdout，且只写合法 JSON-RPC 行；
   顶层 ``try/except`` 包住整个转发循环，任何异常都走 guard.log。
2. **保守转发**：靠 :class:`~mcp_guarder.types.OutgoingLine` 区分 verbatim / rewritten。
3. **不用 SDK 高层 session**：本文件只依赖标准库的 ``json`` / ``subprocess`` / ``threading``。
4. **fail-closed**：见 :meth:`Proxy.handle_client_line` 的分支注释，逐条对应 SPEC §5 那张表。
5. **拒绝一律 ``result.isError: true``**：见 :func:`build_tool_error_response`。
6. **按行读不设固定 buffer 上限**：用二进制流的 ``readline()``，不做 ``read(n)`` 分块。
7. **客户端关 stdin 后终止子进程树**：见 :meth:`Proxy._terminate_upstream`。
8. **自发请求用负数 id 段**：见 :meth:`IdLedger.next_guard_id`（v1 没人调，但留着）。

依赖方向：proxy import 其余所有模块，**其余模块一律不许 import proxy**。
"""

from __future__ import annotations

import io
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, BinaryIO

from mcp_guarder import audit as audit_mod
from mcp_guarder import fingerprint as fingerprint_mod
from mcp_guarder import policy as policy_mod
from mcp_guarder import redact as redact_mod
from mcp_guarder import static_checks as static_mod
from mcp_guarder.audit import AuditLogger, GuardLog
from mcp_guarder.errors import (
    AuditUnavailable,
    ConfigError,
    DetectorError,
    GuarderError,
    UpstreamCrash,
)
from mcp_guarder.fingerprint import FingerprintStore
from mcp_guarder.types import (
    EXIT_GENERIC_ERROR,
    EXIT_OK,
    EXIT_UPSTREAM_CRASH,
    GUARD_REQUEST_ID_START,
    JSONRPC_VERSION,
    METHOD_TOOLS_CALL,
    METHOD_TOOLS_LIST,
    TOOL_USE_ID_META_KEY,
    AuditRecord,
    Decision,
    DecisionBy,
    DetectorName,
    DetectorOutcome,
    DetectorResult,
    Direction,
    FingerprintStatus,
    GuarderConfig,
    JsonObj,
    LatencyMs,
    MessageKind,
    OutgoingLine,
    RedactAction,
    Routed,
    StaticCheckAction,
    UpstreamInfo,
)

#: 客户端关掉 stdin 后，等子进程自己退出的宽限期（秒）；超时就 SIGKILL 整个进程组。
#: SPEC §7 M1-5 要求 ``kill -9 上游`` 后网关 1s 内退出，所以这个值要明显小于 1s 的预算。
TERMINATE_GRACE_SECONDS = 0.5

#: SIGTERM 之后再等多久才升级到 SIGKILL（秒）。加上 TERMINATE_GRACE_SECONDS 仍在 1s 预算内。
_KILL_GRACE_SECONDS = 0.2

#: 收尾时等泵 A（可能永远阻塞在客户端 stdin 上）的时间。上游先死的场景里这段是纯等待，
#: 所以要短 —— SPEC §7 M1-5 给的总预算只有 1s。
_READER_JOIN_SECONDS = 0.1

#: 轮询「进程组还有没有成员」的间隔（秒）。孙子进程不是我们的子进程，wait 不了，只能探。
_GROUP_POLL_SECONDS = 0.01

#: 检测器名 → 审计里的 ``decision_by``。
_DETECTOR_TO_DECISION_BY = {
    DetectorName.FINGERPRINT: DecisionBy.FINGERPRINT,
    DetectorName.STATIC_CHECKS: DecisionBy.STATIC_CHECKS,
    DetectorName.REDACT: DecisionBy.REDACT,
    DetectorName.POLICY: DecisionBy.POLICY,
}

#: 审计里给「没有 method 可用」的报文兜底的 event 名。
_EVENT_RESPONSE = "response"
_EVENT_UNKNOWN = "unknown"

#: 上游崩溃时那条审计记录的 event 名（不是 MCP method，是网关自己的事件）。
_EVENT_UPSTREAM_CRASH = "upstream/crash"

#: 审计写盘失败时给模型看的文案（SPEC §5 第五行）。
_TEXT_AUDIT_UNAVAILABLE = "mcp-guarder: audit unavailable"


# ────────────────────────────────────────────────────────────────────────────
# JSON-RPC 行处理
# ────────────────────────────────────────────────────────────────────────────


def parse_line(raw: bytes) -> JsonObj | None:
    """把一行字节解析成 JSON 对象。

    :return: 解析成功且是 dict 时返回它；空行返回 None（跳过，不算错）。
    :raises ValueError: 非法 JSON 或 JSON 不是 object。调用方决定怎么处置：
        来自**上游**的非 JSON 行 → :class:`~mcp_guarder.errors.UpstreamCrash`（整体退出，SPEC §5 末行）；
        来自**客户端**的非 JSON 行 → 记 guard.log 后原样转给上游（不是我们该管的，
        让真 server 自己去报协议错，代理不擅自造 error 响应）。
    """
    if not raw.strip():
        return None
    try:
        message = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:  # 非 UTF-8 一律当协议错
        raise ValueError(f"line is not valid UTF-8: {exc}") from exc
    if not isinstance(message, dict):
        raise ValueError(f"JSON-RPC line must be an object, got {type(message).__name__}")
    return message


def classify_message(message: JsonObj) -> MessageKind:
    """按 ``id`` / ``method`` / ``result`` / ``error`` 判定报文形态。判不出来一律 UNKNOWN → passthrough。"""
    has_method = isinstance(message.get("method"), str)
    has_id = "id" in message
    if has_method:
        return MessageKind.REQUEST if has_id else MessageKind.NOTIFICATION
    if has_id and ("result" in message or "error" in message):
        return MessageKind.RESPONSE
    return MessageKind.UNKNOWN


def message_method(message: JsonObj) -> str | None:
    """取 ``method``；不是字符串就当没有。"""
    method = message.get("method")
    return method if isinstance(method, str) else None


def message_id(message: JsonObj) -> int | str | None:
    """取 ``id``。JSON-RPC 允许 int / str / null，**不要强转成 int**。"""
    rpc_id = message.get("id")
    if isinstance(rpc_id, bool):  # bool 是 int 的子类，但不是合法 id
        return None
    if isinstance(rpc_id, (int, str)):
        return rpc_id
    return None


def extract_tool_use_id(message: JsonObj) -> str | None:
    """从 ``params._meta`` 里抄 ``claudecode/toolUseId``（SPEC §6）。

    拿不到返回 None —— 只有真客户端会带这个键，``replay.py`` 之类的探针不带。
    """
    params = message.get("params")
    if not isinstance(params, Mapping):
        return None
    meta = params.get("_meta")
    if not isinstance(meta, Mapping):
        return None
    value = meta.get(TOOL_USE_ID_META_KEY)
    return value if isinstance(value, str) else None


def build_tool_error_response(rpc_id: int | str | None, text: str) -> JsonObj:
    """拼一条「被网关拒绝」的响应。**这是全项目唯一的拒绝形态**（SPEC §5 硬规矩）::

        {"jsonrpc": "2.0", "id": <rpc_id>,
         "result": {"content": [{"type": "text", "text": text}], "isError": true}}

    绝不用 JSON-RPC ``error`` —— 那个语义是「协议坏了不太可能恢复」，
    被策略挡住属于 tool execution error，模型应该知道是策略挡的而不是工具坏了。
    """
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": rpc_id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": True,
        },
    }


def serialize_line(message: JsonObj) -> bytes:
    """序列化一条**被改写过**的报文。

    ``json.dumps(message, ensure_ascii=False, separators=(",", ":"))`` + ``b"\\n"``。
    ``ensure_ascii=False`` 是有意的：保持 UTF-8 原貌，别把上游的中文转成 ``\\uXXXX``。
    没被改写的报文**不走这里**，直接回写原始字节（见 :class:`OutgoingLine`）。
    """
    text = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    return text.encode("utf-8") + b"\n"


def tool_name_of(tool: Any) -> str | None:
    """取一个 tool 条目的 ``name``；不是非空字符串就返回 None（= **匿名 tool**）。

    匿名 tool 是个真实的攻击面：``tools/list`` 里的 description 在任何用户同意前
    就进了模型上下文（SPEC §2 T1），有没有 ``name`` 并不影响这一点。
    """
    if isinstance(tool, Mapping):
        name = tool.get("name")
        if isinstance(name, str) and name:
            return name
    return None


def select_dropped_indices(tools: Sequence[Any], drop: Sequence[str]) -> list[int]:
    """把「要剥离的 tool 名」翻译成 ``tools`` 里的下标。

    **为什么不能只按名字比**：没有 ``name`` 的 tool 在 static_checks 那边被记成
    :data:`~mcp_guarder.static_checks.UNNAMED_TOOL`（``"<unnamed>"``），
    按名字剥离会一个都剥不掉 —— 投毒描述照样进模型上下文。
    这里的规则是：``drop`` 里出现 ``"<unnamed>"`` 就把**所有**匿名 tool 一起剥掉
    （宁可多剥，不可漏放）。
    """
    dropped = set(drop)
    drop_unnamed = static_mod.UNNAMED_TOOL in dropped
    indices: list[int] = []
    for index, tool in enumerate(tools):
        name = tool_name_of(tool)
        if name is None:
            if drop_unnamed:
                indices.append(index)
        elif name in dropped:
            indices.append(index)
    return indices


def strip_tools_at(response: JsonObj, indices: Sequence[int]) -> JsonObj:
    """按**下标**从 ``tools/list`` 响应里剥掉 tool，返回新报文（写时复制）。

    - 一个都不剩 → ``result.tools`` 是空列表（SPEC §5：「一个都不剩就返空列表」），
      **不要删掉 ``tools`` 键**，也不要返 error。
    - ``result`` 里的其它键（``nextCursor``、``_meta`` 等）原样保留。
    """
    result = response.get("result")
    if not isinstance(result, dict):
        return response
    tools = result.get("tools")
    if not isinstance(tools, list):
        return response

    dropped = set(indices)
    if not dropped:
        return response

    kept = [tool for index, tool in enumerate(tools) if index not in dropped]
    new_result = dict(result)
    new_result["tools"] = kept
    new_message = dict(response)
    new_message["result"] = new_result
    return new_message


def strip_tools(response: JsonObj, drop: Sequence[str]) -> JsonObj:
    """按**名字**从 ``tools/list`` 响应里剥掉 tool（:func:`strip_tools_at` 的薄封装）。

    ``drop`` 里含 ``"<unnamed>"`` 时，所有匿名 tool 一并剥掉（见
    :func:`select_dropped_indices`）。
    """
    result = response.get("result")
    if not isinstance(result, dict):
        return response
    tools = result.get("tools")
    if not isinstance(tools, list):
        return response
    return strip_tools_at(response, select_dropped_indices(tools, drop))


def extract_tools(response: JsonObj) -> list[JsonObj]:
    """从 ``tools/list`` 响应里取 ``result.tools``；形态不对就返空列表（然后什么都不做，原样转发）。"""
    result = response.get("result")
    if not isinstance(result, dict):
        return []
    tools = result.get("tools")
    if not isinstance(tools, list):
        return []
    return list(tools)


# ────────────────────────────────────────────────────────────────────────────
# id 记账
# ────────────────────────────────────────────────────────────────────────────


class IdLedger:
    """``id → method`` 记账（SPEC §3 第②步）。

    为什么必须记：响应报文里**没有 method**，只有 id。想知道回来的这条是不是
    ``tools/list`` 的响应，只能靠请求时记下来。两个方向各一本账（客户端发的请求
    和 server 反向发的请求，id 空间是各自独立的）。
    """

    def __init__(self) -> None:
        self._client: dict[int | str, str] = {}
        self._server: dict[int | str, str] = {}
        self._lock = threading.Lock()
        self._next_guard_id = GUARD_REQUEST_ID_START

    def record_client_request(self, rpc_id: int | str, method: str) -> None:
        """客户端 → server 的请求记一笔。"""
        with self._lock:
            self._client[rpc_id] = method

    def record_server_request(self, rpc_id: int | str, method: str) -> None:
        """server → 客户端的反向请求（``roots/list`` / ``sampling/createMessage`` /
        ``elicitation/create``）也要记，虽然 v1 全都原样透传。"""
        with self._lock:
            self._server[rpc_id] = method

    def take_client_request(self, rpc_id: int | str) -> str | None:
        """拿到上游响应时，把对应的 method 取出来并**从账上销掉**。未知 id 返回 None。"""
        with self._lock:
            return self._client.pop(rpc_id, None)

    def take_server_request(self, rpc_id: int | str) -> str | None:
        with self._lock:
            return self._server.pop(rpc_id, None)

    def next_guard_id(self) -> int:
        """分配代理自己发起请求用的 id：从
        :data:`~mcp_guarder.types.GUARD_REQUEST_ID_START` 开始递减的负数（SPEC §3）。

        v1 没有任何自发请求（``ask`` 走降级不做 elicitation），这个方法暂时没人调，
        但接口先留着，免得以后有人图省事去借客户端的 id 空间。
        """
        with self._lock:
            rpc_id = self._next_guard_id
            self._next_guard_id -= 1
            return rpc_id


# ────────────────────────────────────────────────────────────────────────────
# 代理主体
# ────────────────────────────────────────────────────────────────────────────


class Proxy:
    """一个 :class:`Proxy` 实例包一个 MCP server 子进程，跑完一整个会话。

    线程模型（**选最简单可靠的那种：两个阻塞式泵**）：
    - 主线程：起子进程、起泵 A、**自己跑泵 B**、收尾。
    - 泵 A（client→upstream，daemon 线程）：读 ``sys.stdin.buffer``，写子进程 stdin。
      设成 daemon 是因为它可能永远阻塞在客户端 stdin 上 —— 上游先死的时候，
      主线程不该被它拖住（进程退出时它自然消失）。
    - 泵 B（upstream→client，跑在主线程）：读子进程 stdout，写 ``sys.stdout.buffer``。
      它一结束就代表会话结束，主线程顺势收尾，不需要额外的同步原语。
    - 子进程的 **stderr 直接继承父进程的 stderr**（``stderr=None``），
      零拷贝原样透传给客户端，我们不插手（SPEC §3 架构图右下角）。

    共享状态：:class:`IdLedger` 和 :class:`~mcp_guarder.audit.AuditLogger` 自带锁；
    两个方向的写出各有一把锁（stdout / 子进程 stdin），保证不会把一行撕成两半。
    """

    def __init__(
        self,
        config: GuarderConfig,
        command: Sequence[str],
        *,
        audit: AuditLogger,
        log: GuardLog,
        fingerprints: FingerprintStore,
        stdin: BinaryIO | None = None,
        stdout: BinaryIO | None = None,
    ) -> None:
        """:param command: ``--`` 之后的完整命令行，**原样传给子进程，不做 shell 拼接**。
        :param stdin/stdout: 默认取 ``sys.stdin.buffer`` / ``sys.stdout.buffer``；
            测试里注入 ``io.BytesIO`` 用。
        """
        self._config = config
        self._command = tuple(str(c) for c in command)
        self._audit = audit
        self._log = log
        self._fingerprints = fingerprints
        self._stdin: BinaryIO = stdin if stdin is not None else sys.stdin.buffer
        self._stdout: BinaryIO = stdout if stdout is not None else sys.stdout.buffer

        self._server_name = config.server.name
        self._ledger = IdLedger()
        self._proc: subprocess.Popen[bytes] | None = None

        self._stdout_lock = threading.Lock()
        self._upstream_lock = threading.Lock()
        #: 已经在收尾（客户端关了 stdin / 我们主动终止上游）—— 此时上游被信号打死不算崩溃。
        self._closing = threading.Event()
        self._exit_code = EXIT_OK
        #: rpc_id → (tool_name, tool_use_id, t0)，给响应侧算 upstream 延迟和补 tool 名。
        self._pending: dict[int | str, tuple[str | None, str | None, float]] = {}
        self._pending_lock = threading.Lock()
        self._reader_thread: threading.Thread | None = None
        #: 回流方向的 deny_call 降级提示只打一次。
        self._inbound_deny_call_warned = False
        #: 子进程独立进程组的 pgid（POSIX，``start_new_session=True`` 之后才有）。
        #: 收尾时靠它把**孙子进程**一起收掉，见 :meth:`_kill_process_group`。
        self._pgid: int | None = None

    # ── 生命周期 ────────────────────────────────────────────────────────

    @property
    def reader_alive(self) -> bool:
        """泵 A 是不是还阻塞在客户端 stdin 上（:func:`run_proxy` 据此决定要不要硬退出）。"""
        return self._reader_thread is not None and self._reader_thread.is_alive()

    def run(self) -> int:
        """跑完整个会话，返回进程退出码。

        流程：启动子进程 → 打启动横幅（完整命令行进 guard.log + stderr，SPEC §2 T8）
        → 起两个泵 → join → 收尾。

        退出码：正常结束 0；上游崩溃 :data:`~mcp_guarder.types.EXIT_UPSTREAM_CRASH`；
        审计启动就不可用 :data:`~mcp_guarder.types.EXIT_AUDIT_UNAVAILABLE`。

        **整个函数体必须被 try/except 包住**：任何未预料的异常都写 guard.log 后
        安静退出，绝不能把 traceback 吐到 stdout。
        """
        try:
            try:
                self._spawn_upstream()
            except OSError as exc:
                self._log.exception(f"cannot start upstream {self._command}", exc)
                return EXIT_UPSTREAM_CRASH

            self._log.banner(
                server=self._server_name,
                command=self._command,
                config_path=self._config.source_path,
            )

            pump_a = threading.Thread(
                target=self._pump_client_to_upstream,
                name="mcp-guarder-client-to-upstream",
                daemon=True,
            )
            self._reader_thread = pump_a
            pump_a.start()
            # 泵 B 跑在主线程：它一结束会话就结束。
            self._pump_upstream_to_client()
            self._terminate_upstream()
            # 给泵 A 一点时间把手上的活干完（它是 daemon，超时也不会拖住退出）。
            pump_a.join(timeout=_READER_JOIN_SECONDS)
            return self._exit_code
        except BaseException as exc:  # noqa: BLE001 —— 顶层兜底，绝不让栈冲到 stdout
            try:
                self._log.exception("proxy loop crashed", exc)
            except Exception:  # noqa: BLE001 - 日志都写不了也不能再抛
                pass
            try:
                self._terminate_upstream()
            except Exception:  # noqa: BLE001
                pass
            if isinstance(exc, GuarderError):
                return exc.exit_code
            return EXIT_GENERIC_ERROR

    def _spawn_upstream(self) -> None:
        """起子进程。

        - ``env`` **完整继承**（含 ``CLAUDE_PROJECT_DIR``），不做任何过滤（SPEC §3）。
        - ``stdin=PIPE, stdout=PIPE, stderr=None``（stderr 继承 = 原样透传）。
        - POSIX 上用 ``start_new_session=True`` 建独立进程组，方便整组 kill。
        - ``bufsize=0``（二进制无缓冲），避免大报文卡在缓冲区里。
        """
        kwargs: dict[str, Any] = {}
        if os.name == "posix":
            kwargs["start_new_session"] = True
        self._proc = subprocess.Popen(  # noqa: S603 - command 来自用户配置，这就是本工具的形态
            list(self._command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # 继承父进程 stderr = 原样透传给客户端
            bufsize=0,
            env=os.environ.copy(),
            close_fds=True,
            **kwargs,
        )
        # 记下子进程的进程组：收尾时要靠它把孙子进程一起收掉（铁律 7）。
        # 只有当它确实**不是**我们自己那个组的时候才记 —— 免得给自己发信号。
        if os.name == "posix":
            try:
                pgid = os.getpgid(self._proc.pid)
                if pgid != os.getpgid(0):
                    self._pgid = pgid
            except OSError:
                self._pgid = None
        # 审计里的 upstream.pid 只有拿到子进程之后才知道（SPEC §6）。
        self._audit.set_upstream(UpstreamInfo(pid=self._proc.pid, cmd=self._command))

    def _terminate_upstream(self) -> None:
        """终止子进程树（铁律 7）。

        客户端关 stdin → 先关子进程 stdin 让它自己退 → 等
        :data:`TERMINATE_GRACE_SECONDS` → 还活着就 ``killpg(SIGTERM)`` →
        再等一小会儿 → ``killpg(SIGKILL)``。**退出后 ``pgrep -P <guard pid>`` 必须为空**
        （SPEC §7 M1-5）。

        子进程本体走完之后**一定要再扫一遍它的进程组**（:meth:`_kill_process_group`）：
        很多 server 自己还会 fork 帮手进程，那些孙子进程继承着子进程的 stdout 写端 ——
        不收掉的话它们既是孤儿，又会让泵 B 永远读不到 EOF，整个网关跟着挂住。
        """
        self._closing.set()
        proc = self._proc
        if proc is None:
            return
        try:
            self._terminate_proc(proc)
        finally:
            self._kill_process_group()

    def _terminate_proc(self, proc: subprocess.Popen[bytes]) -> None:
        """只负责让子进程**本体**死掉并回收句柄（进程组由调用方另外扫）。"""
        if proc.stdin is not None:
            try:
                proc.stdin.close()
            except OSError:
                pass
        if proc.poll() is not None:
            self._reap(proc)
            return
        try:
            proc.wait(timeout=TERMINATE_GRACE_SECONDS)
            self._reap(proc)
            return
        except subprocess.TimeoutExpired:
            pass

        self._signal_group(proc, signal.SIGTERM)
        try:
            proc.wait(timeout=_KILL_GRACE_SECONDS)
            self._reap(proc)
            return
        except subprocess.TimeoutExpired:
            pass

        self._signal_group(proc, signal.SIGKILL)
        try:
            proc.wait(timeout=_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            self._log.warn(f"upstream pid={proc.pid} survived SIGKILL")
        self._reap(proc)

    def _kill_process_group(self) -> None:
        """子进程本体没了之后，把它那个独立进程组里**剩下的孙子进程**扫干净。

        安全性：``_spawn_upstream`` 用 ``start_new_session=True`` 给子进程开了独立
        session/pgid，而且只有确认 ``pgid != 我们自己的 pgid`` 才会记下来 ——
        所以这里发的信号打不到网关自己，也打不到客户端。

        先用 ``killpg(pgid, 0)`` 探一下组还在不在：正常情况下（server 没 fork 帮手）
        组早就空了，直接返回，不给收尾加任何延迟。
        """
        pgid = self._pgid
        if pgid is None or os.name != "posix":
            return
        if not _process_group_alive(pgid):
            return
        self._log.warn(f"upstream process group pgid={pgid} still has members; killing it")
        try:
            os.killpg(pgid, signal.SIGTERM)
        except OSError:
            return
        deadline = time.monotonic() + _KILL_GRACE_SECONDS
        while time.monotonic() < deadline:
            if not _process_group_alive(pgid):
                return
            time.sleep(_GROUP_POLL_SECONDS)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass

    def _signal_group(self, proc: subprocess.Popen[bytes], sig: int) -> None:
        """给整个子进程组发信号；拿不到进程组就退化成只打子进程本身。"""
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), sig)
                return
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.send_signal(sig)
        except (ProcessLookupError, OSError, ValueError):
            pass

    def _reap(self, proc: subprocess.Popen[bytes]) -> None:
        """关掉写端句柄，别留 fd 泄漏。

        **故意不关 stdout**：泵 B 可能正阻塞在上面读，从别的线程把它关掉会让那次
        ``readline()`` 抛 ``ValueError: I/O operation on closed file``。上游一死读端自然 EOF，
        真正的 fd 回收交给 Popen 的 finalizer / 进程退出。
        """
        if proc.stdin is not None:
            try:
                proc.stdin.close()
            except OSError:
                pass

    # ── 两个泵 ──────────────────────────────────────────────────────────

    def _pump_client_to_upstream(self) -> None:
        """泵 A：逐行读客户端 stdin → :meth:`handle_client_line` → 写子进程 stdin。

        读到 EOF（客户端关了 stdin）→ 调 :meth:`_terminate_upstream` 收尾。
        用 ``stream.readline()``，**不设固定 buffer 上限**（铁律 6）。
        """
        try:
            while True:
                raw = self._stdin.readline()
                if not raw:
                    break  # 客户端关了 stdin
                line = raw.rstrip(b"\r\n")
                routed = self.handle_client_line(line)
                if routed.client is not None:
                    self._write_client(routed.client)
                if routed.upstream is not None:
                    self._write_upstream(routed.upstream)
        except UpstreamCrash as exc:
            self._note_upstream_crash(exc)
        except BaseException as exc:  # noqa: BLE001 —— 泵里的异常绝不许冒到 stdout
            self._log.exception("client->upstream pump crashed", exc)
            self._exit_code = self._exit_code or EXIT_GENERIC_ERROR
        finally:
            try:
                self._terminate_upstream()
            except Exception:  # noqa: BLE001
                pass

    def _pump_upstream_to_client(self) -> None:
        """泵 B：逐行读子进程 stdout → :meth:`handle_upstream_line` → 写客户端 stdout。

        - 上游 stdout 出现**非 JSON 行** → 记审计 + guard.log 后**整体退出**
          （:class:`~mcp_guarder.errors.UpstreamCrash`，SPEC §5 末行）。绝不能把这行
          原样转给客户端，否则污染 stdout。
        - 上游 EOF / 进程死了 → 同样按 ``on_upstream_crash: fail`` 整体退出，不静默降级。
        """
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        # ``bufsize=0`` 给回来的是裸 FileIO，它的 readline() 是**一个字节一个 read 系统调用**——
        # 10MB 单行能读到天荒地老（SPEC §7 那条压力用例就会因此撞上收尾宽限期）。
        # 这里套一层 BufferedReader：按块读、按行切，依然**不设固定行长上限**（铁律 6）。
        stream: Any = proc.stdout
        if not isinstance(stream, io.BufferedIOBase):
            stream = io.BufferedReader(stream)
        try:
            while True:
                try:
                    raw = stream.readline()
                except ValueError:
                    break  # 句柄被收尾流程关掉了，按 EOF 处理
                if not raw:
                    break  # 上游 EOF
                line = raw.rstrip(b"\r\n")
                routed = self.handle_upstream_line(line)
                if routed.client is not None:
                    self._write_client(routed.client)
                if routed.upstream is not None:
                    self._write_upstream(routed.upstream)
        except UpstreamCrash as exc:
            self._note_upstream_crash(exc)
            return
        except BaseException as exc:  # noqa: BLE001
            self._log.exception("upstream->client pump crashed", exc)
            self._exit_code = self._exit_code or EXIT_GENERIC_ERROR
            return

        # 走到这儿说明上游把 stdout 关了。
        if self._closing.is_set():
            return  # 是我们自己在收尾，不算崩溃
        returncode = proc.poll()
        if returncode is None:
            try:
                returncode = proc.wait(timeout=TERMINATE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                returncode = None
        if returncode not in (None, 0):
            self._note_upstream_crash(UpstreamCrash.exited(returncode))

    def _note_upstream_crash(self, exc: UpstreamCrash) -> None:
        """记审计 + guard.log，并把退出码定为 :data:`~mcp_guarder.types.EXIT_UPSTREAM_CRASH`。

        对应 ``defaults.on_upstream_crash: fail`` —— 不静默降级（SPEC §5 末行）。
        """
        if self._exit_code == EXIT_UPSTREAM_CRASH:
            return  # 已经记过一次了
        self._exit_code = EXIT_UPSTREAM_CRASH
        self._log.error(f"UPSTREAM CRASH {exc.message}")
        self._safe_audit(
            event=_EVENT_UPSTREAM_CRASH,
            direction=Direction.SERVER_TO_CLIENT,
            decision=Decision.DENY,
            decision_by=DecisionBy.DEFAULT,
            reason=exc.message,
        )
        self._closing.set()

    # ── 单行处理（纯函数式，方便单测直接打） ────────────────────────────

    def handle_client_line(self, raw: bytes) -> Routed:
        """处理一行来自客户端的报文（client→server 方向）。

        分支见 SPEC §5 那张表：解析失败原样转发；非 ``tools/call`` 记账 + 元数据审计 +
        原样转发；``tools/call`` 走「审计降级检查 → 出站脱敏 → 权限门 → 审计 → 放行/拒绝」。

        **deny 时 ``upstream`` 必须是 None** —— 一条被拒的调用绝不能真的打到上游。
        """
        try:
            message = parse_line(raw)
        except ValueError as exc:
            # 客户端自己发了坏报文：不是我们该管的，原样转给真 server 去报协议错。
            self._log.warn(f"client sent a non-JSON line, forwarding verbatim: {exc}")
            return Routed(upstream=OutgoingLine.verbatim(raw))
        if message is None:
            return Routed()  # 空行吞掉

        method = message_method(message)
        rpc_id = message_id(message)
        kind = classify_message(message)

        if method != METHOD_TOOLS_CALL:
            # ── 非深加工路径：记账 + metadata_only 审计 + 字节级原样转发 ──
            if kind is MessageKind.REQUEST and method is not None and rpc_id is not None:
                self._ledger.record_client_request(rpc_id, method)
                with self._pending_lock:
                    self._pending[rpc_id] = (None, None, time.monotonic())
            event = method
            if event is None and kind is MessageKind.RESPONSE and rpc_id is not None:
                # 客户端在回 server 的反向请求（roots/list 之类）。
                event = self._ledger.take_server_request(rpc_id) or _EVENT_RESPONSE
            self._safe_audit(
                event=event or _EVENT_UNKNOWN,
                direction=Direction.CLIENT_TO_SERVER,
                decision=Decision.PASSTHROUGH,
                decision_by=DecisionBy.DEFAULT,
                rpc_id=rpc_id,
                payload=message,
            )
            return Routed(upstream=OutgoingLine.verbatim(raw))

        return self._handle_tools_call_request(message, raw, rpc_id)

    def _handle_tools_call_request(
        self,
        message: JsonObj,
        raw: bytes,
        rpc_id: int | str | None,
    ) -> Routed:
        """``tools/call`` 请求的深加工：③ 出站脱敏 → ④ 权限门 → ⑨ 审计。"""
        t0 = time.monotonic()
        params = message.get("params")
        params_map: Mapping[str, Any] = params if isinstance(params, Mapping) else {}
        tool_name = params_map.get("name")
        tool_name = tool_name if isinstance(tool_name, str) else None
        tool_use_id = extract_tool_use_id(message)
        audit_id = audit_mod.new_audit_id()

        def deny(
            *,
            reason: str,
            decision_by: DecisionBy,
            text: str,
            rule_id: str | None = None,
            detectors: Sequence[DetectorOutcome] = (),
            payload: Any = None,
            redactions_outbound: Sequence[Any] = (),
        ) -> Routed:
            self._safe_audit(
                event=METHOD_TOOLS_CALL,
                direction=Direction.CLIENT_TO_SERVER,
                decision=Decision.DENY,
                decision_by=decision_by,
                rpc_id=rpc_id,
                tool=tool_name,
                tool_use_id=tool_use_id,
                rule_id=rule_id,
                reason=reason,
                detectors=detectors,
                redactions_outbound=redactions_outbound,
                payload=payload,
                audit_id=audit_id,
                latency_ms=LatencyMs(guard=_elapsed_ms(t0)),
            )
            return Routed(client=OutgoingLine.rewritten(build_tool_error_response(rpc_id, text)))

        # (a) 审计已降级 → 一律拒（SPEC §5 第五行）。
        if self._audit.degraded:
            return deny(
                reason="audit unavailable",
                decision_by=DecisionBy.DEFAULT,
                text=_TEXT_AUDIT_UNAVAILABLE,
                payload=None,
            )

        detectors: list[DetectorOutcome] = []
        try:
            # (b) ③ 出站脱敏。审计里存的必须是脱敏之后的报文（store_redacted_only）。
            redaction = redact_mod.redact_outbound(message, config=self._config.redact)
            detectors.append(redaction.outcome())
            redacted = redaction.message

            if redaction.deny:
                self._log.warn(
                    f"redact deny_call on outbound tools/call tool={tool_name} "
                    f"rules={','.join(c.rule_id for c in redaction.counts)}"
                )
                text = policy_mod.render_deny_text(
                    self._config.policy.deny_response.text,
                    reason="secret detected in arguments",
                    rule_id=None,
                    audit_id=audit_id,
                )
                return deny(
                    reason="secret detected in arguments",
                    decision_by=DecisionBy.REDACT,
                    text=text,
                    detectors=detectors,
                    payload=redacted,
                    redactions_outbound=redaction.counts,
                )

            # (c) ④ 权限门（默认拒绝）。SPEC §3 的编号是「先脱敏再过门」，
            #     所以 policy 看到的是脱敏后的 arguments。
            new_params = redacted.get("params")
            arguments = (
                new_params.get("arguments") if isinstance(new_params, Mapping) else None
            )
            decision = policy_mod.evaluate(
                tool_name or "",
                arguments if isinstance(arguments, Mapping) else None,
                config=self._config,
            )
            detectors.append(
                DetectorOutcome(
                    DetectorName.POLICY,
                    DetectorResult.MATCH if decision.rule_id else DetectorResult.CLEAN,
                )
            )
        except DetectorError as exc:
            # (d) 检测器故障 → deny 当前这条消息，异常栈只进 guard.log。
            self._log.exception(f"detector failure on tools/call tool={tool_name}", exc)
            detectors.append(DetectorOutcome(exc.detector, DetectorResult.ERROR))
            return deny(
                reason="detector failure",
                decision_by=_DETECTOR_TO_DECISION_BY.get(exc.detector, DecisionBy.DEFAULT),
                text=exc.model_text,
                detectors=detectors,
            )

        if decision.ask_downgraded:
            # TODO(SPEC §7 末尾 TODO(待验证))：ask 本来要借 elicitation/create，
            # v1 按 SPEC 给的降级方案办 —— 等价 deny + guard.log 提示手工改配置。
            self._log.warn(
                policy_mod.ask_downgrade_message(decision.rule_id or "-", tool_name or "-")
            )

        if not decision.allowed:
            text = policy_mod.render_deny_text(
                self._config.policy.deny_response.text,
                reason=decision.reason,
                rule_id=decision.rule_id,
                audit_id=audit_id,
            )
            return deny(
                reason=decision.reason,
                decision_by=decision.decision_by,
                text=text,
                rule_id=decision.rule_id,
                detectors=detectors,
                payload=redacted,
                redactions_outbound=redaction.counts,
            )

        # (e) 放行。有脱敏就发改写后的报文，没脱敏就原样字节转发。
        record = self._audit.build_record(
            event=METHOD_TOOLS_CALL,
            direction=Direction.CLIENT_TO_SERVER,
            decision=Decision.REWRITE if redaction.changed else Decision.ALLOW,
            decision_by=DecisionBy.REDACT if redaction.changed else decision.decision_by,
            rpc_id=rpc_id,
            tool=tool_name,
            tool_use_id=tool_use_id,
            rule_id=decision.rule_id,
            reason=decision.reason,
            detectors=detectors,
            redactions_outbound=redaction.counts,
            payload=redacted,
            audit_id=audit_id,
            latency_ms=LatencyMs(guard=_elapsed_ms(t0)),
        )
        try:
            self._audit.write(record)
        except AuditUnavailable as exc:
            # 审计写不了 → 这条也 deny（SPEC §5 第五行），后续 tools/call 由 degraded 挡。
            self._log.exception("audit write failed on tools/call", exc)
            return Routed(
                client=OutgoingLine.rewritten(
                    build_tool_error_response(rpc_id, _TEXT_AUDIT_UNAVAILABLE)
                )
            )

        if rpc_id is not None:
            self._ledger.record_client_request(rpc_id, METHOD_TOOLS_CALL)
            with self._pending_lock:
                self._pending[rpc_id] = (tool_name, tool_use_id, t0)

        line = (
            OutgoingLine.rewritten(redacted)
            if redaction.changed
            else OutgoingLine.verbatim(raw)
        )
        return Routed(upstream=line)

    def handle_upstream_line(self, raw: bytes) -> Routed:
        """处理一行来自上游的报文（server→client 方向）。

        分支：
        1. 解析失败 → :class:`~mcp_guarder.errors.UpstreamCrash`（整体退出）。
        2. 是响应且账本查出对应请求是 ``tools/list`` → :meth:`_handle_tools_list_response`。
        3. 是响应且对应请求是 ``tools/call`` → :meth:`_handle_tools_call_response`。
        4. 其余（含 server 反向请求、通知、未知 id 的响应）→ 记账 + 元数据审计 + 原样转发。
           **``notifications/tools/list_changed`` 也是原样转发** —— 客户端会因此重拉
           ``tools/list``，那次重拉自然会再过一遍指纹和静态检查，这正是我们抓 rug pull 的时机。
        """
        try:
            message = parse_line(raw)
        except ValueError as exc:
            raise UpstreamCrash.non_json_line(raw) from exc
        if message is None:
            return Routed()  # 空行吞掉，绝不往 stdout 写空行

        kind = classify_message(message)
        rpc_id = message_id(message)
        method = message_method(message)

        if kind is MessageKind.RESPONSE and rpc_id is not None:
            requested = self._ledger.take_client_request(rpc_id)
            if requested == METHOD_TOOLS_LIST:
                return self._handle_tools_list_response(message, raw)
            if requested == METHOD_TOOLS_CALL:
                return self._handle_tools_call_response(message, raw)
            event = requested or _EVENT_RESPONSE
        elif kind is MessageKind.REQUEST and method is not None and rpc_id is not None:
            # server → client 的反向请求（roots/list / sampling/createMessage /
            # elicitation/create）。v1 一律原样透传，只记一笔账。
            self._ledger.record_server_request(rpc_id, method)
            event = method
        else:
            event = method or _EVENT_UNKNOWN

        self._safe_audit(
            event=event,
            direction=Direction.SERVER_TO_CLIENT,
            decision=Decision.PASSTHROUGH,
            decision_by=DecisionBy.DEFAULT,
            rpc_id=rpc_id,
            payload=message,
            latency_ms=self._take_latency(rpc_id),
        )
        return Routed(client=OutgoingLine.verbatim(raw))

    def _handle_tools_list_response(self, message: JsonObj, raw: bytes) -> Routed:
        """``tools/list`` 响应的深加工（SPEC §5 第六行 / §7 M1-4 / M3-1）。

        顺序：⑥ 指纹 → ⑥ 静态检查 → 剥离命中的 tool → ⑨ 审计。
        检测器抛异常 → **deny 整条响应**（返回空 tools 列表）：宁可没工具，
        也不能把没检测过的描述放进模型上下文。
        """
        t0 = time.monotonic()
        latency = self._take_latency(message_id(message), guard_start=t0)
        rpc_id = message_id(message)
        tools = extract_tools(message)
        if not tools:
            self._safe_audit(
                event=METHOD_TOOLS_LIST,
                direction=Direction.SERVER_TO_CLIENT,
                decision=Decision.PASSTHROUGH,
                decision_by=DecisionBy.DEFAULT,
                rpc_id=rpc_id,
                payload=message,
                latency_ms=latency,
            )
            return Routed(client=OutgoingLine.verbatim(raw))

        detectors: list[DetectorOutcome] = []
        try:
            fp_report = fingerprint_mod.inspect_tools(
                tools,
                config=self._config.inspect.fingerprint,
                store=self._fingerprints,
                server=self._server_name,
                snapshot_dir=self._config.audit.snapshot_dir,
            )
            detectors.append(fp_report.outcome())
            for result in fp_report.results:
                if result.status is FingerprintStatus.FIRST_SEEN:
                    self._log.info(
                        f"FIRST SEEN {self._server_name}/{result.tool} "
                        f"{fingerprint_mod.short_digest(result.new_digest)}…"
                    )
                elif result.is_rug_pull:
                    self._log.warn(
                        fingerprint_mod.rug_pull_log_line(
                            self._server_name,
                            result.tool,
                            result.old_digest or "",
                            result.new_digest,
                        )
                    )

            sc_report = static_mod.scan_tools(
                tools, config=self._config.inspect.static_checks
            )
            detectors.append(sc_report.outcome())
            for tool_name in sc_report.hit_tools:
                self._log.warn(
                    static_mod.static_hit_log_line(
                        self._server_name, tool_name, sc_report.rule_ids_for(tool_name)
                    )
                )
            for hit in sc_report.hits:
                # excerpt 已经过 visible_escape：ANSI 存成字面量 ``\x1b[``，
                # 免得 cat guard.log 的时候终端被二次攻击（SPEC §7 M3-3）。
                self._log.warn(
                    f"static_checks hit {self._server_name}/{hit.tool} "
                    f"{hit.field_path} {hit.rule_id}: {hit.excerpt}"
                )
        except DetectorError as exc:
            # fail-closed：整条 tools/list 的工具全部剥光，返回空列表。
            self._log.exception("detector failure on tools/list", exc)
            detectors.append(DetectorOutcome(exc.detector, DetectorResult.ERROR))
            # 按**下标**全剥：按名字剥只认得有 name 的条目，会把匿名 tool
            # （以及形态不对的条目）漏在响应里 —— 而那正是检测器炸掉的常见原因。
            stripped = strip_tools_at(message, range(len(tools)))
            self._safe_audit(
                event=METHOD_TOOLS_LIST,
                direction=Direction.SERVER_TO_CLIENT,
                decision=Decision.DENY,
                decision_by=_DETECTOR_TO_DECISION_BY.get(exc.detector, DecisionBy.DEFAULT),
                rpc_id=rpc_id,
                reason="detector failure",
                detectors=detectors,
                payload=message,
                latency_ms=latency,
            )
            return Routed(client=OutgoingLine.rewritten(stripped))

        drop: list[str] = list(fp_report.changed_tools)
        static_dropped: list[str] = []
        if self._config.inspect.static_checks.on_hit is StaticCheckAction.DENY:
            static_dropped = [t for t in sc_report.hit_tools if t not in set(drop)]
            drop.extend(static_dropped)

        if not drop:
            self._safe_audit(
                event=METHOD_TOOLS_LIST,
                direction=Direction.SERVER_TO_CLIENT,
                decision=Decision.ALLOW,
                decision_by=DecisionBy.DEFAULT,
                rpc_id=rpc_id,
                detectors=detectors,
                payload=message,
                latency_ms=latency,
            )
            return Routed(client=OutgoingLine.verbatim(raw))

        stripped = strip_tools(message, drop)
        decision_by = (
            DecisionBy.FINGERPRINT if fp_report.changed_tools else DecisionBy.STATIC_CHECKS
        )
        self._log.warn(
            f"stripped {len(drop)} tool(s) from tools/list: {','.join(drop)}"
        )
        self._safe_audit(
            event=METHOD_TOOLS_LIST,
            direction=Direction.SERVER_TO_CLIENT,
            decision=Decision.DENY,
            decision_by=decision_by,
            rpc_id=rpc_id,
            reason=_strip_reason(drop, sc_report.hits),
            detectors=detectors,
            payload=message,
            latency_ms=latency,
        )
        return Routed(client=OutgoingLine.rewritten(stripped))

    def _handle_tools_call_response(self, message: JsonObj, raw: bytes) -> Routed:
        """``tools/call`` 响应的深加工：⑦ 回流脱敏（SPEC §2 T4/T5/T7 / §7 M2-3）。"""
        t0 = time.monotonic()
        rpc_id = message_id(message)
        tool_name, tool_use_id, latency = self._take_call_context(rpc_id, guard_start=t0)

        try:
            redaction = redact_mod.redact_inbound(message, config=self._config.redact)
        except DetectorError as exc:
            self._log.exception("detector failure on tools/call response", exc)
            self._safe_audit(
                event=METHOD_TOOLS_CALL,
                direction=Direction.SERVER_TO_CLIENT,
                decision=Decision.DENY,
                decision_by=_DETECTOR_TO_DECISION_BY.get(exc.detector, DecisionBy.DEFAULT),
                rpc_id=rpc_id,
                tool=tool_name,
                tool_use_id=tool_use_id,
                reason="detector failure",
                detectors=[DetectorOutcome(exc.detector, DetectorResult.ERROR)],
                latency_ms=latency,
            )
            return Routed(
                client=OutgoingLine.rewritten(
                    build_tool_error_response(rpc_id, exc.model_text)
                )
            )

        if (
            redaction.changed
            and self._config.redact.action is RedactAction.DENY_CALL
            and not self._inbound_deny_call_warned
        ):
            self._inbound_deny_call_warned = True
            self._log.warn(redact_mod.INBOUND_DENY_CALL_DOWNGRADE)

        changed = redaction.changed
        record = self._audit.build_record(
            event=METHOD_TOOLS_CALL,
            direction=Direction.SERVER_TO_CLIENT,
            decision=Decision.REWRITE if changed else Decision.PASSTHROUGH,
            decision_by=DecisionBy.REDACT if changed else DecisionBy.DEFAULT,
            rpc_id=rpc_id,
            tool=tool_name,
            tool_use_id=tool_use_id,
            detectors=[redaction.outcome()],
            redactions_inbound=redaction.counts,
            # 铁律 9：落盘的必须是脱敏之后的报文。
            payload=redaction.message,
            latency_ms=latency,
        )
        try:
            self._audit.write(record)
        except AuditUnavailable as exc:
            self._log.exception("audit write failed on tools/call response", exc)
            return Routed(
                client=OutgoingLine.rewritten(
                    build_tool_error_response(rpc_id, _TEXT_AUDIT_UNAVAILABLE)
                )
            )

        line = (
            OutgoingLine.rewritten(redaction.message)
            if changed
            else OutgoingLine.verbatim(raw)
        )
        return Routed(client=line)

    # ── 审计小工具 ──────────────────────────────────────────────────────

    def _safe_audit(self, **kwargs: Any) -> bool:
        """记一条审计。写失败**不抛**（返回 False）—— 调用方是那些「审计挂了也要继续
        原样转发」的路径（非 tools/call 报文，SPEC §5 的降级语义见 errors.AuditUnavailable）。
        """
        try:
            record: AuditRecord = self._audit.build_record(**kwargs)
            self._audit.write(record)
            return True
        except AuditUnavailable as exc:
            self._log.exception("audit write failed", exc)
            return False
        except Exception as exc:  # noqa: BLE001 —— 记账绝不能把转发主干带崩
            self._log.exception("audit record failed", exc)
            return False

    def _take_latency(
        self, rpc_id: int | str | None, *, guard_start: float | None = None
    ) -> LatencyMs:
        """算 ``latency_ms``：``upstream`` 取请求发出到响应回来的时间。"""
        upstream_ms: int | None = None
        if rpc_id is not None:
            with self._pending_lock:
                pending = self._pending.pop(rpc_id, None)
            if pending is not None:
                upstream_ms = _elapsed_ms(pending[2])
        guard_ms = _elapsed_ms(guard_start) if guard_start is not None else None
        return LatencyMs(guard=guard_ms, upstream=upstream_ms)

    def _take_call_context(
        self, rpc_id: int | str | None, *, guard_start: float
    ) -> tuple[str | None, str | None, LatencyMs]:
        """响应侧把请求时记下的 ``(tool, tool_use_id, 起始时间)`` 取回来。"""
        tool_name: str | None = None
        tool_use_id: str | None = None
        upstream_ms: int | None = None
        if rpc_id is not None:
            with self._pending_lock:
                pending = self._pending.pop(rpc_id, None)
            if pending is not None:
                tool_name, tool_use_id, started = pending
                upstream_ms = _elapsed_ms(started)
        return tool_name, tool_use_id, LatencyMs(
            guard=_elapsed_ms(guard_start), upstream=upstream_ms
        )

    # ── IO ──────────────────────────────────────────────────────────────

    def _write_client(self, line: OutgoingLine) -> None:
        """**全项目唯一允许写 stdout 的地方**（铁律 1）。写完立刻 flush。"""
        data = serialize_line(line.message) if line.is_rewritten else (line.raw or b"") + b"\n"
        with self._stdout_lock:
            try:
                self._stdout.write(data)
                self._stdout.flush()
            except BrokenPipeError:
                # 客户端先走了：安静收尾，别往已经关掉的 stdout 上再喊。
                self._closing.set()
            except (OSError, ValueError) as exc:
                self._log.exception("cannot write to client stdout", exc)
                self._closing.set()

    def _write_upstream(self, line: OutgoingLine) -> None:
        """写子进程 stdin。子进程已经死了（BrokenPipe）→ 转
        :class:`~mcp_guarder.errors.UpstreamCrash`。"""
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise UpstreamCrash("upstream stdin is not available")
        data = serialize_line(line.message) if line.is_rewritten else (line.raw or b"") + b"\n"
        with self._upstream_lock:
            try:
                proc.stdin.write(data)
                proc.stdin.flush()
            except (BrokenPipeError, ValueError) as exc:
                raise UpstreamCrash(f"upstream stdin is closed: {exc}", cause=exc) from exc
            except OSError as exc:
                raise UpstreamCrash(f"cannot write to upstream stdin: {exc}", cause=exc) from exc


def _elapsed_ms(start: float) -> int:
    """单调时钟差值 → 毫秒整数。"""
    return int((time.monotonic() - start) * 1000)


def _process_group_alive(pgid: int) -> bool:
    """进程组里还有活着的成员吗？用 ``killpg(pgid, 0)`` 探（不真发信号）。"""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # 组还在，只是里面有我们杀不动的成员
    except OSError:
        return False
    return True


#: 一条审计 ``reason`` 里最多带几条静态命中明细（再多就没人看了，也怕把行撑爆）。
_MAX_REASON_HITS = 8


def _strip_reason(drop: Sequence[str], hits: Sequence[Any]) -> str:
    """拼 ``tools/list`` 被剥离时的审计 ``reason``。

    带上静态检查的命中明细（``<tool>.<field>:<rule_id>:<excerpt>``）——
    ``excerpt`` 在 static_checks 那边已经过 ``visible_escape``，所以 ANSI 进审计
    是可见的 ``\\x1b[`` 字面量而不是真控制字符（SPEC §7 M3-3）。
    """
    reason = f"stripped tools: {','.join(drop)}"
    if not hits:
        return reason
    details = "; ".join(
        f"{h.tool}.{h.field_path}:{h.rule_id}:{h.excerpt}" for h in hits[:_MAX_REASON_HITS]
    )
    return f"{reason} | static_checks: {details}"


# ────────────────────────────────────────────────────────────────────────────
# 入口
# ────────────────────────────────────────────────────────────────────────────


def run_proxy(
    config: GuarderConfig,
    command: Sequence[str],
    *,
    config_path: Path | None = None,
) -> int:
    """CLI 调的顶层入口：建 GuardLog / AuditLogger / FingerprintStore → 跑 :class:`Proxy` → 收尾。

    这一层负责把**启动期**的失败（审计文件建不了、指纹库打不开）转成非零退出码 +
    stderr 提示，而不是带病开跑。

    最后那一下 :func:`_hard_exit` 不是偷懒：上游先死的时候，泵 A 还阻塞在客户端 stdin 上
    （那个 read 没法从外面打断）。让解释器正常 finalize 的话，CPython 会因为 daemon 线程
    还攥着 ``<stdin>`` 的 buffer 锁而 ``Fatal Python error: _enter_buffered_busy`` → SIGABRT，
    退出码变成 -6，还会往 stderr 吐一段 fatal error。所有资源都已经 close 干净之后再
    ``os._exit`` 是这里唯一干净的收场方式。
    """
    log = GuardLog(config.audit.log_file)
    audit = AuditLogger(
        config.audit,
        server=config.server.name,
        upstream=UpstreamInfo(cmd=tuple(str(c) for c in command)),
        log=log,
    )
    store = FingerprintStore(config.inspect.fingerprint.store)
    opened_store = False
    stuck_reader = False
    code = EXIT_GENERIC_ERROR
    try:
        # 启动期审计不可用 → 直接退出（exit 4），不带病开跑。
        audit.open()
        if config.inspect.fingerprint.enabled:
            try:
                store.open()
                opened_store = True
            except Exception as exc:  # noqa: BLE001 - sqlite / OSError 都算启动期配置问题
                raise ConfigError(
                    f"cannot open fingerprint store {config.inspect.fingerprint.store}: {exc}",
                    path=config_path,
                    field_path="inspect.fingerprint.store",
                ) from exc
        if config.source_path is None and config_path is not None:
            config = _with_source(config, config_path)
        proxy = Proxy(
            config,
            command,
            audit=audit,
            log=log,
            fingerprints=store,
        )
        code = proxy.run()
        # 泵 A 还卡在客户端 stdin 上 → 正常 finalize 会 SIGABRT，见 docstring。
        stuck_reader = proxy.reader_alive
        return code
    finally:
        if opened_store:
            try:
                store.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            audit.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            log.close()
        except Exception:  # noqa: BLE001
            pass
        if stuck_reader:
            _hard_exit(code)


def _hard_exit(code: int) -> None:
    """flush 之后 ``os._exit``：绕开 CPython 对「daemon 线程还占着 stdin 锁」的 fatal error。

    只有在**所有资源都已经 close** 之后才允许调 —— ``os._exit`` 不跑 atexit、不 flush。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:  # noqa: BLE001
            pass
    os._exit(code)


def _with_source(config: GuarderConfig, config_path: Path) -> GuarderConfig:
    """补上 ``source_path``（只影响启动横幅里那行 ``config=``）。"""
    from dataclasses import replace

    return replace(config, source_path=config_path)


__all__ = [
    "TERMINATE_GRACE_SECONDS",
    "parse_line",
    "classify_message",
    "message_method",
    "message_id",
    "extract_tool_use_id",
    "build_tool_error_response",
    "serialize_line",
    "strip_tools",
    "strip_tools_at",
    "select_dropped_indices",
    "tool_name_of",
    "extract_tools",
    "IdLedger",
    "Proxy",
    "run_proxy",
]
