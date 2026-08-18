"""透明性对拍工具（SPEC §7 M1 验收第 1 条）。

    「透明性对拍的是 **wire 报文不是模型输出**（``claude -p`` 的输出不确定，不能拿来断言）：
      tests/harness/replay.py 打一串固定的 initialize / tools/list / tools/call，
      裸跑与挂网关两次的响应字节逐字一致。」

用法::

    raw      = run_session([sys.executable, "server.py"], default_script())
    guarded  = run_session(["mcp-guarder", "--config", cfg, "--",
                            sys.executable, "server.py"], default_script())
    assert_transparent(raw, guarded)

三条使用注意：
1. **对拍只在「全放行」的配置下成立**。网关剥离 tool、脱敏、拒绝调用都会（正当地）
   改变 wire 报文 —— 那些场景要用各自的专项用例断言，不要拿来跑 :func:`assert_transparent`。
2. 脚本里的报文一次性全部写进 stdin 然后关掉 —— 这同时也在测「客户端关 stdin 后
   网关必须收尾并终止子进程树」（铁律 7）。
3. 比较的是 **stdout 的字节**。stderr 不比（网关会往 stderr 打启动横幅，那是设计要求）。
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

#: 一条报文的运行时表示（和 ``mcp_guarder.types.JsonObj`` 同义，这里不 import 生产代码）。
JsonObj = dict[str, Any]

#: 对拍脚本里握手用的协议版本（SPEC 头一行写的目标协议时代）。
PROTOCOL_VERSION = "2025-11-25"


def default_script(*, tool: str = "echo", arguments: Mapping[str, Any] | None = None) -> list[JsonObj]:
    """SPEC §7 M1-1 要求的那串固定报文：``initialize`` → 通知 → ``tools/list`` → ``tools/call``。

    故意**不带** ``params._meta.claudecode/toolUseId`` —— 那个只有真客户端会带
    （SPEC §7 M1-2 用真 ``claude -p`` 验，不在这个 harness 的职责里）。
    """
    return [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"roots": {"listChanged": True}, "elicitation": {}},
                "clientInfo": {"name": "replay-harness", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": tool, "arguments": dict(arguments or {"text": "hello"})},
        },
    ]


def encode(messages: Sequence[JsonObj]) -> bytes:
    """把报文序列成一段可以直接灌进 stdin 的字节（一行一条）。"""
    return b"".join(
        json.dumps(m, ensure_ascii=False).encode("utf-8") + b"\n" for m in messages
    )


@dataclass(frozen=True)
class ReplayResult:
    """一次会话的结果。``stdout_lines`` 是**不含换行的原始字节行**，对拍就比它。"""

    command: tuple[str, ...]
    stdout: bytes
    stderr: bytes
    returncode: int
    stdout_lines: tuple[bytes, ...] = field(default=())

    @property
    def responses(self) -> list[JsonObj]:
        """把每一行解析成 dict（任何一行不是合法 JSON 都会在这里抛）。"""
        return [json.loads(line.decode("utf-8")) for line in self.stdout_lines]

    def response_for(self, rpc_id: Any) -> JsonObj | None:
        for message in self.responses:
            if message.get("id") == rpc_id:
                return message
        return None


def run_session(
    command: Sequence[str],
    messages: Sequence[JsonObj],
    *,
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
    timeout: float = 30.0,
    raw_input_bytes: bytes | None = None,
) -> ReplayResult:
    """把 ``messages`` 一次性喂给进程，收集 stdout 的所有行。

    用 ``communicate()`` 而不是自己收发：它内部用线程同时读写，
    不会因为对端输出太大（10MB 单行压力用例）而死锁。

    :param raw_input_bytes: 直接给原始字节（测非法输入 / 超长行时用），给了就忽略 ``messages``。
    """
    payload = raw_input_bytes if raw_input_bytes is not None else encode(messages)
    proc = subprocess.Popen(
        list(command),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(env) if env is not None else None,
        cwd=cwd,
    )
    try:
        out, err = proc.communicate(input=payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        raise AssertionError(
            f"session timed out after {timeout}s: {' '.join(command)}\nstderr:\n"
            f"{err.decode('utf-8', 'replace')[-2000:]}"
        ) from None
    return ReplayResult(
        command=tuple(command),
        stdout=out,
        stderr=err,
        returncode=proc.returncode,
        stdout_lines=tuple(out.splitlines()),
    )


def compare_sessions(raw: ReplayResult, guarded: ReplayResult) -> list[str]:
    """逐行做**字节级**比较，返回差异描述列表（空列表 = 完全透明）。"""
    problems: list[str] = []
    if len(raw.stdout_lines) != len(guarded.stdout_lines):
        problems.append(
            f"line count differs: raw={len(raw.stdout_lines)} guarded={len(guarded.stdout_lines)}"
        )
    for index, (left, right) in enumerate(zip(raw.stdout_lines, guarded.stdout_lines)):
        if left != right:
            problems.append(f"line {index} differs:\n  raw     = {left!r}\n  guarded = {right!r}")
    extra_raw = raw.stdout_lines[len(guarded.stdout_lines) :]
    extra_guarded = guarded.stdout_lines[len(raw.stdout_lines) :]
    for line in extra_raw:
        problems.append(f"only in raw: {line!r}")
    for line in extra_guarded:
        problems.append(f"only in guarded: {line!r}")
    return problems


def assert_transparent(raw: ReplayResult, guarded: ReplayResult) -> None:
    """断言挂网关后 stdout **字节逐字一致**（SPEC §7 M1-1）。"""
    problems = compare_sessions(raw, guarded)
    if problems:
        detail = "\n".join(problems)
        stderr = guarded.stderr.decode("utf-8", "replace")[-2000:]
        raise AssertionError(
            f"mcp-guarder is not byte-transparent:\n{detail}\n--- guarded stderr ---\n{stderr}"
        )


def assert_stdout_purity(result: ReplayResult) -> None:
    """SPEC §7 M1-3：stdout 每一行都能 ``json.loads`` 且带 ``"jsonrpc":"2.0"``。"""
    for index, line in enumerate(result.stdout_lines):
        try:
            message = json.loads(line.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                f"stdout line {index} is not valid JSON: {line[:200]!r} ({exc})"
            ) from exc
        if not isinstance(message, dict):
            raise AssertionError(f"stdout line {index} is not a JSON object: {line[:200]!r}")
        if message.get("jsonrpc") != "2.0":
            raise AssertionError(f"stdout line {index} has no jsonrpc=2.0: {line[:200]!r}")


__all__ = [
    "PROTOCOL_VERSION",
    "JsonObj",
    "ReplayResult",
    "default_script",
    "encode",
    "run_session",
    "compare_sessions",
    "assert_transparent",
    "assert_stdout_purity",
]
