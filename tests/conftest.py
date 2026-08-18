"""公共 fixture 骨架。

原则：
- **一个测试进程不许碰用户真实的 ``~/.mcp-guarder/``**。所有 fixture 一律指到 ``tmp_path``。
- 涉及 ``${PROJECT_DIR}`` 的用例必须用 :func:`project_dir` fixture 显式设置
  ``CLAUDE_PROJECT_DIR``，别依赖跑测试时的 cwd。
- 需要真跑子进程的用例用 :func:`upstream_script` 造一个假 server，
  别依赖任何外部命令。
"""

from __future__ import annotations

import json
import sys
import textwrap
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

import pytest

# ────────────────────────────────────────────────────────────────────────────
# 目录与环境
# ────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def guard_home(tmp_path: Path) -> Path:
    """假的 ``~/.mcp-guarder``：审计、指纹库、快照、guard.log 都塞这儿。"""
    home = tmp_path / "guard-home"
    (home / "audit").mkdir(parents=True)
    (home / "snapshots").mkdir(parents=True)
    return home


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """设置 ``CLAUDE_PROJECT_DIR`` 并返回该目录（policy 的 ``${PROJECT_DIR}`` 用例必备）。"""
    proj = tmp_path / "project"
    proj.mkdir()
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(proj))
    return proj


# ────────────────────────────────────────────────────────────────────────────
# 配置
# ────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def config_yaml(guard_home: Path) -> str:
    """一份最小可用的配置 YAML 文本（server + audit + fingerprint 指到 tmp 目录）。

    需要 policy / redact / static_checks 的用例自己在这份基础上拼字符串，
    或者直接构造 :class:`~mcp_guarder.types.GuarderConfig` dataclass。
    """
    return textwrap.dedent(
        f"""
        version: 1
        server:
          name: demo
          transport: stdio
        inspect:
          fingerprint:
            enabled: true
            store: {guard_home}/fingerprints.sqlite
        audit:
          path: {guard_home}/audit/{{server}}-{{date}}.jsonl
          log_file: {guard_home}/guard.log
          snapshot_dir: {guard_home}/snapshots
        """
    ).strip()


@pytest.fixture
def write_config(tmp_path: Path) -> Callable[[str], Path]:
    """把一段 YAML 文本写成文件并返回路径。"""

    def _write(text: str, name: str = "config.yaml") -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    return _write


@pytest.fixture
def load_config_from(write_config: Callable[[str], Path]):
    """YAML 文本 → :class:`~mcp_guarder.types.GuarderConfig`。

    实现依赖 ``config.load_config``；在 config 模块填好之前，用到它的测试会
    ``NotImplementedError``，这是预期的。
    """
    from mcp_guarder.config import load_config

    def _load(text: str):
        return load_config(write_config(text))

    return _load


# ────────────────────────────────────────────────────────────────────────────
# 假上游 server
# ────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def upstream_script(tmp_path: Path) -> Callable[[str], list[str]]:
    """把一段 Python 源码写成脚本，返回可直接传给代理的 ``command`` 列表。

    脚本自己负责按行读 stdin、往 stdout 写 JSON-RPC 行。**用当前解释器**
    （``sys.executable``），不要写死 ``python3``——系统 python3 是 3.9。
    """

    def _make(source: str, name: str = "fake_server.py") -> list[str]:
        path = tmp_path / name
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        return [sys.executable, str(path)]

    return _make


@pytest.fixture
def echo_upstream(upstream_script: Callable[[str], list[str]]) -> list[str]:
    """最简单的假 server：``initialize`` / ``tools/list`` / ``tools/call`` 各回一条固定响应。

    有需要的用例（rug pull、投毒描述、超长行）自己用 :func:`upstream_script` 另写一个。
    """
    return upstream_script(
        '''
        import json, sys

        TOOLS = [{"name": "echo", "description": "Echo back a string",
                  "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line)
            method, mid = msg.get("method"), msg.get("id")
            if mid is None:
                continue
            if method == "initialize":
                result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                          "serverInfo": {"name": "fake", "version": "0"}}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                args = msg.get("params", {}).get("arguments", {})
                result = {"content": [{"type": "text", "text": json.dumps(args)}], "isError": False}
            else:
                result = {}
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\\n")
            sys.stdout.flush()
        '''
    )


# ────────────────────────────────────────────────────────────────────────────
# 报文与审计的小工具
# ────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def make_request() -> Callable[..., dict]:
    """造一条 JSON-RPC 请求。``tools/call`` 默认带 ``_meta.claudecode/toolUseId``。"""

    def _make(method: str, params: dict | None = None, rpc_id: int = 1) -> dict:
        msg: dict = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
        if params is not None:
            msg["params"] = params
        return msg

    return _make


@pytest.fixture
def read_audit() -> Callable[[Path], list[dict]]:
    """读一个审计 JSONL 文件，逐行 ``json.loads``（坏行直接让它抛，测试就是要抓这个）。"""

    def _read(path: Path) -> list[dict]:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    return _read


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """清掉可能影响用例的环境变量（``CLAUDE_PROJECT_DIR`` 等）。"""
    for key in ("CLAUDE_PROJECT_DIR",):
        monkeypatch.delenv(key, raising=False)
    yield


def run_lines(command: Sequence[str], lines: Sequence[str], *, env: dict[str, str] | None = None) -> list[str]:
    """辅助函数（不是 fixture）：把若干行喂给一个进程，收集它 stdout 的所有行。

    端到端用例（stdout 洁净、透明性对拍）用它。字节级的版本在
    :func:`tests.harness.replay.run_session` —— 那边才是 SPEC §7 M1-1 的对拍主力，
    这里只是给「随手跑一串行看看输出」的用例提供一个文本层的薄封装。
    """
    from tests.harness.replay import run_session

    payload = "".join(line if line.endswith("\n") else line + "\n" for line in lines)
    result = run_session(
        command, (), env=env, raw_input_bytes=payload.encode("utf-8")
    )
    return [line.decode("utf-8") for line in result.stdout_lines]
