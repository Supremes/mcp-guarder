"""从真实 MCP Server 导出 ``tools/list``，扩充正常样本集。**需要手动运行。**

这个脚本会通过 npx / uvx 下载并启动第三方 MCP Server，相当于执行外部代码，
所以没有在开发环境里自动运行。建议在隔离环境（容器 / 一次性 VM）里执行::

    .venv/bin/python -m eval.corpus.export_benign            # 导出全部
    .venv/bin/python -m eval.corpus.export_benign memory git # 只导出指定 slug

- 不使用任何真实凭证：需要 token 才能启动的 Server 传假值，起不来就记为 failed。
- 结果写到 ``eval/.cache/benign/servers/<slug>.json``，清单写到 ``eval/corpus/manifest-servers.json``。
- 失败、超时都写进清单，不静默跳过。
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import subprocess
import sys
import tempfile
import time
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parents[1]
CACHE_DIR = EVAL_DIR / ".cache" / "benign" / "servers"
MANIFEST_PATH = Path(__file__).with_name("manifest-servers.json")
PROTOCOL_VERSION = "2025-11-25"
TIMEOUT_S = 180
SANDBOX = Path(tempfile.gettempdir()) / "mcp-benign-sandbox"
FAKE_TOKEN = "dummy-token-for-tools-list"

#: slug → (启动命令, 额外环境变量)。版本号建议首次运行后按 serverInfo 固定下来。
SERVERS: dict[str, tuple[list[str], dict[str, str]]] = {
    "filesystem": (["npx", "-y", "@modelcontextprotocol/server-filesystem", str(SANDBOX)], {}),
    "memory": (["npx", "-y", "@modelcontextprotocol/server-memory"], {}),
    "everything": (["npx", "-y", "@modelcontextprotocol/server-everything"], {}),
    "sequential-thinking": (["npx", "-y", "@modelcontextprotocol/server-sequential-thinking"], {}),
    "context7": (["npx", "-y", "@upstash/context7-mcp"], {}),
    "playwright": (["npx", "-y", "@playwright/mcp"], {}),
    "chrome-devtools": (["npx", "-y", "chrome-devtools-mcp"], {}),
    "notion": (["npx", "-y", "@notionhq/notion-mcp-server"], {"NOTION_TOKEN": FAKE_TOKEN}),
    "supabase": (
        ["npx", "-y", "@supabase/mcp-server-supabase", "--read-only"],
        {"SUPABASE_ACCESS_TOKEN": FAKE_TOKEN},
    ),
    "firecrawl": (["npx", "-y", "firecrawl-mcp"], {"FIRECRAWL_API_KEY": FAKE_TOKEN}),
    "tavily": (["npx", "-y", "tavily-mcp"], {"TAVILY_API_KEY": FAKE_TOKEN}),
    "brave-search": (["npx", "-y", "@brave/brave-search-mcp-server"], {"BRAVE_API_KEY": FAKE_TOKEN}),
    "kubernetes": (["npx", "-y", "mcp-server-kubernetes"], {}),
    "fetch": (["uvx", "mcp-server-fetch"], {}),
    "git": (["uvx", "mcp-server-git", "--repository", str(SANDBOX)], {}),
    "time": (["uvx", "mcp-server-time"], {}),
    "aws-docs": (["uvx", "awslabs.aws-documentation-mcp-server"], {}),
}


class Session:
    """最小的 stdio JSON-RPC 客户端：按行写请求，按行读响应。"""

    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={**os.environ, **env},
            start_new_session=True,
        )
        self.non_json_lines = 0
        self._next_id = 1

    def request(self, method: str, params: dict, deadline: float) -> dict:
        rpc_id = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params})
        while True:
            msg = self._read(deadline)
            if msg.get("id") == rpc_id:
                if "error" in msg:
                    raise RuntimeError(f"{method} error: {msg['error']}")
                return msg["result"]

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def close(self) -> None:
        try:
            os.killpg(self.proc.pid, 15)
            self.proc.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(self.proc.pid, 9)
            except ProcessLookupError:
                pass

    def _send(self, msg: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()

    def _read(self, deadline: float) -> dict:
        assert self.proc.stdout is not None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for server")
            ready, _, _ = select.select([self.proc.stdout], [], [], remaining)
            if not ready:
                continue
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(f"server exited (code {self.proc.poll()})")
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                self.non_json_lines += 1


def export_one(slug: str) -> dict:
    argv, env = SERVERS[slug]
    session = Session(argv, env)
    deadline = time.monotonic() + TIMEOUT_S
    try:
        init = session.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-guarder-benign-export", "version": "0"},
            },
            deadline,
        )
        session.notify("notifications/initialized")
        tools: list[dict] = []
        cursor = None
        while True:
            result = session.request("tools/list", {"cursor": cursor} if cursor else {}, deadline)
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                break
    finally:
        session.close()
    info = init.get("serverInfo", {})
    record = {
        "server": slug,
        "command": argv,
        "server_info": info,
        "non_json_stdout_lines": session.non_json_lines,
        "tools": tools,
    }
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / f"{slug}.json"
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "status": "ok",
        "server_info": info,
        "tools": len(tools),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def load_tools() -> list[dict]:
    """读已导出的缓存，返回 ``[{id, server, tool}]``。没导出过就是空列表。"""
    items = []
    for path in sorted(CACHE_DIR.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        for tool in record["tools"]:
            items.append({"id": f"{record['server']}:{tool.get('name')}", "server": record["server"], "tool": tool})
    return items


def main(argv: list[str] | None = None) -> int:
    slugs = (argv if argv is not None else sys.argv[1:]) or list(SERVERS)
    unknown = [s for s in slugs if s not in SERVERS]
    if unknown:
        print(f"unknown slug(s): {unknown}", file=sys.stderr)
        return 2
    SANDBOX.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST_PATH.read_text()) if MANIFEST_PATH.exists() else {}
    for slug in slugs:
        print(f"exporting {slug} ...", file=sys.stderr)
        try:
            manifest[slug] = export_one(slug)
        except Exception as exc:  # noqa: BLE001 —— 失败要进清单，不中断其他 Server
            manifest[slug] = {"status": "failed", "error": repr(exc)[:300]}
        print(f"  {manifest[slug]}", file=sys.stderr)
    MANIFEST_PATH.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
