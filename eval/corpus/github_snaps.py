"""真实正常样本：github/github-mcp-server 仓库里的 tool 定义快照（``__toolsnaps__/*.snap``）。

只下载 JSON 数据文件，不执行任何第三方代码。仓库是 MIT 许可，但为了和 MCPTox 处理方式一致，
原文仍只放本地缓存（``eval/.cache/benign/github/``），仓库里只提交 ``manifest-github.json``
（文件名 + sha256）。用法::

    .venv/bin/python -m eval.corpus.github_snaps
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO = "github/github-mcp-server"
#: 2026-10-20 的 main。换版本 = 新的实验版本。
COMMIT = "e3809fe91c7546633241006bf0b91f23b2595e28"
SNAP_DIR = "pkg/github/__toolsnaps__/"

EVAL_DIR = Path(__file__).resolve().parents[1]
CACHE_DIR = EVAL_DIR / ".cache" / "benign" / "github" / COMMIT
MANIFEST_PATH = Path(__file__).with_name("manifest-github.json")


def _list_snap_paths() -> list[str]:
    """用 git tree API 列出快照文件（需要已登录的 ``gh``）。"""
    out = subprocess.run(
        ["gh", "api", f"repos/{REPO}/git/trees/{COMMIT}?recursive=1"],
        capture_output=True, text=True, check=True,
    ).stdout
    tree = json.loads(out)["tree"]
    return sorted(
        e["path"] for e in tree if e["path"].startswith(SNAP_DIR) and e["path"].endswith(".snap")
    )


def fetch() -> Path:
    """有 manifest 时按 manifest 校验并补齐缓存；没有时生成 manifest。"""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST_PATH.read_text()) if MANIFEST_PATH.exists() else None
    names = (
        sorted(manifest["files"])
        if manifest
        else [p.removeprefix(SNAP_DIR) for p in _list_snap_paths()]
    )
    digests: dict[str, str] = {}
    for name in names:
        target = CACHE_DIR / name
        if not target.exists():
            url = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{SNAP_DIR}{name}"
            urllib.request.urlretrieve(url, target)
        digests[name] = hashlib.sha256(target.read_bytes()).hexdigest()
        if manifest and manifest["files"][name] != digests[name]:
            raise RuntimeError(f"sha256 mismatch for {name}")
    if not manifest:
        MANIFEST_PATH.write_text(
            json.dumps({"repo": REPO, "commit": COMMIT, "files": digests}, indent=2) + "\n"
        )
    return CACHE_DIR


def load_tools() -> list[dict]:
    """返回 ``[{id, server, tool}]``，tool 是完整的 MCP tool 对象。"""
    cache = fetch()
    items = []
    for path in sorted(cache.glob("*.snap")):
        tool = json.loads(path.read_text(encoding="utf-8"))
        # 同名工具有不同 schema 的快照，样本身份必须按文件区分。
        items.append({"id": f"github:{path.stem}", "server": "github", "tool": tool})
    return items


def main() -> int:
    tools = load_tools()
    print(f"github-mcp-server @ {COMMIT[:12]}: {len(tools)} tools at {CACHE_DIR}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
