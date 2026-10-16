"""按固定 commit 下载 MCPTox 数据到本地缓存，并校验 sha256。

MCPTox 仓库没有 LICENSE，原始数据**只放本地缓存**（``eval/.cache/``，已 gitignore），
不进本仓库。用法::

    .venv/bin/python -m eval.mcptox.fetch
"""

from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

REPO = "zhiqiangwang4/MCPTox-Benchmark"
#: 2025-12-03 的 main，换版本 = 新的实验版本（见 docs/detection-eval-spec.md §7）。
COMMIT = "f85189f9ad12504c197c7f920ab818a40657b1fa"

FILES: dict[str, str] = {
    "pure_tool.json": "54b1eb0e9d7b2f18465266aa9d9dfda828cd558b1269b74731ec2c5d8579e617",
    "response_all.json": "79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03",
}

CACHE_DIR = Path(__file__).resolve().parents[1] / ".cache" / "mcptox" / COMMIT


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(cache_dir: Path = CACHE_DIR) -> Path:
    """确保所有文件都在缓存里且 sha256 正确，返回缓存目录。校验失败直接抛错，不用坏数据。"""
    cache_dir.mkdir(parents=True, exist_ok=True)
    for name, expected in FILES.items():
        target = cache_dir / name
        if target.exists() and sha256_of(target) == expected:
            continue
        url = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{name}"
        print(f"downloading {url}", file=sys.stderr)
        tmp = target.with_suffix(target.suffix + ".part")
        urllib.request.urlretrieve(url, tmp)
        actual = sha256_of(tmp)
        if actual != expected:
            tmp.unlink()
            raise RuntimeError(f"sha256 mismatch for {name}: expected {expected}, got {actual}")
        tmp.replace(target)
    return cache_dir


def main() -> int:
    path = fetch()
    print(f"MCPTox @ {COMMIT[:12]} ready at {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
