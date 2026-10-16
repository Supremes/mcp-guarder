"""按 Server 固定切分开发集 / 测试集（docs/detection-eval-spec.md §4）。

切分在写任何新规则之前生成一次并提交，之后**不再重新生成**。用法::

    .venv/bin/python -m eval.mcptox.split          # 已存在则拒绝覆盖
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

from eval.mcptox.fetch import COMMIT
from eval.mcptox.load import Dataset, Sample, load

SPLIT_PATH = Path(__file__).with_name("split.json")
SEED = 20261016
TEST_FRACTION = 1 / 3


def make_split(ds: Dataset) -> dict[str, object]:
    servers = ds.servers
    rng = random.Random(SEED)
    shuffled = servers[:]
    rng.shuffle(shuffled)
    n_test = round(len(shuffled) * TEST_FRACTION)
    return {
        "dataset_commit": COMMIT,
        "seed": SEED,
        "test_fraction": TEST_FRACTION,
        "dev": sorted(shuffled[n_test:]),
        "test": sorted(shuffled[:n_test]),
    }


def read_split() -> dict[str, list[str]]:
    data = json.loads(SPLIT_PATH.read_text(encoding="utf-8"))
    if data["dataset_commit"] != COMMIT:
        raise RuntimeError("split.json was generated for a different MCPTox commit")
    return {"dev": data["dev"], "test": data["test"]}


def select(ds: Dataset, split: str) -> list[Sample]:
    """``split`` ∈ dev | test | all。"""
    if split == "all":
        return list(ds.samples)
    servers = set(read_split()[split])
    return [s for s in ds.samples if s.server in servers]


def main() -> int:
    if SPLIT_PATH.exists():
        print(f"{SPLIT_PATH} already exists; refusing to regenerate", file=sys.stderr)
        return 1
    ds = load()
    split = make_split(ds)
    SPLIT_PATH.write_text(json.dumps(split, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for name in ("dev", "test"):
        members = set(split[name])  # type: ignore[arg-type]
        picked = [s for s in ds.samples if s.server in members]
        poisoned = sum(s.label == "poisoned" for s in picked)
        print(
            f"{name}: {len(members)} servers, {poisoned} poisoned, {len(picked) - poisoned} clean",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
