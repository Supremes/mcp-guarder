"""评测用的补充样本集，统一成 :class:`eval.mcptox.load.Sample`。

- ``benign``：真实正常样本。github-mcp-server 快照 + 手动导出的 Server（如果导出过）。
- ``probes``：手写合法描述（label=clean）+ 针对裁判的投毒描述（label=poisoned）。
"""

from __future__ import annotations

from pathlib import Path

import yaml

from eval.corpus import export_benign, github_snaps
from eval.mcptox.load import Sample

PROBES_PATH = Path(__file__).with_name("probes.yaml")


def benign_samples() -> list[Sample]:
    items = github_snaps.load_tools() + export_benign.load_tools()
    return [Sample(id=i["id"], server=i["server"], label="clean", tool=i["tool"]) for i in items]


def probe_samples() -> list[Sample]:
    data = yaml.safe_load(PROBES_PATH.read_text(encoding="utf-8"))
    samples = []
    for group, label in (("benign", "clean"), ("judge_injection", "poisoned")):
        for i, item in enumerate(data[group]):
            samples.append(
                Sample(
                    id=f"probe:{group}:{i}",
                    server="probes",
                    label=label,  # type: ignore[arg-type]
                    tool={"name": item["name"], "description": item["description"],
                          "inputSchema": {"type": "object"}},
                    paradigm=group,
                )
            )
    return samples
