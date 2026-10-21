"""评测样本集的统一入口。

| split | 内容 | 用途 |
|---|---|---|
| ``dev`` / ``test`` | MCPTox 按 Server 固定切分 | 召回率 + 误报率；``test`` 每个版本只跑一次 |
| ``mcptox-all`` | MCPTox 全量 | 拟合覆盖率（规则用全量写成时，只能叫覆盖率） |
| ``benign`` | 真实正常样本（github-mcp-server 快照 + 手动导出） | 误报率 |
| ``probes`` | 手写合法描述 + 针对裁判的投毒描述 | 观察误报方向和裁判被注入，非主指标 |
"""

from __future__ import annotations

from typing import Any

from eval.corpus.benign import benign_samples, probe_samples
from eval.mcptox.load import Sample, load
from eval.mcptox.split import select

SPLITS = ("dev", "test", "mcptox-all", "benign", "probes")


def get_samples(split: str) -> tuple[list[Sample], dict[str, Any]]:
    """返回 (样本, 数据来源元信息)。"""
    if split in ("dev", "test", "mcptox-all"):
        ds = load()
        samples = select(ds, "all" if split == "mcptox-all" else split)
        return samples, {"parse_errors": ds.parse_errors}
    if split == "benign":
        samples = benign_samples()
        return samples, {"servers": sorted({s.server for s in samples})}
    if split == "probes":
        return probe_samples(), {}
    raise ValueError(f"unknown split: {split}")
