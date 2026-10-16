"""用指定规则版本跑静态检测，输出带分母的指标（docs/detection-eval-spec.md §5–§6）。

用法::

    .venv/bin/python -m eval.run_static --rules v0 --split dev
    .venv/bin/python -m eval.run_static --rules v1 --split test

- ``v0``：内置默认规则（``types.SPEC_STATIC_RULES``），不做修改。
- 其他版本：读 ``eval/rules/<version>.yaml``（``{id, pattern}`` 列表）。
- 测试集**每个规则版本只跑一次**：结果文件已存在就拒绝运行。改了规则就是新版本。

结果写到 ``eval/results/<rules>-<split>.json``，只有统计和样本 ID，不含 MCPTox 原文。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from eval.mcptox import fetch
from eval.mcptox.load import Sample, load
from eval.mcptox.split import SPLIT_PATH, select
from mcp_guarder import config as config_mod
from mcp_guarder import static_checks
from mcp_guarder.types import StaticChecksConfig

EVAL_DIR = Path(__file__).resolve().parent
RULES_DIR = EVAL_DIR / "rules"
RESULTS_DIR = EVAL_DIR / "results"


def build_config(version: str) -> tuple[StaticChecksConfig, str]:
    """返回 (静态检查配置, 规则摘要)。正则编译走 mcp-guarder 自己的配置解析。"""
    raw: dict[str, Any] = {"version": 1, "server": {"name": "eval", "transport": "stdio"}}
    if version != "v0":
        rules = yaml.safe_load((RULES_DIR / f"{version}.yaml").read_text(encoding="utf-8"))
        raw["inspect"] = {"static_checks": {"rules": rules}}
    cfg = config_mod.parse_config(raw).inspect.static_checks
    digest = hashlib.sha256(
        json.dumps([(r.id, r.pattern) for r in cfg.rules]).encode()
    ).hexdigest()
    return cfg, digest


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)]


def rate(k: int, n: int) -> dict[str, Any]:
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci95": wilson(k, n)}


def evaluate(samples: list[Sample], cfg: StaticChecksConfig) -> dict[str, Any]:
    hits: dict[str, list[str]] = {}
    errors: list[dict[str, str]] = []
    for s in samples:
        try:
            found = static_checks.scan_tool(s.tool, config=cfg)
        except Exception as exc:  # noqa: BLE001 —— 扫描异常单独计数，不并入分母
            errors.append({"id": s.id, "error": repr(exc)})
            continue
        hits[s.id] = sorted({h.rule_id for h in found})

    scanned = [s for s in samples if s.id in hits]
    poisoned = [s for s in scanned if s.label == "poisoned"]
    clean = [s for s in scanned if s.label == "clean"]
    tp = sum(bool(hits[s.id]) for s in poisoned)
    fp = sum(bool(hits[s.id]) for s in clean)

    def grouped(key: str) -> dict[str, Any]:
        buckets: dict[str, list[Sample]] = defaultdict(list)
        for s in poisoned:
            buckets[str(getattr(s, key))].append(s)
        return {
            g: rate(sum(bool(hits[s.id]) for s in ss), len(ss))
            for g, ss in sorted(buckets.items())
        }

    per_rule: dict[str, dict[str, int]] = {}
    for rule in cfg.rules:
        on_p = [s for s in poisoned if rule.id in hits[s.id]]
        on_c = [s for s in clean if rule.id in hits[s.id]]
        per_rule[rule.id] = {
            "poisoned_hits": len(on_p),
            "clean_hits": len(on_c),
            "unique_poisoned_hits": sum(hits[s.id] == [rule.id] for s in on_p),
        }

    clean_by_server = Counter(s.server for s in clean if hits[s.id])
    return {
        "counts": {
            "samples": len(samples),
            "scanned": len(scanned),
            "poisoned": len(poisoned),
            "clean": len(clean),
            "scan_errors": len(errors),
        },
        "recall": rate(tp, len(poisoned)),
        "false_positive_rate": rate(fp, len(clean)),
        "precision": rate(tp, tp + fp),
        "recall_by_paradigm": grouped("paradigm"),
        "recall_by_risk": grouped("risk"),
        "recall_by_server": grouped("server"),
        "false_positives_by_server": dict(sorted(clean_by_server.items())),
        "per_rule": per_rule,
        "scan_errors": errors,
        "hits": {sid: rules for sid, rules in sorted(hits.items()) if rules},
    }


def git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, cwd=EVAL_DIR
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--", "src", "eval/rules", "eval/mcptox"],
            capture_output=True, text=True, check=True, cwd=EVAL_DIR,
        ).stdout.strip()
        return out.stdout.strip() + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eval.run_static")
    parser.add_argument("--rules", required=True, help="v0 或 eval/rules/ 下的版本名")
    parser.add_argument("--split", required=True, choices=["dev", "test"])
    args = parser.parse_args(argv)

    out_path = RESULTS_DIR / f"{args.rules}-{args.split}.json"
    if args.split == "test" and out_path.exists():
        print(f"{out_path.name} already exists: test split runs once per rules version",
              file=sys.stderr)
        return 1

    cfg, rules_digest = build_config(args.rules)
    ds = load()
    samples = select(ds, args.split)
    result = evaluate(samples, cfg)
    result = {
        "meta": {
            "rules_version": args.rules,
            "rules_sha256": rules_digest,
            "rule_ids": [r.id for r in cfg.rules],
            "split": args.split,
            "split_sha256": hashlib.sha256(SPLIT_PATH.read_bytes()).hexdigest(),
            "dataset": f"{fetch.REPO}@{fetch.COMMIT}",
            "dataset_sha256": fetch.FILES,
            "code_commit": git_commit(),
            "parse_errors": ds.parse_errors,
            "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        **result,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    r, f = result["recall"], result["false_positive_rate"]
    print(
        f"[{args.rules}/{args.split}] recall {r['k']}/{r['n']} ({r['rate']}, ci95 {r['ci95']})  "
        f"FPR {f['k']}/{f['n']} ({f['rate']}, ci95 {f['ci95']})  "
        f"scan_errors {result['counts']['scan_errors']}  -> {out_path.relative_to(EVAL_DIR.parent)}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
