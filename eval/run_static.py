"""跑静态检测评测，输出带分母的指标（docs/detection-eval-spec.md §5–§6）。

用法::

    .venv/bin/python -m eval.run_static --split dev                       # 内置规则
    .venv/bin/python -m eval.run_static --rules my-rules.yaml --split dev # 实验用规则文件

- ``builtin``（默认）：内置规则（``types.SPEC_STATIC_RULES``），每条自带 deny / warn。
- 其他：一个 YAML 文件，格式和配置里的 ``inspect.static_checks.rules`` 相同。
- 留出集（``test``、``benign``）**同一套正则只跑一次**：按 id + pattern 的摘要查已有结果，
  不看名字。只改 deny / warn 不算新规则，deny 层可以用已有结果里的逐条命中重算。

结果写到 ``eval/results/<规则名>-<split>.json``，只有统计和样本 ID，不含 MCPTox 原文。
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
from eval.datasets import SPLITS, get_samples
from eval.mcptox.load import LOADER_VERSION, Sample
from eval.mcptox.split import SPLIT_PATH
from mcp_guarder import config as config_mod
from mcp_guarder import static_checks
from mcp_guarder.types import StaticCheckAction, StaticChecksConfig

EVAL_DIR = Path(__file__).resolve().parent
RESULTS_DIR = EVAL_DIR / "results"
#: 留出集：同一套正则只跑一次（test 测召回，benign 测真实误报）。
HELD_OUT = ("test", "benign")
BUILTIN = "builtin"


def rules_label(rules: str) -> str:
    return rules if rules == BUILTIN else Path(rules).stem


def build_config(rules: str = BUILTIN) -> tuple[StaticChecksConfig, str]:
    """返回 (静态检查配置, 规则摘要)。正则编译走 mcp-guarder 自己的配置解析。"""
    raw: dict[str, Any] = {"version": 1, "server": {"name": "eval", "transport": "stdio"}}
    if rules != BUILTIN:
        loaded = yaml.safe_load(Path(rules).read_text(encoding="utf-8"))
        raw["inspect"] = {"static_checks": {"rules": loaded}}
    cfg = config_mod.parse_config(raw).inspect.static_checks
    digest = hashlib.sha256(
        json.dumps([(r.id, r.pattern) for r in cfg.rules]).encode()
    ).hexdigest()
    return cfg, digest


def held_out_run(split: str, rules_digest: str) -> Path | None:
    """同一套正则（id + pattern 摘要相同）已经跑过这个留出集的结果文件。"""
    for path in sorted(RESULTS_DIR.glob("*.json")):
        meta = json.loads(path.read_text(encoding="utf-8")).get("meta", {})
        if meta.get("split") == split and meta.get("rules_sha256") == rules_digest:
            return path
    return None


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
    result = metrics(samples, hits, errors, rule_ids=[r.id for r in cfg.rules])
    # deny 层：只算处置为 deny 的规则 —— 这才是真正会剥离 tool 的部分。
    deny_rules = {r.id for r in cfg.rules if cfg.action_for(r.id) is StaticCheckAction.DENY}
    deny_hits = {sid: [r for r in rules if r in deny_rules] for sid, rules in hits.items()}
    deny = metrics(samples, deny_hits, errors, rule_ids=[])
    result["deny_layer"] = {
        "rule_ids": sorted(deny_rules),
        "recall": deny["recall"],
        "false_positive_rate": deny["false_positive_rate"],
    }
    return result


def metrics(
    samples: list[Sample],
    hits: dict[str, list[str]],
    errors: list[dict[str, str]],
    *,
    rule_ids: list[str],
) -> dict[str, Any]:
    """``hits``：已判定样本 → 命中的标签（规则 id 或 ``semantic``）；空列表 = 判为正常。
    不在 ``hits`` 里的样本视为没判定成（错误），单独计数，不进任何分母。"""
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
    for rule_id in rule_ids:
        on_p = [s for s in poisoned if rule_id in hits[s.id]]
        on_c = [s for s in clean if rule_id in hits[s.id]]
        per_rule[rule_id] = {
            "poisoned_hits": len(on_p),
            "clean_hits": len(on_c),
            "unique_poisoned_hits": sum(hits[s.id] == [rule_id] for s in on_p),
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
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, cwd=EVAL_DIR.parent
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--", "src", "eval/mcptox", "eval/run_static.py"],
            capture_output=True, text=True, check=True, cwd=EVAL_DIR.parent,
        ).stdout.strip()
        return out.stdout.strip() + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eval.run_static")
    parser.add_argument("--rules", default=BUILTIN, help="builtin（默认）或规则 YAML 文件路径")
    parser.add_argument("--split", required=True, choices=SPLITS)
    args = parser.parse_args(argv)

    label = rules_label(args.rules)
    out_path = RESULTS_DIR / f"{label}-{args.split}.json"
    cfg, rules_digest = build_config(args.rules)
    if args.split in HELD_OUT and (prior := held_out_run(args.split, rules_digest)):
        print(f"{prior.name} already has these rules on {args.split}: held-out splits run once "
              f"per rule set; recompute deny / warn tiers from its per-sample hits instead",
              file=sys.stderr)
        return 1
    if out_path.exists() and args.split in HELD_OUT:
        print(f"{out_path.name} already exists", file=sys.stderr)
        return 1

    samples, source_meta = get_samples(args.split)
    result = evaluate(samples, cfg)
    result = {
        "meta": {
            "rules_version": label,
            "rules_sha256": rules_digest,
            "rule_ids": [r.id for r in cfg.rules],
            "split": args.split,
            "split_sha256": hashlib.sha256(SPLIT_PATH.read_bytes()).hexdigest(),
            "dataset": f"{fetch.REPO}@{fetch.COMMIT}",
            "dataset_sha256": fetch.FILES,
            "loader_version": LOADER_VERSION,
            "code_commit": git_commit(),
            **source_meta,
            "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        **result,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    dl = result["deny_layer"]
    if len(dl["rule_ids"]) != len(result["meta"]["rule_ids"]):
        print(
            f"[{label}/{args.split}] deny layer: recall {dl['recall']['k']}/{dl['recall']['n']}  "
            f"FPR {dl['false_positive_rate']['k']}/{dl['false_positive_rate']['n']}",
            file=sys.stderr,
        )
    r, f = result["recall"], result["false_positive_rate"]
    print(
        f"[{label}/{args.split}] recall {r['k']}/{r['n']} ({r['rate']}, ci95 {r['ci95']})  "
        f"FPR {f['k']}/{f['n']} ({f['rate']}, ci95 {f['ci95']})  "
        f"scan_errors {result['counts']['scan_errors']}  -> {out_path.relative_to(EVAL_DIR.parent)}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
