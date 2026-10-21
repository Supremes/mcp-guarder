"""用 LLM 语义检测器跑评测（OpenAI 兼容接口），需要显式指定本地模型端点。

用法::

    # 先在开发集上小规模试跑，确认模型能正常输出
    .venv/bin/python -m eval.run_semantic --base-url http://localhost:11434/v1 \\
        --model qwen3:8b --tag qwen3-8b --split dev --limit 20

    # 开发集全量（可反复跑，用来调 prompt）
    .venv/bin/python -m eval.run_semantic ... --tag qwen3-8b --split dev

    # 留出集：prompt 冻结后每个 (tag, prompt 版本) 只跑一次
    .venv/bin/python -m eval.run_semantic ... --tag qwen3-8b --split test
    .venv/bin/python -m eval.run_semantic ... --tag qwen3-8b --split benign
    .venv/bin/python -m eval.run_semantic ... --tag qwen3-8b --split probes

评测口径：

- 按 Server 分组，同一个 Server 的投毒和正常样本按固定种子打乱后分批送检，
  这个 Server 的全部工具名作为上下文 —— 模拟投毒 tool 混在正常 tool 里出现的真实情况。
- 不用缓存，每条样本都重新判定。
- 模型不可用 / 输出不合法的样本单独计数，不进召回率和误报率的分母；
  同时给出"部署口径"：按默认配置，输出不合法会被剥离（视为检出）。

结果写到 ``eval/results/semantic-<tag>-<prompt 版本>-<split>.json``（``--limit`` 时写 ``-smoke`` 后缀）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eval.datasets import SPLITS, get_samples
from eval.mcptox.load import LOADER_VERSION, Sample
from eval.run_static import HELD_OUT, RESULTS_DIR, git_commit, metrics, rate
from mcp_guarder import semantic as sem
from mcp_guarder.types import SemanticConfig

SEED = 20261021
LABEL = "semantic"


def plan_batches(samples: list[Sample], batch_size: int) -> list[tuple[str, list[str], list[Sample]]]:
    """→ [(server, 该 Server 全部工具名, 一批样本)]。"""
    by_server: dict[str, list[Sample]] = defaultdict(list)
    for s in samples:
        by_server[s.server].append(s)
    rng = random.Random(SEED)
    plan = []
    for server in sorted(by_server):
        group = by_server[server][:]
        rng.shuffle(group)
        names = sorted({str(s.tool.get("name")) for s in group if s.label == "clean"})
        for start in range(0, len(group), batch_size):
            batch = group[start : start + batch_size]
            siblings = sorted(set(names) | {str(s.tool.get("name")) for s in batch})
            plan.append((server, siblings, batch))
    return plan


def run(
    samples: list[Sample],
    config: SemanticConfig,
    *,
    transport: sem.Transport | None = None,
    progress: bool = True,
) -> dict[str, Any]:
    """逐批调用检测器，返回 (hits, errors, verdict 明细, 用时)。"""
    if len({s.id for s in samples}) != len(samples):
        raise ValueError("duplicate sample IDs would overwrite verdicts; fix dataset identities first")
    judge = sem.SemanticJudge(config, transport=transport)
    hits: dict[str, list[str]] = {}
    errors: list[dict[str, str]] = []
    details: dict[str, dict[str, Any]] = {}
    batch_details: list[dict[str, Any]] = []
    plan = plan_batches(samples, config.max_tools_per_request)
    started = time.monotonic()
    for i, (server, siblings, batch) in enumerate(plan, 1):
        # 判定器按 tool 名对齐结果：批内重名时用下标改名，避免串号。
        tools = []
        for j, s in enumerate(batch):
            t = dict(s.tool)
            if [str(b.tool.get("name")) for b in batch].count(str(t.get("name"))) > 1:
                t["name"] = f"{t.get('name')}#{j}"
            tools.append(t)
        batch_started = time.monotonic()
        report = judge.judge(tools, server=server, sibling_names=siblings)
        batch_details.append({
            "server": server,
            "sample_ids": [s.id for s in batch],
            "elapsed_s": round(time.monotonic() - batch_started, 3),
            "model_calls": report.model_calls,
            "failure_details": list(report.failure_details),
        })
        for s, t in zip(batch, tools):
            name = str(t.get("name"))
            verdict = report.verdict_for(name)
            if verdict is not None:
                hits[s.id] = [LABEL] if verdict.verdict is sem.Verdict.MALICIOUS else []
                details[s.id] = {"verdict": str(verdict.verdict), "confidence": verdict.confidence,
                                 "reason": verdict.reason}
            else:
                kind = report.failures.get(name, sem.FailureKind.UNAVAILABLE)
                errors.append({"id": s.id, "error": str(kind)})
        if progress:
            print(f"  batch {i}/{len(plan)} {server}: {len(batch)} tools, "
                  f"{batch_details[-1]['elapsed_s']}s, errors so far {len(errors)}", file=sys.stderr)
    return {"hits": hits, "errors": errors, "details": details,
            "elapsed_s": round(time.monotonic() - started, 1), "batches": len(plan),
            "batch_details": batch_details}


def summarize(samples: list[Sample], outcome: dict[str, Any]) -> dict[str, Any]:
    result = metrics(samples, outcome["hits"], outcome["errors"], rule_ids=[LABEL])
    result.pop("per_rule")
    by_kind = defaultdict(int)
    for e in outcome["errors"]:
        by_kind[e["error"]] += 1
    # 部署口径：默认 on_invalid_output=deny（剥离 = 检出），on_unavailable=warn（放行 = 漏检）
    invalid = {e["id"] for e in outcome["errors"] if e["error"] == str(sem.FailureKind.INVALID_OUTPUT)}
    def deployed(label: str) -> dict[str, Any]:
        group = [s for s in samples if s.label == label]
        flagged = sum(1 for s in group if outcome["hits"].get(s.id) or s.id in invalid)
        return rate(flagged, len(group))
    result["errors_by_kind"] = dict(by_kind)
    result["deployed_view"] = {
        "note": "默认配置下：输出不合法 → 剥离（算检出），不可用 → 放行（算漏检）",
        "recall": deployed("poisoned"),
        "false_positive_rate": deployed("clean"),
    }
    result["verdict_details"] = outcome["details"]
    result["batch_details"] = outcome["batch_details"]
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eval.run_semantic")
    parser.add_argument("--base-url", required=True, help="例如 http://localhost:11434/v1")
    parser.add_argument("--model", required=True)
    parser.add_argument("--tag", required=True, help="结果文件名里的模型标签，例如 qwen3-8b")
    parser.add_argument("--split", required=True, choices=SPLITS)
    parser.add_argument("--api-key-env", default=None, help="存放 API key 的环境变量名（可选）")
    parser.add_argument("--response-format", default="json_schema",
                        choices=["json_schema", "json_object", "none"])
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--timeout-s", type=float, default=120.0, help="单批请求的时间预算")
    parser.add_argument("--limit", type=int, default=None, help="只取前 N 条样本做冒烟测试")
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    args = parser.parse_args(argv)

    suffix = "-smoke" if args.limit else ""
    out_path = (
        args.results_dir / f"semantic-{args.tag}-{sem.PROMPT_VERSION}-{args.split}{suffix}.json"
    )
    if args.split in HELD_OUT and not args.limit and out_path.exists():
        print(f"{out_path.name} already exists: {args.split} runs once per (tag, prompt version)",
              file=sys.stderr)
        return 1

    samples, source_meta = get_samples(args.split)
    if args.limit:
        samples = random.Random(SEED).sample(samples, min(args.limit, len(samples)))
    config = SemanticConfig(
        enabled=True,
        base_url=args.base_url.rstrip("/"),
        model=args.model,
        api_key_env=args.api_key_env,
        timeout_s=args.timeout_s,
        max_tools_per_request=args.batch_size,
        response_format=args.response_format,
    )
    print(f"judging {len(samples)} samples with {args.model} @ {config.base_url}", file=sys.stderr)
    outcome = run(samples, config)
    result = summarize(samples, outcome)
    result = {
        "meta": {
            "detector": "semantic",
            "tag": args.tag,
            "model": args.model,
            "base_url": config.base_url,
            "prompt_version": sem.PROMPT_VERSION,
            "prompt_sha256": hashlib.sha256(sem.SYSTEM_PROMPT.encode()).hexdigest(),
            "response_format": args.response_format,
            "batch_size": args.batch_size,
            "timeout_s": args.timeout_s,
            "temperature": 0,
            "shuffle_seed": SEED,
            "split": args.split,
            "limit": args.limit,
            "loader_version": LOADER_VERSION,
            "code_commit": git_commit(),
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "detector_sha256": hashlib.sha256(Path(sem.__file__).read_bytes()).hexdigest(),
            "samples_sha256": hashlib.sha256(json.dumps(
                [asdict(s) for s in samples], sort_keys=True, ensure_ascii=False,
                separators=(",", ":"),
            ).encode()).hexdigest(),
            "elapsed_s": outcome["elapsed_s"],
            "batches": outcome["batches"],
            "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **source_meta,
        },
        **result,
    }
    args.results_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    r, f = result["recall"], result["false_positive_rate"]
    print(
        f"[semantic {args.tag}/{args.split}] recall {r['k']}/{r['n']}  FPR {f['k']}/{f['n']}  "
        f"errors {result['errors_by_kind']}  {outcome['elapsed_s']}s -> {out_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
