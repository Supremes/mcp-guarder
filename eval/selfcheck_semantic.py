"""LLM 评测链路自检：不需要真实模型。

起一个本地假 OpenAI 服务，它用 v2 正则给出判定；然后用 ``eval.run_semantic`` 的同一套代码
跑一遍。如果算出来的召回率 / 误报率和直接跑 v2 正则完全一致，就说明
"拼请求 → HTTP → 解析 → 按样本对齐 → 统计"这条链路是对的。再注入一批不合法输出，
确认错误被单独计数、部署口径按默认配置处理。用法::

    .venv/bin/python -m eval.selfcheck_semantic
"""

from __future__ import annotations

import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from eval.datasets import get_samples
from eval.run_semantic import run, summarize
from eval.run_static import RESULTS_DIR, build_config, evaluate
from mcp_guarder import static_checks
from mcp_guarder.types import SemanticConfig

RULES = "v2"


def start_oracle(*, garbage_every: int = 0) -> tuple[ThreadingHTTPServer, str]:
    cfg, _ = build_config(RULES)
    counter = {"n": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            user = body["messages"][1]["content"]
            nonce = re.search(r'<tool_definition id="([0-9a-f]+)" index=', user).group(1)
            blocks = re.findall(
                rf'<tool_definition id="{nonce}" index="\d+">\n(.*?)\n</tool_definition id="{nonce}">',
                user, re.S,
            )
            counter["n"] += 1
            if garbage_every and counter["n"] % garbage_every == 0:
                content = "Looks fine to me."
            else:
                results = []
                for i, block in enumerate(blocks):
                    hit = static_checks.scan_tool(json.loads(block), config=cfg)
                    results.append({"index": i, "verdict": "malicious" if hit else "benign",
                                    "confidence": 1.0, "reason": "oracle"})
                content = json.dumps({"results": results})
            payload = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: Any) -> None:
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/v1"


def check(split: str, *, garbage_every: int = 0) -> dict[str, Any]:
    samples, _ = get_samples(split)
    httpd, base_url = start_oracle(garbage_every=garbage_every)
    try:
        config = SemanticConfig(enabled=True, base_url=base_url, model="oracle-v2",
                                timeout_s=30, max_tools_per_request=8)
        result = summarize(samples, run(samples, config, progress=False))
    finally:
        httpd.shutdown()
    expected = evaluate(samples, build_config(RULES)[0])
    return {"result": result, "expected": expected}


def main() -> int:
    ok = True
    rows: list[dict[str, Any]] = []
    for split in ("dev", "benign", "probes"):
        out = check(split)
        got, exp = out["result"], out["expected"]
        same = all(got[k]["k"] == exp[k]["k"] and got[k]["n"] == exp[k]["n"]
                   for k in ("recall", "false_positive_rate"))
        ok &= same and not got["scan_errors"]
        rows.append({"check": f"oracle-{split}", "passed": same,
                     "runner": [got["recall"]["k"], got["recall"]["n"],
                                got["false_positive_rate"]["k"], got["false_positive_rate"]["n"]],
                     "regex": [exp["recall"]["k"], exp["recall"]["n"],
                               exp["false_positive_rate"]["k"], exp["false_positive_rate"]["n"]]})
        print(f"[{'PASS' if same else 'FAIL'}] {split}: semantic-runner recall "
              f"{got['recall']['k']}/{got['recall']['n']} FPR {got['false_positive_rate']['k']}/"
              f"{got['false_positive_rate']['n']}  vs regex {exp['recall']['k']}/{exp['recall']['n']} "
              f"FPR {exp['false_positive_rate']['k']}/{exp['false_positive_rate']['n']}")

    out = check("dev", garbage_every=3)["result"]
    errors = out["errors_by_kind"].get("invalid_output", 0)
    judged = out["counts"]["scanned"]
    total = out["counts"]["samples"]
    consistent = errors > 0 and judged + errors == total
    ok &= consistent
    print(f"[{'PASS' if consistent else 'FAIL'}] invalid outputs counted separately: "
          f"{errors} invalid + {judged} judged = {total} samples; deployed recall "
          f"{out['deployed_view']['recall']['k']}/{out['deployed_view']['recall']['n']}")
    rows.append({"check": "invalid-output-accounting", "passed": consistent,
                 "invalid": errors, "judged": judged, "samples": total,
                 "deployed_recall": [out["deployed_view"]["recall"]["k"],
                                     out["deployed_view"]["recall"]["n"]]})
    (RESULTS_DIR / "selfcheck-semantic.json").write_text(
        json.dumps({"rules": RULES, "passed": ok, "checks": rows}, indent=2) + "\n"
    )
    print("SELF-CHECK", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
