"""把 MCPTox 原始数据解析成 MCP tool 对象（docs/detection-eval-spec.md §3.3）。

- 投毒样本：``pure_tool.json``，每条一个被投毒的 tool 描述。
- 正常样本：``response_all.json`` → ``servers.*.clean_system_promot`` 里的
  ``Tool: / Description: / Arguments:`` 块。参数只有名字，不编造描述。

解析不了的样本进 ``parse_errors``，不静默丢弃。用法（打印对账结果）::

    .venv/bin/python -m eval.mcptox.load
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from eval.mcptox.fetch import CACHE_DIR, fetch

Label = Literal["poisoned", "clean"]

_TOOL_BLOCK = re.compile(
    r"^Tool: (?P<name>[^\n]+)\n"
    r"Description: (?P<desc>.*?)\n"
    r"Arguments:\n(?P<args>(?:- [^\n]*(?:\n|$))*)",
    re.M | re.S,
)
_ARG_LINE = re.compile(r"^- (?P<name>[^:]+):")
#: 248 条投毒描述末尾残留了字面量 ``\nArguments:\n- No arguments\n\n\n``（prompt 渲染残留，
#: 正常样本里没有）。不剥掉的话规则可以靠它"认出"投毒样本，属于标签泄漏。
_RENDER_RESIDUE = re.compile(r"\\nArguments:\\n.*\Z", re.S)
#: 解析规则有任何变化都要 +1，结果文件里会记录。
LOADER_VERSION = 2


@dataclass(frozen=True, slots=True)
class Sample:
    id: str
    server: str
    label: Label
    tool: dict[str, Any]
    paradigm: str | None = None
    risk: str | None = None


@dataclass(slots=True)
class Dataset:
    samples: list[Sample] = field(default_factory=list)
    parse_errors: list[dict[str, str]] = field(default_factory=list)
    #: 正常样本对账：clean_system_promot 解析出的 tool 名 vs 数据里的 tool_names。
    reconciliation: dict[str, Any] = field(default_factory=dict)

    def by_label(self, label: Label) -> list[Sample]:
        return [s for s in self.samples if s.label == label]

    @property
    def servers(self) -> list[str]:
        return sorted({s.server for s in self.samples})


def load(cache_dir: Path = CACHE_DIR) -> Dataset:
    fetch(cache_dir)
    ds = Dataset()
    _load_poisoned(cache_dir / "pure_tool.json", ds)
    _load_clean(cache_dir / "response_all.json", ds)
    return ds


def _load_poisoned(path: Path, ds: Dataset) -> None:
    raw = json.loads(path.read_text(encoding="utf-8"))
    for group in raw:
        for sample_id, item in group.items():
            try:
                tool = {
                    "name": item["tool_name"],
                    "description": _RENDER_RESIDUE.sub("", item["tool_content"]).strip(),
                    "inputSchema": {"type": "object"},
                }
                ds.samples.append(
                    Sample(
                        id=sample_id,
                        server=item["server_name"],
                        label="poisoned",
                        tool=tool,
                        paradigm=item.get("paradigm"),
                        risk=item.get("security risk"),
                    )
                )
            except (KeyError, AttributeError, TypeError) as exc:
                ds.parse_errors.append({"id": sample_id, "error": repr(exc)})


def _load_clean(path: Path, ds: Dataset) -> None:
    servers = json.loads(path.read_text(encoding="utf-8"))["servers"]
    per_server: dict[str, Any] = {}
    for server, entry in servers.items():
        prompt = entry.get("clean_system_promot") or ""
        declared = set(entry.get("tool_names") or [])
        headers = re.findall(r"^Tool: ", prompt, re.M)
        parsed: list[str] = []
        for match in _TOOL_BLOCK.finditer(prompt):
            name = match["name"].strip()
            properties = {
                m["name"].strip(): {}
                for line in match["args"].splitlines()
                if (m := _ARG_LINE.match(line))
            }
            ds.samples.append(
                Sample(
                    id=f"clean:{server}:{name}",
                    server=server,
                    label="clean",
                    tool={
                        "name": name,
                        "description": match["desc"].strip(),
                        "inputSchema": {"type": "object", "properties": properties},
                    },
                )
            )
            parsed.append(name)
        if len(parsed) != len(headers):
            ds.parse_errors.append(
                {
                    "id": f"clean:{server}",
                    "error": f"{len(headers)} Tool: headers but {len(parsed)} blocks parsed",
                }
            )
        per_server[server] = {
            "parsed": len(parsed),
            "declared": len(declared),
            "only_in_prompt": sorted(set(parsed) - declared),
            "only_in_tool_names": sorted(declared - set(parsed)),
        }
    ds.reconciliation = {
        "parsed_total": sum(v["parsed"] for v in per_server.values()),
        "declared_total": sum(v["declared"] for v in per_server.values()),
        "mismatched_servers": {
            k: v for k, v in per_server.items() if v["only_in_prompt"] or v["only_in_tool_names"]
        },
    }


def main() -> int:
    ds = load()
    print(
        json.dumps(
            {
                "poisoned": len(ds.by_label("poisoned")),
                "clean": len(ds.by_label("clean")),
                "servers": len(ds.servers),
                "parse_errors": ds.parse_errors,
                "reconciliation": ds.reconciliation,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
