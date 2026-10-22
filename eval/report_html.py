"""从 ``eval/results/*.json`` 生成 HTML 评测报告：``docs/eval/detection-report.html``。

配套文字版是 ``docs/eval/detection-report.md``。补充新的结果后重新执行一次::

    .venv/bin/python -m eval.report_html
"""

from __future__ import annotations

import html
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

from eval.run_static import rate

EVAL_DIR = Path(__file__).resolve().parent
RESULTS = EVAL_DIR / "results"
OUT = EVAL_DIR.parent / "docs" / "eval" / "detection-report.html"

#: 规则演进（历史实验编号）；现行内置规则的结果文件是 ``builtin-*.json``。
VERSIONS = ("v0", "v1", "v2")
VERSION_LABEL = {"v0": "v0 原内置 7 条", "v1": "v1 结构规则 19 条", "v2": "v2 扩充规则 31 条"}
#: GitHub 留出集：内置规则和 v2 / v3 的正则逐字相同，沿用 v3 的逐条命中，不重跑。
GITHUB_STATIC = "v3-benign"


def load(name: str) -> dict[str, Any] | None:
    path = RESULTS / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def pct(r: dict[str, Any] | None) -> str:
    if not r or r.get("rate") is None:
        return "—"
    return f"{r['rate'] * 100:.1f}%"


def frac(r: dict[str, Any] | None) -> str:
    if not r or not r.get("n"):
        return "—"
    return f"{r['k']}/{r['n']}"


def ci(r: dict[str, Any] | None) -> str:
    if not r or not r.get("ci95"):
        return "—"
    lo, hi = r["ci95"]
    return f"{lo * 100:.1f}–{hi * 100:.1f}%"


def esc(text: Any) -> str:
    return html.escape(str(text), quote=True)


# ────────────────────────────────────────────────────────────────────────────
# 图表：横向条形 + 95% CI 须线 + 直接标注 + 悬停提示
# ────────────────────────────────────────────────────────────────────────────


def bar_chart(
    title: str,
    subtitle: str,
    groups: list[tuple[str, list[tuple[str, int, dict[str, Any] | None, str]]]],
    series: list[tuple[str, int]],
    max_pct: float,
) -> str:
    """groups: [(组名, [(系列名, 系列槽位, rate 或 None, 备注)])]。"""
    row_h, gap_group, left, right, top = 22, 18, 150, 150, 8
    width = 760
    plot_w = width - left - right
    rows = sum(len(items) for _, items in groups)
    head_h = 20  # 组标题单独占一行，不和第一行的标签挤在一起
    height = top + rows * row_h + (gap_group + head_h) * len(groups) + 28

    def x(v: float) -> float:
        return left + plot_w * min(v, max_pct) / max_pct

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{esc(title)}" class="chart">']
    ticks = [max_pct * i / 4 for i in range(5)]
    axis_y = height - 22
    for t in ticks:
        parts.append(f'<line x1="{x(t):.1f}" y1="{top}" x2="{x(t):.1f}" y2="{axis_y}" class="grid"/>')
        parts.append(f'<text x="{x(t):.1f}" y="{axis_y + 16}" class="tick" text-anchor="middle">{t:.0f}%</text>')
    y = top
    for group, items in groups:
        parts.append(f'<text x="0" y="{y + 14}" class="group">{esc(group)}</text>')
        y += head_h
        for name, slot, r, note in items:
            cy = y + row_h / 2
            if r and r.get("n"):
                v = r["rate"] * 100
                tip = f"{group} · {name}：{frac(r)} = {pct(r)}（95% CI {ci(r)}）{(' · ' + note) if note else ''}"
                w = x(v) - left
                if w >= 8:  # 足够宽：数据端 4px 圆角，基线端直角
                    bar = (f'<path d="M{left},{y + 4} h{w - 4:.1f} a4,4 0 0 1 4,4 v{row_h - 16} '
                           f'a4,4 0 0 1 -4,4 h-{w - 4:.1f} z" class="bar s{slot}"/>')
                elif w > 0:
                    bar = f'<rect x="{left}" y="{y + 4}" width="{max(w, 2):.1f}" height="{row_h - 8}" class="bar s{slot}"/>'
                else:  # 0：不画条，只留基线上的短刻痕
                    bar = f'<line x1="{left}" y1="{y + 4}" x2="{left}" y2="{y + row_h - 4}" class="zero s{slot}"/>'
                parts.append(
                    f'<g class="mark" tabindex="0" data-tip="{esc(tip)}">'
                    f'<rect x="{left}" y="{y + 3}" width="{plot_w}" height="{row_h - 6}" class="hit"/>{bar}'
                )
                if r.get("ci95"):
                    lo, hi = (c * 100 for c in r["ci95"])
                    parts.append(
                        f'<line x1="{x(lo):.1f}" y1="{cy}" x2="{x(hi):.1f}" y2="{cy}" class="ci"/>'
                        f'<line x1="{x(lo):.1f}" y1="{cy - 4}" x2="{x(lo):.1f}" y2="{cy + 4}" class="ci"/>'
                        f'<line x1="{x(hi):.1f}" y1="{cy - 4}" x2="{x(hi):.1f}" y2="{cy + 4}" class="ci"/>'
                    )
                parts.append(
                    f'<text x="{left + plot_w + 8}" y="{cy + 4}" class="value">{frac(r)} · {pct(r)}'
                    f'{" · " + esc(note) if note else ""}</text></g>'
                )
            else:
                parts.append(
                    f'<text x="{left + 4}" y="{cy + 4}" class="muted">{esc(note or "未运行")}</text>'
                )
            parts.append(f'<text x="{left - 8}" y="{cy + 4}" class="label" text-anchor="end">{esc(name)}</text>')
            y += row_h
        y += gap_group
    parts.append("</svg>")
    legend = "".join(
        f'<span class="key"><i class="sw s{slot}"></i>{esc(name)}</span>' for name, slot in series
    )
    return (
        f'<figure><figcaption><b>{esc(title)}</b><span>{esc(subtitle)}</span></figcaption>'
        f'<div class="legend">{legend}</div>{"".join(parts)}</figure>'
    )


# ────────────────────────────────────────────────────────────────────────────
# 页面
# ────────────────────────────────────────────────────────────────────────────


def semantic_files() -> list[dict[str, Any]]:
    out = []
    for path in sorted(RESULTS.glob("semantic-*.json")):
        if path.name.endswith("-smoke.json"):
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        out.append(data)
    return out


def semantic_result(split: str) -> dict[str, Any] | None:
    """有效的 LLM 结果（跳过作废记录）。"""
    for d in semantic_files():
        if d["meta"]["split"] == split and d.get("validation", {}).get("valid", True):
            return d
    return None


def build() -> str:
    r = {f"{v}-{s}": load(f"{v}-{s}") for v in (*VERSIONS, "v3", "builtin")
         for s in ("dev", "test", "mcptox-all", "benign", "probes")}
    selfcheck = load("selfcheck-semantic")
    tests = load("test-summary")
    sem = semantic_files()

    def g(key: str, metric: str) -> dict[str, Any] | None:
        data = r.get(key)
        return data[metric] if data else None

    def dl(key: str, metric: str) -> dict[str, Any] | None:
        data = r.get(key)
        return data["deny_layer"][metric] if data and "deny_layer" in data else None

    def sm(split: str, metric: str) -> dict[str, Any] | None:
        data = semantic_result(split)
        return data[metric] if data else None

    # GitHub 的 deny 层：按现行内置规则的 deny 集合，从已有逐条命中重算。
    builtin_all = r.get("builtin-mcptox-all")
    deny_ids = set(builtin_all["deny_layer"]["rule_ids"]) if builtin_all else set()
    gh = r.get(GITHUB_STATIC)
    gh_all = gh["false_positive_rate"] if gh else None
    gh_deny = (
        rate(sum(bool(set(rules) & deny_ids) for rules in gh["hits"].values()), gh["counts"]["clean"])
        if gh and deny_ids else None
    )

    layer_chart = bar_chart(
        "内置规则：deny 层 vs 全部命中",
        "deny 层 11 条命中即剥离；其余 20 条只告警，开了 LLM 时交给 LLM。MCPTox 全量为拟合口径；GitHub 的 deny 层误报为非独立验证",
        [
            ("召回 · MCPTox 全量（拟合）", [
                ("deny 层", 1, dl("builtin-mcptox-all", "recall"), ""),
                ("全部命中", 2, g("builtin-mcptox-all", "recall"), ""),
            ]),
            ("召回 · 裁判注入样本", [
                ("deny 层", 1, dl("builtin-probes", "recall"), ""),
                ("全部命中", 2, g("builtin-probes", "recall"), ""),
            ]),
            ("误报 · GitHub 真实描述（留出）", [
                ("deny 层", 1, gh_deny, "非独立"),
                ("全部命中", 2, gh_all, ""),
            ]),
            ("误报 · 手写合法描述", [
                ("deny 层", 1, dl("builtin-probes", "false_positive_rate"), ""),
                ("全部命中", 2, g("builtin-probes", "false_positive_rate"), ""),
            ]),
        ],
        [("deny 层（自动剥离）", 1), ("全部命中（含 warn）", 2)],
        100,
    )
    llm_chart = bar_chart(
        "LLM 语义检测 vs 内置规则",
        "测试集召回只比较没看过测试集的检测方式：前 19 条规则（原 v1）只依据开发集编写，LLM 的 prompt 只依据开发集设计",
        [
            ("召回 · MCPTox 测试集（留出）", [
                ("前 19 条规则", 2, g("v1-test", "recall"), "原 v1"),
                ("LLM", 3, sm("test", "recall"), ""),
            ]),
            ("误报 · GitHub 真实描述（留出）", [
                ("deny 层", 1, gh_deny, "非独立"),
                ("全部命中", 2, gh_all, ""),
                ("LLM", 3, sm("benign", "false_positive_rate"), ""),
            ]),
            ("误报 · 手写合法描述", [
                ("deny 层", 1, dl("builtin-probes", "false_positive_rate"), ""),
                ("全部命中", 2, g("builtin-probes", "false_positive_rate"), ""),
                ("LLM", 3, sm("probes", "false_positive_rate"), ""),
            ]),
        ],
        [("内置规则 deny 层", 1), ("内置规则全部命中 / 前 19 条", 2), ("本地 LLM", 3)],
        100,
    )
    history_chart = bar_chart(
        "规则演进：MCPTox 投毒召回",
        "历史实验编号；测试集是泛化参考，v2 用全量数据编写，只能报告拟合覆盖率",
        [
            (VERSION_LABEL[v], [
                ("开发集", 1, g(f"{v}-dev", "recall"), ""),
                ("测试集", 2, g(f"{v}-test", "recall"),
                 "" if r.get(f"{v}-test") else "测试集已用于编写规则，不再评测"),
                ("全量覆盖", 3, g(f"{v}-mcptox-all", "recall"), "拟合" if v == "v2" else ""),
            ])
            for v in VERSIONS
        ],
        [("开发集", 1), ("测试集（留出）", 2), ("全量覆盖（拟合）", 3)],
        100,
    )

    def tile(value: str, label: str, sub: str) -> str:
        return f'<div class="tile"><div class="big">{esc(value)}</div><div>{esc(label)}</div><small>{esc(sub)}</small></div>'

    tiles = "".join([
        tile(pct(dl("builtin-mcptox-all", "recall")), "deny 层自动剥离",
             f"MCPTox {frac(dl('builtin-mcptox-all', 'recall'))}，正常样本 0 误报"),
        tile(pct(g("builtin-mcptox-all", "recall")), "内置规则全部命中",
             f"{frac(g('builtin-mcptox-all', 'recall'))}，拟合口径"),
        tile(pct(sm("test", "recall")), "本地 LLM · 测试集召回",
             f"{frac(sm('test', 'recall'))}，GitHub 误报 {frac(sm('benign', 'false_positive_rate'))}"),
        tile(f"{tests['tests']}" if tests else "—", "测试用例全部通过",
             f"失败 {tests['failures']} · 错误 {tests['errors']}" if tests else ""),
    ])

    # 明细表
    def cells(rc: dict[str, Any] | None, fp: dict[str, Any] | None) -> str:
        return (f"<td>{frac(rc)}</td><td>{pct(rc)}</td><td>{ci(rc)}</td>"
                f"<td>{frac(fp)} · {pct(fp)}</td><td>{ci(fp)}</td>")

    def row(name: str, key: str) -> str:
        d = r.get(key)
        if not d:
            return ""
        return f"<tr><td>{esc(name)}</td>{cells(d['recall'], d['false_positive_rate'])}</tr>"

    def deny_row(name: str, key: str) -> str:
        d = r.get(key)
        if not d or "deny_layer" not in d:
            return ""
        return f"<tr><td>{esc(name)}</td>{cells(d['deny_layer']['recall'], d['deny_layer']['false_positive_rate'])}</tr>"

    current_rows = "".join(
        deny_row(f"deny 层 / {split}", f"builtin-{split}") + row(f"全部命中 / {split}", f"builtin-{split}")
        for split in ("dev", "mcptox-all", "probes")
    ) + (
        f"<tr><td>deny 层 / benign（{GITHUB_STATIC} 重算）</td>{cells(None, gh_deny)}</tr>"
        f"<tr><td>全部命中 / benign（{GITHUB_STATIC}）</td>{cells(None, gh_all)}</tr>"
        if gh else ""
    )
    history_rows = "".join(
        row(f"{v} / {split}", f"{v}-{split}")
        for v in (*VERSIONS, "v3") for split in ("dev", "test", "mcptox-all", "benign", "probes")
    ) + "".join(deny_row(f"v3 deny 层 / {s}", f"v3-{s}") for s in ("dev", "mcptox-all", "benign", "probes"))

    if sem:
        sem_rows = "".join(
            (
                f"<tr><td>{esc(d['meta']['tag'])}</td><td>{esc(d['meta']['split'])}</td>"
                f"<td colspan=5>结果无效：{esc(d['validation']['reason'])}；保留原始记录，不计入结论。</td></tr>"
                if not d.get("validation", {}).get("valid", True) else
                f"<tr><td>{esc(d['meta']['tag'])}</td><td>{esc(d['meta']['split'])}</td>"
                f"<td>{frac(d['recall'])} · {pct(d['recall'])}<br><small>{ci(d['recall'])}</small></td>"
                f"<td>{frac(d['false_positive_rate'])} · {pct(d['false_positive_rate'])}"
                f"<br><small>{ci(d['false_positive_rate'])}</small></td>"
                f"<td>{esc(json.dumps(d.get('errors_by_kind', {}), ensure_ascii=False))}</td>"
                f"<td>{frac(d['deployed_view']['recall'])} / "
                f"{frac(d['deployed_view']['false_positive_rate'])}</td>"
                f"<td>{esc(d['meta']['elapsed_s'])}s</td></tr>"
            )
            for d in sem
        )
        sem_block = (
            "<table><thead><tr><th>模型</th><th>样本集</th><th>召回</th><th>误报</th>"
            "<th>失败</th><th>部署口径检出 / 误报</th><th>用时</th></tr></thead>"
            f"<tbody>{sem_rows}</tbody></table>"
            "<p>召回和误报附 Wilson 95% CI；失败不进入分类指标分母，但保留在部署口径中。"
            "这是独立 LLM 分类器的离线结果，不等于 deny 层 + LLM 的组合效果或 Agent 行为评测。"
            "GitHub 同名工具的 schema 变体按快照区分，不代表同样数量的独立工具。"
            "模型设置、漏报误报分析与延迟见<a href=\"detection-report.md\">文字报告</a>。</p>"
        )
    else:
        sem_block = '<p class="callout">还没有 LLM 评测结果。评测命令见文字报告的「复现」一节。</p>'

    if selfcheck:
        sc_rows = "".join(
            f"<tr><td>{'✅' if c['passed'] else '❌'} {esc(c['check'])}</td><td>"
            + (esc(f"runner {c['runner'][0]}/{c['runner'][1]}, FP {c['runner'][2]}/{c['runner'][3]} = "
                   f"regex {c['regex'][0]}/{c['regex'][1]}, FP {c['regex'][2]}/{c['regex'][3]}")
               if "runner" in c else
               esc(f"{c['invalid']} 条不合法 + {c['judged']} 条已判定 = {c['samples']} 条样本"))
            + "</td></tr>"
            for c in selfcheck["checks"]
        )
    else:
        sc_rows = "<tr><td colspan=2 class=muted>未运行</td></tr>"

    test_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{v}</td></tr>" for k, v in (tests or {}).get("by_module", {}).items()
    )

    return TEMPLATE.format(
        today=date.today().isoformat(),
        tiles=tiles,
        layer_chart=layer_chart,
        llm_chart=llm_chart,
        history_chart=history_chart,
        current_rows=current_rows,
        history_rows=history_rows,
        sem_block=sem_block,
        sc_rows=sc_rows,
        test_rows=test_rows,
    )


TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcp-guarder 投毒检测评测报告</title>
<style>
.viz-root {{
  color-scheme: light;
  --surface-1: #fcfcfb; --surface-2: #f3f2ef; --border: #e2e1dc;
  --text-primary: #0b0b0b; --text-secondary: #52514e; --text-muted: #7a7973;
  --series-1: #2a78d6; --series-2: #eb6834; --series-3: #1baf7a;
}}
@media (prefers-color-scheme: dark) {{
  :root:where(:not([data-theme="light"])) .viz-root {{
    color-scheme: dark;
    --surface-1: #1a1a19; --surface-2: #232321; --border: #3a3a37;
    --text-primary: #f0efec; --text-secondary: #c3c2b7; --text-muted: #8f8e86;
    --series-1: #3987e5; --series-2: #d95926; --series-3: #199e70;
  }}
}}
:root[data-theme="dark"] .viz-root {{
  color-scheme: dark;
  --surface-1: #1a1a19; --surface-2: #232321; --border: #3a3a37;
  --text-primary: #f0efec; --text-secondary: #c3c2b7; --text-muted: #8f8e86;
  --series-1: #3987e5; --series-2: #d95926; --series-3: #199e70;
}}
body {{ margin: 0; }}
.viz-root {{ background: var(--surface-1); color: var(--text-primary); min-height: 100vh;
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "PingFang SC", "Segoe UI", sans-serif; }}
main {{ max-width: 960px; margin: 0 auto; padding: 32px 24px 64px; }}
h1 {{ font-size: 26px; margin: 0 0 4px; }} h2 {{ font-size: 19px; margin: 40px 0 12px; }}
.meta, small, figcaption span, .muted {{ color: var(--text-muted); }}
.tiles {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 24px 0; }}
.tile {{ background: var(--surface-2); border-radius: 8px; padding: 14px 16px; }}
.tile .big {{ font-size: 28px; font-weight: 600; }}
.tile div:not(.big) {{ color: var(--text-secondary); }}
figure {{ margin: 16px 0 28px; }}
figcaption {{ display: flex; flex-direction: column; margin-bottom: 6px; }}
.legend {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 6px 0 8px; color: var(--text-secondary); font-size: 13px; }}
.key {{ display: inline-flex; align-items: center; gap: 6px; }}
.sw {{ width: 12px; height: 12px; border-radius: 3px; display: inline-block; }}
.chart {{ width: 100%; height: auto; font-size: 12px; }}
.grid {{ stroke: var(--border); stroke-width: 1; }}
.tick, .label {{ fill: var(--text-secondary); }}
.group {{ fill: var(--text-primary); font-weight: 600; font-size: 13px; }}
.value {{ fill: var(--text-primary); }}
.muted {{ fill: var(--text-muted); }}
.ci {{ stroke: var(--text-primary); stroke-width: 1.5; opacity: .55; }}
.hit {{ fill: transparent; }}
.zero {{ stroke-width: 3; }}
.zero.s1 {{ stroke: var(--series-1); }} .zero.s2 {{ stroke: var(--series-2); }} .zero.s3 {{ stroke: var(--series-3); }}
.mark:hover .bar, .mark:focus .bar {{ opacity: .85; }}
.mark:focus {{ outline: none; }}
.s1 {{ fill: var(--series-1); background: var(--series-1); }}
.s2 {{ fill: var(--series-2); background: var(--series-2); }}
.s3 {{ fill: var(--series-3); background: var(--series-3); }}
table {{ border-collapse: collapse; width: 100%; font-size: 13.5px; margin: 8px 0; }}
th, td {{ border-bottom: 1px solid var(--border); padding: 6px 8px; text-align: left; vertical-align: top; }}
th {{ color: var(--text-secondary); font-weight: 600; }}
pre {{ background: var(--surface-2); padding: 12px 14px; border-radius: 8px; overflow-x: auto; font-size: 13px; }}
.callout {{ background: var(--surface-2); border-left: 3px solid var(--series-2); padding: 10px 14px; border-radius: 4px; }}
ul {{ padding-left: 20px; }}
code {{ font-size: 13px; background: var(--surface-2); padding: 1px 4px; border-radius: 4px; }}
a {{ color: var(--series-1); }}
#tip {{ position: fixed; pointer-events: none; background: var(--text-primary); color: var(--surface-1);
  padding: 6px 10px; border-radius: 6px; font-size: 12.5px; max-width: 360px; opacity: 0; transition: opacity .08s; }}
.toggle {{ float: right; background: var(--surface-2); color: var(--text-secondary); border: 1px solid var(--border);
  border-radius: 6px; padding: 4px 10px; cursor: pointer; }}
@media (max-width: 720px) {{ .tiles {{ grid-template-columns: repeat(2, 1fr); }} }}
</style>
</head>
<body>
<div class="viz-root">
<main>
<button class="toggle" onclick="const r=document.documentElement;r.dataset.theme=r.dataset.theme==='dark'?'light':'dark'">切换深色 / 浅色</button>
<h1>mcp-guarder 投毒检测评测报告</h1>
<div class="meta">生成于 {today} · 数据：MCPTox @ f85189f，github-mcp-server @ e3809fe · 配套文字版：<a href="detection-report.md">detection-report.md</a> · 迭代过程：<a href="history/">history/</a></div>

<div class="tiles">{tiles}</div>

<h2>结论</h2>
<ul>
<li><b>自动剥离靠 deny 层：零误报，但覆盖有限。</b>11 条高精确度规则在 MCPTox 正常样本和 GitHub 真实描述上都没有误报，能自动拦下 MCPTox 的约五分之一。</li>
<li><b>区分意图靠 LLM。</b>本地 9B 模型在没见过的测试集上召回 94.2%，比只看开发集写出来的正则（72.0%）高 22 个点；GitHub 真实定义全部判为正常。</li>
<li><b>warn 规则只当线索。</b>31 条全部算上能覆盖 MCPTox 的 96.9%，但这是拟合数字；它们在真实描述上已经出现误报，句法上和投毒分不开，所以只告警。</li>
<li><b>没开 LLM 时，自动防护只有 deny 层。</b>deny 层 + LLM 的组合只做过 CLI 冒烟，没有全量评测。</li>
</ul>

<h2>内置规则</h2>
<p>31 条规则，每条自带处置方式。11 条 deny 命中即从 tools/list 剥离，不送 LLM；20 条 warn 只告警，开了 LLM 时由 LLM 判断意图。<code>read-extra-file</code>（<code>~/.ssh/</code>、<code>.env</code> 等路径）刻意放在 deny：没开 LLM 时这是最典型的投毒，代价是手写探测里 1 条合法描述被误剥离。</p>
{layer_chart}

<h2>LLM 语义检测</h2>
{llm_chart}
{sem_block}

<h2>规则演进</h2>
<p>v0–v3 是评测过程中的实验编号，规则已合并为一套内置规则（v3 的正则，<code>read-extra-file</code> 改回 deny）。</p>
{history_chart}

<h2>验证</h2>
<p>评测链路自检：本地假 OpenAI 服务用内置正则作答，评测 runner 必须复现出和直接跑正则完全相同的数字。</p>
<table><thead><tr><th>检查项</th><th>结果</th></tr></thead><tbody>{sc_rows}</tbody></table>
<p>单元测试（按模块）：</p>
<table><thead><tr><th>模块</th><th>用例数</th></tr></thead><tbody>{test_rows}</tbody></table>

<h2>明细数据</h2>
<p>现行内置规则：</p>
<table><thead><tr><th>检测层 / 样本集</th><th>召回</th><th>召回率</th><th>95% CI</th><th>误报</th><th>误报 95% CI</th></tr></thead>
<tbody>{current_rows}</tbody></table>
<p>规则演进（历史实验）：</p>
<table><thead><tr><th>规则 / 样本集</th><th>召回</th><th>召回率</th><th>95% CI</th><th>误报</th><th>误报 95% CI</th></tr></thead>
<tbody>{history_rows}</tbody></table>
<p class="meta">所有比例都附原始计数和 Wilson 95% 置信区间。留出集（test、benign）同一套正则只运行一次。</p>
</main>
<div id="tip" role="tooltip"></div>
</div>
<script>
const tip = document.getElementById('tip');
function show(e, el) {{
  tip.textContent = el.dataset.tip; tip.style.opacity = 1;
  const r = el.getBoundingClientRect();
  const x = e && e.clientX ? e.clientX : r.left + r.width / 2;
  const y = e && e.clientY ? e.clientY : r.top;
  tip.style.left = Math.min(x + 12, window.innerWidth - 380) + 'px';
  tip.style.top = (y + 14) + 'px';
}}
document.querySelectorAll('.mark').forEach(el => {{
  el.addEventListener('mousemove', e => show(e, el));
  el.addEventListener('focus', () => show(null, el));
  el.addEventListener('mouseleave', () => tip.style.opacity = 0);
  el.addEventListener('blur', () => tip.style.opacity = 0);
}});
</script>
</body>
</html>
"""


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(build(), encoding="utf-8")
    print(f"wrote {OUT}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
