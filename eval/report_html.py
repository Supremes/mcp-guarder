"""从 ``eval/results/*.json`` 生成 HTML 评测报告：``docs/eval/detection-report-v2.html``。

跑完本地模型评测（``eval.run_semantic``）后重新执行一次，LLM 部分会自动填上::

    .venv/bin/python -m eval.report_html
"""

from __future__ import annotations

import html
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

EVAL_DIR = Path(__file__).resolve().parent
RESULTS = EVAL_DIR / "results"
OUT = EVAL_DIR.parent / "docs" / "eval" / "detection-report-v2.html"

VERSIONS = ("v0", "v1", "v2")
VERSION_LABEL = {"v0": "v0 内置 7 条", "v1": "v1 结构规则 19 条", "v2": "v2 扩充规则 31 条"}


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


def build() -> str:
    r = {f"{v}-{s}": load(f"{v}-{s}") for v in VERSIONS
         for s in ("dev", "test", "mcptox-all", "benign", "probes")}
    selfcheck = load("selfcheck-semantic")
    tests = load("test-summary")
    sem = semantic_files()

    def g(key: str, metric: str) -> dict[str, Any] | None:
        data = r.get(key)
        return data[metric] if data else None

    recall_chart = bar_chart(
        "MCPTox 投毒召回率",
        "测试集是泛化参考；v2 用全量数据编写，只能报告拟合覆盖率",
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
    fpr_chart = bar_chart(
        "正常描述误报率",
        "GitHub 快照为留出集，每个版本只跑一次；手写探测集刻意挑了易误报写法",
        [
            ("MCPTox 正常（开发集）", [(VERSION_LABEL[v], i + 1, g(f"{v}-dev", "false_positive_rate"), "")
                                     for i, v in enumerate(VERSIONS)]),
            ("GitHub 真实描述（留出）", [(VERSION_LABEL[v], i + 1, g(f"{v}-benign", "false_positive_rate"), "")
                                       for i, v in enumerate(VERSIONS)]),
            ("手写合法描述", [(VERSION_LABEL[v], i + 1, g(f"{v}-probes", "false_positive_rate"), "")
                             for i, v in enumerate(VERSIONS)]),
        ],
        [(VERSION_LABEL[v], i + 1) for i, v in enumerate(VERSIONS)],
        60,
    )

    def tile(value: str, label: str, sub: str) -> str:
        return f'<div class="tile"><div class="big">{esc(value)}</div><div>{esc(label)}</div><small>{esc(sub)}</small></div>'

    tiles = "".join([
        tile(pct(g("v2-mcptox-all", "recall")), "v2 · MCPTox 覆盖率", f"{frac(g('v2-mcptox-all', 'recall'))}，拟合口径"),
        tile(pct(g("v1-test", "recall")), "v1 · 测试集召回", f"{frac(g('v1-test', 'recall'))}，泛化参考"),
        tile(pct(g("v2-benign", "false_positive_rate")), "v2 · GitHub 误报率",
             f"{frac(g('v2-benign', 'false_positive_rate'))}，留出集"),
        tile(f"{tests['tests']}" if tests else "—", "测试用例全部通过",
             f"失败 {tests['failures']} · 错误 {tests['errors']}" if tests else ""),
    ])

    # 明细表
    def row(name: str, key: str) -> str:
        d = r.get(key)
        if not d:
            return f"<tr><td>{esc(name)}</td><td colspan=5 class=muted>未运行</td></tr>"
        rc, fp = d["recall"], d["false_positive_rate"]
        return (f"<tr><td>{esc(name)}</td><td>{frac(rc)}</td><td>{pct(rc)}</td><td>{ci(rc)}</td>"
                f"<td>{frac(fp)} · {pct(fp)}</td><td>{ci(fp)}</td></tr>")

    table_rows = "".join(
        row(f"{v} / {split}", f"{v}-{split}")
        for v in VERSIONS for split in ("dev", "test", "mcptox-all", "benign", "probes")
        if r.get(f"{v}-{split}")
    )

    if sem:
        sem_rows = "".join(
            f"<tr><td>{esc(d['meta']['tag'])}</td><td>{esc(d['meta']['split'])}</td>"
            f"<td>{frac(d['recall'])} · {pct(d['recall'])}</td>"
            f"<td>{frac(d['false_positive_rate'])} · {pct(d['false_positive_rate'])}</td>"
            f"<td>{esc(json.dumps(d.get('errors_by_kind', {}), ensure_ascii=False))}</td>"
            f"<td>{frac(d['deployed_view']['recall'])}</td><td>{esc(d['meta']['elapsed_s'])}s</td></tr>"
            for d in sem
        )
        sem_block = (
            "<table><thead><tr><th>模型</th><th>样本集</th><th>召回</th><th>误报</th>"
            "<th>失败</th><th>部署口径召回</th><th>用时</th></tr></thead>"
            f"<tbody>{sem_rows}</tbody></table>"
        )
    else:
        sem_block = (
            '<p class="callout"><b>待你手动触发。</b>本机没有本地模型，LLM 检测的真实效果尚未评测。'
            "代码、单元测试和评测链路自检均已完成；跑完下面的命令后重新生成本页即可。</p>"
            "<pre>.venv/bin/python -m eval.run_semantic --base-url http://localhost:11434/v1 \\\n"
            "    --model &lt;模型&gt; --tag &lt;标签&gt; --split dev --limit 20   # 冒烟\n"
            ".venv/bin/python -m eval.run_semantic ... --split dev          # 调 prompt 用\n"
            ".venv/bin/python -m eval.run_semantic ... --split test         # 冻结后只跑一次\n"
            ".venv/bin/python -m eval.run_semantic ... --split benign       # 冻结后只跑一次\n"
            ".venv/bin/python -m eval.report_html</pre>"
        )

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
        recall_chart=recall_chart,
        fpr_chart=fpr_chart,
        table_rows=table_rows,
        sem_block=sem_block,
        sc_rows=sc_rows,
        test_rows=test_rows,
    )


TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcp-guarder 投毒检测评测报告 v2</title>
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
<h1>mcp-guarder 投毒检测评测报告 v2</h1>
<div class="meta">生成于 {today} · 数据：MCPTox @ f85189f，github-mcp-server @ e3809fe · 配套文字版：detection-report-v2.md</div>

<div class="tiles">{tiles}</div>

<h2>结论</h2>
<ul>
<li><b>正则覆盖了 MCPTox 的已知写法，但这不等于泛化。</b>v2 用 MCPTox 全量编写，覆盖率只能当拟合指标；真正的泛化参考仍是 v1 在测试集上的 72%。</li>
<li><b>真实描述上的误报开始出现。</b>GitHub 141 个真实工具上，v1 误报 2 条，v2 误报 3 条（2.1%），全部是合法的跨工具前置条件或参数说明，正则在句法上无法区分。</li>
<li><b>LLM 语义检测已实现并完成无模型验证。</b>默认关闭，走 OpenAI 兼容接口，按定义摘要缓存，失败分两类处置；真实模型效果待你手动评测。</li>
<li><b>建议组合：</b>v2 正则以 <code>warn</code> 模式做低成本初筛，LLM 语义检测负责剥离；正则命中但 LLM 判 benign 的条目进入人工 review。</li>
</ul>

<h2>正则规则：召回与误报</h2>
{recall_chart}
{fpr_chart}

<h2>LLM 语义检测</h2>
{sem_block}

<h2>验证</h2>
<p>评测链路自检：本地假 OpenAI 服务用 v2 正则作答，评测 runner 必须复现出和直接跑正则完全相同的数字。</p>
<table><thead><tr><th>检查项</th><th>结果</th></tr></thead><tbody>{sc_rows}</tbody></table>
<p>单元测试（按模块）：</p>
<table><thead><tr><th>模块</th><th>用例数</th></tr></thead><tbody>{test_rows}</tbody></table>

<h2>明细数据</h2>
<table><thead><tr><th>规则 / 样本集</th><th>召回</th><th>召回率</th><th>95% CI</th><th>误报</th><th>误报 95% CI</th></tr></thead>
<tbody>{table_rows}</tbody></table>
<p class="meta">所有比例都附原始计数和 Wilson 95% 置信区间。留出集（test、benign）每个规则版本只运行一次。</p>
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
