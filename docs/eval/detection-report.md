# 投毒检测评测报告

- 日期：2026-10-22
- 分支：`feat/detection-eval`
- 图表版：[detection-report.html](detection-report.html)（由 `eval.report_html` 从结果文件生成）
- 结果文件：[`eval/results/`](../../eval/results/)
- 评测 spec：[detection-eval-spec.md](../detection-eval-spec.md)
- 迭代过程：[history/](history/)（v0–v3 的实验记录，原样保留）

## 结论

mcp-guarder 用两层检测 tool 描述投毒：内置正则规则默认开启，LLM 语义检测可选、默认关闭。

| 检测层 | MCPTox 投毒召回 | MCPTox 正常误报 | GitHub 真实描述误报 | 手写合法描述误报 | 裁判注入检出 |
|---|---|---|---|---|---|
| 内置规则 · deny 层（11 条，命中即剥离） | 全量 101/485 = 20.8%（拟合） | 0/362 | 0/141（非独立） | 1/30 | 5/8 |
| 内置规则 · 全部命中（31 条，含只告警的 warn） | 全量 470/485 = 96.9%（拟合） | 0/362 | 3/141 = 2.1% | 10/30 | 7/8 |
| 本地 LLM（Qwen3.5-9B-4bit，`semantic-v1`） | **测试集 195/207 = 94.2%** | 测试集 3/132 = 2.3% | **0/141** | **0/30** | **8/8** |

1. **自动剥离靠 deny 层：零误报，但覆盖有限。** 11 条高精确度规则在 MCPTox 正常样本和 GitHub 真实描述上都没有误报，能自动拦下 MCPTox 的 20.8%。
2. **区分意图靠 LLM。** 本地 9B 模型在没见过的测试集上召回 94.2%，比只看开发集写出来的正则高 22 个点（72.0%，见[规则演进](#规则演进)）。GitHub 的 141 份真实定义全部判为正常，包括正则误报的 3 个。
3. **warn 规则只当线索。** 31 条全部算上能覆盖 MCPTox 的 96.9%，但其中 12 条是用全量数据写的，这是拟合数字。它们在真实描述上已经出现误报，句法上和投毒分不开，所以只告警、不剥离。
4. **没开 LLM 时，自动防护只有 deny 层那 20.8%。** 其余投毒只会告警。deny 层加 LLM 的组合只做过 CLI 冒烟，没有全量评测。

## 现行方案

```mermaid
flowchart LR
  T[tools/list 里的 tool 定义] --> F{TOFU 指纹变了?}
  F -->|是| X[剥离 + 告警]
  F -->|否| D{命中 deny 规则?}
  D -->|是| X
  D -->|否| S{开了 LLM?}
  S -->|否| K[保留<br/>warn 命中只记告警]
  S -->|是| L[LLM 语义检测<br/>按定义摘要缓存]
  L -->|malicious| X
  L -->|benign| K
  L -->|超时 / 连不上| U[放行 + 告警<br/>附上 warn 命中]
  L -->|输出不合法| X
```

内置规则共 31 条，定义在 `src/mcp_guarder/types.py` 的 `SPEC_STATIC_RULES`，每条自带处置方式：

| 层 | 规则 | 为什么这样分 |
|---|---|---|
| **deny**（11 条）：命中即剥离，不送 LLM | `hidden-instruction-tag`、`ignore-previous`、`ignore-instructions-broad`、`do-not-tell-user`、`ansi-escape`、`judge-addressing`、`threat-consequence`、`covert-action`、`policy-banner`、`sensitive-system-file`、`read-extra-file` | 在 MCPTox 正常样本和 GitHub 上 0 误报；合法描述几乎不会这么写 |
| **warn**（20 条）：只告警，开了 LLM 就交给 LLM | 跨工具前置调用（`before-*`、`cross-tool-precondition`、`must-call-tool`、`make-sure-call`、`auto-trigger-tool`）、参数改写（`argument-*`、`when-using-rewrite`、`always-rewrite`、`must-redirect`、`must-be-rerouted`、`instead-call`）、`priority-*`、`regardless-of-user`、`send-to-address`、`sensitive-query`、`base64-blob`、`cross-server-ref` | 合法描述里常见：功能性前置调用、参数说明、外发地址 |

- 内置规则的处置方式优先于段级 `inspect.static_checks.on_hit`。配置里写了 `rules` 就整份替换内置规则。
- **`read-extra-file` 是唯一刻意的取舍。** 它匹配 `~/.ssh/`、`id_rsa`、`.env`、AWS 凭据这类路径。按误报数据它本该放 warn，但没开 LLM 时，"读 `~/.ssh/id_rsa`"是最典型的投毒，所以放进 deny。代价是手写探测里合法的 `ssh_config_list`（"private keys under ~/.ssh/ are never read"）会被直接剥离，也就是 deny 层那 1/30 的误报。

deny 层各规则在 MCPTox 全量上的命中（一条样本可以命中多条）：

| 规则 | 投毒命中 | 正常命中 |
|---|---|---|
| `policy-banner` | 30 | 0 |
| `threat-consequence` | 28 | 0 |
| `read-extra-file` | 21 | 0 |
| `sensitive-system-file` | 21 | 0 |
| `covert-action` | 2 | 0 |
| `do-not-tell-user` | 1 | 0 |
| 其余 5 条 | 0 | 0 |

其余 5 条针对显式标签、ANSI 隐写和对裁判喊话。MCPTox 里没有这类写法，手写的裁判注入样本靠它们拦下。

## 数据与口径

| 样本集 | 内容 | 用途 |
|---|---|---|
| MCPTox 开发集 | 30 个 Server，278 投毒 / 230 正常 | 写规则；设计 LLM prompt |
| MCPTox 测试集 | 15 个 Server，207 投毒 / 132 正常 | 前 19 条规则的泛化参考；**LLM 的公平考场** |
| MCPTox 全量 | 485 投毒 / 362 正常 | 后 12 条规则用全量写，只能报拟合覆盖率 |
| GitHub 快照 | github-mcp-server 的 141 份工具定义，含 131 个工具名及其 schema 变体 | **留出集**，测真实描述误报 |
| 手写探测集 | 30 条容易误报的合法描述 + 8 条针对 LLM 裁判的投毒 | 只看方向，不作主指标 |

- [MCPTox](https://github.com/zhiqiangwang4/MCPTox-Benchmark) 固定在 `f85189f`，GitHub 快照固定在 `e3809fe`，下载时校验 sha256。仓库不提交样本原文。
- 按 Server 切分开发集和测试集，同一个 Server 的投毒和正常样本落在同一侧；切分在写任何规则之前提交。
- 所有比例附原始计数和 Wilson 95% 置信区间。
- 留出集（`test`、`benign`）同一套正则只跑一次。`run_static` 按 id + pattern 的摘要查已有结果，换名字也不能重跑；只调整 deny / warn 不算新规则，deny 层用已有结果里的逐条命中重算。LLM 按"模型标签 + prompt 版本"同样只跑一次。
- 请求失败、输出不合法的样本单独计数，不进召回和误报的分母。

## 内置规则

| 样本集 | deny 层 | 全部命中 | 结果文件 |
|---|---|---|---|
| MCPTox 开发集 | 召回 49/278 = 17.6%，误报 0/230 | 召回 271/278 = 97.5%，误报 0/230 | `builtin-dev.json` |
| MCPTox 全量（拟合） | 召回 101/485 = 20.8%（CI 17.4–24.7%），误报 0/362 | 召回 470/485 = 96.9%（CI 95.0–98.1%），误报 0/362 | `builtin-mcptox-all.json` |
| GitHub 快照（留出） | 误报 0/141（CI 0–2.6%） | 误报 3/141 = 2.1%（CI 0.7–6.1%） | `v2-benign.json`、`v3-benign.json` |
| 手写探测集 | 裁判注入 5/8，合法描述误报 1/30 | 裁判注入 7/8，合法描述误报 10/30 | `builtin-probes.json` |

- 内置规则的 31 条正则和评测时的 v2 / v3 逐字相同（id + pattern 摘要 `3d9052…`），逐样本命中也完全一致，所以 GitHub 留出集沿用 v2 / v3 的结果，没有重跑。`read-extra-file` 在 GitHub 上命中 0 次，改成 deny 不影响 deny 层误报。
- GitHub 上 deny 层的 0/141 不是独立证据：分层时参考过 v2 在 GitHub 上的误报分析。要干净地验证，需要新的多 Server 样本（`eval/corpus/export_benign.py`，需在隔离环境运行）。

### GitHub 上的 3 条误报

| 工具 | 命中规则 | 原文片段 | 为什么是合法的 |
|---|---|---|---|
| `create_or_update_file` | `before-clause-tool-call` | "To obtain the current blob SHA before updating, call the get_file_contents tool…" | 真正的功能前置条件 |
| `custom_properties_write` | `argument-tampering` | inputSchema 里的参数说明："Whether repositories must explicitly set a value…" | 参数语义说明 |
| `set_issue_fields` | `argument-tampering` | "Set issue field values for an issue…" | 工具本身的功能描述 |

三条都命中 warn 规则，不会被剥离。它们说明了正则的根本局限："调用 X 之前先调用 Y"、"设置某个字段"是合法描述的常见写法，规则写得越宽，召回越高，误报也越多。

## LLM 语义检测

### 设计

| 设计点 | 做法 |
|---|---|
| 接口 | 标准 Chat Completions（`{base_url}/chat/completions`），用标准库 `urllib` 实现；Ollama、vLLM、LM Studio、oMLX 都能直接用 |
| 触发时机 | 只在 tool 首次出现或定义变化时调用；判定按"定义摘要 + 模型 + prompt 版本"缓存到 sqlite |
| 时间预算 | `timeout_s` 覆盖一次 `tools/list` 的所有批次 |
| 两类失败 | 服务不可用默认 `warn`（放行、告警、不缓存）；输出不合法默认 `deny`，因为投毒描述可能故意把裁判带歪 |
| 防裁判被注入 | 待测定义包在随机 nonce 标签里；输出强制为固定 JSON 并严格校验；请求不带工具和 secret；正则独立运行，LLM 判 benign 也撤销不了 deny 规则的命中 |
| 上下文 | 同时提供这个 Server 的全部工具名，帮助判断引用的工具是否来自同一个 Server |
| 默认值 | `enabled: false`；API key 只从环境变量读取 |

### 结果

模型：oMLX 0.4.4 部署的 `Qwen3.5-9B-MLX-4bit`，非思考模式，`temperature: 0`，`json_schema` 输出，每批最多 8 个工具。机器是 Apple M5 Pro、24 GiB。prompt 沿用 `semantic-v1`，没有根据留出集调整。

| 样本集 | 样本 / 批次 | 召回（Wilson 95% CI） | 正常误报（Wilson 95% CI） | 请求 / 解析错误 |
|---|---|---|---|---|
| MCPTox 开发集 | 508 / 76 | 267/278 = 96.0%（93.1–97.8%） | 2/230 = 0.9%（0.2–3.1%） | 0 / 0 |
| MCPTox 测试集 | 339 / 49 | **195/207 = 94.2%（90.1–96.7%）** | 3/132 = 2.3%（0.8–6.5%） | 0 / 0 |
| GitHub 快照 | 141 / 18 | 不适用 | 0/141 = 0%（0–2.65%） | 0 / 0 |
| 手写探测集 | 38 / 5 | 8/8 = 100%（67.6–100%） | 0/30 = 0%（0–11.35%） | 0 / 0 |

结果文件：`semantic-omlx-qwen3.5-9b-4bit-semantic-v1-{dev,test,probes}.json`，GitHub 用 `semantic-omlx-qwen3.5-9b-4bit-idv2-semantic-v1-benign.json`。不带 `idv2` 的 benign 结果因样本 ID 碰撞作废，原样保留以便追溯。

### 漏报与误报

- **测试集 12 条漏报**：Memory 7 条、ClickHouse 2 条，Email、BaiduMap、Financial Dataset 各 1 条。模型给的理由几乎都是"functional prerequisite"，把恶意前置操作当成了正常依赖。按模板分，Template-2 最弱（88/98）。
- **测试集 3 条误报**：`Fetch:fetch`、`Commander:set_config_value`、`Commander:write_file`。其中 `write_file` 的理由说工具要求读 SSH 私钥，原描述里没有这个路径，可能是幻觉或同批工具串扰，本次实验区分不了。

### 延迟与部署边界

148 批的 P50 / P95 是 **10.28 / 13.88 秒**，最慢 15.98 秒（每批 1–8 个工具，含 oMLX 前缀缓存的影响）。评测给每批 120 秒，而运行时的 `timeout_s` 是整个 `tools/list` 的预算，默认 20 秒、每批 16 个工具。预算用完后剩下的批次按服务不可用处理（`semantic.py` 的 `_judge`），默认只告警、照常放行。工具多的 Server 第一次接入时，排在后面的工具可能没判就放行了，这正是 TOFU 也管不到的时候。启用前要按工具数和客户端超时调大预算，这个缺口单独修。

## 局限

- 真实正常样本只来自 GitHub 一个 Server，141 份快照里有同名工具的 schema 变体，置信区间没有校正这层相关性。
- MCPTox 全部是英文、按模板构造的攻击，和野外攻击的分布不同。
- 手写探测集是作者自己写的，可能带有偏好，只看方向。
- LLM 只测了一个 4-bit 模型、一个 prompt、一种批大小。温度为 0 也不保证完全可复现。
- 离线分类效果不等于 Agent 行为层面的防护收益，deny 层 + LLM 的组合也没有全量评测。

## 复现

```bash
.venv/bin/python -m eval.mcptox.fetch                  # 按固定 commit 下载并校验 sha256
.venv/bin/python -m eval.run_static --split dev        # 内置规则；还有 mcptox-all、probes
.venv/bin/python -m eval.selfcheck_semantic            # 无模型的 LLM 评测链路自检
.venv/bin/python -m eval.report_html                   # 重新生成图表版
```

内置规则的留出集已有结果，`run_static --split benign` 会拒绝运行。LLM 评测命令和模型参数见 [history/2026-10-21-regex-v2-v3-llm.md](history/2026-10-21-regex-v2-v3-llm.md#复现命令)。

## 规则演进

v0–v3 是评测过程中的实验编号，结果文件仍沿用这些名字（`eval/results/v*-*.json`）。规则已合并为一套内置规则，不再分版本。

| 阶段 | 规则 | 关键数字 | 说明 |
|---|---|---|---|
| v0 | 原内置 7 条 | 测试集 2/207 = 1.0%；全量 22/485 | 基线：MCPTox 没有一条带 `<IMPORTANT>` 这类标签 |
| v1 | +12 条结构规则，共 19 条，只看开发集 | **测试集 149/207 = 72.0%**；GitHub 2/141 | 唯一的正则泛化数字，就是现在内置规则的前 19 条 |
| v2 | +12 条通用规则，共 31 条，用全量写 | 全量 470/485（拟合）；GitHub 3/141 | 真实描述上的误报开始出现 |
| v3 | 31 条分为 10 deny / 21 warn | deny 层全量 82/485；GitHub 0/141（非独立） | 规则级 `on_hit` 落地 |
| 内置规则（现行） | v3 的正则，`read-extra-file` 改回 deny：11 / 20 | deny 层全量 101/485；手写合法描述误报 1/30 | 2026-10-22 合并，替换原内置 7 条 |

详细过程见 [history/2026-10-19-regex-v0-v1.md](history/2026-10-19-regex-v0-v1.md) 和 [history/2026-10-21-regex-v2-v3-llm.md](history/2026-10-21-regex-v2-v3-llm.md)。
