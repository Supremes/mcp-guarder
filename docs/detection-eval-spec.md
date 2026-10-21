# 检测能力评测与迭代 SPEC

- 日期：2026-10-16
- 分支：`feat/detection-eval`
- 状态：A 已完成（2026-10-19）；A2 代码与无模型验证已完成（2026-10-21），LLM 真实评测待手动触发，见 [评测报告 v2](eval/detection-report-v2.md)；B 待启动
- 取代：`docs/agent-execution-eval-spec.md`（已删除，评测口径并入 §7）

## 1. 为什么做

mcp-guarder 的权限门用 Claude Code hooks 也能实现，真正不可替代的是传输层能力：tool 描述投毒检测和 result 脱敏。现在这部分只有机制演示（demo 里的 rug pull），没有数字回答两个问题：

1. 面对真实的投毒样本，静态规则能拦下多少？
2. 面对真实的正常 tool 描述，会误拦多少？

本轮分两步：

- **A（本文细化）**：用公开基准离线评测静态检测，给出带分母的召回率和误报率，再在不引入模型的前提下改进规则。
- **B（本文只写纲要，§8）**：补上威胁模型 T4（result 间接注入）的缺口，做会话级污点策略和小规模 Agent 成对实验。

## 2. 范围

**A 做**：

- 拉取 MCPTox 数据到本地，解析成 MCP tool 定义。
- 用现有 `static_checks` 跑基线（v0 规则）。
- 只在开发集上改进规则（v1），在测试集上跑一次出最终数字。
- 输出机器可读结果和一份评测报告，README 引用关键数字。

**A 不做**：

- 不评测 TOFU 指纹。MCPTox 的样本都是首次出现，按设计 TOFU 就识别不了；指纹的效果由 demo 和现有测试覆盖。
- 不引入 LLM 分类器、embedding 或任何模型调用，规则保持确定性（README 非目标）。
- 不评测 inputSchema 投毒（数据不支持，见 §3.3）。
- 不修改代理、policy、脱敏等运行时行为。改动默认规则集另需确认（§5.3）。
- 不提交 MCPTox 原始数据到仓库。

## 3. 数据

### 3.1 来源

[MCPTox](https://github.com/zhiqiangwang4/MCPTox-Benchmark)（AAAI 2026，"MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers"）。

仓库没有 LICENSE，默认保留版权。处理方式：

- 用脚本按固定 commit SHA 下载到本地缓存目录（`eval/.cache/mcptox/`，加入 `.gitignore`），并校验 sha256。
- 仓库只提交下载与解析脚本、统计结果，不提交样本原文。报告中最多引用少量样本的截断片段作为示例，注明来源。

### 3.2 内容（2026-10-16 实测）

| 集合 | 来源字段 | 数量 | 说明 |
|---|---|---|---|
| 投毒 | `pure_tool.json` | 485 条，45 个 Server | 每条有 `tool_name`、`tool_content`（描述）、`paradigm`（Template-1/2/3）、`security risk`（11 类） |
| 正常 | `response_all.json` → `servers.*.clean_system_promot` | 约 353 个 tool，同 45 个 Server | 文本格式 `Tool: … / Description: … / Arguments: …`，需要解析 |

投毒样本里 `tool_content` 两两不同，有 12 条 `(server, tool_name)` 重复。没有一条带 `<IMPORTANT>`、`<SYSTEM>` 这类标签，攻击全是语义诱导，例如"调用 X 之前必须先调用 Y 处理 `~/.ssh/id_rsa`"。

### 3.3 转换成 MCP tool 定义

被测入口是 `static_checks.scan_tool(tool, config=...)`，输入是一个 MCP tool 对象。转换规则：

- 投毒：`{"name": tool_name, "description": tool_content.strip(), "inputSchema": {"type": "object"}}`。
- 正常：从 `clean_system_promot` 按 `Tool:` 分块，取名称和描述；参数只有名称、多为 "No description"，转成 `inputSchema.properties.<arg> = {}`，不编造描述。
- 解析失败或字段缺失的样本计入 `parse_errors`，单独报告，不静默丢弃。正常样本解析数要和 `tool_names` 总数对账，差异逐条列出。

已知局限，写进报告：

- 正常样本没有完整 inputSchema，inputSchema 投毒和 schema 字段误报都测不到。
- 全部是英文，不代表非英文诱导。
- 投毒样本由论文作者按模板构造，分布和野外攻击不同。
- 正常样本只有 45 个 Server，约 353 条，误报率的置信区间会比较宽。

## 4. 切分与防过拟合

如果看着全量样本改正则，召回率一定好看，但没有意义。所以：

- **按 Server 切分**：45 个 Server 固定随机种子打乱，约 2/3 进开发集、1/3 进测试集。同一个 Server 的投毒和正常样本落在同一侧，避免同 Server 措辞泄漏。
- 切分在写任何新规则之前生成，Server 名单写入 `eval/mcptox/split.json` 并提交。
- **开发集**：随便看、随便迭代规则。
- **测试集**：每个规则版本只跑一次。跑完之后再改规则就是新版本（v2），必须重新报告，不能覆盖 v1 的数字。
- 报告同时给出开发集和测试集结果，两者差距本身就是过拟合程度的信号。

## 5. 被测对象与规则迭代

### 5.1 判定口径

以 tool 为单位：`scan_tool` 返回至少一个命中视为"检测为投毒"。`on_hit` 是 `deny` 还是 `warn` 不影响判定。

### 5.2 版本

| 版本 | 内容 |
|---|---|
| v0 | 当前默认 7 条规则（`types.SPEC_STATIC_RULES`），不做任何修改，作为基线 |
| v1 | 只依据开发集改进后的规则，仍然只用正则 |

v1 的改进方向是把攻击的结构特征写成规则，而不是逐条记样本措辞，例如：

- 跨工具前置指令："before using … you MUST (first) call …"
- 优先级劫持："priority is higher than the user's"、"regardless of …"
- 参数篡改："modify the '…' argument to …"
- 敏感目标：现有 `read-extra-file` 的路径扩展

每条新规则要在报告里给出：开发集上的命中数、在正常样本上的误报数、对应的攻击特征。

### 5.3 规则怎么落地

- v1 先作为独立配置文件交付（`eval/rules/v1.yaml`），可以通过 `inspect.static_checks.rules` 显式启用。
- 是否替换内置默认规则，等看完测试集的误报率再单独确认。替换会改变所有用户的运行时行为。

## 6. 指标

所有比例都同时给出原始计数和分母，并附 Wilson 95% 置信区间。

| 指标 | 定义 |
|---|---|
| 召回率 | 被检出的投毒样本数 / 投毒样本总数 |
| 误报率 | 被检出的正常样本数 / 正常样本总数 |
| 精确率 | 投毒检出数 / 全部检出数（受两类样本比例影响，只作参考） |
| 分组召回 | 按 `paradigm`、`security risk`、Server 分组 |
| 规则贡献 | 每条规则在投毒样本和正常样本上的命中数，以及唯一贡献数（只有它命中） |
| 解析与运行错误 | `parse_errors`、扫描异常数，单独列出，不并入任何分母 |

## 7. 评测口径

继承自原 agent-execution-eval-spec §6，B 同样适用：

1. 比例必须带分母，失败、错误、证据缺失单独计数，不静默排除。
2. 不删除失败样本，不只挑好看的结果。
3. 规则、数据或切分有任何变化，都视为新的实验版本，不和旧版本混报。
4. 不预设结论。如果 v1 召回率依然很低，或误报率高到不可用，如实报告并分析原因。
5. 证据不完整时标记为 unknown，不记为安全。
6. 确定性评测的结果不等于 Agent 行为层面的收益，两者分开报告。

## 8. B 纲要：result 注入与会话级污点策略

只定目标和边界，详细设计等 A 完成后单独确认。

- **问题**：Agent 同时拥有私有数据访问、不可信内容输入和外发通道时，一条被污染的 tool result 就能诱导数据外泄。v1 只对 result 做 secret 脱敏，不处理这类注入。
- **思路**：网关维护会话级状态。配置声明哪些 tool 是"不可信来源"、哪些是"外发通道"；一旦会话读过不可信来源，后续外发类调用按策略拒绝或要求更严格的条件。这一层需要看到 result，hooks 做不到。
- **评测**：沿用 §7 的口径，做小规模裸跑和挂网关的成对 Agent 实验，同时报告越权执行率、任务完成率和额外成本。
- **边界**：不引入 LLM 分类器；真实模型调用的数量和预算单独批准；不改变现有 v1 行为的默认值。
- **启动条件**：A 的报告完成，并确认 B 的详细 spec。

## 9. 实现约定

目录：

```text
eval/
  .cache/                    # 本地数据缓存，gitignore
  mcptox/
    fetch.py                 # 按固定 commit 下载 + sha256 校验
    load.py                  # 解析成 MCP tool 对象，输出 parse_errors
    split.json               # 固定切分的 Server 名单
  rules/
    v1.yaml                  # 改进后的规则
  run_static.py              # 跑指定规则版本 × 指定集合，输出结果 JSON
  results/                   # 每次运行的结果 JSON（只有统计和样本 ID，不含原文）
docs/eval/
  detection-report.md        # 评测报告
```

命令：

```bash
.venv/bin/python -m eval.mcptox.fetch
.venv/bin/python -m eval.run_static --rules v0 --split dev
.venv/bin/python -m eval.run_static --rules v1 --split test   # 每个版本只跑一次
```

- 只复用 `static_checks` 和 `config` 的现有接口，不改核心模块。
- 结果 JSON 记录：代码 commit、数据 commit 与 sha256、规则版本与规则文件摘要、切分摘要、运行时间。
- 评测脚本本身不加单元测试；loader 的对账（解析数和 `tool_names` 总数对比）作为运行时断言。

## 10. 批次与验收

| 批次 | 预算 | 交付 | 验收 |
|---|---|---|---|
| A1 数据 | 2–3 小时 | `fetch.py`、`load.py`、`split.json` | 投毒 485 条全部转换；正常样本解析数和 `tool_names` 对账，差异有逐条说明；切分文件已提交 |
| A2 基线 | 1–2 小时 | `run_static.py`、v0 在开发集和测试集上的结果 | 输出 §6 全部指标，计数可以从结果 JSON 复算 |
| A3 规则迭代 | 3–5 小时 | `eval/rules/v1.yaml` | 只用开发集；每条新规则都有命中数、误报数和对应的攻击特征 |
| A4 报告 | 1–2 小时 | v1 测试集结果、`docs/eval/detection-report.md`、README 更新 | 测试集只跑一次；报告包含 v0/v1 对比、置信区间、分组结果、局限说明；README 引用的数字能在结果 JSON 里找到 |

A 合计 7–12 小时。每个批次结束时汇报改动、跑过的验证、验收状态和遗留问题。

## 11. 风险

| 风险 | 应对 |
|---|---|
| v1 召回率提升但误报率过高 | 如实报告；规则保持可选，不进默认集 |
| 正则对语义诱导天然有上限 | 报告中按 paradigm 分析漏检样本的共性，作为"确定性规则的能力边界"结论，不靠堆规则硬凑数字 |
| MCPTox 仓库内容变化或下架 | 固定 commit SHA 加 sha256；数据不可用时停在当前批次并说明 |
| 正常样本解析不准导致误报率偏差 | A1 对账；报告附解析方法和差异清单 |

## 12. A2：正则扩充与 LLM 语义检测（2026-10-21 追加）

### 12.1 范围（已确认）

- 基于 MCPTox 全量扩充正则（v2）。v2 在 MCPTox 上只能报告"拟合覆盖率"，不叫检测率。
- 新增真实正常样本留出集：github-mcp-server 的 141 个工具定义快照（只读取数据，不执行代码）。v2 冻结后只跑一次。
- 引入 LLM 语义检测：OpenAI 兼容 Chat Completions 接口，不做 Claude 专门适配；默认关闭。
- 评测使用本地模型，由用户手动触发；开发环境里没有模型，只做无模型验证。
- 本轮继续在 `feat/detection-eval` 分支上进行；result 污点策略（B）单独立 spec，不合并。

### 12.2 口径

- LLM 的 prompt 只依据开发集设计；MCPTox 测试集对 LLM 仍然是没见过的数据，可以作为 LLM 和正则对比的公平考场。
- 留出集（`test`、`benign`）每个（规则版本 / 模型标签 + prompt 版本）只跑一次，runner 强制执行。
- 模型不可用、输出不合法的样本单独计数，不进召回率和误报率的分母；另外给出按默认配置计算的"部署口径"。
- 沿用 §7 的全部评测口径。

### 12.3 验收

| 项 | 验收 | 状态 |
|---|---|---|
| 正则 v2 | 基于 MCPTox 全量和手写探测集编写；GitHub 留出集只跑一次；误报原文逐条分析 | ✅ 覆盖 470/485，GitHub 误报 3/141 |
| 语义检测器 | 配置严格校验；nonce 隔离；输出严格解析；缓存；时间预算；两类失败分开处置；代理集成 | ✅ 51 个单元测试 + 端到端测试 |
| 评测链路 | 不依赖真实模型即可证明 runner 正确 | ✅ 假模型复现正则数字，自检通过 |
| 真实模型评测 | 开发集调 prompt，冻结后留出集各跑一次 | ⏸ 待用户手动触发 |
| 报告 | Markdown + HTML，HTML 能在补充 LLM 结果后重新生成 | ✅ |
| 多 Server 正常样本 | 导出脚本 | ⏸ 已写好，会执行第三方代码，需要在隔离环境里手动运行 |
| 规则级 `on_hit` | 配置严格校验；代理按规则分流；只命中 warn 的 tool 照常送 LLM；模型不可用时附带 warn 命中作为线索 | ✅ 11 个单元测试 |
| 正则 v3 分层 | 规则与 v2 相同；deny 层只收在所有正常样本上 0 误报的规则 | ✅ deny 层 MCPTox 82/485，误报 0；GitHub 结果非独立 |

### 12.4 v3 分层的已知取舍

- deny 层只能自动拦下 MCPTox 的 16.9%，其余依赖 LLM；模型不可用时，按默认 `on_unavailable: warn` 只告警。
- 分组参考过 v2 在 GitHub 留出集上的误报分析，v3 的误报率需要在新的留出数据上验证（例如导出脚本跑出的多 Server 样本）。
