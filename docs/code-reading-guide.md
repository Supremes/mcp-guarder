# mcp-guarder 代码全流程阅读指南

TLDR：这是一个夹在 MCP Client 和 MCP Server 之间的 Python 命令行程序。先理解消息怎么进出，再读安全规则；不要从最长的文件第一行开始硬读。

本文面向能看懂少量 Python、但还不熟悉进程、JSON-RPC 和代理的读者。说明以当前源码为准；设计文档中的未来计划不等于已经实现的能力。

导航：[基本概念](#1-先建立一张脑内地图) / [文件地图](#4-每个文件属于哪个模块) / [完整流转](#5-一次会话的完整代码流转) / [模块阅读](#6-各模块怎么读) / [运维命令](#7-运维命令的代码流程) / [隔离练习](#9-不接真实模型的隔离练习)。

## 1. 先建立一张脑内地图

假设你在 AI 客户端里说：“调用 echo 工具，返回我输入的内容。”

实际执行工具的不是模型本身。客户端把请求发给 MCP Server，Server 执行后再返回结果。mcp-guarder 插在这条通信路径中，检查它能看到的消息。

```text
用户 -> AI 客户端 / MCP Client
                |
                | 客户端发出的 JSON-RPC 消息
                v
           mcp-guarder
                |
                | 通过检查后转发
                v
            MCP Server
                |
                | 工具描述 / 调用结果 / 其他消息
                v
           mcp-guarder -> MCP Client -> 用户
```

打开[交互式架构图](mcp-guarder-runtime.html)，先找客户端、代理和上游 Server，再看安全检查的分支。图中的策略、指纹、脱敏、审计是程序内部模块，不是额外部署的四个服务。

你需要先认识这些词：

| 概念 | 在本项目里怎么理解 |
| --- | --- |
| 进程 | 正在运行的程序。网关是一个进程，上游 Server 是它启动的另一个进程。 |
| 子进程 | 网关启动并管理的 Server；退出时也需要负责清理它。 |
| `stdin` / `stdout` | 程序输入与输出的字节通道。代理模式下用于协议通信，不是普通提示信息的显示区。 |
| `stderr` | 日志和错误提示通道；不能把调试 `print()` 随便写到代理的 `stdout`。 |
| stdio wrapper | 包住原 Server 命令，使用标准输入输出接管通信；不是 HTTP 服务。 |
| JSON-RPC | 消息格式。`method` 表示做什么，`params` 是参数，`id` 用于将请求与响应配对。 |
| 工具描述 | 工具的名字、说明、参数结构等。通常在真正调用工具之前就会被客户端读取。 |
| TOFU | Trust On First Use，首次见到时建立信任基线；之后比较是否改变，不代表首次内容已经安全。 |
| fail-closed | 某些安全检查出错时拒绝继续，而不是假装检查通过。具体动作还取决于消息分支。 |

三类 JSON-RPC 消息不要混淆：

```json
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
```

这是请求。它的响应具有相同的 `id`，但通常没有 `method`：

```json
{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}
```

没有 `id` 的通知不等待响应，例如：

```json
{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}
```

所以代理需要记住“某个请求 ID 对应哪种方法”，才能知道返回的消息应该进入哪个检查分支。

## 2. 第一次阅读的顺序

1. 读本文第 1 节，能分清客户端、网关、Server。
2. 读 [../pyproject.toml](../pyproject.toml)，找到命令行入口和运行依赖。
3. 读 [../src/mcp_guarder/cli.py](../src/mcp_guarder/cli.py)，先只看 `main()`、`split_argv()`、`cmd_proxy()`、`resolve_config()`。
4. 读 [../src/mcp_guarder/types.py](../src/mcp_guarder/types.py) 和 [../src/mcp_guarder/config.py](../src/mcp_guarder/config.py)，理解配置如何变成对象。
5. 带着一条 `tools/list` 和一条 `tools/call` 消息读 [../src/mcp_guarder/proxy.py](../src/mcp_guarder/proxy.py)。遇到安全模块调用时，再跳过去读。
6. 最后读审计、异常、运维子命令、demo 和测试，补齐失败与退出流程。

第一次不必逐行弄懂所有正则、锁和文件轮转。先回答三个问题：这个函数接收什么、决定什么、把结果交给谁？

## 3. 从命令行走进程序

入口文件：[../src/mcp_guarder/cli.py](../src/mcp_guarder/cli.py)。

假设执行：

```bash
mcp-guarder --config demo/demo.yaml -- python3 demo/rugpull_server.py
```

这是入口结构示意；实际隔离练习见本文后面的动手章节，避免使用默认路径写入个人信任记录。

```text
命令行入口 -> main(argv)
                |
                +-> split_argv() 按第一个 -- 分为两部分
                |      head: [--config, demo/demo.yaml]
                |      command: [python3, demo/rugpull_server.py]
                |
                +-> build_parser() / parse_args() 只解析 head
                |
                +-> 没有子命令 -> cmd_proxy(args, command)
                |                    |
                |                    +-> resolve_config() -> config.load_config()
                |                    +-> proxy.run_proxy(config, command, ...)
                |
                +-> diff / trust / audit -> 对应运维函数，不启动代理
```

**先读控制流，再读参数细节。** `main()` 决定执行哪个模式；`cmd_proxy()` 负责装配，真正收发和检查消息的是代理模块。

`--` 是网关参数和上游命令的分界。后半段按参数数组传递，不拼接成 shell 命令。上游命令自己的参数不能被网关的 argparse 消耗掉。

### `audit_mod` 是什么？

你会在入口文件中看到：

```python
from mcp_guarder import audit as audit_mod
```

意思是导入审计模块，并在这个文件里把它叫作 `audit_mod`。它不是对象实例，也不是函数。`audit_mod.audit_files_for(...)` 是调用审计模块中的函数；`audit_mod.GuardLog(...)` 则是通过该模块中的类创建日志对象。同样，`config_mod`、`proxy_mod` 等都是模块别名。

### 入口层的异常如何收尾？

`main()` 捕获配置错误、项目定义的错误以及未预期异常，打印到 `stderr`，返回退出码。代理模式的 `stdout` 留给 JSON-RPC；独立执行的 `diff`、`audit` 等运维命令可以向自己的 `stdout` 打印结果。

自查：能否解释为什么不能在代理处理函数里直接写 `print("开始检查")`？因为客户端会把这行调试文字当成协议输入。

## 4. 每个文件属于哪个模块

下面覆盖当前版本控制中的项目文件，以及本指南。不把虚拟环境、Git 内部文件、运行时日志和缓存当作需要逐个阅读的源码。

### 业务代码

| 文件 | 所属模块 | 初次阅读时关注什么 |
| --- | --- | --- |
| [../src/mcp_guarder/__init__.py](../src/mcp_guarder/__init__.py) | 包入口 | 包与版本信息；不是代理启动入口。 |
| [../src/mcp_guarder/cli.py](../src/mcp_guarder/cli.py) | 命令行 | 解析参数、选择模式、统一报错；`audit_mod` 等模块别名也从这里认识。 |
| [../src/mcp_guarder/types.py](../src/mcp_guarder/types.py) | 共享契约 | 配置对象、决策枚举、检测结果、报文与路由结果的类型。 |
| [../src/mcp_guarder/config.py](../src/mcp_guarder/config.py) | 配置 | YAML 读取、字段校验、正则编译和路径展开。 |
| [../src/mcp_guarder/proxy.py](../src/mcp_guarder/proxy.py) | 运行时编排 | 启动 Server、双向收发、请求 ID 记账、选择安全检查分支、关闭资源。 |
| [../src/mcp_guarder/fingerprint.py](../src/mcp_guarder/fingerprint.py) | 工具完整性 | 为工具定义生成摘要、保存首见基线、识别后续变化、保存快照。 |
| [../src/mcp_guarder/static_checks.py](../src/mcp_guarder/static_checks.py) | 描述静态检查 | 递归扫描工具定义中的字符串，按配置规则报告命中。 |
| [../src/mcp_guarder/policy.py](../src/mcp_guarder/policy.py) | 调用权限 | 对工具名和参数求值，返回允许或拒绝；不负责网络或进程收发。 |
| [../src/mcp_guarder/redact.py](../src/mcp_guarder/redact.py) | 内容脱敏 | 改写请求参数或返回内容，报告命中次数、是否改写、是否拒绝。 |
| [../src/mcp_guarder/audit.py](../src/mcp_guarder/audit.py) | 日志与审计 | JSONL 记录、人类日志、文件轮转、审计查询和故障降级状态。 |
| [../src/mcp_guarder/errors.py](../src/mcp_guarder/errors.py) | 故障契约 | 哪些错误应该拒绝消息、哪些必须退出，以及显示给人和模型的错误内容。 |

### 演示与现有测试

| 文件 | 所属模块 | 阅读用途 |
| --- | --- | --- |
| [../demo/README.md](../demo/README.md) | 演示文档 | 真实客户端的 rug pull 演示步骤；第一次先做本文的隔离练习。 |
| [../demo/demo.yaml](../demo/demo.yaml) | 演示配置 | 看一份完整可读的安全配置，不必先背全部配置类型。 |
| [../demo/rugpull_server.py](../demo/rugpull_server.py) | 演示 Server | 看工具描述如何变化，以及工具列表变更通知如何触发重新发现。 |
| [../tests/__init__.py](../tests/__init__.py) | 测试包 | 让测试辅助代码可作为 Python 包导入。 |
| [../tests/conftest.py](../tests/conftest.py) | 共享夹具 | 测试如何准备临时目录、配置及对象；不会使用个人真实存储。 |
| [../tests/harness/__init__.py](../tests/harness/__init__.py) | 回放包 | 回放辅助包入口。 |
| [../tests/harness/replay.py](../tests/harness/replay.py) | 协议回放 | 不接真实模型也能重放消息，观察转发、改写和拒绝。 |
| [../tests/test_config.py](../tests/test_config.py) | 配置验证 | 合法配置和应当拒绝启动的配置。 |
| [../tests/test_proxy.py](../tests/test_proxy.py) | 代理验证 | 消息路由、协议保真、拒绝分支、进程生命周期。 |
| [../tests/test_fingerprint.py](../tests/test_fingerprint.py) | 指纹验证 | 首见、不变、变化和快照存储。 |
| [../tests/test_static_checks.py](../tests/test_static_checks.py) | 静态检查验证 | 扫描字段、嵌套字符串、控制字符和规则命中。 |
| [../tests/test_policy.py](../tests/test_policy.py) | 权限验证 | 规则顺序、参数条件、默认拒绝及 `ask` 降级。 |
| [../tests/test_redact.py](../tests/test_redact.py) | 脱敏验证 | 掩码、字段删除、拒绝调用和入站处理边界。 |
| [../tests/test_audit.py](../tests/test_audit.py) | 审计验证 | 记录字段、轮转、读取与写入故障。 |

### 项目配置与文档产物

| 文件 | 所属模块 | 阅读用途 |
| --- | --- | --- |
| [../pyproject.toml](../pyproject.toml) | 构建与安装 | Python 版本、依赖、CLI 入口、pytest 配置。 |
| [../.gitignore](../.gitignore) | 开发辅助 | 哪些本地生成物不提交。 |
| [../LICENSE](../LICENSE) | 许可 | 项目的使用与分发条件。 |
| [../README.md](../README.md) | 项目入口 | 目标、接入方式和范围。 |
| [../SPEC.md](../SPEC.md) | 设计说明 | 设计动机、配置、故障语义及阶段规划；与源码不一致时先核对实现。 |
| [code-reading-guide.md](code-reading-guide.md) | 学习路线 | 本文：文件归属、模块指南、完整流转和练习。 |
| [agent-execution-eval-spec.md](agent-execution-eval-spec.md) | 评测设计 | 阅读评测目标与方案，不等同于已实现的评测系统。 |
| [cli-flow.svg](cli-flow.svg) | 局部流程图 | 辅助查看 CLI 分支；函数行为仍以源码为准。 |
| [mcp-guarder-runtime.architecture.json](mcp-guarder-runtime.architecture.json) | 架构图源 | Archify 可编辑结构；不是网关配置，程序运行不读取它。 |
| [mcp-guarder-runtime.html](mcp-guarder-runtime.html) | 交互式架构图 | 浏览器里查看总架构，无需启动开发服务器。 |
| [mcp-guarder-runtime.visual-check.json](mcp-guarder-runtime.visual-check.json) | 图形检查记录 | 各视口的溢出与截图检查数据。 |
| [mcp-guarder-runtime.visual-check.html](mcp-guarder-runtime.visual-check.html) | 截图索引 | 汇总查看生成的检查图片。 |
| [mcp-guarder-runtime.visual-check.1440x900.light.png](mcp-guarder-runtime.visual-check.1440x900.light.png) | 检查截图 | 小桌面尺寸、亮色主题。 |
| [mcp-guarder-runtime.visual-check.1440x900.dark.png](mcp-guarder-runtime.visual-check.1440x900.dark.png) | 检查截图 | 小桌面尺寸、暗色主题。 |
| [mcp-guarder-runtime.visual-check.2048x1320.light.png](mcp-guarder-runtime.visual-check.2048x1320.light.png) | 检查截图 | 大桌面尺寸、亮色主题。 |
| [mcp-guarder-runtime.visual-check.2048x1320.dark.png](mcp-guarder-runtime.visual-check.2048x1320.dark.png) | 检查截图 | 大桌面尺寸、暗色主题。 |

测试在这里是“带有预期结果的使用示例”。不必先通读测试框架；先看输入和断言，再回到对应函数。

## 5. 一次会话的完整代码流转

### 5.1 启动：先准备安全依赖，再启动 Server

从 [run_proxy()](../src/mcp_guarder/proxy.py#L1293) 进入：

```text
cli.cmd_proxy()
  -> config.load_config() -> GuarderConfig
  -> proxy.run_proxy()
       -> 创建 GuardLog / AuditLogger / FingerprintStore
       -> audit.open()：先确认审计可用
       -> 指纹检测启用时 store.open()
       -> 创建 Proxy -> Proxy.run()
            -> _spawn_upstream() 启动子进程
            -> 记录启动信息
            -> 启动线程 A，主线程执行 B
            -> 会话结束，清理子进程
       -> finally 关闭指纹库、审计和日志
```

审计在启动时不可用，不能带病开始；指纹检测启用但数据库打不开，也会阻止启动。

两个方向为什么要同时读？Server 可以主动发通知甚至反向请求，不能把协议实现成“每发一次请求，才读取一次结果”。

| 执行位置 | 读哪里 | 调哪个处理函数 | 写到哪里 |
| --- | --- | --- | --- |
| 线程 A：`_pump_client_to_upstream()` | 网关 `stdin` | `handle_client_line()` | 上游 `stdin`；拒绝时也可能直接写给客户端。 |
| 主线程 B：`_pump_upstream_to_client()` | 上游 `stdout` | `handle_upstream_line()` | 网关 `stdout`，即客户端的接收端。 |

“泵”在这里就是不断读一行、处理一行、写一行的循环。它不是第三方框架。双向写入有锁，避免两条消息的字节混在一起。

### 5.2 初始化：先理解透明转发

客户端发出 `initialize`，之后可能发送 `notifications/initialized`。它们不属于两种深加工方法，代理记录必要元数据并转发，不自行模拟握手结果。响应通过请求 ID 找回对应方法。

入口：[handle_client_line()](../src/mcp_guarder/proxy.py#L715) 与 [handle_upstream_line()](../src/mcp_guarder/proxy.py#L929)。

### 5.3 发现工具：`tools/list`

```text
Client -- tools/list 请求 --> 网关
  -> IdLedger 记住 id 对应 tools/list
  -> 原样转发给 Server
Server -- 相同 id 的响应 --> 网关
  -> IdLedger 取回请求方法
  -> _handle_tools_list_response()
       -> extract_tools()
       -> fingerprint.inspect_tools()：首见记账 / 比较变化
       -> static_checks.scan_tools()：检查工具定义字符串
       -> 汇总要移除的工具 -> strip_tools()
       -> 记录审计
  -> 将保留的工具列表发给 Client
```

读 [工具发现处理函数](../src/mcp_guarder/proxy.py#L977) 时，分别跟踪以下分支：

- 指纹不变、静态规则未要求阻断：保留工具。
- 指纹变化：移除该工具，保留旧信任基线，保存新快照供排查。
- 静态规则命中：`on_hit: deny` 移除，`warn` 仅记录告警。
- 检测器故障：清空工具列表；不把未检查的工具定义继续传给客户端。
- 响应没有可供处理的工具列表：走原样转发分支。

**这里没有串接 `redact_inbound()`。** 工具定义检查与调用结果脱敏是不同分支。部分工具被移除时，客户端收到的仍可能是正常的 `tools/list` 响应，不一定是整条请求报错。

**隐藏工具不等于撤销调用权限。** 当前调用路径按策略独立判断，不维护一个由 `tools/list` 过滤结果生成的全局禁用名单。客户端若直接按名字调用，仍会走下一节的权限门。

### 5.4 发起调用：`tools/call` 请求

入口：[_handle_tools_call_request()](../src/mcp_guarder/proxy.py#L758)。

```text
读 params.name / params.arguments，生成 audit_id
  -> 审计已降级？是：直接拒绝
  -> redact.redact_outbound() 处理参数
       -> deny_call 命中？是：直接拒绝
  -> policy.evaluate() 检查脱敏后的参数
       -> 不允许 / ask 降级？是：拒绝
  -> audit.build_record() / audit.write()
       -> 写入失败？是：拒绝
  -> 记录请求 id、工具名、tool_use_id、起始时间
  -> 有改写则重新序列化，否则保留原报文正文
  -> 转发给 Server
```

这是必须记住的顺序：**出站脱敏 -> 权限判断 -> 审计写入 -> 真正转发。** 判断某条参数规则时，需要考虑 secret 已经被替换或字段已经被删除。

拒绝分支返回 `Routed(client=...)`，没有 `upstream`，所以 Server 不会执行被拒绝的请求。拒绝由 `build_tool_error_response()` 生成 MCP 工具错误结果，而不是 JSON-RPC 顶层 `error`：

```json
{"jsonrpc":"2.0","id":2,"result":{"isError":true,"content":[{"type":"text","text":"mcp-guarder denied: ..."}]}}
```

### 5.5 调用返回：`tools/call` 响应

入口：[_handle_tools_call_response()](../src/mcp_guarder/proxy.py#L1102)。

```text
Server 返回相同 id 的响应
  -> IdLedger 确认它对应 tools/call
  -> 取回工具名、tool_use_id 和计时上下文
  -> redact.redact_inbound() 处理返回内容
  -> 写审计，payload 使用处理后的报文
  -> 有改写：序列化新报文；无改写：转发原正文
  -> Client 收到结果
```

回流脱敏器异常或该响应的审计写入失败时，用工具错误结果代替原响应。入站 `deny_call` 会降级为 `mask`：工具已经执行过，不能假装它没执行。

### 5.6 工具变更通知、反向请求和未知方法

Server 发 `notifications/tools/list_changed` 时，网关原样转发；**是否重新发送 `tools/list` 由客户端决定**。只有重新取得工具列表，才会再次进行指纹与静态检查。网关不会收到通知后自己重拉列表。

Server 也可能向 Client 发出 `roots/list`、`sampling/createMessage` 或 `elicitation/create`。`IdLedger` 用两个方向的账本区分 Client 和 Server 发起的请求，避免同一个 ID 在反向通信中被误认；客户端的响应再按原方向转回 Server。v1 对这些方法不做内容级权限或脱敏检查。

其他方法和没有匹配请求记录的响应走兼容转发路径。因此这不是一个覆盖任意 MCP 方法内容的通用过滤器。

### 5.7 失败与退出

| 情况 | 当前实现的动作 |
| --- | --- |
| 客户端发来无法解析的非 JSON 行 | 告警后转给 Server，让真正的 Server 处理协议问题。 |
| 上游发来非 JSON 行 | 视为 `UpstreamCrash`，结束会话；不向客户端输出这行协议噪声。 |
| 空行 | 忽略，不向客户端生成空行。 |
| 配置错误 | 不启动，退出码 `2`。 |
| 上游启动失败或非正常崩溃 | 结束会话，退出码 `3`。 |
| 审计在启动时不可用 | 不启动，退出码 `4`。 |
| 审计在运行中写入失败 | 标记降级；阻断调用，其他兼容转发路径不因此全部停止。 |
| Client 关闭输入或接收端 | 进入收尾，终止上游并关闭资源。 |

退出时不仅要关 Python 对象，还要终止 Server 的进程组并回收子进程。POSIX 系统使用独立进程组管理上游及其派生进程。

如果上游已经结束，但线程 A 仍堵在客户端输入上，`run_proxy()` 会在资源关闭后调用 `_hard_exit()`，绕过 Python 解释器关闭时的缓冲锁问题。这是特定退出路径，不是每条拒绝消息都会退出整个程序。

## 6. 各模块怎么读

这部分适合第二遍阅读。每次只打开一个模块，再对照一份相邻测试。不要把“检测报告”误当成“已经完成拦截”：多数安全模块只返回结果，由代理决定真正向哪边写消息。

### 6.1 类型与配置：先把配置变成可信的输入

阅读顺序：[共享类型](../src/mcp_guarder/types.py#L1) 中的 `GuarderConfig`、`Decision`、`DetectorOutcome`，然后进入 [load_config()](../src/mcp_guarder/config.py#L117)。

```text
配置路径 -> expand_path() -> load_yaml()
         -> parse_config() 构造各配置段、编译规则
         -> validate_config() 检查冲突
         -> GuarderConfig -> CLI / Proxy / 检测模块
```

输入是路径或已经解析的字典；输出是带类型的配置对象。`load_config()` 会执行解析和最终校验；练习中若直接调用 `parse_config()`，还应显式调用 `validate_config()`。

`dataclass` 可以先理解成“自动生成构造函数的数据容器”，`frozen=True` 禁止直接重设属性。它不等于把每个嵌套对象都变成不可变对象。`StrEnum` 则把 `allow`、`deny` 等字符串限制为有名字的选项。

配置缺失、未知字段、坏正则、非法操作符都会报错，不会偷偷放行。同一个 `tool` glob 字面量出现两次会被拒绝；不同 glob 是否重叠，不在这项静态校验的分析范围内。

`${PROJECT_DIR}` 的展开由配置模块统一提供，策略调用它。`starts_with` 只是字符串前缀判断，不是文件系统真实路径解析，也不是沙箱边界。

自查：为什么正则在启动期编译？尽早拒绝坏配置，避免每次消息都重复编译。对照 [../tests/test_config.py](../tests/test_config.py)。

### 6.2 代理：先读路由，再读 IO 细节

阅读顺序：[运行时入口](../src/mcp_guarder/proxy.py#L1293) -> `Proxy.run()` -> 两个 `handle_*_line()` -> 三个深加工函数 -> 两个泵和两个写出函数。

输入是一行 `bytes`，处理中用 JSON 字典检查内容，输出是 `Routed`。`Routed.upstream`、`Routed.client` 表示分别发给谁；`OutgoingLine` 区分原正文和需要序列化的新对象。

把 [IdLedger](../src/mcp_guarder/proxy.py#L303) 看作“请求方法登记表”，把 `_pending` 看作“工具名及计时补充信息”。两者用途不同。看到响应缺少 `method` 时，就知道为什么需要这些状态。

未改写的消息尽量保留原正文与未知字段；改写也只修改需要变更的位置，不把协议整条重新建模成固定字段的 dataclass。行结束符由 IO 层统一处理，“原样”并不是整个字节流绝对不变。

自查：策略拒绝后为什么请求不会到 Server？看 `Routed` 是否包含 `upstream`，再看泵如何消费这个返回值。对照 [../tests/test_proxy.py](../tests/test_proxy.py)。

### 6.3 指纹：判断“有没有变”，不是判断“是否安全”

阅读顺序：[指纹模块](../src/mcp_guarder/fingerprint.py#L1) 的 `inspect_tools()` -> `tool_digest()` -> `canonical_json()` -> `FingerprintStore` -> 快照函数。

输入是工具定义列表、配置、Server 名和存储对象；输出是 `FingerprintReport`，同时可能写入 SQLite 和快照文件。稳定的 JSON 编码加摘要算法，使 JSON 对象的键顺序变化不会被误当成语义变化。只对配置指定的字段计算信任指纹，不是对工具实现代码做签名认证。

| 状态 | 数据库与快照 | 代理后续动作 |
| --- | --- | --- |
| `FIRST_SEEN` | 保存基线，尝试保存工具快照。 | 继续后续静态检查，不是直接绕过全部检查。 |
| `UNCHANGED` | 更新最后见到时间。 | 继续静态检查。 |
| `CHANGED` | 尝试保存新快照，但不覆盖旧基线。 | 将变化工具从列表移除并告警。 |

快照是取证材料，保存快照发生 `OSError` 不会改变指纹判定；SQLite 等检测故障则会包装为 `DetectorError`。这两种存储失败的语义不同。

自查：为什么发现变化时不直接更新数据库？否则第二次收到同一变化就会变成“没变”。对照 [../tests/test_fingerprint.py](../tests/test_fingerprint.py)。

### 6.4 静态检查：找到可疑字符串，交给代理处置

阅读顺序：[scan_tools()](../src/mcp_guarder/static_checks.py#L44) -> `scan_tool()` -> `iter_scan_targets()` / `iter_string_leaves()` -> `_iter_matches()` -> `make_excerpt()`。

输入是工具列表和预编译规则；输出是包含工具名、规则 ID、字段路径、片段的 `StaticCheckReport`。模块本身不删除工具。

不仅检查 `description`，还按配置检查 `inputSchema`、`annotations` 等字段里的嵌套字符串，包含字典键名。对某个字符串，一条规则只取首个匹配，但会继续检查其他规则，所以一个工具能命中多种规则。

`visible_escape()` 将控制字符转换为可见字面量，避免输出片段时终端执行 ANSI 控制序列。它不是 secret 脱敏，也不是对 prompt injection 的完整语义理解。

自查：`deny` 与 `warn` 的扫描结果为什么可以一样？处置由代理决定，扫描只负责报告。对照 [../tests/test_static_checks.py](../tests/test_static_checks.py)。

### 6.5 策略：按顺序找第一条完整匹配的规则

阅读顺序：[evaluate()](../src/mcp_guarder/policy.py#L60) -> `rule_matches()` -> `evaluate_condition()` -> `_decide()`。

输入是裸工具名、脱敏后的参数和配置；输出是 `PolicyDecision`，包含决定、原因、规则 ID。正常拒绝是返回值，检测器内部异常才会抛 `DetectorError`。

真正的匹配条件是“工具名 glob 匹配，并且全部 `when` 条件成立”。不满足就继续看后面的规则；第一条完整匹配的规则决定结果。源码个别注释简写为“第一条 tool 匹配即定案”，阅读时应以函数实际逻辑为准。

| 条件 | 含义 |
| --- | --- |
| `starts_with` / `equals` | 对字符串做前缀 / 相等比较，先展开配置中的项目目录占位符。 |
| `matches` / `not_matches` | 对字符串执行正则 `search`；不是默认全串匹配。 |
| `one_of` | 字符串是否等于列表中某个展开后的值。 |
| `exists` | 检查参数键是否存在；`exists: false` 可以匹配参数缺席。 |

`tool` 使用大小写敏感的 glob，不是正则；条件读取参数键，不把点号自动解释成嵌套路径。除 `exists` 外，参数缺席或不是字符串会让条件不成立。没有 `when` 的规则不要求额外参数条件。

没有规则匹配则拒绝。`allow: ask` 在 v1 中也拒绝并提示，不会弹出交互确认框。

自查：第一条规则的工具名匹配，但参数条件失败，是否立刻拒绝？不会，会继续向下查找。对照 [../tests/test_policy.py](../tests/test_policy.py)。

### 6.6 脱敏：定位字段、匹配字符串、改写局部内容

阅读顺序：[出站入口](../src/mcp_guarder/redact.py#L79) / `redact_inbound()` -> `apply_at_paths()` -> `redact_value()` -> `redact_text()`。

输入是整条消息及脱敏配置；输出是 `RedactionReport`，里面有处理后的消息、命中统计、是否改写与是否拒绝。

扫描位置由配置指定。常见出站路径是 `params.arguments`；回流路径包括 `result.content[].text`、`result.content[].resource.text` 和 `result.structuredContent`。这里的路径语法只支持对象键和 `[]` 数组遍历，不是完整 JSONPath。不存在或结构不匹配的路径会跳过。

- `mask`：替换命中的字符串片段。
- `drop_field`：删除承载命中字符串的字段或数组元素。
- `deny_call`：出站拒绝调用，但为审计仍生成掩码内容；回流按掩码处理。

它处理字符串值，不改参数键名。允许列表在命中片段上检查；重叠命中按规则顺序处理，替换出来的掩码不会再次被其他规则扫描。

写时复制意味着只为改变的容器链生成新对象，未命中的内容继续保留。不能据此宣称所有 secret 都被处理：覆盖范围仍取决于扫描路径、规则、允许列表和开关。

自查：为什么回流 `deny_call` 不能撤销工具副作用？Server 已完成执行。对照 [../tests/test_redact.py](../tests/test_redact.py)。

### 6.7 审计：谁处理内容，谁记录决定

阅读顺序：[AuditLogger](../src/mcp_guarder/audit.py#L273) 的 `open()` -> `build_record()` -> `_summarize()` -> `write()`，再看 `GuardLog` 和读取函数。

`AuditLogger` 接收调用分支传来的决定、上下文和 payload，生成 `AuditRecord` 并追加到 JSONL，一行一个 JSON 对象。`GuardLog` 面向人，记录启动信息、告警和异常。两者不是同一份文件。

| 数据 | 主要用途 |
| --- | --- |
| `audit_id` | 一条审计事件的标识；与请求的 `rpc_id` 不同。 |
| `rpc_id` / `tool_use_id` | 分别关联协议请求，以及客户端可选传入的工具使用标识。 |
| `event` / `direction` | 哪种方法、哪个方向。 |
| `decision` / `decision_by` / `rule_id` | 决定是什么、由谁决定、哪条规则。 |
| `detectors` / `redactions_*` | 检测器结论与脱敏次数。 |
| `payload_digest` / `payload_preview` | 内容摘要与可选截断预览，不应把预览当作完整原文。 |

`build_record()` **不会自动调用脱敏器**。工具调用分支先脱敏，再把结果交给它；`tools/list` 的预览收敛为工具名和描述、schema 的摘要。指纹快照则保存工具原始定义以供 diff，不能将“调用审计使用脱敏内容”推广成“所有落盘文件都没有敏感信息”。

写入锁保证两条泵不会把 JSONL 行写乱；跨日切换文件，`fsync` 决定持久化频率。IO 失败会设置本会话的 `degraded` 状态，代理据此阻止后续调用。

自查：审计不可用为什么影响工具调用放行？当前设计要求允许执行之前先成功记录。对照 [../tests/test_audit.py](../tests/test_audit.py)。

### 6.8 错误契约：把拒绝、检测失败和会话故障分开

阅读 [../src/mcp_guarder/errors.py](../src/mcp_guarder/errors.py)，按 `GuarderError` -> `ConfigError` / `DetectorError` / `AuditUnavailable` / `UpstreamCrash` 的顺序。

这些类使调用层能够区分“配置有问题”“检测器没能完成”“审计不可用”“上游已坏掉”。`model_text` 是可交给客户端的错误内容，详细异常栈用于排障，不应混入协议 `stdout`。

看到 `raise ... from exc`，可以理解成保留原始错误原因并给上层一个统一错误类型；看到 `finally`，则关注成功和失败都必须关闭的资源。用第 5.7 节的表验证自己是否分清了当前消息失败与整个进程退出。

## 7. 运维命令的代码流程

回到 [CLI 子命令](../src/mcp_guarder/cli.py#L1)。这些命令会加载同一份配置，但不运行代理，也不执行上游工具。

| 命令 | 阅读顺序 | 关键边界 |
| --- | --- | --- |
| `diff <server> <tool>` | `cmd_diff()` -> 查询已信任指纹 -> 加载对应快照 -> `_latest_other_snapshot()` -> `difflib.unified_diff()`。 | 找的是该工具最新一份不同摘要快照，不保证它一定是恶意版本；输出前转义控制字符。 |
| `trust <server> [tool]` | `cmd_trust()` -> `FingerprintStore.delete()` -> `GuardLog.warn()`。 | 显式删除旧基线，下一次 `tools/list` 才重新 TOFU；不是此刻扫描并认证新版本。省略工具名会影响该 Server 的全部指纹。 |
| `audit tail` | `cmd_audit_tail()` -> `audit_files_for()` -> `tail_records()` -> `format_record()`。 | 只读查看，`-f` 持续跟随，`--server` 可选定命名空间。 |
| `audit grep <pattern>` | `cmd_audit_grep()` -> `grep_records()` -> `format_record()`。 | 正则匹配审计原始行，不是搜索工具快照。 |

实操时先检查 `diff`，确认变化来源之后再考虑 `trust`。不要把重新信任当作解决所有拦截的通用按钮；静态规则和调用权限仍独立生效。

## 8. 演示和测试模块怎么读

[演示 Server](../demo/rugpull_server.py#L1) 的阅读顺序是 `main()` -> `handle()` -> `current_description()` / `handle_tools_call()`。它自己按行读写 JSON-RPC，第一次返回干净的工具描述，第二次开始返回变化后的描述；`RUGPULL_STATE` 指定跨进程计数文件。它是安全验证用的探针，不是生产 Server 模板，不要把其中的指令交给真实模型执行。

[回放模块](../tests/harness/replay.py#L1) 的阅读顺序是 `default_script()` -> `encode()` -> `run_session()` -> `ReplayResult.response_for()`。它通过 `communicate()` 一次性输入固定消息并关闭输入，然后收集 stdout、stderr 和退出码。它不是实现了所有协议协商和通知行为的完整 MCP 客户端。

`assert_stdout_purity()` 检查协议输出是否都是合法 JSON-RPC；`assert_transparent()` 对比两次运行的报文正文。透明性对比只适用于全部放行、没有改写的场景，而且两边 Server 的状态必须相同。不要拿“干净的第一次运行”和“描述已改变的第二次运行”直接做透明性对拍，也不要比较具有随机性的模型自然语言输出。

读测试时，先找测试函数中的输入和最后的 `assert`，再看 fixture 准备了什么。`conftest` 的作用是复用准备工作；`tmp_path` 是 pytest 提供的临时目录。涉及进程和协议的问题看代理测试，纯规则问题看对应模块测试。测试覆盖特定行为，不等于所有真实客户端场景已经验证。

## 9. 不接真实模型的隔离练习

### 9.1 准备环境

在项目根目录执行，要求 Python 3.12 或更新版本。已经有安装好项目的虚拟环境时，跳过安装步骤；不要用系统旧版 Python 勉强运行。

```bash
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

可以先独立验证入口的参数切分，不启动上游、不创建日志：

```bash
.venv/bin/python -c 'from mcp_guarder.cli import split_argv; print(split_argv(["--config", "demo/demo.yaml", "--", "python3", "server.py", "--flag"]))'
```

预期得到两个列表：网关只拿到 `--config`，`--flag` 留在 Server 命令列表里。

### 9.2 跑通六个关键现象

下面的程序调用真实 CLI 和演示 Server，但只使用假样本，不接模型、不读取真实凭证，也不改客户端 MCP 配置。四类网关存储路径和 demo 状态都指向新建临时目录，程序结束后自动清理。

```bash
.venv/bin/python - <<'PY'
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from tests.harness.replay import assert_stdout_purity, default_script, run_session

with TemporaryDirectory(prefix="mcp-guarder-reading-") as temporary:
     directory = Path(temporary)
     config = yaml.safe_load(Path("demo/demo.yaml").read_text(encoding="utf-8"))
     config["inspect"]["fingerprint"]["store"] = str(directory / "fingerprints.sqlite")
     config["audit"]["path"] = str(directory / "audit/{server}-{date}.jsonl")
     config["audit"]["log_file"] = str(directory / "guard.log")
     config["audit"]["snapshot_dir"] = str(directory / "snapshots")
     config_path = directory / "config.yaml"
     config_path.write_text(yaml.safe_dump(config, allow_unicode=True), encoding="utf-8")

     environment = dict(os.environ)
     environment.update({
          "RUGPULL_STATE": str(directory / "rugpull.state"),
          "RUGPULL_NOTIFY_LIST_CHANGED": "0",
          "RUGPULL_ANSI": "0",
     })
     command = [
          sys.executable, "-m", "mcp_guarder.cli", "--config", str(config_path),
          "--", sys.executable, str(Path("demo/rugpull_server.py").resolve()),
     ]

     script = default_script(arguments={"text": "sk-" + "A" * 24})
     script.extend([
          {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
           "params": {"name": "exec_shell", "arguments": {}}},
          {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
           "params": {"name": "echo", "arguments": {"text": "leak"}}},
     ])
     first = run_session(command, script, env=environment)
     assert first.returncode == 0, first.stderr.decode("utf-8", "replace")
     assert_stdout_purity(first)
     first_results = {message["id"]: message["result"] for message in first.responses}
     first_tools = len(first_results[2]["tools"])
     outbound_masked = "[REDACTED:openai-key]" in first_results[3]["content"][0]["text"]
     policy_denied = first_results[4]["isError"]
     inbound_jwt_masked = "[REDACTED:bearer-jwt]" in first_results[5]["content"][0]["text"]

     second = run_session(command, default_script(), env=environment)
     assert second.returncode == 0, second.stderr.decode("utf-8", "replace")
     assert_stdout_purity(second)
     second_results = {message["id"]: message["result"] for message in second.responses}
     second_tools = len(second_results[2]["tools"])
     direct_echo_still_allowed = second_results[3]["isError"] is False

     assert first_tools == 1 and second_tools == 0
     assert outbound_masked and policy_denied and inbound_jwt_masked
     assert direct_echo_still_allowed
     print("first_tools:", first_tools)
     print("outbound_masked:", outbound_masked)
     print("policy_denied:", policy_denied)
     print("inbound_jwt_masked:", inbound_jwt_masked)
     print("second_tools:", second_tools)
     print("direct_echo_still_allowed:", direct_echo_still_allowed)
PY
```

预期输出：

```text
first_tools: 1
outbound_masked: True
policy_denied: True
inbound_jwt_masked: True
second_tools: 0
direct_echo_still_allowed: True
```

结果分别对应：第一次发现 echo、出站假 key 被替换、调用被策略拒绝、回流假 JWT 被替换、第二次发现时变化工具被过滤，以及直接按名字调用 echo 仍由原来的允许策略放行。

最后一行不是要绕过网关，而是让你验证发现检查与调用授权的实际边界。回放脚本明确发出了调用，不像普通客户端那样根据当前工具列表决定下一步。

`leak` 是演示 Server 的固定触发词，返回的是代码内置假样本；这里仅验证其中的 JWT 脱敏，不保证返回的任意其他字符串也一定匹配规则。

### 9.3 用已有测试定位不理解的分支

```bash
.venv/bin/python -m pytest -q tests/test_proxy.py tests/test_policy.py tests/test_redact.py
```

这个命令复用现有测试，不调用真实模型。需要追踪具体行为时，选择其中一个测试，在对应的 `handle_*` 或 `evaluate()` 函数处打断点，观察 `raw`、`message`、`rpc_id`、`decision` 和 `Routed`；不要通过向代理 stdout 添加调试打印来观察。

## 10. 阅读完成后的自查与排障入口

| 现象 / 问题 | 先去哪里看 |
| --- | --- |
| 命令启动就退出 | CLI 的错误输出、`load_config()`、审计和指纹存储打开流程。 |
| 工具列表里少了一个工具 | 工具列表响应处理、指纹变化、静态规则命中，再看 diff 与日志。 |
| 列表有工具，但调用被拒绝 | 出站脱敏结果、`policy.evaluate()`、审计降级状态。 |
| 参数或结果被改了 | 脱敏路径、规则、允许列表，以及 `redactions_*` 统计。 |
| 上游日志破坏协议 | 检查它是否错误地往 stdout 打普通文字。 |
| 客户端断开后还有进程 | 两个泵的 EOF 路径、`_terminate_upstream()` 和进程组清理。 |

最后尝试不看本文，回答四个问题：为什么响应要查 ID 账本？为什么列表过滤不是调用授权？为什么回流脱敏不能撤销执行？为什么审计写入要放在请求转发之前？能沿源码找到答案，就已经掌握了项目主干。

记住保护边界：只覆盖经过该代理的 stdio 消息；上游仍继承环境和 stderr，也能按自身权限访问文件与网络。它不是操作系统沙箱，不处理 HTTP/SSE，也不能保证阻止所有 prompt injection 或识别所有 secret。