"""静态投毒检测：扫 tool 的 name/title/description/inputSchema/annotations（SPEC §2 T1/T6 / §4 / §7 M3）。

命中处置由 ``inspect.static_checks.on_hit`` 决定：
- ``deny``（默认）：该 tool 从 ``tools/list`` 响应里**剥离**，一个都不剩就返空列表
  （SPEC §5 第六行）。模型看不到这个工具，后续调用自然走 no-match deny。
- ``warn``：只记 guard.log + 审计，不剥离。

本模块只负责**扫出命中**，剥不剥离由 proxy 看 ``config.on_hit`` 决定 ——
两种模式扫描逻辑完全一样，报告也一样。

关键细节：
- ``inputSchema`` 要**递归扫所有字符串叶子**（字段的 ``description``、``enum`` 值、
  ``title``、``default`` 全都能藏东西）—— SPEC §2 末尾的 full-schema poisoning 那条
  ``TODO(待验证)`` 明确要求 v1 把 inputSchema 纳入扫描范围。``annotations`` 同理。
- 命中片段写审计前必须做**可见化转义**（:func:`visible_escape`）：ANSI 存成字面量
  ``\\x1b[``，不能把控制字符原样写进 JSONL，否则 ``cat`` 审计文件时终端会被二次攻击
  （SPEC §7 M3-3 的验收就是查这个）。

依赖方向：types / errors / config。**不 import proxy / audit。**
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence

from mcp_guarder.errors import DetectorError
from mcp_guarder.types import (
    DetectorName,
    JsonObj,
    JsonValue,
    StaticCheckReport,
    StaticChecksConfig,
    StaticHit,
)

#: 命中片段写进审计/日志时保留的最大字符数，超了截断加省略号。
EXCERPT_MAX_CHARS = 120

#: tool 没有可用 ``name`` 时的占位名。
UNNAMED_TOOL = "<unnamed>"


def scan_tools(
    tools: Sequence[JsonObj],
    *,
    config: StaticChecksConfig,
) -> StaticCheckReport:
    """检测器统一入口：扫一批 tool。

    - ``config.enabled`` 为 False → ``StaticCheckReport(skipped=True)``。
    - 逐 tool 逐字段逐规则跑，**所有命中都要收集**（不要 short-circuit）：
      SPEC §7 M3-1 的验收要求同一个描述同时命中 ``hidden-instruction-tag``
      和 ``read-extra-file`` 两条。

    :raises DetectorError: 内部异常包成 ``DetectorError.wrap(DetectorName.STATIC_CHECKS, exc)``。
        注意正则本身在配置解析期就编译过了，运行期主要防的是奇怪的数据形态
        （tool 不是 dict、字段是二进制之类）和 catastrophic backtracking。
        形态怪到扫不动就 fail-closed：整条 ``tools/list`` 被 proxy 拒掉，不放行未扫过的内容。
    """
    if not config.enabled:
        return StaticCheckReport(hits=(), skipped=True)

    try:
        hits: list[StaticHit] = []
        for tool in tools:
            hits.extend(scan_tool(tool, config=config))
        return StaticCheckReport(hits=tuple(hits), skipped=False)
    except DetectorError:
        raise
    except Exception as exc:  # noqa: BLE001 —— 检测器故障统一形态，proxy 只认 DetectorError
        raise DetectorError.wrap(DetectorName.STATIC_CHECKS, exc) from exc


def scan_tool(tool: JsonObj, *, config: StaticChecksConfig) -> tuple[StaticHit, ...]:
    """扫单个 tool，返回它的全部命中。tool 没有 ``name`` 时用 ``"<unnamed>"`` 占位。"""
    if not isinstance(tool, Mapping):
        # 正常的 MCP server 不会这么发。形态不对就抛，由 scan_tools 包成 DetectorError → fail-closed。
        raise TypeError(f"tool entry must be a JSON object, got {type(tool).__name__}")

    raw_name = tool.get("name")
    tool_name = raw_name if isinstance(raw_name, str) and raw_name else UNNAMED_TOOL

    hits: list[StaticHit] = []
    for field_path, text in iter_scan_targets(tool, config.scan_fields):
        for rule_id, match in _iter_matches(text, config):
            hits.append(
                StaticHit(
                    tool=tool_name,
                    rule_id=rule_id,
                    field_path=field_path,
                    excerpt=make_excerpt(text, match.start(), match.end()),
                )
            )
    return tuple(hits)


def scan_text(text: str, *, config: StaticChecksConfig) -> tuple[tuple[str, str], ...]:
    """扫一段纯文本，返回 ``((rule_id, 命中片段), ...)``（片段**未**转义）。

    ``redact`` 之外唯一的纯文本扫描入口，CLI ``diff`` 高亮投毒片段时也复用它。

    同一条规则在同一段文本里**只报第一处**：命中与否才是决策依据，报 50 遍
    只会把审计刷爆（也避免超长文本上做无谓的全量扫描）。
    """
    return tuple((rule_id, match.group(0)) for rule_id, match in _iter_matches(text, config))


def _iter_matches(text: str, config: StaticChecksConfig) -> Iterator[tuple[str, re.Match[str]]]:
    """逐条规则跑 ``re.search``，yield ``(rule_id, match)``。

    规则之间**不 short-circuit**（SPEC §7 M3-1 要求一个描述能同时报两条规则），
    单条规则内只取第一处命中。
    """
    if not isinstance(text, str):
        return
    for rule in config.rules:
        match = rule.regex.search(text)
        if match is not None:
            yield rule.id, match


def iter_scan_targets(
    tool: JsonObj,
    scan_fields: Sequence[str],
) -> Iterator[tuple[str, str]]:
    """遍历一个 tool 里所有该扫的字符串，yield ``(字段路径, 文本)``。

    - 顶层字段名不在 ``scan_fields`` 里的直接跳过。
    - 值是 str → 直接 yield，路径就是字段名。
    - 值是 dict/list（``inputSchema`` / ``annotations``）→ **递归所有字符串叶子**，
      路径拼成 ``inputSchema.properties.path.description`` / ``inputSchema.enum[0]``。
      **dict 的 key 本身也要扫**（key 里同样能塞指令），路径记成
      ``inputSchema.properties.<key>#key``。
    - 数字/bool/None 跳过。
    """
    for field_name in scan_fields:
        if field_name not in tool:
            continue
        yield from iter_string_leaves(tool[field_name], field_name)


def iter_string_leaves(value: JsonValue, prefix: str) -> Iterator[tuple[str, str]]:
    """递归 yield 任意 JSON 值里的 ``(路径, 字符串)``。:func:`iter_scan_targets` 的底层。

    嵌套深到把栈撑爆时 ``RecursionError`` 会一路抛给 :func:`scan_tools`，
    在那里包成 :class:`~mcp_guarder.errors.DetectorError` → fail-closed。
    **不做深度截断** —— 截断等于给攻击者留一条"埋深一点就扫不到"的旁路。
    """
    if isinstance(value, str):
        yield prefix, value
        return

    if isinstance(value, Mapping):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(key, str):
                # key 本身也能藏指令，单独当一个扫描目标。
                yield f"{child_prefix}#key", key
            yield from iter_string_leaves(child, child_prefix)
        return

    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            yield from iter_string_leaves(child, f"{prefix}[{index}]")
        return

    # 数字 / bool / None / 其它形态：没有可扫的文本。


#: 控制字符 → 可见字面量的映射表（``str.translate`` 用）。
_ESCAPE_TABLE: dict[int, str] = {
    0x1B: "\\x1b",
    0x0A: "\\n",
    0x0D: "\\r",
    0x09: "\\t",
}
for _cp in [*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0)]:
    _ESCAPE_TABLE.setdefault(_cp, f"\\x{_cp:02x}")
del _cp


def visible_escape(text: str) -> str:
    """把控制字符转成可见字面量，供审计和 guard.log 使用。

    ``\\x1b`` → 字面量 ``\\x1b``（4 个可见字符），``\\r`` / ``\\n`` / ``\\t`` 同理，
    其余 C0/C1 控制字符统一转 ``\\xNN``。可打印字符原样保留。

    SPEC §7 M3-3：「ANSI 隐藏指令样本 → ``ansi-escape`` 命中，审计里存的是可见的
    ``\\x1b[`` 字面量」。
    """
    if not isinstance(text, str):
        text = str(text)
    return text.translate(_ESCAPE_TABLE)


def make_excerpt(text: str, start: int, end: int, *, max_chars: int = EXCERPT_MAX_CHARS) -> str:
    """从命中位置切一段上下文，做完 :func:`visible_escape` 再返回，长度不超过 ``max_chars``。

    命中片段居中，两侧各补一点上下文；窗口两头还有内容时加省略号。
    转义之后可能变长（一个 ESC 变 4 个字符），所以最后再硬裁一刀保证不超长。
    """
    if max_chars <= 0:
        return ""

    length = len(text)
    start = max(0, min(start, length))
    end = max(start, min(end, length))

    span = end - start
    if span >= max_chars:
        window_start, window_end = start, start + max_chars
    else:
        pad = (max_chars - span) // 2
        window_start = max(0, start - pad)
        window_end = min(length, end + pad)

    body = visible_escape(text[window_start:window_end])
    lead = "…" if window_start > 0 else ""
    tail = "…" if window_end < length else ""
    excerpt = f"{lead}{body}{tail}"

    if len(excerpt) > max_chars:
        excerpt = excerpt[: max_chars - 1] + "…"
    return excerpt


def static_hit_log_line(server: str, tool: str, rule_ids: Sequence[str]) -> str:
    """拼 guard.log 那行：``static_checks: hidden-instruction-tag,read-extra-file``
    （SPEC §8 第 5 步的期望输出）。

    完整形态是 ``demo/echo static_checks: hidden-instruction-tag,read-extra-file``，
    尾巴逐字对齐 SPEC §8；前缀 ``[mcp-guarder]`` 由 GuardLog 自己加。
    """
    seen: dict[str, None] = {}
    for rule_id in rule_ids:
        seen.setdefault(rule_id, None)
    return f"{server}/{tool} static_checks: {','.join(seen)}"


__all__ = [
    "EXCERPT_MAX_CHARS",
    "UNNAMED_TOOL",
    "scan_tools",
    "scan_tool",
    "scan_text",
    "iter_scan_targets",
    "iter_string_leaves",
    "visible_escape",
    "make_excerpt",
    "static_hit_log_line",
]
