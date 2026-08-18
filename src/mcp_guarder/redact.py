"""双向 secret 脱敏：出站 ``params.arguments`` + 回流 ``result``（SPEC §2 T5/T7 / §4 redact 段）。

扫描位置由配置给（都是"路径表达式"，见 :func:`parse_scan_path`）：
- ``outbound_scan: [params.arguments]``  → 递归扫所有字符串叶子
- ``inbound_scan: [result.content[].text, result.content[].resource.text, result.structuredContent]``

处置由 ``redact.action`` 决定：``mask``（默认，用 ``mask_template`` 换掉命中片段）、
``drop_field``（删掉命中的那个字段）、``deny_call``（整条 tools/call 直接拒）。

两条铁律：
1. **审计里存的必须是脱敏之后的内容**（``store_redacted_only: true``）——
   proxy 的顺序永远是「先脱敏，再拿脱敏后的对象去记账」。
2. **未命中的字段必须原样保留**：改写走深拷贝 + 定点替换，
   绝不能把报文重新建模一遍（会吃掉未知字段）。

实现上的几条自我约束（都是为了铁律 2）：
- **写时复制**：只有真的被改到的那条链路上的 dict/list 才浅拷贝一层，
  其余子树直接复用原对象引用；整棵树没命中就原样返回**同一个对象**（``is`` 可判）。
- **只动字符串叶子的值，不动 key**。改 key 等于改参数名，会把调用直接改坏。
- **命中区间在原文上一次性算完再重建字符串**，所以打码后的 ``[REDACTED:xxx]``
  绝不会被后一条规则二次命中。

依赖方向：types / errors。**不 import proxy / audit / config**
（config 会在启动校验时反过来调本模块的 :func:`parse_scan_path`，不能成环）。
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence

from mcp_guarder.errors import ConfigError, DetectorError
from mcp_guarder.types import (
    DetectorName,
    JsonObj,
    JsonValue,
    RedactAction,
    RedactConfig,
    RedactionCount,
    RedactionReport,
)


class _DropField:
    """``action: drop_field`` 时用的哨兵：告诉上一层"把承载这个值的字段整个删掉"。

    只在模块内部（以及 :func:`apply_at_paths` 与 :func:`redact_value` 之间）流转，
    永远不会出现在返回给 proxy 的报文里。
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - 纯调试用
        return "<redact.DROP>"


#: 唯一的 drop_field 哨兵实例。判断一律用 ``is DROP``。
DROP = _DropField()

#: ``action: deny_call`` 出现在回流方向时的降级提示语（回流没有"拒绝调用"可言）。
#: 本模块不碰 guard.log（不 import audit），由 proxy 拿这句话写一次日志。
INBOUND_DENY_CALL_DOWNGRADE = (
    "redact.action=deny_call has no meaning on the inbound direction; "
    "treated as mask for this response"
)

#: 路径表达式里一个合法 segment：``key`` 或 ``key[]``（``[]`` 可叠加表示嵌套数组）。
_PATH_SEGMENT_RE = re.compile(r"\A([A-Za-z0-9_-]+)((?:\[\])*)\Z")

#: ``[]`` token 的字面量。
_ARRAY_TOKEN = "[]"


# ────────────────────────────────────────────────────────────────────────────
# 入口：出站 / 回流
# ────────────────────────────────────────────────────────────────────────────


def redact_outbound(message: JsonObj, *, config: RedactConfig) -> RedactionReport:
    """出站方向（client→server）：按 ``config.outbound_scan`` 脱敏一条 ``tools/call`` 请求。

    - ``config.enabled`` 为 False → ``RedactionReport(message=message, skipped=True)``。
    - 没有任何命中 → 返回**原对象**且 ``counts`` 为空，proxy 会走字节级原样转发。
    - ``action: deny_call`` 且有命中 → ``deny=True``，proxy 直接拒这次调用
      （``decision_by=redact``），不要把打了码的参数发给上游。
      注意 ``report.message`` **仍然是打过码的那份** —— 因为审计要拿它记账，
      而"secret 不落盘"是硬要求（SPEC §4 ``store_redacted_only: true``）。

    :raises DetectorError: 内部异常包成 ``DetectorError.wrap(DetectorName.REDACT, exc)``。
    """
    try:
        if not config.enabled:
            return RedactionReport(message=message, skipped=True)
        new_message, counts = apply_at_paths(
            message,
            config.outbound_scan,
            lambda value: redact_value(value, config=config),
        )
        deny = bool(counts) and config.action is RedactAction.DENY_CALL
        return RedactionReport(message=new_message, counts=counts, deny=deny)
    except DetectorError:
        raise
    except Exception as exc:  # noqa: BLE001 - 检测器统一 fail-closed
        raise DetectorError.wrap(DetectorName.REDACT, exc) from exc


def redact_inbound(message: JsonObj, *, config: RedactConfig) -> RedactionReport:
    """回流方向（server→client）：按 ``config.inbound_scan`` 脱敏一条 ``tools/call`` 响应。

    覆盖范围必须包含 SPEC §4 列的三处：``result.content[].text``、
    内嵌资源全文 ``result.content[].resource.text``、任意 JSON 的 ``result.structuredContent``
    （递归所有字符串叶子）。

    ``action: deny_call`` 在回流方向没有"拒绝调用"可言 —— 此时按 ``mask`` 处理
    （``deny`` 恒为 False），并由 proxy 拿 :data:`INBOUND_DENY_CALL_DOWNGRADE`
    往 guard.log 提示一次配置语义降级。
    """
    try:
        if not config.enabled:
            return RedactionReport(message=message, skipped=True)
        new_message, counts = apply_at_paths(
            message,
            config.inbound_scan,
            lambda value: redact_value(value, config=config),
        )
        # deny_call 在这个方向降级成 mask：调用早就发出去了，拒无可拒。
        return RedactionReport(message=new_message, counts=counts, deny=False)
    except DetectorError:
        raise
    except Exception as exc:  # noqa: BLE001 - 检测器统一 fail-closed
        raise DetectorError.wrap(DetectorName.REDACT, exc) from exc


# ────────────────────────────────────────────────────────────────────────────
# 递归脱敏
# ────────────────────────────────────────────────────────────────────────────


def redact_value(value: JsonValue, *, config: RedactConfig) -> tuple[JsonValue, tuple[RedactionCount, ...]]:
    """递归脱敏任意 JSON 值里的所有字符串叶子。

    :return: ``(新值, 命中计数)``。没命中时**返回原对象本身**（不拷贝），
        让上层能靠 ``is`` 判断有没有改过。

    ``action: drop_field`` 时的返回约定：
    - 值本身就是命中的字符串 → 返回 :data:`DROP` 哨兵，
      由**调用方**（上一层 dict/list，或 :func:`apply_at_paths`）负责把承载它的字段删掉；
    - 命中发生在更深处 → 那一层自己把 key 删掉，本层照常返回新容器。

    dict 的 **key 一律不动**：改 key 等于改参数名，会把调用改坏
    （静态检查那边扫 key 是为了发现投毒，脱敏这边不是）。
    """
    if isinstance(value, str):
        new_text, counts = redact_text(value, config=config)
        if not counts:
            return value, ()
        if config.action is RedactAction.DROP_FIELD:
            return DROP, counts
        return new_text, counts

    if isinstance(value, list):
        groups: list[tuple[RedactionCount, ...]] = []
        new_items: list[JsonValue] = []
        changed = False
        for item in value:
            new_item, counts = redact_value(item, config=config)
            if counts:
                groups.append(counts)
            if new_item is DROP:
                changed = True  # drop_field：数组元素整个丢掉
                continue
            if new_item is not item:
                changed = True
            new_items.append(new_item)
        merged = merge_counts(*groups)
        return (new_items if changed else value), merged

    if isinstance(value, dict):
        groups = []
        new_obj: JsonObj = {}
        changed = False
        for key, item in value.items():
            new_item, counts = redact_value(item, config=config)
            if counts:
                groups.append(counts)
            if new_item is DROP:
                changed = True  # drop_field：把这个 key 删掉
                continue
            if new_item is not item:
                changed = True
            new_obj[key] = new_item
        merged = merge_counts(*groups)
        return (new_obj if changed else value), merged

    # None / bool / int / float：没有字符串内容可脱敏，原样返回。
    return value, ()


def redact_text(text: str, *, config: RedactConfig) -> tuple[str, tuple[RedactionCount, ...]]:
    """脱敏一段文本，返回打码后的文本和每条规则的命中次数。

    - 逐条规则 ``finditer``；命中片段先过 ``config.allowlist``（任一 allowlist 正则
      在该片段上 ``search`` 命中就跳过，不算数、不计数）。
    - ``mask_template`` 里只有 ``{rule_id}`` 一个占位符。
    - 多条规则可能命中重叠区间：**所有区间都在原文上算完**，按规则声明顺序取，
      后来的区间与已选区间重叠就丢弃（也不计数）；最后一次性重建字符串。
      所以替换进去的 ``[REDACTED:xxx]`` 不可能被后续规则重复命中。

    本函数是纯粹的 **mask 引擎**：``drop_field`` / ``deny_call`` 的处置在上层
    （:func:`redact_value` / :func:`redact_outbound`）做，这里照样返回打码后的文本，
    因为审计要的就是这份脱敏后的内容。
    """
    if not text or not config.rules:
        return text, ()

    # 已采纳的命中区间，按 start 有序，用于 O(log n) 判重叠。
    accepted: list[tuple[int, int, str]] = []
    starts: list[int] = []
    tally: dict[str, int] = {}

    for rule in config.rules:
        for match in rule.regex.finditer(text):
            start, end = match.span()
            if end <= start:
                continue  # 零长度命中（例如 `x*`）没有可替换的内容，跳过
            fragment = text[start:end]
            if _is_allowlisted(fragment, config.allowlist):
                continue
            if not _insert_span(accepted, starts, start, end, rule.id):
                continue  # 与已采纳区间重叠，按先声明的规则为准
            tally[rule.id] = tally.get(rule.id, 0) + 1

    if not accepted:
        return text, ()

    pieces: list[str] = []
    cursor = 0
    for start, end, rule_id in accepted:
        pieces.append(text[cursor:start])
        pieces.append(_render_mask(config.mask_template, rule_id))
        cursor = end
    pieces.append(text[cursor:])

    counts = tuple(
        RedactionCount(rule_id=rule.id, count=tally[rule.id]) for rule in config.rules if rule.id in tally
    )
    return "".join(pieces), counts


# ────────────────────────────────────────────────────────────────────────────
# 路径表达式
# ────────────────────────────────────────────────────────────────────────────


def parse_scan_path(path: str) -> tuple[str, ...]:
    """把 ``result.content[].resource.text`` 这种路径表达式拆成 token 序列。

    支持的语法**只有两种**（配置里出现别的形态 → ConfigError，由 config 校验时调本函数）：
    - ``.`` 分隔的对象 key
    - ``[]`` 表示"这一层是数组，对每个元素继续往下走"

    例：``result.content[].text`` → ``("result", "content", "[]", "text")``。
    不支持下标 ``[0]``、通配 ``*``、引号 key。
    """
    if not isinstance(path, str) or not path:
        raise ConfigError(
            "scan path must be a non-empty string",
            problems=[f"invalid scan path: {path!r}"],
        )

    tokens: list[str] = []
    for segment in path.split("."):
        matched = _PATH_SEGMENT_RE.match(segment)
        if matched is None:
            raise ConfigError(
                f"invalid scan path {path!r}",
                problems=[
                    f"bad segment {segment!r}: only `key` and `key[]` are supported "
                    "(no [0] index, no * wildcard, no quoted key)"
                ],
            )
        key, brackets = matched.group(1), matched.group(2)
        tokens.append(key)
        tokens.extend(_ARRAY_TOKEN for _ in range(len(brackets) // 2))
    return tuple(tokens)


def apply_at_paths(
    message: JsonObj,
    paths: Sequence[str],
    fn: Callable[[JsonValue], tuple[JsonValue, tuple[RedactionCount, ...]]],
) -> tuple[JsonObj, tuple[RedactionCount, ...]]:
    """在 ``message`` 的指定路径上套用 ``fn``，返回新报文和合并后的计数。

    要点：
    - 路径不存在就跳过，**不要报错**（不同 server 的 result 形态差别很大）；
      路径中间的类型对不上（比如 ``content`` 不是数组）同样跳过。
    - 只在真的发生改写时才做**写时复制**：沿路径把涉及的 dict/list 浅拷贝一层，
      没被碰到的子树直接复用原对象引用。这样既不破坏未知字段，又不用整棵树深拷贝。
    - ``fn`` 返回 :data:`DROP` 时，把承载这个值的 key（或数组元素）删掉。
    - 同一条 message 上多个路径的计数按 ``rule_id`` 合并求和（见 :func:`merge_counts`）。
    """
    current: JsonValue = message
    groups: list[tuple[RedactionCount, ...]] = []
    for path in paths:
        tokens = parse_scan_path(path)
        new_value, counts = _apply_tokens(current, tokens, fn)
        if counts:
            groups.append(counts)
        if new_value is DROP:
            # 路径只有一层且整个根被判 drop —— 报文根不允许消失，退化成保持原样。
            continue
        current = new_value
    # current 一定还是 dict：_apply_tokens 只会在内部做浅拷贝，不换类型。
    return current, merge_counts(*groups)  # type: ignore[return-value]


def merge_counts(*groups: Sequence[RedactionCount]) -> tuple[RedactionCount, ...]:
    """按 ``rule_id`` 合并计数，保持首次出现顺序。"""
    totals: dict[str, int] = {}
    for group in groups:
        for item in group:
            totals[item.rule_id] = totals.get(item.rule_id, 0) + item.count
    return tuple(RedactionCount(rule_id=rid, count=n) for rid, n in totals.items())


# ────────────────────────────────────────────────────────────────────────────
# 内部工具
# ────────────────────────────────────────────────────────────────────────────


def _apply_tokens(
    node: JsonValue,
    tokens: tuple[str, ...],
    fn: Callable[[JsonValue], tuple[JsonValue, tuple[RedactionCount, ...]]],
) -> tuple[JsonValue, tuple[RedactionCount, ...]]:
    """沿 token 序列往下走，在叶子上调 ``fn``；写时复制地把结果装回去。"""
    if not tokens:
        return fn(node)

    token, rest = tokens[0], tokens[1:]

    if token == _ARRAY_TOKEN:
        if not isinstance(node, list):
            return node, ()  # 形态对不上就跳过，不报错
        groups: list[tuple[RedactionCount, ...]] = []
        new_items: list[JsonValue] = []
        changed = False
        for item in node:
            new_item, counts = _apply_tokens(item, rest, fn)
            if counts:
                groups.append(counts)
            if new_item is DROP:
                changed = True
                continue
            if new_item is not item:
                changed = True
            new_items.append(new_item)
        return (new_items if changed else node), merge_counts(*groups)

    if not isinstance(node, dict) or token not in node:
        return node, ()

    child = node[token]
    new_child, counts = _apply_tokens(child, rest, fn)
    if new_child is DROP:
        new_obj = dict(node)
        del new_obj[token]
        return new_obj, counts
    if new_child is child:
        return node, counts
    new_obj = dict(node)
    new_obj[token] = new_child
    return new_obj, counts


def _is_allowlisted(fragment: str, allowlist: Iterable[re.Pattern[str]]) -> bool:
    """命中片段是否在 allowlist 里（例如 AWS 文档里的 ``AKIAIOSFODNN7EXAMPLE``）。"""
    for pattern in allowlist:
        if pattern.search(fragment):
            return True
    return False


def _insert_span(
    accepted: list[tuple[int, int, str]],
    starts: list[int],
    start: int,
    end: int,
    rule_id: str,
) -> bool:
    """把 ``[start, end)`` 插进有序的已采纳区间表；与已有区间重叠就拒绝（返回 False）。"""
    # bisect 手写版：避免为了一个二分再引依赖，标准库 bisect 也行，这里保持零花活。
    lo, hi = 0, len(starts)
    while lo < hi:
        mid = (lo + hi) // 2
        if starts[mid] < start:
            lo = mid + 1
        else:
            hi = mid
    idx = lo
    if idx > 0 and accepted[idx - 1][1] > start:
        return False  # 与左邻区间重叠
    if idx < len(accepted) and end > accepted[idx][0]:
        return False  # 与右邻区间重叠
    accepted.insert(idx, (start, end, rule_id))
    starts.insert(idx, start)
    return True


def _render_mask(template: str, rule_id: str) -> str:
    """渲染 ``mask_template``。只认 ``{rule_id}`` 一个占位符，其余花括号原样保留。

    故意不用 ``str.format`` —— 用户模板里出现别的花括号时不该抛 KeyError。
    """
    return template.replace("{rule_id}", rule_id)


__all__ = [
    "DROP",
    "INBOUND_DENY_CALL_DOWNGRADE",
    "redact_outbound",
    "redact_inbound",
    "redact_value",
    "redact_text",
    "parse_scan_path",
    "apply_at_paths",
    "merge_counts",
]
