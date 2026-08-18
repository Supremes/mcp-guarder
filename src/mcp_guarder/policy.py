"""权限门：默认拒绝（SPEC §4 policy 段 / §5 fail-closed 表）。

语义（一条都不能少）：
- 规则自上而下，**第一条 ``tool`` glob 匹配的规则即定案，不再往下看**。
- ``tool`` 是 glob（``*`` / ``?``），**不是正则** —— 用 ``fnmatch.fnmatchcase``，大小写敏感。
- ``when`` 里的条件之间是 AND；任一不满足 → **这条规则不算命中**，
  继续往下找后面的规则（不是直接 deny）。全找完还没命中 → no-match → deny。
- ``when`` 引用了不存在的参数 → 视为不满足（SPEC §5 第二行）。
- ``${PROJECT_DIR}`` 展开为空 → 条件不满足（调 :func:`~mcp_guarder.config.expand_project_dir`，
  **不许自己再实现一遍**）。
- ``allow: ask`` → v1 一律等价于 deny（见 :func:`ask_downgrade_message`）。

拒绝的呈现形式：``result.isError = true``，**绝不用 JSON-RPC error**（SPEC §5 硬规矩）。
报文由 proxy 用 :func:`~mcp_guarder.proxy.build_tool_error_response` 拼，本模块只出决策和文案。

依赖方向：types / errors / config。**不 import proxy / audit。**
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from typing import Any

# 注意：import 的是**模块**而不是函数本身。
# ``${PROJECT_DIR}`` 的展开只有 config 一处实现（SPEC §4），这里走属性查找调用它，
# 别写成 ``from ... import expand_project_dir`` —— 那样测试就没法替换实现了。
# 变量名故意叫 guarder_config，避开下面各函数 ``config: GuarderConfig`` 形参的遮蔽。
from mcp_guarder import config as guarder_config
from mcp_guarder.errors import DetectorError
from mcp_guarder.types import (
    AllowMode,
    Decision,
    DecisionBy,
    DetectorName,
    GuarderConfig,
    PolicyDecision,
    PolicyRule,
    WhenCondition,
    WhenOperator,
)

#: no-match 时给模型看的原因文本。SPEC §5 明确要求 text 里出现 ``no matching rule``，
#: §7 M2-1 的验收也 grep 这句，**不要改写措辞**。
REASON_NO_MATCH = "no matching rule"

#: 命中 ``allow: false`` 且规则没写 ``reason`` 时的兜底文案。
REASON_RULE_DENY = "denied by rule"

#: 命中 ``allow: ask`` 时的原因文本（v1 降级成 deny）。
REASON_ASK_DOWNGRADED = "ask is not supported in v1 (downgraded to deny)"

#: 命中 ``allow: true`` 且规则没写 ``reason`` 时的兜底文案（只进审计，模型看不到）。
_REASON_RULE_ALLOW = "allowed by rule"

#: ``rule_id`` 为 None 时填进 deny 文案的占位符。
_RULE_ID_PLACEHOLDER = "-"


def evaluate(
    tool_name: str,
    arguments: Mapping[str, Any] | None,
    *,
    config: GuarderConfig,
    project_dir: str | None = None,
) -> PolicyDecision:
    """检测器统一入口：判一次 ``tools/call`` 放不放。

    :param tool_name: ``params.name``，**是裸的 tool 名**（客户端已经把
        ``mcp__<server>__`` 前缀剥掉了），别再自己去剥。
    :param arguments: ``params.arguments``；缺省或不是 dict 时按空 dict 处理
        （这样所有 ``when`` 条件都不满足 → 落到 no-match → deny，符合 fail-closed）。
    :param project_dir: 显式传入则不查环境（测试用），否则由
        :func:`~mcp_guarder.config.expand_project_dir` 内部走
        :func:`~mcp_guarder.config.get_project_dir`。
    :return: :class:`~mcp_guarder.types.PolicyDecision`，只会是 ALLOW 或 DENY。
    :raises DetectorError: 内部异常包成 ``DetectorError.wrap(DetectorName.POLICY, exc)``
        再抛；proxy 按「检测器故障 → deny 当前消息」处置。

    **注意**：正常的"拒绝"走返回值而不是异常。只有 policy 自己坏了才抛。
    """
    try:
        args: Mapping[str, Any] = arguments if isinstance(arguments, Mapping) else {}

        for rule in config.policy.rules:
            matched, _why = rule_matches(rule, tool_name, args, project_dir=project_dir)
            if not matched:
                # tool glob 不匹配，或某个 when 条件不满足 —— 这条不算命中，继续往下找。
                continue
            return _decide(rule)

        # 一条都没命中 → defaults.on_no_match（v1 只允许 deny，见 ALLOWED_DEFAULT_ACTIONS）。
        return PolicyDecision(
            decision=Decision.DENY,
            decision_by=DecisionBy.DEFAULT,
            reason=REASON_NO_MATCH,
            rule_id=None,
            allow_mode=None,
        )
    except DetectorError:
        raise
    except Exception as exc:  # noqa: BLE001 —— 检测器故障统一形态，proxy 只认 DetectorError
        raise DetectorError.wrap(DetectorName.POLICY, exc) from exc


def _decide(rule: PolicyRule) -> PolicyDecision:
    """一条规则真的命中之后，把 ``allow`` 三态翻译成最终决策。"""
    if rule.allow is AllowMode.ALLOW:
        return PolicyDecision(
            decision=Decision.ALLOW,
            decision_by=DecisionBy.POLICY,
            reason=rule.reason or _REASON_RULE_ALLOW,
            rule_id=rule.id,
            allow_mode=AllowMode.ALLOW,
        )

    if rule.allow is AllowMode.ASK:
        # TODO(SPEC §7 末尾 TODO(待验证))：ask 原计划借 elicitation/create 实现，
        # 但代理自建 server→client 请求要占 id 空间、UX 没验过 —— v1 按 SPEC 给的降级
        # 方案一律等价 deny，并由 proxy 拿 ask_downgrade_message() 往 guard.log 写提示。
        return PolicyDecision(
            decision=Decision.DENY,
            decision_by=DecisionBy.POLICY,
            reason=REASON_ASK_DOWNGRADED,
            rule_id=rule.id,
            allow_mode=AllowMode.ASK,
        )

    # AllowMode.DENY，以及任何不认识的取值 —— fail-closed 一律拒。
    return PolicyDecision(
        decision=Decision.DENY,
        decision_by=DecisionBy.POLICY,
        reason=rule.reason or REASON_RULE_DENY,
        rule_id=rule.id,
        allow_mode=AllowMode.DENY if rule.allow is AllowMode.DENY else None,
    )


def match_tool(pattern: str, tool_name: str) -> bool:
    """glob 匹配 tool 名。``fnmatch.fnmatchcase``，大小写敏感，不做正则。"""
    return fnmatch.fnmatchcase(tool_name, pattern)


def rule_matches(
    rule: PolicyRule,
    tool_name: str,
    arguments: Mapping[str, Any],
    *,
    project_dir: str | None,
) -> tuple[bool, str | None]:
    """判断一条规则是否命中。

    先看 ``tool`` glob，再 AND 所有 ``when`` 条件；任一不满足就整条不命中。

    :return: ``(命中?, 不命中的原因)``。原因只用于 guard.log 排障和审计 ``reason``，
        例如 ``"when[0] arg 'path' missing"`` / ``"when[1] not_matches hit"``。
    """
    if not match_tool(rule.tool, tool_name):
        return False, f"tool glob {rule.tool!r} does not match {tool_name!r}"

    for index, cond in enumerate(rule.when):
        ok, explanation = evaluate_condition(cond, arguments, project_dir=project_dir)
        if not ok:
            return False, f"when[{index}] {explanation}"

    return True, None


def evaluate_condition(
    cond: WhenCondition,
    arguments: Mapping[str, Any],
    *,
    project_dir: str | None,
) -> tuple[bool, str]:
    """求值单个 ``when`` 条件。

    六个操作符的语义：
    - ``exists``：``cond.value`` 为 True 时要求 arg 存在，为 False 时要求不存在。
    - 其余五个：**arg 不存在一律 False**（SPEC §5 第二行）。
    - ``starts_with`` / ``equals``：先展开 ``${PROJECT_DIR}``；展开为 None → False。
      比较对象是参数值的字符串形态；参数值不是 str 时（数字/dict）一律 False，别做隐式转换。
    - ``matches`` / ``not_matches``：用解析期编译好的 ``cond.regex`` 做 ``re.search``。
    - ``one_of``：逐项展开 ``${PROJECT_DIR}`` 后判断相等。

    :return: ``(结果, 一句话解释)``。
    """
    present = cond.arg in arguments

    # exists 是唯一允许 arg 缺席的操作符。
    if cond.op is WhenOperator.EXISTS:
        want = bool(cond.value)
        ok = present is want
        return ok, f"exists({cond.arg}) is {present}, want {want}"

    if not present:
        return False, f"arg {cond.arg!r} missing"

    raw_value = arguments[cond.arg]
    if not isinstance(raw_value, str):
        # 不做隐式转换：数字/dict/list 一律判不满足（fail-closed）。
        return False, f"arg {cond.arg!r} is {type(raw_value).__name__}, not str"

    if cond.op is WhenOperator.STARTS_WITH:
        expected = _expand(cond.value, project_dir=project_dir)
        if expected is None:
            return False, f"starts_with value {cond.value!r} expanded to empty"
        return raw_value.startswith(expected), f"starts_with {expected!r}"

    if cond.op is WhenOperator.EQUALS:
        expected = _expand(cond.value, project_dir=project_dir)
        if expected is None:
            return False, f"equals value {cond.value!r} expanded to empty"
        return raw_value == expected, f"equals {expected!r}"

    if cond.op is WhenOperator.MATCHES:
        regex = _require_regex(cond)
        return regex.search(raw_value) is not None, f"matches {cond.value!r}"

    if cond.op is WhenOperator.NOT_MATCHES:
        regex = _require_regex(cond)
        return regex.search(raw_value) is None, f"not_matches {cond.value!r}"

    if cond.op is WhenOperator.ONE_OF:
        if not isinstance(cond.value, (list, tuple)):
            raise ValueError(f"one_of value must be a list, got {type(cond.value).__name__}")
        for item in cond.value:
            expanded = _expand(item, project_dir=project_dir)
            if expanded is None:
                # 该项展开为空 —— 当它不存在，绝不拿空串去比（SPEC §4）。
                continue
            if raw_value == expanded:
                return True, f"one_of matched {expanded!r}"
        return False, "one_of matched nothing"

    # 配置解析期就该拦住的取值；跑到这里说明 policy 自己坏了 → evaluate 会包成 DetectorError。
    raise ValueError(f"unsupported when operator: {cond.op!r}")


def _expand(value: Any, *, project_dir: str | None) -> str | None:
    """展开 ``${PROJECT_DIR}``。**唯一实现在 config，这里只是转发。**

    非 str 的取值直接判不满足（返回 None），别做隐式转换。
    """
    if not isinstance(value, str):
        return None
    return guarder_config.expand_project_dir(value, project_dir=project_dir)


def _require_regex(cond: WhenCondition):
    """``matches`` / ``not_matches`` 的正则必须在配置解析期编译好。"""
    if cond.regex is None:
        raise ValueError(f"when condition {cond.op} on arg {cond.arg!r} has no compiled regex")
    return cond.regex


def render_deny_text(
    template: str,
    *,
    reason: str,
    rule_id: str | None,
    audit_id: str,
) -> str:
    """渲染 ``policy.deny_response.text``。

    模板占位符只有三个：``{reason}`` / ``{rule_id}`` / ``{audit_id}``。
    ``rule_id`` 为 None 时填 ``"-"``。模板里出现别的占位符不要抛异常 ——
    用容错的替换（缺失的键原样保留），拒绝路径上再炸一次就没法给模型交代了。
    """
    values = {
        "reason": reason,
        "rule_id": rule_id if rule_id else _RULE_ID_PLACEHOLDER,
        "audit_id": audit_id,
    }
    try:
        return template.format_map(_ForgivingDict(values))
    except Exception:  # noqa: BLE001 —— 模板本身写坏了（落单大括号之类）也不许炸
        text = template
        for key, value in values.items():
            text = text.replace("{" + key + "}", value)
        return text


class _ForgivingDict(dict):
    """``str.format_map`` 用的容错字典：认不出来的占位符原样留着。"""

    def __missing__(self, key: str) -> str:  # pragma: no cover - 一行
        return "{" + key + "}"


def ask_downgrade_message(rule_id: str, tool_name: str) -> str:
    """``allow: ask`` 命中时往 guard.log 写的那行提示。

    TODO(SPEC §7 末尾 ``TODO(待验证)``)：``ask`` 原计划借 ``elicitation/create`` 实现，
    但代理自建 server→client 请求要占 id 空间、UX 也没验过，**v1 按 SPEC 给的降级方案
    做：ask == deny + 提示用户手工改配置**。真要做 elicitation 请先补技术验证。

    文案形如::

        ask is not implemented in v1: rule=<rule_id> tool=<tool> denied.
        Change `allow: ask` to true/false in your config.
    """
    return (
        f"ask is not implemented in v1: rule={rule_id} tool={tool_name} denied. "
        "Change `allow: ask` to true/false in your config."
    )


__all__ = [
    "REASON_NO_MATCH",
    "REASON_RULE_DENY",
    "REASON_ASK_DOWNGRADED",
    "evaluate",
    "match_tool",
    "rule_matches",
    "evaluate_condition",
    "render_deny_text",
    "ask_downgrade_message",
]
