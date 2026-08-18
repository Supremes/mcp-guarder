"""``mcp_guarder.policy`` 的单测（SPEC §4 policy 段 / §5 fail-closed 表 / §7 M2）。

重点覆盖：
- 默认拒绝：一条规则都不命中 → deny，文案里必须有 ``no matching rule``。
- 第一条完整命中的规则定案，不再往下看。
- ``when`` 之间 AND；任一不满足 → 这条不算命中 → 继续往下找 → 最后落到 no-match。
- ``${PROJECT_DIR}`` 展开为空 → 条件不满足（绝不能退化成"匹配一切绝对路径"）。
- ``allow: ask`` 一律降级成 deny。
- 检测器自身故障 → DetectorError（proxy 按 fail-closed 处置）。
"""

from __future__ import annotations

import re
import textwrap

import pytest

from mcp_guarder import policy
from mcp_guarder.errors import DetectorError
from mcp_guarder.types import (
    AllowMode,
    Decision,
    DecisionBy,
    DenyResponseConfig,
    GuarderConfig,
    PolicyConfig,
    PolicyRule,
    WhenCondition,
    WhenOperator,
)

# ────────────────────────────────────────────────────────────────────────────
# 小工具：直接构造 frozen dataclass，不依赖 YAML 解析（那是 config 模块的用例）
# ────────────────────────────────────────────────────────────────────────────

_REGEX_OPS = {WhenOperator.MATCHES, WhenOperator.NOT_MATCHES}


def when(arg: str, op: WhenOperator, value) -> WhenCondition:
    """造一个 ``when`` 条件；正则操作符在这里先编译好（模拟配置解析期的行为）。"""
    regex = re.compile(value) if op in _REGEX_OPS else None
    return WhenCondition(arg=arg, op=op, value=value, regex=regex)


def rule(
    rule_id: str,
    tool: str,
    allow: AllowMode,
    *conditions: WhenCondition,
    reason: str | None = None,
) -> PolicyRule:
    return PolicyRule(id=rule_id, tool=tool, allow=allow, when=tuple(conditions), reason=reason)


def config_with(*rules: PolicyRule, deny_text: str | None = None) -> GuarderConfig:
    deny_response = (
        DenyResponseConfig(text=deny_text) if deny_text is not None else DenyResponseConfig()
    )
    return GuarderConfig(policy=PolicyConfig(rules=tuple(rules), deny_response=deny_response))


PROJECT = "/Users/x/proj"


# ────────────────────────────────────────────────────────────────────────────
# SPEC §7 M2 验收第 2 条：pytest -k policy_matrix
# 四条 deny 路径 —— no-match / 条件不满足 / 规则冲突 / 检测器异常
# ────────────────────────────────────────────────────────────────────────────


def test_policy_matrix_no_match() -> None:
    """路径一：空 policy（或没有任何 tool glob 命中）→ deny by default。"""
    decision = policy.evaluate("echo", {"text": "hi"}, config=config_with(), project_dir=PROJECT)

    assert decision.decision is Decision.DENY
    assert decision.decision_by is DecisionBy.DEFAULT
    assert decision.reason == "no matching rule"  # SPEC §5 第一行 + §7 M2-1 会 grep 这句
    assert decision.rule_id is None
    assert decision.allowed is False

    # tool glob 压根不匹配的规则同样落到 no-match。
    cfg = config_with(rule("allow-read", "read_file", AllowMode.ALLOW))
    other = policy.evaluate("write_file", {}, config=cfg, project_dir=PROJECT)
    assert other.decision is Decision.DENY
    assert other.decision_by is DecisionBy.DEFAULT
    assert other.reason == policy.REASON_NO_MATCH


def test_policy_matrix_condition_unsatisfied() -> None:
    """路径二：tool 匹配但 ``when`` 不满足 → 这条不算命中 → 落到 no-match → deny（SPEC §5 第二行）。"""
    cfg = config_with(
        rule(
            "allow-read-in-project",
            "read_file",
            AllowMode.ALLOW,
            when("path", WhenOperator.STARTS_WITH, "${PROJECT_DIR}/"),
        )
    )

    inside = policy.evaluate(
        "read_file", {"path": f"{PROJECT}/src/main.py"}, config=cfg, project_dir=PROJECT
    )
    assert inside.decision is Decision.ALLOW
    assert inside.rule_id == "allow-read-in-project"

    outside = policy.evaluate(
        "read_file", {"path": "/etc/passwd"}, config=cfg, project_dir=PROJECT
    )
    assert outside.decision is Decision.DENY
    assert outside.decision_by is DecisionBy.DEFAULT
    assert outside.reason == policy.REASON_NO_MATCH

    # 参数干脆不存在，同样是"条件不满足"，不是异常。
    missing = policy.evaluate("read_file", {}, config=cfg, project_dir=PROJECT)
    assert missing.decision is Decision.DENY
    assert missing.decision_by is DecisionBy.DEFAULT


def test_policy_matrix_rule_conflict_first_wins() -> None:
    """路径三：同一 tool 出现相反结论 → **第一条生效**（SPEC §5 第三行）。

    注：SPEC 要求这种配置在**启动期**就被 ``config.validate_config`` 拒掉；
    真跑到 policy 这一层时的兜底语义是"第一条定案，不再往下看"，
    第一条是 deny 就 deny，不会被后面的 allow 翻盘。
    """
    cfg = config_with(
        rule("block-shell", "exec_*", AllowMode.DENY, reason="shell 执行一律走人工"),
        rule("allow-shell", "exec_*", AllowMode.ALLOW),
    )

    decision = policy.evaluate("exec_bash", {"cmd": "ls"}, config=cfg, project_dir=PROJECT)
    assert decision.decision is Decision.DENY
    assert decision.decision_by is DecisionBy.POLICY
    assert decision.rule_id == "block-shell"
    assert decision.reason == "shell 执行一律走人工"


def test_policy_matrix_detector_error() -> None:
    """路径四：policy 自己坏了 → DetectorError（proxy 转成 isError "detector failure"）。"""
    # 配置解析期就该拦住的非法操作符；跑到运行期说明内部状态坏了。
    bogus = WhenCondition(arg="path", op="totally-bogus", value="x")  # type: ignore[arg-type]
    cfg = config_with(rule("broken", "read_file", AllowMode.ALLOW, bogus))

    with pytest.raises(DetectorError) as excinfo:
        policy.evaluate("read_file", {"path": "/tmp/a"}, config=cfg, project_dir=PROJECT)

    assert excinfo.value.detector == "policy"
    assert "detector failure" in excinfo.value.model_text
    assert "policy" in excinfo.value.model_text

    # matches/not_matches 缺编译好的正则 —— 同样是内部坏了，不是"不命中"。
    no_regex = WhenCondition(arg="path", op=WhenOperator.MATCHES, value=".*", regex=None)
    cfg2 = config_with(rule("broken2", "read_file", AllowMode.ALLOW, no_regex))
    with pytest.raises(DetectorError):
        policy.evaluate("read_file", {"path": "/tmp/a"}, config=cfg2, project_dir=PROJECT)


def test_policy_matrix_ask_is_denied() -> None:
    """附加路径：``allow: ask`` v1 一律等价 deny（SPEC §7 末尾 TODO 的降级方案）。"""
    cfg = config_with(rule("write-needs-confirm", "write_file", AllowMode.ASK))

    decision = policy.evaluate(
        "write_file", {"path": f"{PROJECT}/a.txt"}, config=cfg, project_dir=PROJECT
    )
    assert decision.decision is Decision.DENY
    assert decision.decision_by is DecisionBy.POLICY
    assert decision.allow_mode is AllowMode.ASK
    assert decision.ask_downgraded is True
    assert decision.reason == policy.REASON_ASK_DOWNGRADED


# ────────────────────────────────────────────────────────────────────────────
# 规则匹配：glob 不是正则；第一条完整命中即定案
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("pattern", "tool", "expected"),
    [
        ("read_file", "read_file", True),
        ("read_file", "read_files", False),
        ("exec_*", "exec_bash", True),
        ("exec_*", "execbash", False),
        ("read_?ile", "read_file", True),
        ("read_?ile", "read_xxile", False),
        ("*", "anything", True),
        # glob 不是正则：`.` 是字面量，`.*` 不是"任意字符"
        ("read_.*", "read_file", False),
        ("read_.*", "read_.x", True),
        # 大小写敏感
        ("read_*", "READ_FILE", False),
    ],
)
def test_match_tool_is_glob_not_regex(pattern: str, tool: str, expected: bool) -> None:
    assert policy.match_tool(pattern, tool) is expected


def test_unmatched_rule_falls_through_to_next() -> None:
    """条件不满足的规则不算命中，要继续往下找 —— 不是直接 deny。"""
    cfg = config_with(
        rule(
            "allow-in-project",
            "read_file",
            AllowMode.ALLOW,
            when("path", WhenOperator.STARTS_WITH, "${PROJECT_DIR}/"),
        ),
        rule("allow-tmp", "read_file", AllowMode.ALLOW, when("path", WhenOperator.STARTS_WITH, "/tmp/")),
    )

    decision = policy.evaluate("read_file", {"path": "/tmp/x"}, config=cfg, project_dir=PROJECT)
    assert decision.decision is Decision.ALLOW
    assert decision.rule_id == "allow-tmp"


def test_when_conditions_are_anded() -> None:
    """SPEC §4 的 allow-read-in-project：两个条件都满足才放行。"""
    cfg = config_with(
        rule(
            "allow-read-in-project",
            "read_file",
            AllowMode.ALLOW,
            when("path", WhenOperator.STARTS_WITH, "${PROJECT_DIR}/"),
            when(
                "path",
                WhenOperator.NOT_MATCHES,
                r"(?i)(\.env|/\.git/|id_rsa|credentials|\.claude\.json)",
            ),
        )
    )

    ok = policy.evaluate(
        "read_file", {"path": f"{PROJECT}/README.md"}, config=cfg, project_dir=PROJECT
    )
    assert ok.decision is Decision.ALLOW

    # 在项目里，但踩了 not_matches → 第二个条件不满足 → 不命中 → no-match deny
    secret = policy.evaluate(
        "read_file", {"path": f"{PROJECT}/.env"}, config=cfg, project_dir=PROJECT
    )
    assert secret.decision is Decision.DENY
    assert secret.reason == policy.REASON_NO_MATCH

    matched, why = policy.rule_matches(
        cfg.policy.rules[0], "read_file", {"path": f"{PROJECT}/.env"}, project_dir=PROJECT
    )
    assert matched is False
    assert why is not None and why.startswith("when[1]")


def test_rule_without_when_matches_any_arguments() -> None:
    cfg = config_with(rule("block-shell", "exec_*", AllowMode.DENY))
    for args in ({}, None, {"cmd": "rm -rf /"}, "not-a-dict"):
        decision = policy.evaluate("exec_bash", args, config=cfg, project_dir=PROJECT)  # type: ignore[arg-type]
        assert decision.decision is Decision.DENY
        assert decision.rule_id == "block-shell"
        assert decision.reason == policy.REASON_RULE_DENY


def test_non_dict_arguments_are_treated_as_empty() -> None:
    """``params.arguments`` 缺失/形态不对 → 按空 dict 处理 → 所有 when 不满足 → deny。"""
    cfg = config_with(
        rule("allow-read", "read_file", AllowMode.ALLOW, when("path", WhenOperator.EXISTS, True))
    )
    for args in (None, [], "x", 3):
        decision = policy.evaluate("read_file", args, config=cfg, project_dir=PROJECT)  # type: ignore[arg-type]
        assert decision.decision is Decision.DENY
        assert decision.decision_by is DecisionBy.DEFAULT


# ────────────────────────────────────────────────────────────────────────────
# 六个操作符
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("op", "value", "args", "expected"),
    [
        (WhenOperator.STARTS_WITH, "/tmp/", {"path": "/tmp/a"}, True),
        (WhenOperator.STARTS_WITH, "/tmp/", {"path": "/var/a"}, False),
        (WhenOperator.STARTS_WITH, "/tmp/", {}, False),
        (WhenOperator.EQUALS, "main", {"branch": "main"}, True),
        (WhenOperator.EQUALS, "main", {"branch": "main2"}, False),
        (WhenOperator.MATCHES, r"^\d+$", {"branch": "123"}, True),
        (WhenOperator.MATCHES, r"^\d+$", {"branch": "12a"}, False),
        (WhenOperator.NOT_MATCHES, r"id_rsa", {"branch": "safe"}, True),
        (WhenOperator.NOT_MATCHES, r"id_rsa", {"branch": "x/id_rsa"}, False),
        (WhenOperator.ONE_OF, ["a", "b"], {"branch": "b"}, True),
        (WhenOperator.ONE_OF, ["a", "b"], {"branch": "c"}, False),
        (WhenOperator.EXISTS, True, {"branch": "c"}, True),
        (WhenOperator.EXISTS, True, {}, False),
        (WhenOperator.EXISTS, False, {}, True),
        (WhenOperator.EXISTS, False, {"branch": None}, False),
    ],
)
def test_evaluate_condition_operators(op: WhenOperator, value, args, expected: bool) -> None:
    arg = "path" if op is WhenOperator.STARTS_WITH else "branch"
    ok, explanation = policy.evaluate_condition(when(arg, op, value), args, project_dir=PROJECT)
    assert ok is expected
    assert explanation  # 永远给一句人话，方便 guard.log 排障


@pytest.mark.parametrize(
    "op",
    [
        WhenOperator.STARTS_WITH,
        WhenOperator.EQUALS,
        WhenOperator.MATCHES,
        WhenOperator.NOT_MATCHES,
        WhenOperator.ONE_OF,
    ],
)
def test_non_string_argument_never_satisfies(op: WhenOperator) -> None:
    """参数值不是 str（数字/dict/list/None）一律判不满足，不做隐式转换。

    注意 ``not_matches`` 也是 False —— fail-closed 优先于"直觉上没命中就该放行"。
    """
    value = ["/tmp/"] if op is WhenOperator.ONE_OF else "/tmp/"
    cond = when("path", op, value)
    for bad in (123, None, {"a": 1}, ["/tmp/x"], True):
        ok, _ = policy.evaluate_condition(cond, {"path": bad}, project_dir=PROJECT)
        assert ok is False


def test_exists_is_the_only_operator_that_tolerates_missing_arg() -> None:
    ok, _ = policy.evaluate_condition(
        when("path", WhenOperator.EXISTS, False), {}, project_dir=PROJECT
    )
    assert ok is True

    ok, why = policy.evaluate_condition(
        when("path", WhenOperator.NOT_MATCHES, "x"), {}, project_dir=PROJECT
    )
    assert ok is False
    assert "missing" in why


# ────────────────────────────────────────────────────────────────────────────
# ${PROJECT_DIR}
# ────────────────────────────────────────────────────────────────────────────


def test_project_dir_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """不显式传 project_dir 时走 config 的共享展开（读 CLAUDE_PROJECT_DIR）。"""
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", "/env/proj")
    cfg = config_with(
        rule(
            "allow-read",
            "read_file",
            AllowMode.ALLOW,
            when("path", WhenOperator.STARTS_WITH, "${PROJECT_DIR}/"),
        )
    )

    assert policy.evaluate("read_file", {"path": "/env/proj/a"}, config=cfg).decision is Decision.ALLOW
    assert policy.evaluate("read_file", {"path": "/other/a"}, config=cfg).decision is Decision.DENY


def test_empty_project_dir_never_degrades_into_match_all() -> None:
    """展开为空 → 条件不满足。**绝不能**退化成 ``startswith("/")`` 匹配一切绝对路径。"""
    cfg = config_with(
        rule(
            "allow-read",
            "read_file",
            AllowMode.ALLOW,
            when("path", WhenOperator.STARTS_WITH, "${PROJECT_DIR}/"),
        )
    )

    decision = policy.evaluate("read_file", {"path": "/etc/passwd"}, config=cfg, project_dir="")
    assert decision.decision is Decision.DENY
    assert decision.decision_by is DecisionBy.DEFAULT

    ok, why = policy.evaluate_condition(
        when("path", WhenOperator.STARTS_WITH, "${PROJECT_DIR}/"),
        {"path": "/etc/passwd"},
        project_dir="",
    )
    assert ok is False
    assert "empty" in why


def test_one_of_expands_project_dir() -> None:
    cond = when("path", WhenOperator.ONE_OF, ["${PROJECT_DIR}/a", "/tmp/b"])
    assert policy.evaluate_condition(cond, {"path": f"{PROJECT}/a"}, project_dir=PROJECT)[0] is True
    assert policy.evaluate_condition(cond, {"path": "/tmp/b"}, project_dir=PROJECT)[0] is True
    assert policy.evaluate_condition(cond, {"path": "/tmp/c"}, project_dir=PROJECT)[0] is False

    # 展开为空的那一项直接跳过，不会拿空串去比。
    assert policy.evaluate_condition(cond, {"path": "/a"}, project_dir="")[0] is False
    assert policy.evaluate_condition(cond, {"path": "/tmp/b"}, project_dir="")[0] is True


# ────────────────────────────────────────────────────────────────────────────
# deny 文案渲染
# ────────────────────────────────────────────────────────────────────────────


def test_render_deny_text_default_template() -> None:
    text = policy.render_deny_text(
        DenyResponseConfig().text,
        reason=policy.REASON_NO_MATCH,
        rule_id=None,
        audit_id="01J8Z9Q3K7",
    )
    assert text == "mcp-guarder denied: no matching rule (rule=-, event=01J8Z9Q3K7)"


def test_render_deny_text_is_forgiving() -> None:
    """模板里出现别的占位符、甚至写坏了，都不许抛 —— 拒绝路径上再炸一次就没法交代了。"""
    text = policy.render_deny_text(
        "{reason} / {rule_id} / {audit_id} / {unknown}",
        reason="r",
        rule_id="rid",
        audit_id="aid",
    )
    assert text == "r / rid / aid / {unknown}"

    broken = policy.render_deny_text("oops { {reason}", reason="r", rule_id=None, audit_id="a")
    assert "r" in broken


def test_ask_downgrade_message_tells_user_what_to_do() -> None:
    message = policy.ask_downgrade_message("write-needs-confirm", "write_file")
    assert "ask is not implemented in v1" in message
    assert "rule=write-needs-confirm" in message
    assert "tool=write_file" in message
    assert "allow: ask" in message


# ────────────────────────────────────────────────────────────────────────────
# 端到端：直接吃 SPEC §4 里那份 policy YAML
# ────────────────────────────────────────────────────────────────────────────

SPEC_POLICY_YAML = textwrap.dedent(
    """
    version: 1
    server:
      name: filesystem
      transport: stdio
    policy:
      rules:
        - id: allow-read-in-project
          tool: read_file
          allow: true
          when:
            - {arg: path, starts_with: "${PROJECT_DIR}/"}
            - {arg: path, not_matches: '(?i)(\\.env|/\\.git/|id_rsa|credentials|\\.claude\\.json)'}
        - id: write-needs-confirm
          tool: write_file
          allow: ask
          when:
            - {arg: path, starts_with: "${PROJECT_DIR}/"}
        - id: block-shell
          tool: "exec_*"
          allow: false
          reason: "shell 执行一律走人工"
      deny_response:
        kind: tool_result_error
        text: "mcp-guarder denied: {reason} (rule={rule_id}, event={audit_id})"
    """
).strip()


def test_spec_policy_yaml_end_to_end(load_config_from, project_dir) -> None:
    cfg = load_config_from(SPEC_POLICY_YAML)
    proj = str(project_dir)

    allowed = policy.evaluate("read_file", {"path": f"{proj}/src/a.py"}, config=cfg)
    assert allowed.decision is Decision.ALLOW
    assert allowed.rule_id == "allow-read-in-project"

    secret = policy.evaluate("read_file", {"path": f"{proj}/.env"}, config=cfg)
    assert secret.decision is Decision.DENY
    assert secret.reason == policy.REASON_NO_MATCH

    outside = policy.evaluate("read_file", {"path": "/etc/passwd"}, config=cfg)
    assert outside.decision is Decision.DENY

    ask = policy.evaluate("write_file", {"path": f"{proj}/a.txt"}, config=cfg)
    assert ask.decision is Decision.DENY
    assert ask.ask_downgraded is True

    shell = policy.evaluate("exec_bash", {"cmd": "ls"}, config=cfg)
    assert shell.decision is Decision.DENY
    assert shell.rule_id == "block-shell"

    unknown = policy.evaluate("list_dir", {"path": proj}, config=cfg)
    assert unknown.decision is Decision.DENY
    assert unknown.decision_by is DecisionBy.DEFAULT

    text = policy.render_deny_text(
        cfg.policy.deny_response.text,
        reason=unknown.reason,
        rule_id=unknown.rule_id,
        audit_id="01J8Z9Q3K7",
    )
    assert text == "mcp-guarder denied: no matching rule (rule=-, event=01J8Z9Q3K7)"
