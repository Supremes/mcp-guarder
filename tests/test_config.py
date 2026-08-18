"""config 模块单测（SPEC §4 配置格式 / §5 fail-closed 表）。

覆盖重点（任务书点名的几条）：
- 未知字段一律拒绝启动，且报错里要指出是哪个字段。
- ``when`` 只认 6 个操作符，出现第七个直接拒。
- 同一个 tool 被多条规则定义 → 拒绝启动并打印冲突 rule id。
- 坏正则在**启动期**就炸，不留到运行期。
- ``${PROJECT_DIR}`` 三种情况：有值 / 无值退到 cwd / 展开为空返回 None。
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

from mcp_guarder.config import (
    coerce_enum,
    compile_pattern_rules,
    compile_regex,
    ensure_no_unknown_keys,
    expand_path,
    expand_project_dir,
    get_project_dir,
    load_config,
    load_yaml,
    parse_audit,
    parse_config,
    parse_policy,
    parse_when_condition,
    validate_config,
)
from mcp_guarder.errors import ConfigError
from mcp_guarder.types import (
    EXIT_CONFIG_ERROR,
    SPEC_REDACT_RULES,
    SPEC_STATIC_RULES,
    AllowMode,
    FailClosedAction,
    FsyncMode,
    RecordMode,
    RedactAction,
    StaticCheckAction,
    Transport,
    WhenOperator,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

MINIMAL = textwrap.dedent(
    """
    version: 1
    server:
      name: demo
    """
).strip()


def yaml_with(extra: str) -> str:
    """最小配置 + 一段附加 YAML。"""
    return MINIMAL + "\n" + textwrap.dedent(extra).strip() + "\n"


def problems_text(exc: ConfigError) -> str:
    """把 ConfigError 的所有问题拼成一段文本，方便断言。"""
    return exc.format_report()


# ────────────────────────────────────────────────────────────────────────────
# 1. happy path
# ────────────────────────────────────────────────────────────────────────────


def spec_example_yaml() -> str:
    """从 SPEC §4 里原样抠出那份 YAML —— 它必须永远能解析。"""
    text = (REPO_ROOT / "SPEC.md").read_text(encoding="utf-8")
    start = text.index("```yaml\nversion: 1")
    end = text.index("```", start + len("```yaml\n"))
    return text[start + len("```yaml\n") : end]


def test_spec_section4_example_parses(write_config, monkeypatch, tmp_path):
    """SPEC §4 那份 YAML 是唯一真相，逐条对齐。"""
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = load_config(write_config(spec_example_yaml()))

    assert cfg.version == 1
    assert cfg.server.name == "filesystem"
    assert cfg.server.transport is Transport.STDIO

    assert cfg.defaults.on_no_match is FailClosedAction.DENY
    assert cfg.defaults.on_unknown_method is FailClosedAction.PASSTHROUGH
    assert cfg.defaults.on_upstream_crash is FailClosedAction.FAIL

    assert cfg.inspect.fingerprint.fields == ("name", "title", "description", "inputSchema")
    assert [r.id for r in cfg.inspect.static_checks.rules] == [r[0] for r in SPEC_STATIC_RULES]
    assert cfg.inspect.static_checks.on_hit is StaticCheckAction.DENY

    assert [r.id for r in cfg.policy.rules] == [
        "allow-read-in-project",
        "write-needs-confirm",
        "block-shell",
    ]
    assert [r.allow for r in cfg.policy.rules] == [
        AllowMode.ALLOW,
        AllowMode.ASK,
        AllowMode.DENY,
    ]
    assert cfg.policy.rules[0].when[0].op is WhenOperator.STARTS_WITH
    assert cfg.policy.rules[0].when[0].value == "${PROJECT_DIR}/"  # 保留未展开原文
    assert cfg.policy.rules[0].when[1].regex is not None  # not_matches 解析期已编译

    assert [r.id for r in cfg.redact.rules] == [r[0] for r in SPEC_REDACT_RULES]
    assert cfg.redact.action is RedactAction.MASK
    assert cfg.redact.allowlist and cfg.redact.allowlist[0].search("AKIAIOSFODNN7EXAMPLE")

    # audit.path 保留模板原文；log_file / snapshot_dir 展开成绝对路径
    assert cfg.audit.path == "~/.mcp-guarder/audit/{server}-{date}.jsonl"
    assert cfg.audit.log_file.is_absolute() and "~" not in str(cfg.audit.log_file)
    assert cfg.audit.snapshot_dir.is_absolute()
    assert cfg.audit.fsync is FsyncMode.EVERY_RECORD
    assert cfg.audit.record.other_methods is RecordMode.METADATA_ONLY
    assert cfg.audit.payload.max_bytes == 4096


def test_minimal_config_fills_spec_defaults(load_config_from):
    """只写 version + server.name，其余全部落到 SPEC §4 的默认值。"""
    cfg = load_config_from(MINIMAL)

    assert cfg.server.name == "demo"
    assert cfg.defaults.on_no_match is FailClosedAction.DENY
    assert cfg.inspect.fingerprint.enabled is True
    assert cfg.inspect.fingerprint.store.is_absolute()
    # policy.rules 缺省是空 → 一切 tools/call 走 no-match deny
    assert cfg.policy.rules == ()
    assert [r.id for r in cfg.inspect.static_checks.rules] == [r[0] for r in SPEC_STATIC_RULES]
    assert [r.id for r in cfg.redact.rules] == [r[0] for r in SPEC_REDACT_RULES]
    assert cfg.redact.outbound_scan == ("params.arguments",)


def test_source_path_recorded(write_config):
    path = write_config(MINIMAL)
    assert load_config(path).source_path == expand_path(path)


def test_explicit_empty_rule_lists_are_respected(load_config_from):
    """显式写 ``rules: []`` 就是空规则集，不再拿 SPEC 默认值兜底。"""
    cfg = load_config_from(
        yaml_with(
            """
            inspect:
              static_checks:
                rules: []
            redact:
              rules: []
              allowlist: []
            """
        )
    )
    assert cfg.inspect.static_checks.rules == ()
    assert cfg.redact.rules == ()
    assert cfg.redact.allowlist == ()


# ────────────────────────────────────────────────────────────────────────────
# 2. 未知字段（SPEC §5：出现未知字段 → 拒绝启动）
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("extra", "needle"),
    [
        ("wat: 1", "wat"),
        ("server:\n  name: demo\n  colour: red", "server.colour"),
        ("inspect:\n  fingerprint:\n    storee: /tmp/x", "inspect.fingerprint.storee"),
        ("audit:\n  rotate: daily", "audit.rotate"),
        ("redact:\n  actions: mask", "redact.actions"),
        ("policy:\n  rules: []\n  denyresponse: {}", "policy.denyresponse"),
        ("defaults:\n  on_everything: deny", "defaults.on_everything"),
    ],
)
def test_unknown_field_refuses_to_start(write_config, extra, needle):
    text = MINIMAL + "\n" + textwrap.dedent(extra).strip() + "\n"
    if extra.startswith("server:"):  # 别让 server 段写两遍
        text = "version: 1\n" + textwrap.dedent(extra).strip() + "\n"

    with pytest.raises(ConfigError) as excinfo:
        load_config(write_config(text))

    report = problems_text(excinfo.value)
    assert needle in report
    assert "unknown field" in report
    assert excinfo.value.exit_code == EXIT_CONFIG_ERROR


def test_unknown_field_inside_pattern_rule(write_config):
    with pytest.raises(ConfigError) as excinfo:
        load_config(
            write_config(
                yaml_with(
                    """
                    redact:
                      rules:
                        - {id: x, pattern: 'a', severity: high}
                    """
                )
            )
        )
    assert "redact.rules[0].severity" in problems_text(excinfo.value)


def test_all_problems_reported_at_once(write_config):
    """别让用户改一条跑一次：一次解析要把能发现的问题都列出来。"""
    with pytest.raises(ConfigError) as excinfo:
        load_config(
            write_config(
                textwrap.dedent(
                    """
                    version: 2
                    bogus_top: 1
                    server:
                      name: demo
                      transport: http
                    defaults:
                      on_no_match: allow
                    """
                ).strip()
            )
        )
    report = problems_text(excinfo.value)
    assert len(excinfo.value.problems) >= 4
    for needle in ("version", "bogus_top", "server.transport", "defaults.on_no_match"):
        assert needle in report


# ────────────────────────────────────────────────────────────────────────────
# 3. 基础字段与枚举
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text",
    [
        "server:\n  name: demo",  # 缺 version
        "version: 2\nserver:\n  name: demo",
        "version: '1'\nserver:\n  name: demo",
        "version: 1",  # 缺 server
        "version: 1\nserver:\n  transport: stdio",  # 缺 server.name
        "version: 1\nserver:\n  name: ''",  # 空名字
        "version: 1\nserver:\n  name: demo\n  transport: http",
    ],
)
def test_bad_core_fields_refuse_to_start(write_config, text):
    with pytest.raises(ConfigError):
        load_config(write_config(text))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("on_no_match", "allow"),
        ("on_no_match", "passthrough"),
        ("on_rule_conflict", "passthrough"),
        ("on_detector_error", "fail"),
        ("on_audit_write_failure", "passthrough"),
        ("on_unknown_method", "deny"),
        ("on_upstream_crash", "passthrough"),
    ],
)
def test_defaults_only_accept_fail_closed_values(write_config, key, value):
    """defaults 六个开关只接受 fail-closed 的那一侧，要放宽必须改代码。"""
    with pytest.raises(ConfigError) as excinfo:
        load_config(write_config(yaml_with(f"defaults:\n  {key}: {value}")))
    assert f"defaults.{key}" in problems_text(excinfo.value)


def test_defaults_accept_spec_values(load_config_from):
    cfg = load_config_from(
        yaml_with(
            """
            defaults:
              on_no_match: deny
              on_rule_conflict: deny
              on_detector_error: deny
              on_audit_write_failure: deny
              on_unknown_method: passthrough
              on_upstream_crash: fail
            """
        )
    )
    assert cfg.defaults == cfg.defaults  # dataclass 相等即可，值在上面的断言里已覆盖
    assert cfg.defaults.on_upstream_crash is FailClosedAction.FAIL


# ────────────────────────────────────────────────────────────────────────────
# 4. policy：allow 三态 / when 六操作符 / 冲突检查
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("true", AllowMode.ALLOW), ("false", AllowMode.DENY), ("ask", AllowMode.ASK)],
)
def test_allow_three_states(load_config_from, raw, expected):
    cfg = load_config_from(
        yaml_with(
            f"""
            policy:
              rules:
                - id: r1
                  tool: t
                  allow: {raw}
            """
        )
    )
    assert cfg.policy.rules[0].allow is expected


@pytest.mark.parametrize("raw", ["'yes'", "1", "'allow'", "null", "[]", "'ASK'", "'Ask'"])
def test_allow_rejects_other_values(write_config, raw):
    with pytest.raises(ConfigError) as excinfo:
        load_config(
            write_config(
                yaml_with(
                    f"""
                    policy:
                      rules:
                        - id: r1
                          tool: t
                          allow: {raw}
                    """
                )
            )
        )
    assert "policy.rules[0].allow" in problems_text(excinfo.value)


def test_bare_yes_is_a_yaml_boolean_not_a_string(load_config_from):
    """记录一个 YAML 1.1 的坑：不加引号的 ``yes``/``on`` 在 PyYAML 里就是 ``true``。

    所以 ``allow: yes`` 等价于 ``allow: true`` —— 这是 YAML 层的语义，
    config 拿到的已经是 bool，无从分辨。要拒必须写 ``allow: 'yes'``（带引号）。
    """
    cfg = load_config_from(
        yaml_with(
            """
            policy:
              rules:
                - {id: r1, tool: t, allow: yes}
            """
        )
    )
    assert cfg.policy.rules[0].allow is AllowMode.ALLOW


def test_policy_rule_missing_required_fields(write_config):
    with pytest.raises(ConfigError) as excinfo:
        load_config(write_config(yaml_with("policy:\n  rules:\n    - {reason: nope}")))
    report = problems_text(excinfo.value)
    for needle in ("policy.rules[0].id", "policy.rules[0].tool", "policy.rules[0].allow"):
        assert needle in report


def test_all_six_when_operators_parse():
    cfg = parse_policy(
        {
            "rules": [
                {
                    "id": "r1",
                    "tool": "read_file",
                    "allow": True,
                    "when": [
                        {"arg": "path", "starts_with": "${PROJECT_DIR}/"},
                        {"arg": "mode", "equals": "r"},
                        {"arg": "path", "matches": r"\.txt$"},
                        {"arg": "path", "not_matches": r"id_rsa"},
                        {"arg": "kind", "one_of": ["a", "b"]},
                        {"arg": "path", "exists": True},
                    ],
                }
            ]
        }
    )
    ops = [c.op for c in cfg.rules[0].when]
    assert ops == [
        WhenOperator.STARTS_WITH,
        WhenOperator.EQUALS,
        WhenOperator.MATCHES,
        WhenOperator.NOT_MATCHES,
        WhenOperator.ONE_OF,
        WhenOperator.EXISTS,
    ]
    assert cfg.rules[0].when[2].regex is not None
    assert cfg.rules[0].when[3].regex is not None
    assert cfg.rules[0].when[0].regex is None  # 只有 matches/not_matches 才编译


@pytest.mark.parametrize("op", ["contains", "ends_with", "gt", "regex", "in"])
def test_seventh_operator_refuses_to_start(write_config, op):
    """SPEC §4：when 操作符全集就 6 个，出现别的直接拒绝启动。"""
    with pytest.raises(ConfigError) as excinfo:
        load_config(
            write_config(
                yaml_with(
                    f"""
                    policy:
                      rules:
                        - id: r1
                          tool: t
                          allow: true
                          when:
                            - {{arg: path, {op}: x}}
                    """
                )
            )
        )
    report = problems_text(excinfo.value)
    assert "policy.rules[0].when[0]" in report
    assert op in report and "unknown operator" in report


@pytest.mark.parametrize(
    "cond",
    [
        {"arg": "path"},  # 一个操作符都没有
        {"arg": "path", "equals": "a", "starts_with": "b"},  # 两个操作符
        {"equals": "a"},  # 缺 arg
        {"arg": 1, "equals": "a"},  # arg 不是字符串
        {"arg": "path", "one_of": "a"},  # one_of 必须是 list
        {"arg": "path", "one_of": []},  # 空 list 没意义
        {"arg": "path", "exists": "yes"},  # exists 必须是 bool
        {"arg": "path", "starts_with": 3},  # starts_with 必须是 str
        {"arg": "path", "matches": ["a"]},  # matches 必须是 str
    ],
)
def test_bad_when_conditions(cond):
    with pytest.raises(ConfigError) as excinfo:
        parse_when_condition(cond, where="policy.rules[0].when[0]")
    assert "policy.rules[0].when[0]" in problems_text(excinfo.value)


def test_when_bad_regex_refuses_to_start(write_config):
    with pytest.raises(ConfigError) as excinfo:
        load_config(
            write_config(
                yaml_with(
                    """
                    policy:
                      rules:
                        - id: r1
                          tool: t
                          allow: true
                          when:
                            - {arg: path, matches: '([unclosed'}
                    """
                )
            )
        )
    report = problems_text(excinfo.value)
    assert "policy.rules[0].when[0].matches" in report
    assert "invalid regex" in report


def test_duplicate_tool_refuses_to_start_and_prints_rule_ids(write_config):
    """SPEC §5 第三行：同一 tool 重复定义 → 拒绝启动，打印冲突 rule id。"""
    with pytest.raises(ConfigError) as excinfo:
        load_config(
            write_config(
                yaml_with(
                    """
                    policy:
                      rules:
                        - {id: allow-read, tool: read_file, allow: true}
                        - {id: deny-read,  tool: read_file, allow: false}
                    """
                )
            )
        )
    report = problems_text(excinfo.value)
    assert "read_file" in report
    assert "allow-read" in report and "deny-read" in report


def test_different_tool_globs_are_not_duplicates(load_config_from):
    """v1 只比字面量，不做 glob 交集分析 —— ``read_*`` 和 ``read_file`` 不算冲突。"""
    cfg = load_config_from(
        yaml_with(
            """
            policy:
              rules:
                - {id: r1, tool: read_file, allow: true}
                - {id: r2, tool: 'read_*', allow: false}
            """
        )
    )
    assert len(cfg.policy.rules) == 2


def test_duplicate_policy_rule_id_refuses_to_start(write_config):
    with pytest.raises(ConfigError) as excinfo:
        load_config(
            write_config(
                yaml_with(
                    """
                    policy:
                      rules:
                        - {id: same, tool: a, allow: true}
                        - {id: same, tool: b, allow: false}
                    """
                )
            )
        )
    report = problems_text(excinfo.value)
    assert "duplicate rule id" in report and "same" in report


def test_duplicate_pattern_rule_ids_refuse_to_start(write_config):
    with pytest.raises(ConfigError) as excinfo:
        load_config(
            write_config(
                yaml_with(
                    """
                    inspect:
                      static_checks:
                        rules:
                          - {id: dup, pattern: 'a'}
                          - {id: dup, pattern: 'b'}
                    redact:
                      rules:
                        - {id: rdup, pattern: 'a'}

                        - {id: rdup, pattern: 'b'}
                    """
                )
            )
        )
    report = problems_text(excinfo.value)
    assert "inspect.static_checks.rules" in report and "dup" in report
    assert "redact.rules" in report and "rdup" in report


# ────────────────────────────────────────────────────────────────────────────
# 5. 正则必须在启动期编译
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("section", "where"),
    [
        ("inspect:\n  static_checks:\n    rules:\n      - {id: bad, pattern: '(['}", "inspect.static_checks.rules[0].pattern"),
        ("redact:\n  rules:\n    - {id: bad, pattern: '*oops'}", "redact.rules[0].pattern"),
        ("redact:\n  allowlist: ['(?P<']", "redact.allowlist[0]"),
    ],
)
def test_bad_regex_refuses_to_start(write_config, section, where):
    with pytest.raises(ConfigError) as excinfo:
        load_config(write_config(yaml_with(section)))
    report = problems_text(excinfo.value)
    assert where in report
    assert "invalid regex" in report


def test_pattern_rule_missing_keys(write_config):
    with pytest.raises(ConfigError) as excinfo:
        load_config(write_config(yaml_with("redact:\n  rules:\n    - {id: only-id}")))
    assert "missing required key" in problems_text(excinfo.value)


def test_compile_pattern_rules_accepts_tuple_pairs():
    rules = compile_pattern_rules(SPEC_STATIC_RULES, where="x")
    assert len(rules) == len(SPEC_STATIC_RULES)
    assert all(isinstance(r.regex, re.Pattern) for r in rules)
    assert rules[0].id == "hidden-instruction-tag"


def test_compile_regex_reports_field_path():
    with pytest.raises(ConfigError) as excinfo:
        compile_regex("(", where="somewhere.deep")
    assert "somewhere.deep" in problems_text(excinfo.value)


# ────────────────────────────────────────────────────────────────────────────
# 6. ${PROJECT_DIR} 三种情况
# ────────────────────────────────────────────────────────────────────────────


def test_project_dir_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path) + "/")
    assert get_project_dir() == str(tmp_path)  # 尾斜杠被去掉
    assert expand_project_dir("${PROJECT_DIR}/src") == f"{tmp_path}/src"


def test_project_dir_falls_back_to_cwd(monkeypatch, tmp_path):
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    expected = str(Path.cwd())
    assert get_project_dir() == expected.rstrip("/")
    assert expand_project_dir("${PROJECT_DIR}/x") == f"{expected}/x"


def test_project_dir_empty_env_falls_back_to_cwd(monkeypatch, tmp_path):
    """环境变量存在但是空串 → 按"取不到"处理，退到 cwd。"""
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", "")
    monkeypatch.chdir(tmp_path)
    assert get_project_dir() == str(Path.cwd())


def test_project_dir_expands_to_empty_returns_none(monkeypatch):
    """展开为空 → None = 条件不满足。**绝不能退化成空串去做前缀匹配。**"""
    assert expand_project_dir("${PROJECT_DIR}/", project_dir="") is None
    assert expand_project_dir("${PROJECT_DIR}/", project_dir="   ") is None
    # 项目根退化成 "/" 同样按取不到处理，否则 starts_with 会匹配一切绝对路径
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", "/")
    assert get_project_dir() == ""
    assert expand_project_dir("${PROJECT_DIR}/") is None


def test_expand_project_dir_without_placeholder_is_identity(monkeypatch):
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    assert expand_project_dir("/abs/path") == "/abs/path"
    assert expand_project_dir("", project_dir="") == ""


def test_expand_project_dir_explicit_argument_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", "/env/value")
    assert expand_project_dir("${PROJECT_DIR}/a", project_dir=str(tmp_path)) == f"{tmp_path}/a"


# ────────────────────────────────────────────────────────────────────────────
# 7. 路径展开
# ────────────────────────────────────────────────────────────────────────────


def test_expand_path_handles_tilde_and_vars(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SOME_DIR", str(tmp_path / "sub"))
    assert expand_path("~/.mcp-guarder/x.sqlite") == tmp_path / ".mcp-guarder" / "x.sqlite"
    assert expand_path("$SOME_DIR/y") == tmp_path / "sub" / "y"
    assert expand_path(Path("relative/z")).is_absolute()


def test_path_fields_are_expanded(load_config_from, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = load_config_from(
        yaml_with(
            """
            inspect:
              fingerprint:
                store: ~/fp.sqlite
            audit:
              path: ~/audit/{server}-{date}.jsonl
              log_file: ~/guard.log
              snapshot_dir: ~/snaps
            """
        )
    )
    assert cfg.inspect.fingerprint.store == tmp_path / "fp.sqlite"
    assert cfg.audit.log_file == tmp_path / "guard.log"
    assert cfg.audit.snapshot_dir == tmp_path / "snaps"
    # 模板原文保留，{server}/{date} 留给 audit 模块在写入时算
    assert cfg.audit.path == "~/audit/{server}-{date}.jsonl"


@pytest.mark.parametrize(
    "section",
    [
        "audit:\n  path: '~/audit/{srever}-{date}.jsonl'",
        "redact:\n  mask_template: '[REDACTED:{rule}]'",
    ],
)
def test_unknown_template_placeholder_refuses_to_start(write_config, section):
    """模板里写错占位符在运行期是 KeyError（→ 全线 fail-closed），启动期就该拒。"""
    with pytest.raises(ConfigError) as excinfo:
        load_config(write_config(yaml_with(section)))
    assert "unknown placeholder" in problems_text(excinfo.value)


# ────────────────────────────────────────────────────────────────────────────
# 8. audit / redact / fingerprint 的其它校验
# ────────────────────────────────────────────────────────────────────────────


def test_audit_defaults_are_absolute(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    audit = parse_audit(None)
    assert audit.log_file == tmp_path / ".mcp-guarder" / "guard.log"
    assert audit.snapshot_dir == tmp_path / ".mcp-guarder" / "snapshots"
    assert audit.path == "~/.mcp-guarder/audit/{server}-{date}.jsonl"


@pytest.mark.parametrize(
    "section",
    [
        "audit:\n  fsync: sometimes",
        "audit:\n  record:\n    tools_call: partial",
        "audit:\n  payload:\n    max_bytes: 0",
        "audit:\n  payload:\n    max_bytes: '4096'",
        "audit:\n  payload:\n    store_redacted_only: false",
    ],
)
def test_bad_audit_section(write_config, section):
    with pytest.raises(ConfigError):
        load_config(write_config(yaml_with(section)))


def test_audit_accepts_all_fsync_modes(load_config_from):
    for mode in ("every_record", "interval", "never"):
        cfg = load_config_from(yaml_with(f"audit:\n  fsync: {mode}"))
        assert str(cfg.audit.fsync) == mode


def test_redact_accepts_all_actions(load_config_from):
    for action in ("mask", "drop_field", "deny_call"):
        cfg = load_config_from(yaml_with(f"redact:\n  action: {action}"))
        assert str(cfg.redact.action) == action


@pytest.mark.parametrize(
    "path",
    ["result.content[0].text", "result.*.text", "result..text", "result.content[]!", ""],
)
def test_bad_scan_path_refuses_to_start(write_config, path):
    with pytest.raises(ConfigError) as excinfo:
        load_config(write_config(yaml_with(f"redact:\n  inbound_scan: ['{path}']")))
    assert "redact.inbound_scan[0]" in problems_text(excinfo.value)


def test_spec_scan_paths_are_valid(load_config_from):
    cfg = load_config_from(
        yaml_with(
            """
            redact:
              outbound_scan: [params.arguments]
              inbound_scan:
                - result.content[].text
                - result.content[].resource.text
                - result.structuredContent
            """
        )
    )
    assert cfg.redact.inbound_scan[1] == "result.content[].resource.text"


def test_empty_fingerprint_fields_refuse_to_start(write_config):
    with pytest.raises(ConfigError):
        load_config(write_config(yaml_with("inspect:\n  fingerprint:\n    fields: []")))


def test_validate_config_catches_empty_fields_on_hand_built_config(load_config_from):
    """直接构造 GuarderConfig 的路径也要被 validate_config 兜住。"""
    import dataclasses

    cfg = load_config_from(MINIMAL)
    broken_fp = dataclasses.replace(cfg.inspect.fingerprint, fields=())
    broken = dataclasses.replace(
        cfg, inspect=dataclasses.replace(cfg.inspect, fingerprint=broken_fp)
    )
    with pytest.raises(ConfigError) as excinfo:
        validate_config(broken)
    assert "inspect.fingerprint.fields" in problems_text(excinfo.value)


@pytest.mark.parametrize(
    "section",
    [
        "inspect:\n  fingerprint:\n    enabled: yes_please",
        "inspect:\n  static_checks:\n    on_hit: explode",
        "inspect:\n  static_checks:\n    scan_fields: []",
        "inspect:\n  fingerprint:\n    on_change: allow",
        "inspect:\n  fingerprint:\n    on_first_seen: deny",
        "redact:\n  enabled: 1",
        "policy:\n  deny_response:\n    kind: jsonrpc_error",
    ],
)
def test_bad_inspect_and_policy_values(write_config, section):
    with pytest.raises(ConfigError):
        load_config(write_config(yaml_with(section)))


def test_static_checks_warn_mode_is_allowed(load_config_from):
    cfg = load_config_from(yaml_with("inspect:\n  static_checks:\n    on_hit: warn"))
    assert cfg.inspect.static_checks.on_hit is StaticCheckAction.WARN


# ────────────────────────────────────────────────────────────────────────────
# 9. 文件层：load_yaml / load_config
# ────────────────────────────────────────────────────────────────────────────


def test_missing_file_is_config_error(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load_config(tmp_path / "nope.yaml")
    assert "not found" in problems_text(excinfo.value)
    assert excinfo.value.exit_code == EXIT_CONFIG_ERROR


def test_default_path_missing_is_config_error(monkeypatch, tmp_path):
    """没有配置文件 ≠ 用全默认跑：宁可起不来。"""
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(ConfigError):
        load_config(None)


@pytest.mark.parametrize("text", ["", "- a\n- b", "just a string", "version: 1\n  bad indent:"])
def test_bad_yaml_is_config_error(write_config, text):
    with pytest.raises(ConfigError):
        load_yaml(write_config(text))


def test_load_yaml_returns_mapping(write_config):
    assert load_yaml(write_config(MINIMAL))["server"]["name"] == "demo"


def test_parse_config_rejects_non_mapping_root():
    with pytest.raises(ConfigError):
        parse_config(["not", "a", "mapping"])  # type: ignore[arg-type]


# ────────────────────────────────────────────────────────────────────────────
# 10. 小工具
# ────────────────────────────────────────────────────────────────────────────


def test_ensure_no_unknown_keys_lists_every_offender():
    with pytest.raises(ConfigError) as excinfo:
        ensure_no_unknown_keys({"a": 1, "b": 2, "c": 3}, ["a"], where="sec")
    assert len(excinfo.value.problems) == 2
    assert "sec.b" in problems_text(excinfo.value)
    assert "sec.c" in problems_text(excinfo.value)


def test_ensure_no_unknown_keys_ok():
    ensure_no_unknown_keys({"a": 1}, ["a", "b"], where="sec")


def test_coerce_enum_narrowing():
    assert coerce_enum("stdio", Transport, where="x") is Transport.STDIO
    with pytest.raises(ConfigError):
        coerce_enum("deny", FailClosedAction, where="x", allowed=[FailClosedAction.PASSTHROUGH])
    with pytest.raises(ConfigError):
        coerce_enum(True, Transport, where="x")


def test_config_error_exit_code_is_two():
    assert ConfigError("x").exit_code == EXIT_CONFIG_ERROR
