"""配置加载：解析 + 严格校验 + 启动期冲突检查（SPEC §4 / §5）。

三件事，任何一件失败都抛 :class:`~mcp_guarder.errors.ConfigError`（→ 拒绝启动，exit 2）：

1. **解析**：读 YAML → 构造 :class:`~mcp_guarder.types.GuarderConfig`（frozen dataclass）。
2. **严格校验**：出现未知字段、枚举取值不对、正则编译不过、``when`` 用了 6 个操作符
   以外的东西 —— 一律拒绝启动（SPEC §4「配置里出现别的直接拒绝启动」）。
3. **启动期冲突检查**：同一个 ``tool`` 被多条 policy 规则重复定义、rule id 重复
   —— 拒绝启动并打印冲突 rule id（SPEC §5 第三行）。

本模块还是 ``${PROJECT_DIR}`` 展开的**唯一实现处**（SPEC §4）：
policy 不许自己再写一份展开逻辑，一律调 :func:`expand_project_dir`。

依赖方向：只 import ``types`` / ``errors`` / 标准库 / yaml。

实现约定：
- 每条问题（problem）都以**字段路径**开头，例如
  ``policy.rules[1].when[0]: unknown operator 'contains' ...``，用户扫一眼就知道改哪。
- 能一次发现的问题一次性列全（:class:`ConfigError` 的 ``problems``），
  别让用户改一条跑一次。
"""

from __future__ import annotations

import os
import re
import string
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from mcp_guarder.errors import ConfigError
from mcp_guarder.types import (
    ALLOWED_DEFAULT_ACTIONS,
    DEFAULT_CONFIG_PATH,
    PROJECT_DIR_ENV,
    PROJECT_DIR_PLACEHOLDER,
    SPEC_REDACT_ALLOWLIST,
    SPEC_REDACT_RULES,
    SPEC_STATIC_RULES,
    SUPPORTED_CONFIG_VERSION,
    WHEN_OPERATOR_NAMES,
    AllowMode,
    AuditConfig,
    AuditPayloadConfig,
    AuditRecordConfig,
    DefaultsConfig,
    DenyResponseConfig,
    DenyResponseKind,
    FailClosedAction,
    FingerprintChangeAction,
    FingerprintConfig,
    FirstSeenAction,
    FsyncMode,
    GuarderConfig,
    InspectConfig,
    JsonValue,
    PatternRule,
    PolicyConfig,
    PolicyRule,
    RecordMode,
    RedactAction,
    RedactConfig,
    ServerConfig,
    StaticCheckAction,
    StaticChecksConfig,
    Transport,
    WhenCondition,
    WhenOperator,
)

# ────────────────────────────────────────────────────────────────────────────
# 各段允许出现的 key（严格模式：出现别的一律拒绝启动，SPEC §5）
# ────────────────────────────────────────────────────────────────────────────

_TOP_LEVEL_KEYS = ("version", "server", "defaults", "inspect", "policy", "redact", "audit")
_SERVER_KEYS = ("name", "transport")
_DEFAULTS_KEYS = tuple(ALLOWED_DEFAULT_ACTIONS)
_INSPECT_KEYS = ("fingerprint", "static_checks")
_FINGERPRINT_KEYS = ("enabled", "store", "fields", "on_first_seen", "on_change")
_STATIC_CHECKS_KEYS = ("enabled", "on_hit", "scan_fields", "rules")
_POLICY_KEYS = ("rules", "deny_response")
_POLICY_RULE_KEYS = ("id", "tool", "allow", "when", "reason")
_DENY_RESPONSE_KEYS = ("kind", "text")
_REDACT_KEYS = (
    "enabled",
    "outbound_scan",
    "inbound_scan",
    "action",
    "mask_template",
    "rules",
    "allowlist",
)
_AUDIT_KEYS = ("path", "fsync", "record", "payload", "log_file", "snapshot_dir")
_AUDIT_RECORD_KEYS = ("tools_list", "tools_call", "other_methods")
_AUDIT_PAYLOAD_KEYS = ("max_bytes", "store_redacted_only")
_PATTERN_RULE_KEYS = ("id", "pattern")

#: ``audit.path`` 模板里允许出现的占位符（SPEC §4）。
_AUDIT_PATH_PLACEHOLDERS = frozenset({"server", "date"})

#: ``redact.mask_template`` 里允许出现的占位符（SPEC §4）。
_MASK_TEMPLATE_PLACEHOLDERS = frozenset({"rule_id"})

#: 扫描路径表达式里单个 segment 的合法形态：``name`` 或 ``name[]``。
#: 不支持下标 ``[0]``、通配 ``*``、引号 key（见 ``redact.parse_scan_path``）。
_SCAN_SEGMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(\[\])*$")


# ────────────────────────────────────────────────────────────────────────────
# 入口
# ────────────────────────────────────────────────────────────────────────────


def load_config(path: Path | str | None = None) -> GuarderConfig:
    """从磁盘加载配置：读文件 → :func:`parse_config` → :func:`validate_config`。

    :param path: ``--config`` 指定的路径；None 时用
        :data:`~mcp_guarder.types.DEFAULT_CONFIG_PATH`（``~/.mcp-guarder/config.yaml``）。
    :raises ConfigError: 文件不存在、YAML 语法错、校验不过、冲突检查不过。

    **fail-closed**：宁可起不来也不能带着半截配置跑。文件不存在也是 ConfigError，
    不要"没有配置就用全默认"——那等于悄悄放宽安全边界。
    """
    resolved = expand_path(DEFAULT_CONFIG_PATH if path is None else path)
    raw = load_yaml(resolved)
    # load_yaml 已经保证是 mapping。
    cfg = parse_config(raw, source=resolved)  # type: ignore[arg-type]
    validate_config(cfg)
    return cfg


def parse_config(raw: Mapping[str, Any], *, source: Path | None = None) -> GuarderConfig:
    """把 YAML 反序列化出来的 dict 转成 :class:`GuarderConfig`。

    要点：
    - ``version`` 必须等于 :data:`~mcp_guarder.types.SUPPORTED_CONFIG_VERSION`（1）。
    - ``server.name`` 必填且非空（它是审计和指纹的命名空间键）；
      ``server.transport`` 只认 ``stdio``。
    - 缺省的段落用 SPEC §4 里那份 YAML 的值兜底：``inspect.static_checks.rules`` 缺省
      用 :data:`~mcp_guarder.types.SPEC_STATIC_RULES`，``redact.rules`` 缺省用
      :data:`~mcp_guarder.types.SPEC_REDACT_RULES`，allowlist 用
      :data:`~mcp_guarder.types.SPEC_REDACT_ALLOWLIST`。
      **``policy.rules`` 缺省是空列表**（→ 一切 tools/call 走 no-match deny，这是对的）。
    - 所有正则在这里编译（:func:`compile_pattern_rules`），运行期不再编译。
    - 所有路径字段（fingerprint.store / audit.log_file / audit.snapshot_dir）在这里
      展开 ``~`` 和 ``$VAR`` 并转成绝对路径；``audit.path`` 是模板字符串，**不展开**
      （含 ``{server}`` / ``{date}``，由 audit 模块在写入时算）。
    - 未知字段一律报错（:func:`ensure_no_unknown_keys`）。

    :raises ConfigError: 任何字段不合法。ConfigError.problems 要把能一次发现的问题都列出来。
    """
    if not isinstance(raw, Mapping):
        raise ConfigError(
            f"config root must be a mapping, got {_type_name(raw)}",
            problems=(f"(root): expected a mapping, got {_type_name(raw)}",),
            path=source,
        )

    problems: list[str] = []
    _capture(problems, lambda: ensure_no_unknown_keys(raw, _TOP_LEVEL_KEYS, where="(root)"))

    version = _capture(problems, lambda: _parse_version(raw.get("version")))
    server = _capture(problems, lambda: _parse_server(raw.get("server")))
    defaults = _capture(problems, lambda: _parse_defaults(raw.get("defaults")))
    inspect_cfg = _capture(problems, lambda: _parse_inspect(raw.get("inspect")))
    policy = _capture(problems, lambda: parse_policy(raw.get("policy")))
    redact = _capture(problems, lambda: _parse_redact(raw.get("redact")))
    audit = _capture(problems, lambda: parse_audit(raw.get("audit")))

    if problems:
        raise ConfigError(
            f"{len(problems)} problem(s) found while parsing config",
            problems=problems,
            path=source,
        )

    return GuarderConfig(
        version=version,  # type: ignore[arg-type]
        server=server,  # type: ignore[arg-type]
        defaults=defaults,  # type: ignore[arg-type]
        inspect=inspect_cfg,  # type: ignore[arg-type]
        policy=policy,  # type: ignore[arg-type]
        redact=redact,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        source_path=source,
    )


def validate_config(cfg: GuarderConfig) -> None:
    """启动期冲突检查（SPEC §5 第三行）。跑在 :func:`parse_config` 之后。

    必须检出并拒绝启动的情况：
    1. **同一个 ``tool`` glob 被两条 policy 规则重复定义** → 报错并打印两条 rule id。
       （SPEC 的原话是「同一 tool 出现相反结论 …… 启动时静态检查发现同 tool 重复定义
       就拒绝启动」，v1 采用最保守解释：只要 ``tool`` 字段字面量相同就算重复，
       不去做 glob 交集的语义分析。）
    2. policy 规则 ``id`` 重复。
    3. static_checks / redact 规则 ``id`` 重复。
    4. ``inspect.fingerprint.fields`` 为空、``redact.outbound_scan``/``inbound_scan``
       里出现非法路径语法（见 :func:`~mcp_guarder.redact.parse_scan_path`）。

    :raises ConfigError: 带上全部冲突条目，一次性打给用户。
    """
    problems: list[str] = []

    # 1. 同一个 tool 被多条规则定义（字面量相同即算重复）。
    by_tool: dict[str, list[str]] = {}
    for rule in cfg.policy.rules:
        by_tool.setdefault(rule.tool, []).append(rule.id)
    for tool, rule_ids in by_tool.items():
        if len(rule_ids) > 1:
            problems.append(
                f"policy.rules: tool {tool!r} is defined more than once by rules: "
                + ", ".join(rule_ids)
            )

    # 2. policy 规则 id 重复。
    problems.extend(_duplicate_id_problems([r.id for r in cfg.policy.rules], where="policy.rules"))

    # 3. static_checks / redact 规则 id 重复。
    problems.extend(
        _duplicate_id_problems(
            [r.id for r in cfg.inspect.static_checks.rules],
            where="inspect.static_checks.rules",
        )
    )
    problems.extend(
        _duplicate_id_problems([r.id for r in cfg.redact.rules], where="redact.rules")
    )

    # 4a. 指纹字段不能为空 —— 空字段集会让所有 tool 的 digest 相同，指纹直接失效。
    if not cfg.inspect.fingerprint.fields:
        problems.append("inspect.fingerprint.fields: must not be empty")

    # 4b. 脱敏扫描路径的语法。
    for where, paths in (
        ("redact.outbound_scan", cfg.redact.outbound_scan),
        ("redact.inbound_scan", cfg.redact.inbound_scan),
    ):
        for index, path in enumerate(paths):
            problem = _scan_path_problem(path, where=f"{where}[{index}]")
            if problem is not None:
                problems.append(problem)

    if problems:
        raise ConfigError(
            f"{len(problems)} conflict(s) found in config",
            problems=problems,
            path=cfg.source_path,
        )


# ────────────────────────────────────────────────────────────────────────────
# 分段解析（parse_config 的内部拆分，导出是为了单测能单独打）
# ────────────────────────────────────────────────────────────────────────────


def parse_policy(raw: Mapping[str, Any] | None) -> PolicyConfig:
    """解析 ``policy:`` 段。

    ``allow`` 的三态映射：YAML ``true`` → ALLOW，``false`` → DENY，字符串 ``"ask"`` → ASK。
    其它值（``"yes"``、``1``、``None``）一律 ConfigError。

    TODO(SPEC §7 末尾的 TODO(待验证))：``ask`` 依赖 ``elicitation/create``，UX 没验过。
    **v1 不实现 elicitation**，解析阶段照常接受 ``ask`` 并保留在 AllowMode.ASK，
    由 :func:`~mcp_guarder.policy.evaluate` 降级成 deny 并让 proxy 往 guard.log
    写一行提示（见 :func:`~mcp_guarder.policy.ask_downgrade_message`）。
    """
    if raw is None:
        return PolicyConfig()

    section = _require_mapping(raw, where="policy")
    problems: list[str] = []
    _capture(problems, lambda: ensure_no_unknown_keys(section, _POLICY_KEYS, where="policy"))

    rules: list[PolicyRule] = []
    raw_rules = section.get("rules")
    if raw_rules is not None:
        items = _capture(problems, lambda: _require_list(raw_rules, where="policy.rules"))
        for index, item in enumerate(items or ()):
            rule = _capture(problems, lambda i=index, it=item: _parse_policy_rule(it, index=i))
            if rule is not None:
                rules.append(rule)

    deny_response = _capture(
        problems, lambda: _parse_deny_response(section.get("deny_response"))
    )

    if problems:
        raise ConfigError("invalid policy section", problems=problems)

    return PolicyConfig(
        rules=tuple(rules),
        deny_response=deny_response or DenyResponseConfig(),
    )


def parse_when_condition(raw: Mapping[str, Any], *, where: str) -> WhenCondition:
    """解析一个 ``when`` 条件。

    形态：``{arg: <name>, <operator>: <value>}`` —— 除 ``arg`` 外**有且只有一个** key。

    - 操作符必须属于 :data:`~mcp_guarder.types.WHEN_OPERATOR_NAMES` 那 6 个，
      否则 ConfigError（SPEC §4「配置里出现别的直接拒绝启动」）。
    - ``matches`` / ``not_matches``：value 必须是 str，在这里编译成 regex。
    - ``one_of``：value 必须是 ``list[str]``。
    - ``exists``：value 必须是 bool。
    - ``starts_with`` / ``equals``：value 必须是 str（可含 ``${PROJECT_DIR}``，不在这里展开）。

    :param where: 出错时报给用户的字段路径，例如 ``policy.rules[0].when[1]``。
    """
    cond = _require_mapping(raw, where=where)

    if "arg" not in cond:
        raise ConfigError(
            f"{where}: missing required key 'arg'",
            problems=(f"{where}: missing required key 'arg'",),
            field_path=where,
        )
    arg = _require_str(cond["arg"], where=f"{where}.arg")

    operators = [key for key in cond if key != "arg"]
    if len(operators) != 1:
        detail = (
            "expected exactly one operator besides 'arg', got "
            + (f"{len(operators)}: {sorted(operators)}" if operators else "none")
            + f" (allowed: {_sorted_list(WHEN_OPERATOR_NAMES)})"
        )
        raise ConfigError(
            f"{where}: {detail}", problems=(f"{where}: {detail}",), field_path=where
        )

    op_name = operators[0]
    if op_name not in WHEN_OPERATOR_NAMES:
        detail = f"unknown operator {op_name!r} (allowed: {_sorted_list(WHEN_OPERATOR_NAMES)})"
        raise ConfigError(
            f"{where}: {detail}", problems=(f"{where}: {detail}",), field_path=where
        )

    op = WhenOperator(op_name)
    raw_value = cond[op_name]
    value_where = f"{where}.{op_name}"
    regex: re.Pattern[str] | None = None

    if op in (WhenOperator.MATCHES, WhenOperator.NOT_MATCHES):
        value: str | list[str] | bool = _require_str(raw_value, where=value_where)
        regex = compile_regex(value, where=value_where)
    elif op is WhenOperator.ONE_OF:
        value = list(_require_str_list(raw_value, where=value_where, allow_empty=False))
    elif op is WhenOperator.EXISTS:
        value = _require_bool(raw_value, where=value_where)
    else:  # starts_with / equals
        value = _require_str(raw_value, where=value_where, allow_empty=False)

    return WhenCondition(arg=arg, op=op, value=value, regex=regex)


def parse_audit(raw: Mapping[str, Any] | None) -> AuditConfig:
    """解析 ``audit:`` 段。``path`` 保留模板原文，``log_file``/``snapshot_dir`` 展开成绝对路径。"""
    defaults = AuditConfig()
    if raw is None:
        return AuditConfig(
            path=defaults.path,
            fsync=defaults.fsync,
            record=defaults.record,
            payload=defaults.payload,
            log_file=expand_path(defaults.log_file),
            snapshot_dir=expand_path(defaults.snapshot_dir),
        )

    section = _require_mapping(raw, where="audit")
    problems: list[str] = []
    _capture(problems, lambda: ensure_no_unknown_keys(section, _AUDIT_KEYS, where="audit"))

    path = defaults.path
    if "path" in section:
        candidate = _capture(problems, lambda: _require_str(section["path"], where="audit.path"))
        if candidate is not None:
            _capture(
                problems,
                lambda c=candidate: _check_template_placeholders(
                    c, allowed=_AUDIT_PATH_PLACEHOLDERS, where="audit.path"
                ),
            )
            path = candidate

    fsync = defaults.fsync
    if "fsync" in section:
        fsync = (
            _capture(
                problems,
                lambda: coerce_enum(section["fsync"], FsyncMode, where="audit.fsync"),
            )
            or defaults.fsync
        )

    record = _capture(problems, lambda: _parse_audit_record(section.get("record")))
    payload = _capture(problems, lambda: _parse_audit_payload(section.get("payload")))

    log_file = expand_path(defaults.log_file)
    if "log_file" in section:
        raw_log = _capture(
            problems, lambda: _require_path_like(section["log_file"], where="audit.log_file")
        )
        if raw_log is not None:
            log_file = expand_path(raw_log)

    snapshot_dir = expand_path(defaults.snapshot_dir)
    if "snapshot_dir" in section:
        raw_snap = _capture(
            problems,
            lambda: _require_path_like(section["snapshot_dir"], where="audit.snapshot_dir"),
        )
        if raw_snap is not None:
            snapshot_dir = expand_path(raw_snap)

    if problems:
        raise ConfigError("invalid audit section", problems=problems)

    return AuditConfig(
        path=path,
        fsync=fsync,
        record=record or AuditRecordConfig(),
        payload=payload or AuditPayloadConfig(),
        log_file=log_file,
        snapshot_dir=snapshot_dir,
    )


def compile_pattern_rules(
    raw_rules: Sequence[Mapping[str, Any]] | Sequence[tuple[str, str]],
    *,
    where: str,
) -> tuple[PatternRule, ...]:
    """把 ``[{id, pattern}, ...]`` 编译成 :class:`PatternRule` 元组。

    正则编译失败 → ConfigError（启动期就拒，别留到运行期变成 DetectorError）。
    也接受 ``[(id, pattern), ...]`` 形态，方便直接吃
    :data:`~mcp_guarder.types.SPEC_STATIC_RULES` 这类常量。
    """
    items = _require_list(raw_rules, where=where)

    problems: list[str] = []
    rules: list[PatternRule] = []

    for index, item in enumerate(items):
        item_where = f"{where}[{index}]"
        rule_id: Any
        pattern: Any

        if isinstance(item, Mapping):
            _capture(
                problems,
                lambda it=item, w=item_where: ensure_no_unknown_keys(
                    it, _PATTERN_RULE_KEYS, where=w
                ),
            )
            missing = [key for key in _PATTERN_RULE_KEYS if key not in item]
            if missing:
                problems.append(f"{item_where}: missing required key(s): {', '.join(missing)}")
                continue
            rule_id = item["id"]
            pattern = item["pattern"]
        elif isinstance(item, (tuple, list)) and not isinstance(item, (str, bytes)):
            if len(item) != 2:
                problems.append(
                    f"{item_where}: expected a 2-item (id, pattern) pair, got {len(item)} item(s)"
                )
                continue
            rule_id, pattern = item
        else:
            problems.append(
                f"{item_where}: expected a mapping with keys {list(_PATTERN_RULE_KEYS)}, "
                f"got {_type_name(item)}"
            )
            continue

        checked_id = _capture(
            problems, lambda v=rule_id, w=item_where: _require_str(v, where=f"{w}.id")
        )
        checked_pattern = _capture(
            problems, lambda v=pattern, w=item_where: _require_str(v, where=f"{w}.pattern")
        )
        if checked_id is None or checked_pattern is None:
            continue

        regex = _capture(
            problems,
            lambda p=checked_pattern, w=item_where: compile_regex(p, where=f"{w}.pattern"),
        )
        if regex is None:
            continue

        rules.append(PatternRule(id=checked_id, pattern=checked_pattern, regex=regex))

    if problems:
        raise ConfigError(f"invalid pattern rules in {where}", problems=problems, field_path=where)

    return tuple(rules)


# ────────────────────────────────────────────────────────────────────────────
# 共享工具（policy / audit / fingerprint 都从这里取，不许各写一份）
# ────────────────────────────────────────────────────────────────────────────


def get_project_dir() -> str:
    """取项目根目录：环境变量 ``CLAUDE_PROJECT_DIR``，**取不到就退到进程 cwd**（SPEC §4）。

    返回值不带尾部斜杠。注意这里读的是 mcp-guarder 自己进程的环境和 cwd ——
    因为 environ 是从 Claude Code 完整继承下来的（SPEC §3）。

    拿不到任何可用目录（环境变量是空串且 cwd 也取不到）时返回空串，
    调用方（:func:`expand_project_dir`）会把它翻译成 None = 条件不满足。
    另：项目根目录退化成 ``/`` 时同样返回空串 —— 否则
    ``starts_with: "${PROJECT_DIR}/"`` 会退化成匹配一切绝对路径。
    """
    value = os.environ.get(PROJECT_DIR_ENV) or ""
    if not value.strip():
        try:
            value = os.getcwd()
        except OSError:  # pragma: no cover - cwd 被删掉才会走到
            value = ""
    return value.strip().rstrip("/")


def expand_project_dir(template: str, *, project_dir: str | None = None) -> str | None:
    """把字符串里的 ``${PROJECT_DIR}`` 展开。

    规则（SPEC §4，**唯一实现处**）：
    - ``${PROJECT_DIR}`` = 环境变量 ``CLAUDE_PROJECT_DIR``，取不到退到进程 cwd。
    - **展开为空（环境变量存在但是空串、且 cwd 也拿不到）→ 返回 None，表示"条件不满足"**，
      调用方（policy）必须把这个条件判成 False，绝不能拿空串去做前缀匹配 ——
      那会让 ``starts_with: "${PROJECT_DIR}/"`` 退化成匹配一切以 ``/`` 开头的路径。
    - 不含占位符的字符串原样返回。

    :param project_dir: 显式传入则不查环境（测试用）。
    """
    if PROJECT_DIR_PLACEHOLDER not in template:
        return template

    resolved = get_project_dir() if project_dir is None else project_dir.strip().rstrip("/")
    if not resolved:
        return None

    expanded = template.replace(PROJECT_DIR_PLACEHOLDER, resolved)
    return expanded or None


def expand_path(value: str | Path) -> Path:
    """展开 ``~`` 与 ``$VAR`` 并转成绝对路径。用于 store / log_file / snapshot_dir。"""
    text = os.path.expandvars(str(value))
    text = os.path.expanduser(text)
    return Path(os.path.abspath(text))


def ensure_no_unknown_keys(
    raw: Mapping[str, Any],
    allowed: Iterable[str],
    *,
    where: str,
) -> None:
    """严格模式校验：``raw`` 里出现 ``allowed`` 之外的 key 就抛 ConfigError。

    SPEC §5：「配置解析失败 / 出现未知字段 → 拒绝启动」。
    ``where`` 是字段路径前缀，用来拼出人看得懂的报错。
    """
    allowed_keys = tuple(allowed)
    unknown = sorted(str(key) for key in raw if key not in allowed_keys)
    if not unknown:
        return

    problems = tuple(
        f"{_join_field(where, key)}: unknown field (allowed here: {list(allowed_keys)})"
        for key in unknown
    )
    raise ConfigError(
        f"{where}: unknown field(s): {', '.join(unknown)}",
        problems=problems,
        field_path=where,
    )


def coerce_enum(
    value: Any,
    enum_cls: type,
    *,
    where: str,
    allowed: Iterable[Any] | None = None,
) -> Any:
    """把 YAML 里的字符串转成枚举成员；不是合法取值就 ConfigError。

    :param allowed: 进一步收窄允许的成员子集（例如 ``defaults.on_upstream_crash``
        只允许 ``fail``，见 :data:`~mcp_guarder.types.ALLOWED_DEFAULT_ACTIONS`）。
    """
    choices = tuple(allowed) if allowed is not None else tuple(enum_cls)  # type: ignore[call-overload]
    choice_names = [str(c) for c in choices]

    if isinstance(value, enum_cls):
        member: Any = value
    elif isinstance(value, str):
        try:
            member = enum_cls(value)  # type: ignore[call-arg]
        except ValueError:
            return _fail(where, f"invalid value {value!r} (allowed: {choice_names})")
    else:
        return _fail(
            where,
            f"expected one of {choice_names}, got {_type_name(value)} ({value!r})",
        )

    if member not in choices:
        return _fail(where, f"value {str(member)!r} is not allowed here (allowed: {choice_names})")
    return member


def load_yaml(path: Path) -> JsonValue:
    """读 YAML 文件。用 ``yaml.safe_load``，**绝不用 ``yaml.load``**。

    文件不存在、不是 mapping、YAML 语法错 → ConfigError。
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(
            f"config file not found: {path}",
            problems=(f"{path}: no such file",),
            path=Path(path),
        ) from exc
    except OSError as exc:
        raise ConfigError(
            f"cannot read config file {path}: {exc}",
            problems=(f"{path}: {type(exc).__name__}: {exc}",),
            path=Path(path),
        ) from exc

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(
            f"invalid YAML in {path}: {exc}",
            problems=(f"{path}: YAML syntax error: {exc}",),
            path=Path(path),
        ) from exc

    if data is None:
        raise ConfigError(
            f"config file is empty: {path}",
            problems=(f"{path}: file is empty, expected a YAML mapping",),
            path=Path(path),
        )
    if not isinstance(data, Mapping):
        raise ConfigError(
            f"config root must be a mapping, got {_type_name(data)}: {path}",
            problems=(f"{path}: expected a YAML mapping, got {_type_name(data)}",),
            path=Path(path),
        )
    return dict(data)


def compile_regex(pattern: str, *, where: str) -> re.Pattern[str]:
    """编译单条正则，失败转 ConfigError（带上字段路径和原始 pattern）。"""
    if not isinstance(pattern, str):
        _fail(where, f"expected a regex string, got {_type_name(pattern)}")
    try:
        return re.compile(pattern)
    except re.error as exc:
        _fail(where, f"invalid regex {pattern!r}: {exc}")


# ────────────────────────────────────────────────────────────────────────────
# 内部：分段解析
# ────────────────────────────────────────────────────────────────────────────


def _parse_version(value: Any) -> int:
    """``version`` 必须显式写，且只认 1。"""
    if value is None:
        _fail("version", f"missing required field (must be {SUPPORTED_CONFIG_VERSION})")
    if isinstance(value, bool) or not isinstance(value, int):
        _fail("version", f"expected int {SUPPORTED_CONFIG_VERSION}, got {_type_name(value)}")
    if value != SUPPORTED_CONFIG_VERSION:
        _fail("version", f"unsupported config version {value} (this build only supports {SUPPORTED_CONFIG_VERSION})")
    return value


def _parse_server(raw: Any) -> ServerConfig:
    """``server:`` 段。``name`` 必填 —— 它是审计和指纹的命名空间键。"""
    if raw is None:
        _fail("server", "missing required section (server.name is the audit/fingerprint namespace)")
    section = _require_mapping(raw, where="server")

    problems: list[str] = []
    _capture(problems, lambda: ensure_no_unknown_keys(section, _SERVER_KEYS, where="server"))

    name = None
    if "name" not in section:
        problems.append("server.name: missing required field")
    else:
        name = _capture(problems, lambda: _require_str(section["name"], where="server.name"))

    transport = Transport.STDIO
    if "transport" in section:
        transport = (
            _capture(
                problems,
                lambda: coerce_enum(section["transport"], Transport, where="server.transport"),
            )
            or Transport.STDIO
        )

    if problems:
        raise ConfigError("invalid server section", problems=problems)
    return ServerConfig(name=name, transport=transport)  # type: ignore[arg-type]


def _parse_defaults(raw: Any) -> DefaultsConfig:
    """``defaults:`` 段。每个 key 只接受 :data:`ALLOWED_DEFAULT_ACTIONS` 里的取值。"""
    if raw is None:
        return DefaultsConfig()
    section = _require_mapping(raw, where="defaults")

    problems: list[str] = []
    _capture(problems, lambda: ensure_no_unknown_keys(section, _DEFAULTS_KEYS, where="defaults"))

    values: dict[str, FailClosedAction] = {}
    for key, allowed in ALLOWED_DEFAULT_ACTIONS.items():
        if key not in section:
            continue
        member = _capture(
            problems,
            lambda k=key, a=allowed: coerce_enum(
                section[k], FailClosedAction, where=f"defaults.{k}", allowed=sorted(a)
            ),
        )
        if member is not None:
            values[key] = member

    if problems:
        raise ConfigError("invalid defaults section", problems=problems)
    return DefaultsConfig(**values)


def _parse_inspect(raw: Any) -> InspectConfig:
    """``inspect:`` 段。"""
    if raw is None:
        return InspectConfig(
            fingerprint=_parse_fingerprint(None),
            static_checks=_parse_static_checks(None),
        )
    section = _require_mapping(raw, where="inspect")

    problems: list[str] = []
    _capture(problems, lambda: ensure_no_unknown_keys(section, _INSPECT_KEYS, where="inspect"))
    fingerprint = _capture(problems, lambda: _parse_fingerprint(section.get("fingerprint")))
    static_checks = _capture(problems, lambda: _parse_static_checks(section.get("static_checks")))

    if problems:
        raise ConfigError("invalid inspect section", problems=problems)
    return InspectConfig(
        fingerprint=fingerprint or _parse_fingerprint(None),
        static_checks=static_checks or _parse_static_checks(None),
    )


def _parse_fingerprint(raw: Any) -> FingerprintConfig:
    """``inspect.fingerprint:`` 段。``store`` 在这里展开成绝对路径。"""
    defaults = FingerprintConfig()
    if raw is None:
        return FingerprintConfig(
            enabled=defaults.enabled,
            store=expand_path(defaults.store),
            fields=defaults.fields,
            on_first_seen=defaults.on_first_seen,
            on_change=defaults.on_change,
        )
    section = _require_mapping(raw, where="inspect.fingerprint")

    problems: list[str] = []
    _capture(
        problems,
        lambda: ensure_no_unknown_keys(section, _FINGERPRINT_KEYS, where="inspect.fingerprint"),
    )

    enabled = defaults.enabled
    if "enabled" in section:
        value = _capture(
            problems,
            lambda: _require_bool(section["enabled"], where="inspect.fingerprint.enabled"),
        )
        if value is not None:
            enabled = value

    store = expand_path(defaults.store)
    if "store" in section:
        raw_store = _capture(
            problems,
            lambda: _require_path_like(section["store"], where="inspect.fingerprint.store"),
        )
        if raw_store is not None:
            store = expand_path(raw_store)

    fields = defaults.fields
    if "fields" in section:
        value = _capture(
            problems,
            lambda: _require_str_list(
                section["fields"], where="inspect.fingerprint.fields", allow_empty=False
            ),
        )
        if value is not None:
            fields = value

    on_first_seen = defaults.on_first_seen
    if "on_first_seen" in section:
        value = _capture(
            problems,
            lambda: coerce_enum(
                section["on_first_seen"],
                FirstSeenAction,
                where="inspect.fingerprint.on_first_seen",
            ),
        )
        if value is not None:
            on_first_seen = value

    on_change = defaults.on_change
    if "on_change" in section:
        value = _capture(
            problems,
            lambda: coerce_enum(
                section["on_change"],
                FingerprintChangeAction,
                where="inspect.fingerprint.on_change",
            ),
        )
        if value is not None:
            on_change = value

    if problems:
        raise ConfigError("invalid inspect.fingerprint section", problems=problems)
    return FingerprintConfig(
        enabled=enabled,
        store=store,
        fields=fields,
        on_first_seen=on_first_seen,
        on_change=on_change,
    )


def _parse_static_checks(raw: Any) -> StaticChecksConfig:
    """``inspect.static_checks:`` 段。规则缺省用 SPEC §4 那 7 条。"""
    defaults = StaticChecksConfig()
    if raw is None:
        return StaticChecksConfig(
            enabled=defaults.enabled,
            on_hit=defaults.on_hit,
            scan_fields=defaults.scan_fields,
            rules=compile_pattern_rules(
                SPEC_STATIC_RULES, where="inspect.static_checks.rules"
            ),
        )
    section = _require_mapping(raw, where="inspect.static_checks")

    problems: list[str] = []
    _capture(
        problems,
        lambda: ensure_no_unknown_keys(
            section, _STATIC_CHECKS_KEYS, where="inspect.static_checks"
        ),
    )

    enabled = defaults.enabled
    if "enabled" in section:
        value = _capture(
            problems,
            lambda: _require_bool(section["enabled"], where="inspect.static_checks.enabled"),
        )
        if value is not None:
            enabled = value

    on_hit = defaults.on_hit
    if "on_hit" in section:
        value = _capture(
            problems,
            lambda: coerce_enum(
                section["on_hit"], StaticCheckAction, where="inspect.static_checks.on_hit"
            ),
        )
        if value is not None:
            on_hit = value

    scan_fields = defaults.scan_fields
    if "scan_fields" in section:
        value = _capture(
            problems,
            lambda: _require_str_list(
                section["scan_fields"],
                where="inspect.static_checks.scan_fields",
                allow_empty=False,
            ),
        )
        if value is not None:
            scan_fields = value

    # 缺省用 SPEC 的规则集；显式写了（哪怕是空列表）就用用户的。
    rules = _capture(
        problems,
        lambda: compile_pattern_rules(
            section["rules"] if "rules" in section else SPEC_STATIC_RULES,
            where="inspect.static_checks.rules",
        ),
    )

    if problems:
        raise ConfigError("invalid inspect.static_checks section", problems=problems)
    return StaticChecksConfig(
        enabled=enabled,
        on_hit=on_hit,
        scan_fields=scan_fields,
        rules=rules or (),
    )


def _parse_policy_rule(raw: Any, *, index: int) -> PolicyRule:
    """``policy.rules[i]``。"""
    where = f"policy.rules[{index}]"
    rule = _require_mapping(raw, where=where)

    problems: list[str] = []
    _capture(problems, lambda: ensure_no_unknown_keys(rule, _POLICY_RULE_KEYS, where=where))

    rule_id = None
    if "id" not in rule:
        problems.append(f"{where}.id: missing required field")
    else:
        rule_id = _capture(problems, lambda: _require_str(rule["id"], where=f"{where}.id"))

    tool = None
    if "tool" not in rule:
        problems.append(f"{where}.tool: missing required field")
    else:
        tool = _capture(problems, lambda: _require_str(rule["tool"], where=f"{where}.tool"))

    allow = None
    if "allow" not in rule:
        problems.append(f"{where}.allow: missing required field (true | false | ask)")
    else:
        allow = _capture(problems, lambda: _parse_allow(rule["allow"], where=f"{where}.allow"))

    conditions: list[WhenCondition] = []
    if "when" in rule and rule["when"] is not None:
        items = _capture(problems, lambda: _require_list(rule["when"], where=f"{where}.when"))
        for cond_index, item in enumerate(items or ()):
            cond = _capture(
                problems,
                lambda it=item, ci=cond_index: parse_when_condition(
                    it, where=f"{where}.when[{ci}]"
                ),
            )
            if cond is not None:
                conditions.append(cond)

    reason = None
    if rule.get("reason") is not None:
        reason = _capture(problems, lambda: _require_str(rule["reason"], where=f"{where}.reason"))

    if problems:
        raise ConfigError(f"invalid policy rule at {where}", problems=problems, field_path=where)

    return PolicyRule(
        id=rule_id,  # type: ignore[arg-type]
        tool=tool,  # type: ignore[arg-type]
        allow=allow,  # type: ignore[arg-type]
        when=tuple(conditions),
        reason=reason,
    )


def _parse_allow(value: Any, *, where: str) -> AllowMode:
    """``allow``：YAML ``true`` → ALLOW，``false`` → DENY，``"ask"`` → ASK，其余一律拒。

    TODO(SPEC §7 末尾的 ``TODO(待验证)``)：``ask`` 本来要靠 ``elicitation/create``，
    v1 不实现，解析期照常接受、由 policy 降级成 deny。
    """
    if isinstance(value, bool):
        return AllowMode.ALLOW if value else AllowMode.DENY
    if isinstance(value, str) and value == str(AllowMode.ASK):
        return AllowMode.ASK
    _fail(where, f"expected true | false | 'ask', got {_type_name(value)} ({value!r})")


def _parse_deny_response(raw: Any) -> DenyResponseConfig:
    """``policy.deny_response:`` 段。"""
    defaults = DenyResponseConfig()
    if raw is None:
        return defaults
    section = _require_mapping(raw, where="policy.deny_response")

    problems: list[str] = []
    _capture(
        problems,
        lambda: ensure_no_unknown_keys(
            section, _DENY_RESPONSE_KEYS, where="policy.deny_response"
        ),
    )

    kind = defaults.kind
    if "kind" in section:
        value = _capture(
            problems,
            lambda: coerce_enum(
                section["kind"], DenyResponseKind, where="policy.deny_response.kind"
            ),
        )
        if value is not None:
            kind = value

    text = defaults.text
    if "text" in section:
        value = _capture(
            problems, lambda: _require_str(section["text"], where="policy.deny_response.text")
        )
        if value is not None:
            text = value

    if problems:
        raise ConfigError("invalid policy.deny_response section", problems=problems)
    return DenyResponseConfig(kind=kind, text=text)


def _parse_redact(raw: Any) -> RedactConfig:
    """``redact:`` 段。规则/allowlist 缺省用 SPEC §4 那份清单。"""
    defaults = RedactConfig()
    if raw is None:
        return RedactConfig(
            enabled=defaults.enabled,
            outbound_scan=defaults.outbound_scan,
            inbound_scan=defaults.inbound_scan,
            action=defaults.action,
            mask_template=defaults.mask_template,
            rules=compile_pattern_rules(SPEC_REDACT_RULES, where="redact.rules"),
            allowlist=tuple(
                compile_regex(p, where=f"redact.allowlist[{i}]")
                for i, p in enumerate(SPEC_REDACT_ALLOWLIST)
            ),
        )
    section = _require_mapping(raw, where="redact")

    problems: list[str] = []
    _capture(problems, lambda: ensure_no_unknown_keys(section, _REDACT_KEYS, where="redact"))

    enabled = defaults.enabled
    if "enabled" in section:
        value = _capture(problems, lambda: _require_bool(section["enabled"], where="redact.enabled"))
        if value is not None:
            enabled = value

    outbound_scan = defaults.outbound_scan
    if "outbound_scan" in section:
        value = _capture(
            problems,
            lambda: _require_str_list(
                section["outbound_scan"], where="redact.outbound_scan", allow_empty=True
            ),
        )
        if value is not None:
            outbound_scan = value

    inbound_scan = defaults.inbound_scan
    if "inbound_scan" in section:
        value = _capture(
            problems,
            lambda: _require_str_list(
                section["inbound_scan"], where="redact.inbound_scan", allow_empty=True
            ),
        )
        if value is not None:
            inbound_scan = value

    action = defaults.action
    if "action" in section:
        value = _capture(
            problems, lambda: coerce_enum(section["action"], RedactAction, where="redact.action")
        )
        if value is not None:
            action = value

    mask_template = defaults.mask_template
    if "mask_template" in section:
        value = _capture(
            problems, lambda: _require_str(section["mask_template"], where="redact.mask_template")
        )
        if value is not None:
            _capture(
                problems,
                lambda v=value: _check_template_placeholders(
                    v, allowed=_MASK_TEMPLATE_PLACEHOLDERS, where="redact.mask_template"
                ),
            )
            mask_template = value

    rules = _capture(
        problems,
        lambda: compile_pattern_rules(
            section["rules"] if "rules" in section else SPEC_REDACT_RULES,
            where="redact.rules",
        ),
    )

    allowlist_source = (
        section["allowlist"] if "allowlist" in section else list(SPEC_REDACT_ALLOWLIST)
    )
    allowlist_patterns = _capture(
        problems,
        lambda: _require_str_list(allowlist_source, where="redact.allowlist", allow_empty=True),
    )
    allowlist: tuple[re.Pattern[str], ...] = ()
    if allowlist_patterns is not None:
        compiled: list[re.Pattern[str]] = []
        for index, pattern in enumerate(allowlist_patterns):
            regex = _capture(
                problems,
                lambda p=pattern, i=index: compile_regex(p, where=f"redact.allowlist[{i}]"),
            )
            if regex is not None:
                compiled.append(regex)
        allowlist = tuple(compiled)

    if problems:
        raise ConfigError("invalid redact section", problems=problems)
    return RedactConfig(
        enabled=enabled,
        outbound_scan=outbound_scan,
        inbound_scan=inbound_scan,
        action=action,
        mask_template=mask_template,
        rules=rules or (),
        allowlist=allowlist,
    )


def _parse_audit_record(raw: Any) -> AuditRecordConfig:
    """``audit.record:`` 段。"""
    defaults = AuditRecordConfig()
    if raw is None:
        return defaults
    section = _require_mapping(raw, where="audit.record")

    problems: list[str] = []
    _capture(
        problems,
        lambda: ensure_no_unknown_keys(section, _AUDIT_RECORD_KEYS, where="audit.record"),
    )

    values: dict[str, RecordMode] = {}
    for key in _AUDIT_RECORD_KEYS:
        if key not in section:
            continue
        member = _capture(
            problems,
            lambda k=key: coerce_enum(section[k], RecordMode, where=f"audit.record.{k}"),
        )
        if member is not None:
            values[key] = member

    if problems:
        raise ConfigError("invalid audit.record section", problems=problems)
    return AuditRecordConfig(**values) if values else defaults


def _parse_audit_payload(raw: Any) -> AuditPayloadConfig:
    """``audit.payload:`` 段。

    ``store_redacted_only`` 只接受 ``true``：v1 的 proxy 只会把**脱敏后**的对象交给
    audit（SPEC §4「secret 不落盘」），配成 false 也没有对应实现 ——
    与其静默忽略一个安全开关，不如启动期就拒掉。
    """
    defaults = AuditPayloadConfig()
    if raw is None:
        return defaults
    section = _require_mapping(raw, where="audit.payload")

    problems: list[str] = []
    _capture(
        problems,
        lambda: ensure_no_unknown_keys(section, _AUDIT_PAYLOAD_KEYS, where="audit.payload"),
    )

    max_bytes = defaults.max_bytes
    if "max_bytes" in section:
        value = _capture(
            problems,
            lambda: _require_int(section["max_bytes"], where="audit.payload.max_bytes", minimum=1),
        )
        if value is not None:
            max_bytes = value

    store_redacted_only = defaults.store_redacted_only
    if "store_redacted_only" in section:
        value = _capture(
            problems,
            lambda: _require_bool(
                section["store_redacted_only"], where="audit.payload.store_redacted_only"
            ),
        )
        if value is False:
            problems.append(
                "audit.payload.store_redacted_only: only true is supported in v1 "
                "(secrets must never hit the audit log)"
            )
        elif value is not None:
            store_redacted_only = value

    if problems:
        raise ConfigError("invalid audit.payload section", problems=problems)
    return AuditPayloadConfig(max_bytes=max_bytes, store_redacted_only=store_redacted_only)


# ────────────────────────────────────────────────────────────────────────────
# 内部：小工具
# ────────────────────────────────────────────────────────────────────────────


def _fail(where: str, detail: str) -> Any:
    """抛一条带字段路径的 ConfigError。返回类型写成 Any 只是为了让调用点好写。"""
    problem = f"{where}: {detail}"
    raise ConfigError(problem, problems=(problem,), field_path=where)


def _capture(problems: list[str], fn: Callable[[], Any]) -> Any:
    """跑 ``fn``，把 ConfigError 收进 ``problems`` 而不是立刻炸。

    这样一次解析能把所有毛病都列出来（SPEC §5：别让用户改一条跑一次）。
    """
    try:
        return fn()
    except ConfigError as exc:
        if exc.problems:
            problems.extend(exc.problems)
        else:
            problems.append(exc.message)
        return None


def _type_name(value: Any) -> str:
    return type(value).__name__


def _sorted_list(values: Iterable[str]) -> list[str]:
    return sorted(str(v) for v in values)


def _join_field(where: str, key: str) -> str:
    if not where or where == "(root)":
        return key
    return f"{where}.{key}"


def _require_mapping(value: Any, *, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(where, f"expected a mapping, got {_type_name(value)}")
    return value


def _require_list(value: Any, *, where: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        _fail(where, f"expected a list, got {_type_name(value)}")
    return value


def _require_str(value: Any, *, where: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        _fail(where, f"expected a string, got {_type_name(value)} ({value!r})")
    if not allow_empty and not value.strip():
        _fail(where, "expected a non-empty string")
    return value


def _require_bool(value: Any, *, where: str) -> bool:
    if not isinstance(value, bool):
        _fail(where, f"expected true/false, got {_type_name(value)} ({value!r})")
    return value


def _require_int(value: Any, *, where: str, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(where, f"expected an integer, got {_type_name(value)} ({value!r})")
    if minimum is not None and value < minimum:
        _fail(where, f"expected an integer >= {minimum}, got {value}")
    return value


def _require_str_list(value: Any, *, where: str, allow_empty: bool = True) -> tuple[str, ...]:
    items = _require_list(value, where=where)
    if not allow_empty and len(items) == 0:
        _fail(where, "expected a non-empty list of strings")

    problems: list[str] = []
    result: list[str] = []
    for index, item in enumerate(items):
        checked = _capture(problems, lambda it=item, i=index: _require_str(it, where=f"{where}[{i}]"))
        if checked is not None:
            result.append(checked)
    if problems:
        raise ConfigError(f"invalid list at {where}", problems=problems, field_path=where)
    return tuple(result)


def _require_path_like(value: Any, *, where: str) -> str:
    if isinstance(value, Path):
        return str(value)
    return _require_str(value, where=where)


def _check_template_placeholders(
    template: str, *, allowed: Iterable[str], where: str
) -> None:
    """校验 ``str.format`` 模板里只出现允许的占位符。

    模板里写错占位符（比如 ``{sever}``）在运行期是 KeyError，那时候只能 fail-closed
    拒绝一切调用 —— 不如启动期就拒。
    """
    allowed_names = set(allowed)
    try:
        fields = [name for _, name, _, _ in string.Formatter().parse(template) if name is not None]
    except ValueError as exc:
        _fail(where, f"invalid format template {template!r}: {exc}")

    unknown = sorted({name for name in fields if name.split(".")[0].split("[")[0] not in allowed_names})
    if unknown:
        _fail(
            where,
            f"unknown placeholder(s) {unknown} in template {template!r} "
            f"(allowed: {sorted(allowed_names)})",
        )


def _scan_path_problem(path: str, *, where: str) -> str | None:
    """校验一条扫描路径表达式的语法，合法返回 None，不合法返回 problem 文本。

    语法只有两种（与 ``redact.parse_scan_path`` 对齐）：``.`` 分隔的 key，
    以及 ``[]`` 表示"这一层是数组"。不支持下标 ``[0]``、通配 ``*``、引号 key。
    """
    if not isinstance(path, str) or not path.strip():
        return f"{where}: expected a non-empty path expression, got {path!r}"
    for segment in path.split("."):
        if not _SCAN_SEGMENT_RE.match(segment):
            return (
                f"{where}: invalid segment {segment!r} in path {path!r} "
                "(only 'key' and 'key[]' are supported; no [0], no '*', no quoted keys)"
            )
    return None


def _duplicate_id_problems(ids: Sequence[str], *, where: str) -> list[str]:
    """找出重复的 id，按首次出现顺序返回 problem 文本。"""
    counts: dict[str, int] = {}
    for rule_id in ids:
        counts[rule_id] = counts.get(rule_id, 0) + 1
    return [
        f"{where}: duplicate rule id {rule_id!r} ({count} occurrences)"
        for rule_id, count in counts.items()
        if count > 1
    ]


__all__ = [
    "load_config",
    "parse_config",
    "validate_config",
    "parse_policy",
    "parse_when_condition",
    "parse_audit",
    "compile_pattern_rules",
    "get_project_dir",
    "expand_project_dir",
    "expand_path",
    "ensure_no_unknown_keys",
    "coerce_enum",
    "load_yaml",
    "compile_regex",
]
