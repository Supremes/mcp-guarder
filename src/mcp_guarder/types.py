"""跨模块共享的类型、枚举与常量（完整实现，不是 stub）。

对应 SPEC §4（配置格式）、§5（fail-closed 语义）、§6（审计记录格式）。

设计约束：
- 本模块**不 import 任何兄弟模块**（除了标准库），避免循环依赖。
- 配置对象一律 frozen dataclass，解析期一次性构造好（正则也在解析期编译），
  运行期只读，避免热路径反复编译正则。
- JSON 报文本身**永远用 ``dict[str, Any]`` 表示，不做 dataclass 建模**——
  代理的第一诫是"不认识的字段 100% 原样保留"（SPEC §3），
  任何把报文塞进 dataclass 再序列化回去的做法都会吃掉未知字段。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Union

# ────────────────────────────────────────────────────────────────────────────
# 基础常量
# ────────────────────────────────────────────────────────────────────────────

#: 写进每条审计记录的 ``guard_version``（SPEC §6），与 pyproject 的 version 保持一致。
GUARD_VERSION = "0.1.0"

#: JSON-RPC 版本号，所有自造报文必须带。
JSONRPC_VERSION = "2.0"

#: 配置文件 ``version`` 字段唯一接受的值（SPEC §4）。
SUPPORTED_CONFIG_VERSION = 1

#: 代理自己发起 server→client 请求时用的独立负数 id 段（SPEC §3）。
#: 从这个值开始**递减**分配，保证永远不会撞上客户端的 id 空间。
#: v1 不实现 ``elicitation/create``，这个段目前没人用，但分配器要留着。
GUARD_REQUEST_ID_START = -1_000_000

#: 默认配置文件路径（未展开 ``~``）。
DEFAULT_CONFIG_PATH = Path("~/.mcp-guarder/config.yaml")

#: 指纹摘要算法名前缀，写进审计和 guard.log 时统一是 ``blake2b:<hex>``。
DIGEST_ALGO = "blake2b"

#: blake2b 摘要长度（字节）。16 字节 = 32 个 hex 字符，够用且日志里不至于刷屏。
DIGEST_SIZE = 16

#: 环境变量名：Claude Code 会把项目根目录塞进来（SPEC §4 ``${PROJECT_DIR}``）。
PROJECT_DIR_ENV = "CLAUDE_PROJECT_DIR"

#: 配置里 ``${PROJECT_DIR}`` 的字面量占位符。
PROJECT_DIR_PLACEHOLDER = "${PROJECT_DIR}"

#: 从 ``tools/call`` 的 ``params._meta`` 里抄 ``tool_use_id`` 的键（SPEC §6）。
TOOL_USE_ID_META_KEY = "claudecode/toolUseId"

# 进程退出码。SPEC §5：配置失败 / 上游崩溃 / 审计不可用都必须非零退出。
EXIT_OK = 0
EXIT_GENERIC_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_UPSTREAM_CRASH = 3
EXIT_AUDIT_UNAVAILABLE = 4

# ────────────────────────────────────────────────────────────────────────────
# JSON 别名
# ────────────────────────────────────────────────────────────────────────────

#: 一条 JSON-RPC 报文的运行时表示。**只能是 dict，不许换成 dataclass。**
JsonObj = dict[str, Any]

#: 任意 JSON 值。
JsonValue = Union[None, bool, int, float, str, list[Any], dict[str, Any]]

# ────────────────────────────────────────────────────────────────────────────
# MCP method 名（只有这两个会被深加工，其余一律原样透传）
# ────────────────────────────────────────────────────────────────────────────

METHOD_TOOLS_LIST = "tools/list"
METHOD_TOOLS_CALL = "tools/call"
METHOD_INITIALIZE = "initialize"
METHOD_TOOLS_LIST_CHANGED = "notifications/tools/list_changed"

#: 唯一需要深加工的两个 method（SPEC §3）。其它任何 method 走 passthrough。
DEEP_INSPECTED_METHODS = frozenset({METHOD_TOOLS_LIST, METHOD_TOOLS_CALL})


# ────────────────────────────────────────────────────────────────────────────
# 枚举
# ────────────────────────────────────────────────────────────────────────────


class Transport(StrEnum):
    """``server.transport``。v1 只认 stdio（SPEC §1 不做 HTTP/SSE）。"""

    STDIO = "stdio"


class Decision(StrEnum):
    """审计记录的 ``decision`` 字段（SPEC §6）。"""

    ALLOW = "allow"
    DENY = "deny"
    REWRITE = "rewrite"  # 报文被改写后放行（脱敏、剥离 tool）
    PASSTHROUGH = "passthrough"  # 未做深加工，字节级原样转发


class DecisionBy(StrEnum):
    """审计记录的 ``decision_by`` 字段（SPEC §6）：谁做的这个决定。"""

    POLICY = "policy"
    FINGERPRINT = "fingerprint"
    STATIC_CHECKS = "static_checks"
    REDACT = "redact"
    DEFAULT = "default"  # 没有任何规则命中，落到 defaults.* 的兜底


class DetectorName(StrEnum):
    """检测器名字，用于 ``detectors[].name`` 和 DetectorError 归因。"""

    FINGERPRINT = "fingerprint"
    STATIC_CHECKS = "static_checks"
    REDACT = "redact"
    POLICY = "policy"


class DetectorResult(StrEnum):
    """单个检测器的结论，写进审计 ``detectors[].result``。"""

    CLEAN = "clean"  # 跑完了，没命中
    MATCH = "match"  # 跑完了，命中（指纹变化 / 静态规则命中 / 有脱敏发生）
    ERROR = "error"  # 检测器自己炸了 → fail-closed
    SKIPPED = "skipped"  # 配置里 enabled: false


class Direction(StrEnum):
    """审计记录的 ``direction`` 字段（SPEC §6）。"""

    CLIENT_TO_SERVER = "client->server"
    SERVER_TO_CLIENT = "server->client"


class FailClosedAction(StrEnum):
    """``defaults.*`` 的取值全集（SPEC §4）。

    每个 key 只接受其中一个子集，见 :data:`ALLOWED_DEFAULT_ACTIONS`：
    - ``on_no_match`` / ``on_rule_conflict`` / ``on_detector_error`` /
      ``on_audit_write_failure``：只接受 ``deny``（v1 不给放宽的口子；
      要放宽必须显式改代码，配置层不提供）。
    - ``on_unknown_method``：只接受 ``passthrough``（这不是安全决策是兼容决策）。
    - ``on_upstream_crash``：只接受 ``fail``（子进程死了整体退出，不静默降级）。
    """

    DENY = "deny"
    PASSTHROUGH = "passthrough"
    FAIL = "fail"


#: 每个 ``defaults.*`` key 允许的取值（配置校验用）。SPEC §4 那份 YAML 就这几种组合，
#: 出现别的值一律 ConfigError —— "SPEC 没写的不要自由发挥"。
ALLOWED_DEFAULT_ACTIONS: dict[str, frozenset[FailClosedAction]] = {
    "on_no_match": frozenset({FailClosedAction.DENY}),
    "on_rule_conflict": frozenset({FailClosedAction.DENY}),
    "on_detector_error": frozenset({FailClosedAction.DENY}),
    "on_audit_write_failure": frozenset({FailClosedAction.DENY}),
    "on_unknown_method": frozenset({FailClosedAction.PASSTHROUGH}),
    "on_upstream_crash": frozenset({FailClosedAction.FAIL}),
}


class FirstSeenAction(StrEnum):
    """``inspect.fingerprint.on_first_seen``。TOFU：首见记账并放行。"""

    ALLOW_AND_RECORD = "allow_and_record"


class FingerprintChangeAction(StrEnum):
    """``inspect.fingerprint.on_change``。rug pull：变了就拒 + 告警。"""

    DENY_AND_ALERT = "deny_and_alert"


class StaticCheckAction(StrEnum):
    """``inspect.static_checks.on_hit``。"""

    DENY = "deny"  # 命中即把该 tool 从 tools/list 剥离
    WARN = "warn"  # 只记 guard.log + 审计，不剥离


class RedactAction(StrEnum):
    """``redact.action``。"""

    MASK = "mask"  # 用 mask_template 替换命中片段
    DROP_FIELD = "drop_field"  # 删掉命中的那个字段
    DENY_CALL = "deny_call"  # 整条 tools/call 直接拒绝


class WhenOperator(StrEnum):
    """``policy.rules[].when[]`` 的操作符全集。

    **v1 就这 6 个，配置里出现别的直接拒绝启动**（SPEC §4）。
    """

    STARTS_WITH = "starts_with"  # 值是 str，先展开 ${PROJECT_DIR} 再前缀匹配
    EQUALS = "equals"  # 值是 str，先展开 ${PROJECT_DIR} 再全等
    MATCHES = "matches"  # 值是正则字符串，re.search 命中即真
    NOT_MATCHES = "not_matches"  # 值是正则字符串，re.search 不命中才真
    ONE_OF = "one_of"  # 值是 list[str]，逐项展开 ${PROJECT_DIR} 后判断成员
    EXISTS = "exists"  # 值是 bool，判断 arg 在 arguments 里存不存在


#: 6 个操作符的名字集合，config 校验用。
WHEN_OPERATOR_NAMES: frozenset[str] = frozenset(op.value for op in WhenOperator)


class AllowMode(StrEnum):
    """``policy.rules[].allow`` 的三态。

    YAML 里写的是 ``true`` / ``false`` / ``ask``，解析成这个枚举。

    TODO(SPEC §7 末尾的 ``TODO(待验证)``)：``ask`` 本来打算借 ``elicitation/create``，
    但代理自己发 server→client 请求要占 id 空间、UX 也没验过。**v1 按 SPEC 给的降级
    方案做：``ask`` 一律等价于 ``deny``，同时往 guard.log 写一行提示让用户手工改配置。**
    不要在 v1 里实现 elicitation。
    """

    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


class DenyResponseKind(StrEnum):
    """``policy.deny_response.kind``。

    只有 ``tool_result_error`` 一个值：拒绝一律返 ``result.isError=true``，
    **绝不用 JSON-RPC ``error``**（SPEC §5 两条硬规矩之一）。
    """

    TOOL_RESULT_ERROR = "tool_result_error"


class FsyncMode(StrEnum):
    """``audit.fsync``。"""

    EVERY_RECORD = "every_record"
    INTERVAL = "interval"
    NEVER = "never"


class RecordMode(StrEnum):
    """``audit.record.*``：某类事件记多细。"""

    FULL = "full"  # 记 payload_preview（截断 + 摘要）
    METADATA_ONLY = "metadata_only"  # 只记 ts/event/rpc_id 这类元数据，不碰 payload


class MessageKind(StrEnum):
    """一条 JSON-RPC 报文的形态。按 ``id`` / ``method`` / ``result`` / ``error`` 判定。"""

    REQUEST = "request"  # 有 method 有 id
    NOTIFICATION = "notification"  # 有 method 无 id
    RESPONSE = "response"  # 无 method 有 id（result 或 error）
    UNKNOWN = "unknown"  # 都对不上，按 passthrough 处理，不许拦


class FingerprintStatus(StrEnum):
    """单个 tool 的指纹比对结论。"""

    FIRST_SEEN = "first_seen"  # TOFU，记账后放行
    UNCHANGED = "unchanged"
    CHANGED = "changed"  # rug pull，剥离该 tool + 告警


# ────────────────────────────────────────────────────────────────────────────
# 配置对象（SPEC §4 那份 YAML 的一比一映射）
# ────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ServerConfig:
    """``server:`` 段。"""

    name: str  # 审计和指纹的命名空间键，必须稳定
    transport: Transport = Transport.STDIO


@dataclass(frozen=True, slots=True)
class DefaultsConfig:
    """``defaults:`` 段 —— fail-closed 开关（SPEC §4 / §5）。"""

    on_no_match: FailClosedAction = FailClosedAction.DENY
    on_rule_conflict: FailClosedAction = FailClosedAction.DENY
    on_detector_error: FailClosedAction = FailClosedAction.DENY
    on_audit_write_failure: FailClosedAction = FailClosedAction.DENY
    on_unknown_method: FailClosedAction = FailClosedAction.PASSTHROUGH
    on_upstream_crash: FailClosedAction = FailClosedAction.FAIL


@dataclass(frozen=True, slots=True)
class FingerprintConfig:
    """``inspect.fingerprint:`` 段。"""

    enabled: bool = True
    store: Path = Path("~/.mcp-guarder/fingerprints.sqlite")  # 解析期已展开为绝对路径
    fields: tuple[str, ...] = ("name", "title", "description", "inputSchema")
    on_first_seen: FirstSeenAction = FirstSeenAction.ALLOW_AND_RECORD
    on_change: FingerprintChangeAction = FingerprintChangeAction.DENY_AND_ALERT


@dataclass(frozen=True, slots=True)
class PatternRule:
    """一条 ``{id, pattern}`` 规则（静态检查和脱敏共用同一形态）。

    ``regex`` 在**配置解析期**编译，编译失败直接 ConfigError（启动期拒绝），
    运行期不会再因为坏正则抛异常。
    """

    id: str
    pattern: str
    regex: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class StaticChecksConfig:
    """``inspect.static_checks:`` 段。"""

    enabled: bool = True
    on_hit: StaticCheckAction = StaticCheckAction.DENY
    scan_fields: tuple[str, ...] = (
        "name",
        "title",
        "description",
        "inputSchema",
        "annotations",
    )
    rules: tuple[PatternRule, ...] = ()


@dataclass(frozen=True, slots=True)
class InspectConfig:
    """``inspect:`` 段。"""

    fingerprint: FingerprintConfig = field(default_factory=FingerprintConfig)
    static_checks: StaticChecksConfig = field(default_factory=StaticChecksConfig)


@dataclass(frozen=True, slots=True)
class WhenCondition:
    """``policy.rules[].when[]`` 里的一个条件。

    YAML 形态是 ``{arg: path, starts_with: "${PROJECT_DIR}/"}`` ——
    一个 dict 里除 ``arg`` 外**有且只有一个** key，就是操作符。

    - ``value``：原始值（未展开 ``${PROJECT_DIR}``）。展开必须在求值期做，
      因为 ``CLAUDE_PROJECT_DIR`` 是运行时环境。
    - ``regex``：只有 ``matches`` / ``not_matches`` 才有，解析期编译。
    """

    arg: str
    op: WhenOperator
    value: str | list[str] | bool
    regex: re.Pattern[str] | None = None


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """``policy.rules[]`` 里的一条规则。"""

    id: str
    tool: str  # glob（`*` / `?`），**不是正则**
    allow: AllowMode
    when: tuple[WhenCondition, ...] = ()  # 条件之间 AND；任一不满足 → 这条不算命中
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class DenyResponseConfig:
    """``policy.deny_response:`` 段。"""

    kind: DenyResponseKind = DenyResponseKind.TOOL_RESULT_ERROR
    text: str = "mcp-guarder denied: {reason} (rule={rule_id}, event={audit_id})"


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    """``policy:`` 段。规则自上而下，**第一条 tool 匹配即定案，不再往下看**。"""

    rules: tuple[PolicyRule, ...] = ()
    deny_response: DenyResponseConfig = field(default_factory=DenyResponseConfig)


@dataclass(frozen=True, slots=True)
class RedactConfig:
    """``redact:`` 段。"""

    enabled: bool = True
    outbound_scan: tuple[str, ...] = ("params.arguments",)
    inbound_scan: tuple[str, ...] = (
        "result.content[].text",
        "result.content[].resource.text",
        "result.structuredContent",
    )
    action: RedactAction = RedactAction.MASK
    mask_template: str = "[REDACTED:{rule_id}]"
    rules: tuple[PatternRule, ...] = ()
    allowlist: tuple[re.Pattern[str], ...] = ()  # 解析期编译；命中 allowlist 的片段不打码


@dataclass(frozen=True, slots=True)
class AuditPayloadConfig:
    """``audit.payload:`` 段。"""

    max_bytes: int = 4096  # 超出截断，另记全量 sha256/blake2b 摘要
    store_redacted_only: bool = True  # 铁律：secret 不落盘


@dataclass(frozen=True, slots=True)
class AuditRecordConfig:
    """``audit.record:`` 段。"""

    tools_list: RecordMode = RecordMode.FULL
    tools_call: RecordMode = RecordMode.FULL
    other_methods: RecordMode = RecordMode.METADATA_ONLY


@dataclass(frozen=True, slots=True)
class AuditConfig:
    """``audit:`` 段。

    ``path`` 是**模板**，含 ``{server}`` / ``{date}`` 占位符，
    真实路径由 ``audit.resolve_audit_path()`` 在写入时算，不在解析期定死
    （跨天要滚动文件名）。
    """

    path: str = "~/.mcp-guarder/audit/{server}-{date}.jsonl"
    fsync: FsyncMode = FsyncMode.EVERY_RECORD
    record: AuditRecordConfig = field(default_factory=AuditRecordConfig)
    payload: AuditPayloadConfig = field(default_factory=AuditPayloadConfig)
    log_file: Path = Path("~/.mcp-guarder/guard.log")  # 解析期已展开为绝对路径
    snapshot_dir: Path = Path("~/.mcp-guarder/snapshots")  # SPEC §6：tools/list 全文快照


@dataclass(frozen=True, slots=True)
class GuarderConfig:
    """整份配置文件。``config.load_config()`` 的返回值，运行期只读。"""

    version: int = SUPPORTED_CONFIG_VERSION
    server: ServerConfig = field(default_factory=lambda: ServerConfig(name="unnamed"))
    defaults: DefaultsConfig = field(default_factory=DefaultsConfig)
    inspect: InspectConfig = field(default_factory=InspectConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    redact: RedactConfig = field(default_factory=RedactConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    source_path: Path | None = None  # 配置文件真实路径，只用于日志和报错


# ────────────────────────────────────────────────────────────────────────────
# 检测器的返回类型（四个检测器统一风格：入口函数返回一个 Report，不抛业务异常）
# ────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DetectorOutcome:
    """写进审计 ``detectors[]`` 的一项：``{"name": ..., "result": ...}``。"""

    name: DetectorName
    result: DetectorResult

    def to_dict(self) -> dict[str, str]:
        return {"name": str(self.name), "result": str(self.result)}


@dataclass(frozen=True, slots=True)
class ToolFingerprint:
    """指纹库里的一行。"""

    server: str
    tool: str
    digest: str  # "blake2b:<hex>"，对 fields 拼接后的 canonical_json 求值
    fields: tuple[str, ...]  # 算这个 digest 时用了哪些字段
    first_seen_ts: str  # ISO8601 UTC，带毫秒和 Z
    last_seen_ts: str
    snapshot_path: str | None = None  # 对应的全文快照文件（供 diff 用）


@dataclass(frozen=True, slots=True)
class ToolFingerprintResult:
    """单个 tool 的指纹比对结果。"""

    tool: str
    status: FingerprintStatus
    new_digest: str
    old_digest: str | None = None

    @property
    def is_rug_pull(self) -> bool:
        return self.status is FingerprintStatus.CHANGED


@dataclass(frozen=True, slots=True)
class FingerprintReport:
    """``fingerprint.inspect_tools()`` 的返回值。"""

    results: tuple[ToolFingerprintResult, ...] = ()
    skipped: bool = False  # enabled: false 时为 True

    @property
    def changed_tools(self) -> tuple[str, ...]:
        """指纹变了的 tool 名字 —— 这些要从 ``tools/list`` 响应里剥离。"""
        return tuple(r.tool for r in self.results if r.is_rug_pull)

    def outcome(self) -> DetectorOutcome:
        if self.skipped:
            result = DetectorResult.SKIPPED
        elif self.changed_tools:
            result = DetectorResult.MATCH
        else:
            result = DetectorResult.CLEAN
        return DetectorOutcome(DetectorName.FINGERPRINT, result)


@dataclass(frozen=True, slots=True)
class StaticHit:
    """一条静态规则在某个 tool 的某个字段上的命中。"""

    tool: str
    rule_id: str
    field_path: str  # 例如 "description" / "inputSchema.properties.path.description"
    excerpt: str  # 命中片段，**已做可见化转义**（ANSI 存成字面量 "\x1b["，SPEC §7 M3-3）


@dataclass(frozen=True, slots=True)
class StaticCheckReport:
    """``static_checks.scan_tools()`` 的返回值。"""

    hits: tuple[StaticHit, ...] = ()
    skipped: bool = False

    @property
    def hit_tools(self) -> tuple[str, ...]:
        """命中的 tool 名字（去重，保持首次出现顺序）。"""
        seen: dict[str, None] = {}
        for h in self.hits:
            seen.setdefault(h.tool, None)
        return tuple(seen)

    def rule_ids_for(self, tool: str) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for h in self.hits:
            if h.tool == tool:
                seen.setdefault(h.rule_id, None)
        return tuple(seen)

    def outcome(self) -> DetectorOutcome:
        if self.skipped:
            result = DetectorResult.SKIPPED
        elif self.hits:
            result = DetectorResult.MATCH
        else:
            result = DetectorResult.CLEAN
        return DetectorOutcome(DetectorName.STATIC_CHECKS, result)


@dataclass(frozen=True, slots=True)
class RedactionCount:
    """审计里 ``redactions.outbound[] / .inbound[]`` 的一项。"""

    rule_id: str
    count: int

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "count": self.count}


@dataclass(frozen=True, slots=True)
class RedactionReport:
    """``redact.redact_outbound() / redact_inbound()`` 的返回值。

    - ``message``：脱敏后的**新报文对象**（深拷贝，未命中的字段原样保留）。
      没有任何命中时，实现可以直接返回原对象（此时 ``changed`` 为 False，
      proxy 会走字节级原样转发那条路）。
    - ``deny``：``action: deny_call`` 且有命中时为 True，proxy 要拒掉整条 tools/call。
    """

    message: JsonObj
    counts: tuple[RedactionCount, ...] = ()
    deny: bool = False
    skipped: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.counts)

    def outcome(self) -> DetectorOutcome:
        if self.skipped:
            result = DetectorResult.SKIPPED
        elif self.counts:
            result = DetectorResult.MATCH
        else:
            result = DetectorResult.CLEAN
        return DetectorOutcome(DetectorName.REDACT, result)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """``policy.evaluate()`` 的返回值。"""

    decision: Decision  # 只会是 ALLOW 或 DENY
    decision_by: DecisionBy  # 命中规则 → POLICY；无规则命中 → DEFAULT
    reason: str  # 给模型看的短原因，例如 "no matching rule"
    rule_id: str | None = None
    allow_mode: AllowMode | None = None  # 命中规则原始的 allow 值，ASK 降级时用来打日志

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def ask_downgraded(self) -> bool:
        """命中了 ``allow: ask`` 并被降级成 deny —— proxy 要往 guard.log 写提示。"""
        return self.allow_mode is AllowMode.ASK


# ────────────────────────────────────────────────────────────────────────────
# 审计记录（SPEC §6，字段只增不改名）
# ────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class LatencyMs:
    """``latency_ms``：网关自身耗时 / 上游耗时（毫秒，整数）。"""

    guard: int | None = None
    upstream: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"guard": self.guard, "upstream": self.upstream}


@dataclass(frozen=True, slots=True)
class UpstreamInfo:
    """``upstream``：被包的子进程信息。"""

    pid: int | None = None
    cmd: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"pid": self.pid, "cmd": list(self.cmd)}


@dataclass(frozen=True, slots=True)
class ToolDigestPreview:
    """``event == "tools/list"`` 时 ``payload_preview`` 里的一项（SPEC §6）。"""

    name: str
    desc_digest: str
    schema_digest: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "desc_digest": self.desc_digest,
            "schema_digest": self.schema_digest,
        }


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """一条审计记录（JSONL 里的一行）。字段与顺序严格按 SPEC §6。

    可选字段一律保留并写成 ``null``，**不要因为是 None 就省掉 key** ——
    下游 grep/jq 依赖字段稳定存在。
    """

    ts: str  # ISO8601 UTC 带毫秒和 Z，例如 "2026-08-17T10:32:41.518Z"
    audit_id: str  # 单调递增的短 id（ULID 风格 Crockford base32）
    server: str
    event: str  # method 名，如 "tools/call" / "tools/list" / "initialize"
    direction: Direction
    decision: Decision
    decision_by: DecisionBy
    guard_version: str = GUARD_VERSION
    rpc_id: int | str | None = None
    tool: str | None = None
    tool_use_id: str | None = None
    rule_id: str | None = None
    reason: str | None = None
    detectors: tuple[DetectorOutcome, ...] = ()
    redactions_outbound: tuple[RedactionCount, ...] = ()
    redactions_inbound: tuple[RedactionCount, ...] = ()
    payload_digest: str | None = None  # "blake2b:<hex>"，对**全量**报文求值
    payload_preview: JsonValue = None  # 已脱敏 + 已截断的预览
    truncated: bool = False
    latency_ms: LatencyMs = field(default_factory=LatencyMs)
    upstream: UpstreamInfo = field(default_factory=UpstreamInfo)

    def to_dict(self) -> dict[str, Any]:
        """转成写进 JSONL 的 dict。字段顺序与 SPEC §6 的示例保持一致。"""
        return {
            "ts": self.ts,
            "audit_id": self.audit_id,
            "guard_version": self.guard_version,
            "server": self.server,
            "event": self.event,
            "direction": str(self.direction),
            "rpc_id": self.rpc_id,
            "tool": self.tool,
            "tool_use_id": self.tool_use_id,
            "decision": str(self.decision),
            "decision_by": str(self.decision_by),
            "rule_id": self.rule_id,
            "reason": self.reason,
            "detectors": [d.to_dict() for d in self.detectors],
            "redactions": {
                "outbound": [c.to_dict() for c in self.redactions_outbound],
                "inbound": [c.to_dict() for c in self.redactions_inbound],
            },
            "payload_digest": self.payload_digest,
            "payload_preview": self.payload_preview,
            "truncated": self.truncated,
            "latency_ms": self.latency_ms.to_dict(),
            "upstream": self.upstream.to_dict(),
        }


# ────────────────────────────────────────────────────────────────────────────
# 转发主干用的传输类型
# ────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class OutgoingLine:
    """要写出去的一行。

    **字节级保守转发的关键**：没被改写的报文一律回写 ``raw``（读进来的原始字节），
    绝不做 ``json.loads`` → ``json.dumps`` 的往返 —— 否则 key 顺序、空格、
    ``ensure_ascii`` 转义都会变，SPEC §7 M1-1 那个"裸跑与挂网关响应字节逐字一致"
    的对拍用例就过不了。

    只有真的改了内容（剥离 tool / 脱敏 / 自造 deny 响应）才用 ``message``。
    """

    raw: bytes | None = None
    message: JsonObj | None = None

    @classmethod
    def verbatim(cls, raw: bytes) -> OutgoingLine:
        """原样转发：raw 是**不含换行符**的原始行字节。"""
        return cls(raw=raw, message=None)

    @classmethod
    def rewritten(cls, message: JsonObj) -> OutgoingLine:
        """改写后转发：序列化时用 ``ensure_ascii=False``，保持 UTF-8 原貌。"""
        return cls(raw=None, message=message)

    @property
    def is_rewritten(self) -> bool:
        return self.message is not None


@dataclass(frozen=True, slots=True)
class Routed:
    """处理完一行报文后的路由结果。

    - ``upstream``：要发给真 MCP server 的行（None = 不发，通常是被拦下了）。
    - ``client``：要发给 Claude Code 的行（None = 不发）。

    两者可以同时为 None（例如吞掉一条纯内部记账的报文，v1 不会出现）。
    正常 passthrough 时只有一个非 None；policy 拒绝时 ``upstream=None`` +
    ``client=<isError 响应>``。
    """

    upstream: OutgoingLine | None = None
    client: OutgoingLine | None = None


# ────────────────────────────────────────────────────────────────────────────
# SPEC §4 里写死的默认规则集（配置省略该段时用这份兜底）
# 这些正则**逐字抄自 SPEC §4**，不要自己改写、不要加规则。
# ────────────────────────────────────────────────────────────────────────────

SPEC_STATIC_RULES: tuple[tuple[str, str], ...] = (
    ("hidden-instruction-tag", r"(?is)<\s*(IMPORTANT|SYSTEM|SECRET|INSTRUCTIONS)\s*>"),
    ("ignore-previous", r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instruction|prompt)"),
    ("read-extra-file", r"(?i)(~/\.ssh/|id_rsa|/\.env\b|~/\.aws/credentials|\.claude\.json)"),
    ("do-not-tell-user", r"(?i)(do not|don't)\s+(tell|mention|reveal).{0,40}(user|human)"),
    ("base64-blob", r"[A-Za-z0-9+/]{200,}={0,2}"),
    ("ansi-escape", r"\x1b\[[0-9;]*[A-Za-z]"),
    ("cross-server-ref", r"(?i)\bmcp__[a-z0-9_]+__"),
)

SPEC_REDACT_RULES: tuple[tuple[str, str], ...] = (
    ("aws-akid", r"\bAKIA[0-9A-Z]{16}\b"),
    ("bearer-jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("openai-key", r"\bsk-[A-Za-z0-9]{20,}\b"),
    ("github-pat", r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    ("private-key-block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

SPEC_REDACT_ALLOWLIST: tuple[str, ...] = (r"\bAKIAIOSFODNN7EXAMPLE\b",)


__all__ = [
    # 常量
    "GUARD_VERSION",
    "JSONRPC_VERSION",
    "SUPPORTED_CONFIG_VERSION",
    "GUARD_REQUEST_ID_START",
    "DEFAULT_CONFIG_PATH",
    "DIGEST_ALGO",
    "DIGEST_SIZE",
    "PROJECT_DIR_ENV",
    "PROJECT_DIR_PLACEHOLDER",
    "TOOL_USE_ID_META_KEY",
    "EXIT_OK",
    "EXIT_GENERIC_ERROR",
    "EXIT_CONFIG_ERROR",
    "EXIT_UPSTREAM_CRASH",
    "EXIT_AUDIT_UNAVAILABLE",
    "METHOD_TOOLS_LIST",
    "METHOD_TOOLS_CALL",
    "METHOD_INITIALIZE",
    "METHOD_TOOLS_LIST_CHANGED",
    "DEEP_INSPECTED_METHODS",
    "ALLOWED_DEFAULT_ACTIONS",
    "WHEN_OPERATOR_NAMES",
    "SPEC_STATIC_RULES",
    "SPEC_REDACT_RULES",
    "SPEC_REDACT_ALLOWLIST",
    # 别名
    "JsonObj",
    "JsonValue",
    # 枚举
    "Transport",
    "Decision",
    "DecisionBy",
    "DetectorName",
    "DetectorResult",
    "Direction",
    "FailClosedAction",
    "FirstSeenAction",
    "FingerprintChangeAction",
    "StaticCheckAction",
    "RedactAction",
    "WhenOperator",
    "AllowMode",
    "DenyResponseKind",
    "FsyncMode",
    "RecordMode",
    "MessageKind",
    "FingerprintStatus",
    # 配置
    "ServerConfig",
    "DefaultsConfig",
    "FingerprintConfig",
    "PatternRule",
    "StaticChecksConfig",
    "InspectConfig",
    "WhenCondition",
    "PolicyRule",
    "DenyResponseConfig",
    "PolicyConfig",
    "RedactConfig",
    "AuditPayloadConfig",
    "AuditRecordConfig",
    "AuditConfig",
    "GuarderConfig",
    # 检测器返回值
    "DetectorOutcome",
    "ToolFingerprint",
    "ToolFingerprintResult",
    "FingerprintReport",
    "StaticHit",
    "StaticCheckReport",
    "RedactionCount",
    "RedactionReport",
    "PolicyDecision",
    # 审计
    "LatencyMs",
    "UpstreamInfo",
    "ToolDigestPreview",
    "AuditRecord",
    # 转发
    "OutgoingLine",
    "Routed",
]
