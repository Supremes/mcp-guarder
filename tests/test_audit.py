"""audit 模块单测：SPEC §6 记录格式 / §4 audit 配置段 / §5 写盘失败语义。

覆盖点（对应任务里的测试重点）：
- 字段完整性（SPEC §6 那 20 个 key，顺序也对）
- payload 截断 + 全量摘要
- ``tools/list`` 的 preview 形态（只存 name/desc_digest/schema_digest）
- ``tool_use_id`` 有 / 无两种
- 写盘失败抛 :class:`AuditUnavailable` 并置 degraded
- fsync 三种模式
- guard.log 与审计 JSONL **绝不进 stdout**
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mcp_guarder import audit
from mcp_guarder.audit import AuditLogger, GuardLog
from mcp_guarder.errors import AuditUnavailable, GuarderError
from mcp_guarder.types import (
    EXIT_AUDIT_UNAVAILABLE,
    AuditConfig,
    AuditPayloadConfig,
    AuditRecordConfig,
    Decision,
    DecisionBy,
    DetectorName,
    DetectorOutcome,
    DetectorResult,
    Direction,
    FsyncMode,
    LatencyMs,
    RecordMode,
    RedactionCount,
    UpstreamInfo,
)

# ────────────────────────────────────────────────────────────────────────────
# fixture
# ────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def audit_config(guard_home: Path) -> AuditConfig:
    """指到 tmp 目录的 audit 配置，绝不碰用户真实的 ~/.mcp-guarder/。"""
    return AuditConfig(
        path=str(guard_home / "audit" / "{server}-{date}.jsonl"),
        fsync=FsyncMode.EVERY_RECORD,
        log_file=guard_home / "guard.log",
        snapshot_dir=guard_home / "snapshots",
    )


@pytest.fixture
def upstream() -> UpstreamInfo:
    return UpstreamInfo(pid=48213, cmd=("python3", "/path/server.py"))


@pytest.fixture
def logger(audit_config: AuditConfig, upstream: UpstreamInfo):
    lg = AuditLogger(audit_config, server="demo", upstream=upstream)
    lg.open()
    yield lg
    lg.close()


def read_lines(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


# ────────────────────────────────────────────────────────────────────────────
# 时间与 id
# ────────────────────────────────────────────────────────────────────────────


def test_utc_now_iso_shape():
    """SPEC §6 的 ts 形态：UTC、毫秒、Z 结尾。"""
    ts = audit.utc_now_iso(datetime(2026, 8, 17, 10, 32, 41, 518_000, tzinfo=timezone.utc))
    assert ts == "2026-08-17T10:32:41.518Z"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", audit.utc_now_iso())


def test_utc_now_iso_converts_non_utc_tz():
    """带时区的时间要先归一到 UTC，不能原样带偏移写进去。"""
    tz = timezone(timedelta(hours=8))
    ts = audit.utc_now_iso(datetime(2026, 8, 17, 18, 32, 41, 518_000, tzinfo=tz))
    assert ts == "2026-08-17T10:32:41.518Z"


def test_new_audit_id_alphabet_and_monotonic():
    """Crockford base32、字典序 == 时间序、同进程内不重复。"""
    ids = [audit.new_audit_id() for _ in range(500)]
    for value in ids:
        assert re.fullmatch(r"[0-9A-HJKMNP-TV-Z]+", value), value
    assert len(set(ids)) == len(ids), "同一毫秒内也必须互不相同"
    assert ids == sorted(ids), "id 必须单调递增，否则审计文件排序就乱了"


def test_new_audit_id_prefix_follows_explicit_time():
    """显式传 now 时前缀按该时刻算，且更晚的时刻排在更后面。"""
    early = audit.new_audit_id(datetime(2020, 1, 1, tzinfo=timezone.utc))
    late = audit.new_audit_id(datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert early[:10] < late[:10]
    # 不能污染进程内的单调状态：传了一个 2020 之后，实时 id 仍然大于它
    assert audit.new_audit_id() > early


def test_resolve_audit_path_expands_placeholders(audit_config: AuditConfig, guard_home: Path):
    """{server} / {date} 都要展开，{date} 用本地日期和 shell 的 date +%F 对齐。"""
    now = datetime(2026, 8, 17, 23, 59)
    path = audit.resolve_audit_path(audit_config, "filesystem", now)
    assert path == guard_home / "audit" / "filesystem-2026-08-17.jsonl"


def test_resolve_audit_path_expands_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """``~`` 必须展开成绝对路径。"""
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = AuditConfig(path="~/.mcp-guarder/audit/{server}-{date}.jsonl")
    path = audit.resolve_audit_path(cfg, "demo", datetime(2026, 8, 17))
    assert path.is_absolute()
    assert "~" not in str(path)
    assert path.name == "demo-2026-08-17.jsonl"


# ────────────────────────────────────────────────────────────────────────────
# payload：截断 + 全量摘要
# ────────────────────────────────────────────────────────────────────────────


def test_payload_preview_under_limit_is_verbatim():
    payload = {"path": "/Users/x/.ssh/id_rsa"}
    preview, truncated, digest = audit.build_payload_preview(payload, max_bytes=4096)
    assert preview == payload
    assert truncated is False
    assert digest.startswith("blake2b:")


def test_payload_preview_truncates_and_keeps_full_digest():
    """超 max_bytes → 截断成 _truncated/_bytes/_head，digest 仍对全量求值（SPEC §4）。"""
    payload = {"text": "x" * 5000}
    preview, truncated, digest = audit.build_payload_preview(payload, max_bytes=64)

    assert truncated is True
    assert isinstance(preview, dict)
    assert preview["_truncated"] is True
    assert preview["_bytes"] == len(audit.canonical_json(payload))
    assert preview["_bytes"] > 5000
    assert len(preview["_head"]) <= audit.TRUNCATED_HEAD_MAX_CHARS
    # 全量摘要 ≠ 截断后预览的摘要，这就是「另记全量摘要」的意义
    assert digest == audit.digest_value(payload)
    assert digest != audit.digest_value(preview)


def test_payload_preview_head_does_not_split_utf8():
    """截断点不能把多字节字符劈开成乱码。"""
    payload = {"text": "中文" * 2000}
    preview, truncated, _ = audit.build_payload_preview(payload, max_bytes=32)
    assert truncated is True
    assert "�" not in preview["_head"], "不该出现 U+FFFD 替换字符"


def test_record_mode_for_three_buckets():
    cfg = AuditConfig(
        record=AuditRecordConfig(
            tools_list=RecordMode.FULL,
            tools_call=RecordMode.FULL,
            other_methods=RecordMode.METADATA_ONLY,
        )
    )
    assert audit.record_mode_for(cfg, "tools/list") is RecordMode.FULL
    assert audit.record_mode_for(cfg, "tools/call") is RecordMode.FULL
    assert audit.record_mode_for(cfg, "initialize") is RecordMode.METADATA_ONLY
    assert audit.record_mode_for(cfg, "notifications/whatever") is RecordMode.METADATA_ONLY


# ────────────────────────────────────────────────────────────────────────────
# 记录字段完整性（SPEC §6）
# ────────────────────────────────────────────────────────────────────────────

SPEC_KEYS = [
    "ts",
    "audit_id",
    "guard_version",
    "server",
    "event",
    "direction",
    "rpc_id",
    "tool",
    "tool_use_id",
    "decision",
    "decision_by",
    "rule_id",
    "reason",
    "detectors",
    "redactions",
    "payload_digest",
    "payload_preview",
    "truncated",
    "latency_ms",
    "upstream",
]


def test_written_record_has_all_spec_fields(logger: AuditLogger):
    """一条完整的 tools/call deny 记录，字段和顺序都按 SPEC §6。"""
    record = logger.build_record(
        event="tools/call",
        direction=Direction.CLIENT_TO_SERVER,
        decision=Decision.DENY,
        decision_by=DecisionBy.POLICY,
        rpc_id=7,
        tool="read_file",
        tool_use_id="toolu_01ABC",
        rule_id="allow-read-in-project",
        reason="path not under ${PROJECT_DIR}",
        detectors=[
            DetectorOutcome(DetectorName.FINGERPRINT, DetectorResult.MATCH),
            DetectorOutcome(DetectorName.STATIC_CHECKS, DetectorResult.CLEAN),
        ],
        redactions_inbound=[RedactionCount("bearer-jwt", 2)],
        payload={"path": "/Users/x/.ssh/id_rsa"},
        latency_ms=LatencyMs(guard=3),
    )
    logger.write(record)

    [line] = read_lines(logger.path)
    assert list(line) == SPEC_KEYS, "字段顺序必须和 SPEC §6 的样例一致"
    assert line["event"] == "tools/call"
    assert line["direction"] == "client->server"
    assert line["decision"] == "deny"
    assert line["decision_by"] == "policy"
    assert line["rpc_id"] == 7
    assert line["tool"] == "read_file"
    assert line["tool_use_id"] == "toolu_01ABC"
    assert line["rule_id"] == "allow-read-in-project"
    assert line["detectors"] == [
        {"name": "fingerprint", "result": "match"},
        {"name": "static_checks", "result": "clean"},
    ]
    assert line["redactions"] == {
        "outbound": [],
        "inbound": [{"rule_id": "bearer-jwt", "count": 2}],
    }
    assert line["payload_preview"] == {"path": "/Users/x/.ssh/id_rsa"}
    assert line["payload_digest"].startswith("blake2b:")
    assert line["truncated"] is False
    assert line["latency_ms"] == {"guard": 3, "upstream": None}
    assert line["upstream"] == {"pid": 48213, "cmd": ["python3", "/path/server.py"]}
    assert line["guard_version"] == "0.1.0"
    assert line["server"] == "demo"


def test_optional_fields_are_null_not_missing(logger: AuditLogger):
    """None 字段写成 null，**不许省 key** —— 下游 jq/grep 依赖字段稳定存在。"""
    logger.write(
        logger.build_record(
            event="initialize",
            direction=Direction.CLIENT_TO_SERVER,
            decision=Decision.PASSTHROUGH,
            decision_by=DecisionBy.DEFAULT,
        )
    )
    [line] = read_lines(logger.path)
    assert list(line) == SPEC_KEYS
    for key in ("rpc_id", "tool", "tool_use_id", "rule_id", "reason", "payload_digest"):
        assert line[key] is None


def test_tool_use_id_present_and_absent(logger: AuditLogger):
    """SPEC §6：``tool_use_id`` 抄自 params._meta['claudecode/toolUseId']，取不到就 null。

    提取本身归 proxy.extract_tool_use_id（契约里在 proxy 模块）；这里验证 audit 侧
    「给了就落盘、没给就 null」这两条。
    """
    logger.write(
        logger.build_record(
            event="tools/call",
            direction=Direction.CLIENT_TO_SERVER,
            decision=Decision.ALLOW,
            decision_by=DecisionBy.POLICY,
            tool="echo",
            tool_use_id="toolu_01XYZ",
        )
    )
    logger.write(
        logger.build_record(
            event="tools/call",
            direction=Direction.CLIENT_TO_SERVER,
            decision=Decision.ALLOW,
            decision_by=DecisionBy.POLICY,
            tool="echo",
        )
    )
    with_meta, without_meta = read_lines(logger.path)
    assert with_meta["tool_use_id"] == "toolu_01XYZ"
    assert without_meta["tool_use_id"] is None


def test_audit_ids_are_unique_and_overridable(logger: AuditLogger):
    """proxy 要先拿 audit_id 拼 deny 文案，再用同一个 id 落审计。"""
    auto = logger.build_record(
        event="ping",
        direction=Direction.CLIENT_TO_SERVER,
        decision=Decision.PASSTHROUGH,
        decision_by=DecisionBy.DEFAULT,
    )
    fixed = logger.build_record(
        event="ping",
        direction=Direction.CLIENT_TO_SERVER,
        decision=Decision.PASSTHROUGH,
        decision_by=DecisionBy.DEFAULT,
        audit_id="01J8Z9Q3K7",
    )
    assert auto.audit_id != fixed.audit_id
    assert fixed.audit_id == "01J8Z9Q3K7"


def test_metadata_only_drops_preview_but_keeps_digest(logger: AuditLogger):
    """other_methods=metadata_only：preview 为 None，digest 仍然算（事后能对账）。"""
    logger.write(
        logger.build_record(
            event="resources/read",
            direction=Direction.CLIENT_TO_SERVER,
            decision=Decision.PASSTHROUGH,
            decision_by=DecisionBy.DEFAULT,
            payload={"uri": "file:///tmp/x", "secretish": "y" * 100},
        )
    )
    [line] = read_lines(logger.path)
    assert line["payload_preview"] is None
    assert line["payload_digest"].startswith("blake2b:")
    assert "secretish" not in json.dumps(line)


def test_tools_list_preview_is_digests_only(logger: AuditLogger):
    """SPEC §6：event=tools/list 时 preview 只存 {name, desc_digest, schema_digest} 列表。"""
    tools = [
        {
            "name": "echo",
            "description": "Echo back a string",
            "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
        },
        {"name": "write_file", "description": "Write a file", "inputSchema": {}},
    ]
    logger.write(
        logger.build_record(
            event="tools/list",
            direction=Direction.SERVER_TO_CLIENT,
            decision=Decision.PASSTHROUGH,
            decision_by=DecisionBy.DEFAULT,
            payload={"tools": tools},
        )
    )
    [line] = read_lines(logger.path)
    preview = line["payload_preview"]
    assert isinstance(preview, list) and len(preview) == 2
    assert [p["name"] for p in preview] == ["echo", "write_file"]
    for item in preview:
        assert set(item) == {"name", "desc_digest", "schema_digest"}
        assert item["desc_digest"].startswith("blake2b:")
        assert item["schema_digest"].startswith("blake2b:")
    # 全文一个字都不许进审计（全文归 snapshots，供 mcp-guarder diff 用）
    raw = logger.path.read_text(encoding="utf-8")
    assert "Echo back a string" not in raw
    assert "inputSchema" not in raw
    # digest 仍然对全量 payload 求值
    assert line["payload_digest"] == audit.digest_value({"tools": tools})


def test_tools_list_preview_accepts_whole_response(logger: AuditLogger):
    """proxy 直接把整条响应报文丢进来也要能收敛成摘要列表。"""
    payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"tools": [{"name": "echo", "description": "Echo back a string"}]},
    }
    logger.write(
        logger.build_record(
            event="tools/list",
            direction=Direction.SERVER_TO_CLIENT,
            decision=Decision.PASSTHROUGH,
            decision_by=DecisionBy.DEFAULT,
            payload=payload,
        )
    )
    [line] = read_lines(logger.path)
    assert [p["name"] for p in line["payload_preview"]] == ["echo"]
    assert "Echo back a string" not in logger.path.read_text(encoding="utf-8")


def test_tools_list_with_odd_shape_falls_back_to_plain_preview(logger: AuditLogger):
    """形态对不上（比如空列表 / 缺 name）就退回普通 preview，不要炸。"""
    logger.write(
        logger.build_record(
            event="tools/list",
            direction=Direction.SERVER_TO_CLIENT,
            decision=Decision.PASSTHROUGH,
            decision_by=DecisionBy.DEFAULT,
            payload={"tools": [], "nextCursor": "abc"},
        )
    )
    [line] = read_lines(logger.path)
    assert line["payload_preview"] == {"tools": [], "nextCursor": "abc"}


def test_truncated_flag_lands_in_record(audit_config: AuditConfig, upstream: UpstreamInfo):
    cfg = AuditConfig(
        path=audit_config.path,
        payload=AuditPayloadConfig(max_bytes=128),
        log_file=audit_config.log_file,
    )
    lg = AuditLogger(cfg, server="demo", upstream=upstream)
    lg.open()
    try:
        big = {"text": "x" * 4000}
        lg.write(
            lg.build_record(
                event="tools/call",
                direction=Direction.SERVER_TO_CLIENT,
                decision=Decision.ALLOW,
                decision_by=DecisionBy.POLICY,
                tool="echo",
                payload=big,
            )
        )
        [line] = read_lines(lg.path)
        assert line["truncated"] is True
        assert line["payload_preview"]["_truncated"] is True
        assert line["payload_digest"] == audit.digest_value(big)
    finally:
        lg.close()


def test_non_ascii_is_not_escaped(logger: AuditLogger):
    """ensure_ascii=False：中文原样落盘，别写成 \\uXXXX 让人没法看。"""
    logger.write(
        logger.build_record(
            event="tools/call",
            direction=Direction.CLIENT_TO_SERVER,
            decision=Decision.DENY,
            decision_by=DecisionBy.POLICY,
            reason="路径不在项目目录里",
        )
    )
    raw = logger.path.read_text(encoding="utf-8")
    assert "路径不在项目目录里" in raw
    assert "\\u8def" not in raw


def test_unserializable_payload_does_not_raise(logger: AuditLogger):
    """不可序列化的对象转成字符串，绝不能让 TypeError 冒到转发主干。"""

    class Weird:
        def __str__(self) -> str:
            return "weird-object"

    logger.write(
        logger.build_record(
            event="tools/call",
            direction=Direction.CLIENT_TO_SERVER,
            decision=Decision.ALLOW,
            decision_by=DecisionBy.POLICY,
            payload={"blob": Weird()},
        )
    )
    [line] = read_lines(logger.path)
    assert line["payload_preview"] == {"blob": "weird-object"}


# ────────────────────────────────────────────────────────────────────────────
# store_redacted_only：secret 不落盘（SPEC §7 M2-3 的硬要求）
# ────────────────────────────────────────────────────────────────────────────


def test_redacted_payload_leaves_no_secret_on_disk(logger: AuditLogger):
    """proxy 先脱敏再记账 → 审计里 grep 不到 AKIA（SPEC §7 M2-3）。"""
    logger.write(
        logger.build_record(
            event="tools/call",
            direction=Direction.SERVER_TO_CLIENT,
            decision=Decision.REWRITE,
            decision_by=DecisionBy.REDACT,
            tool="read_file",
            payload={"content": "key=[REDACTED:aws-akid]"},
            redactions_inbound=[RedactionCount("aws-akid", 1)],
        )
    )
    raw = logger.path.read_text(encoding="utf-8")
    assert raw.count("AKIA") == 0
    assert "[REDACTED:aws-akid]" in raw


def test_audit_does_not_redact_by_itself(logger: AuditLogger):
    """反向钉死契约：audit **不做**脱敏，传进来是明文就是明文落盘。

    这是故意的分工（build_payload_preview 的 docstring 写了），proxy 必须
    「先脱敏 → 再拿脱敏后的对象记账」。这个用例是给以后改代码的人看的警告。
    """
    logger.write(
        logger.build_record(
            event="tools/call",
            direction=Direction.SERVER_TO_CLIENT,
            decision=Decision.ALLOW,
            decision_by=DecisionBy.POLICY,
            payload={"content": "AKIAIOSFODNN7EXAMPLE"},
        )
    )
    assert "AKIAIOSFODNN7EXAMPLE" in logger.path.read_text(encoding="utf-8")


# ────────────────────────────────────────────────────────────────────────────
# 写盘失败 → AuditUnavailable + degraded（SPEC §5 第五行）
# ────────────────────────────────────────────────────────────────────────────


def test_open_failure_raises_audit_unavailable(tmp_path: Path, upstream: UpstreamInfo):
    """目录建不出来（父路径是个文件）→ 启动期 AuditUnavailable，exit code 4。"""
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a dir", encoding="utf-8")
    cfg = AuditConfig(path=str(blocker / "audit" / "{server}-{date}.jsonl"))
    lg = AuditLogger(cfg, server="demo", upstream=upstream)

    with pytest.raises(AuditUnavailable) as excinfo:
        lg.open()
    assert excinfo.value.exit_code == EXIT_AUDIT_UNAVAILABLE
    assert excinfo.value.model_text == "mcp-guarder: audit unavailable"
    assert excinfo.value.path is not None
    assert lg.degraded is True


def test_write_failure_sets_degraded_and_raises(logger: AuditLogger, guard_home: Path):
    """运行期写失败 → 置 degraded（永久）+ 抛 AuditUnavailable，proxy 靠这个 deny 后续 tools/call。"""
    assert logger.degraded is False
    record = logger.build_record(
        event="tools/call",
        direction=Direction.CLIENT_TO_SERVER,
        decision=Decision.ALLOW,
        decision_by=DecisionBy.POLICY,
    )
    logger._fh.close()  # 模拟句柄失效（磁盘满/被抢走）

    with pytest.raises(AuditUnavailable):
        logger.write(record)
    assert logger.degraded is True
    # degraded 是永久的：换个好句柄也不会自动恢复
    assert logger.degraded is True


def test_fsync_failure_is_also_audit_unavailable(
    logger: AuditLogger, monkeypatch: pytest.MonkeyPatch
):
    """fsync 失败（磁盘满典型症状）同样 fail-closed。"""

    def boom(_fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(audit.os, "fsync", boom)
    with pytest.raises(AuditUnavailable):
        logger.write(
            logger.build_record(
                event="tools/call",
                direction=Direction.CLIENT_TO_SERVER,
                decision=Decision.ALLOW,
                decision_by=DecisionBy.POLICY,
            )
        )
    assert logger.degraded is True


def test_degradation_is_logged_once_to_guard_log(
    audit_config: AuditConfig, upstream: UpstreamInfo, guard_home: Path
):
    """降级只往 guard.log 记一次，别刷屏。"""
    log = GuardLog(guard_home / "guard.log", also_stderr=False)
    lg = AuditLogger(audit_config, server="demo", upstream=upstream, log=log)
    lg.open()
    record = lg.build_record(
        event="tools/call",
        direction=Direction.CLIENT_TO_SERVER,
        decision=Decision.ALLOW,
        decision_by=DecisionBy.POLICY,
    )
    lg._fh.close()
    for _ in range(3):
        with pytest.raises(AuditUnavailable):
            lg.write(record)
    log.close()

    text = (guard_home / "guard.log").read_text(encoding="utf-8")
    assert text.count("AUDIT UNAVAILABLE") == 1


# ────────────────────────────────────────────────────────────────────────────
# fsync 三种模式
# ────────────────────────────────────────────────────────────────────────────


def _count_fsync(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []
    real = os.fsync

    def counting(fd):
        calls.append(fd)
        return real(fd)

    monkeypatch.setattr(audit.os, "fsync", counting)
    return calls


def _write_n(lg: AuditLogger, n: int) -> None:
    for _ in range(n):
        lg.write(
            lg.build_record(
                event="ping",
                direction=Direction.CLIENT_TO_SERVER,
                decision=Decision.PASSTHROUGH,
                decision_by=DecisionBy.DEFAULT,
            )
        )


@pytest.mark.parametrize(
    ("mode", "expected"),
    [(FsyncMode.EVERY_RECORD, 3), (FsyncMode.NEVER, 0)],
)
def test_fsync_modes(
    audit_config: AuditConfig,
    upstream: UpstreamInfo,
    monkeypatch: pytest.MonkeyPatch,
    mode: FsyncMode,
    expected: int,
):
    cfg = AuditConfig(path=audit_config.path, fsync=mode, log_file=audit_config.log_file)
    lg = AuditLogger(cfg, server="demo", upstream=upstream)
    lg.open()
    calls = _count_fsync(monkeypatch)
    _write_n(lg, 3)
    assert len(calls) == expected
    # 无论哪种模式，内容都必须已经在文件里（每行都 flush 过）
    assert len(read_lines(lg.path)) == 3
    lg.close()


def test_fsync_interval_batches(
    audit_config: AuditConfig, upstream: UpstreamInfo, monkeypatch: pytest.MonkeyPatch
):
    """interval 模式：间隔没到就攒着不 fsync；间隔调成 0 就每条都 fsync。"""
    cfg = AuditConfig(
        path=audit_config.path, fsync=FsyncMode.INTERVAL, log_file=audit_config.log_file
    )
    lg = AuditLogger(cfg, server="demo", upstream=upstream)
    lg.open()
    calls = _count_fsync(monkeypatch)

    monkeypatch.setattr(audit, "FSYNC_INTERVAL_SECONDS", 3600.0)
    _write_n(lg, 3)
    assert len(calls) == 0, "间隔没到不该 fsync"

    monkeypatch.setattr(audit, "FSYNC_INTERVAL_SECONDS", 0.0)
    _write_n(lg, 2)
    assert len(calls) == 2

    lg.close()
    assert len(read_lines(lg.path)) == 5


def test_close_is_idempotent(audit_config: AuditConfig, upstream: UpstreamInfo):
    lg = AuditLogger(audit_config, server="demo", upstream=upstream)
    lg.open()
    _write_n(lg, 1)
    lg.close()
    lg.close()  # 第二次不许炸


def test_rotates_across_days(
    audit_config: AuditConfig, upstream: UpstreamInfo, monkeypatch: pytest.MonkeyPatch
):
    """跨天滚新文件（SPEC §4 path 模板里的 {date}）。"""
    lg = AuditLogger(audit_config, server="demo", upstream=upstream)
    monkeypatch.setattr(audit, "_local_date", lambda now=None: "2026-08-17")
    lg.open()
    _write_n(lg, 1)
    first = lg.path

    monkeypatch.setattr(audit, "_local_date", lambda now=None: "2026-08-18")
    _write_n(lg, 1)
    second = lg.path
    lg.close()

    assert first.name == "demo-2026-08-17.jsonl"
    assert second.name == "demo-2026-08-18.jsonl"
    assert len(read_lines(first)) == 1
    assert len(read_lines(second)) == 1


def test_write_without_open_still_works(audit_config: AuditConfig, upstream: UpstreamInfo):
    """proxy 忘了 open 也不能丢记录。"""
    lg = AuditLogger(audit_config, server="demo", upstream=upstream)
    _write_n(lg, 1)
    lg.close()
    assert len(read_lines(lg.path)) == 1


def test_concurrent_writes_do_not_interleave(audit_config: AuditConfig, upstream: UpstreamInfo):
    """proxy 有两条泵并发写，JSONL 不许被撕成半行。"""
    lg = AuditLogger(audit_config, server="demo", upstream=upstream)
    lg.open()

    def worker(tag: str) -> None:
        for _ in range(50):
            lg.write(
                lg.build_record(
                    event="tools/call",
                    direction=Direction.CLIENT_TO_SERVER,
                    decision=Decision.ALLOW,
                    decision_by=DecisionBy.POLICY,
                    tool=tag,
                    reason="x" * 500,
                )
            )

    threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lg.close()

    lines = read_lines(lg.path)  # 任何一行坏了这里就 json.loads 炸
    assert len(lines) == 200


# ────────────────────────────────────────────────────────────────────────────
# stdout 洁净（铁律）
# ────────────────────────────────────────────────────────────────────────────


def test_audit_writes_nothing_to_stdout(
    audit_config: AuditConfig, upstream: UpstreamInfo, capsys: pytest.CaptureFixture[str]
):
    lg = AuditLogger(audit_config, server="demo", upstream=upstream)
    lg.open()
    _write_n(lg, 3)
    lg.close()
    assert capsys.readouterr().out == ""


def test_guard_log_never_touches_stdout(guard_home: Path, capsys: pytest.CaptureFixture[str]):
    """guard.log 的每种输出都只能进文件 / stderr。"""
    log = GuardLog(guard_home / "guard.log", also_stderr=True)
    log.info("RUG PULL demo/echo 4f2a -> 9b71")
    log.warn("something smells")
    log.error("boom")
    try:
        raise RuntimeError("kaboom")
    except RuntimeError as exc:
        log.exception("detector blew up", exc)
    log.banner(server="demo", command=["python3", "/path/server.py"], config_path=Path("/x.yaml"))
    log.close()

    captured = capsys.readouterr()
    assert captured.out == "", "stdout 必须一个字节都没有"
    assert "RUG PULL" in captured.err

    text = (guard_home / "guard.log").read_text(encoding="utf-8")
    assert "[mcp-guarder] RUG PULL demo/echo 4f2a -> 9b71" in text
    assert "WARN something smells" in text
    assert "ERROR boom" in text
    assert "python3 /path/server.py" in text


def test_guard_log_traceback_only_in_file(
    guard_home: Path, capsys: pytest.CaptureFixture[str]
):
    """SPEC §5：异常栈只进 guard.log，stderr 只留一行摘要。"""
    log = GuardLog(guard_home / "guard.log", also_stderr=True)
    try:
        raise ValueError("inner detail")
    except ValueError as exc:
        log.exception("detector failure (static_checks)", exc)
    log.close()

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "detector failure (static_checks)" in captured.err
    assert "Traceback" not in captured.err

    text = (guard_home / "guard.log").read_text(encoding="utf-8")
    assert "Traceback" in text
    assert "ValueError: inner detail" in text


def test_guard_log_survives_unwritable_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """日志文件开不了也不能反过来搞挂网关，降级成只写 stderr。"""
    blocker = tmp_path / "blocker"
    blocker.write_text("file", encoding="utf-8")
    log = GuardLog(blocker / "sub" / "guard.log", also_stderr=True)
    log.info("still alive")  # 不许抛
    log.close()

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "still alive" in captured.err


def test_guard_log_line_shape(guard_home: Path):
    """行首是 UTC 时间戳，紧跟 [mcp-guarder]。"""
    log = GuardLog(guard_home / "guard.log", also_stderr=False)
    log.info("hello")
    log.close()
    line = (guard_home / "guard.log").read_text(encoding="utf-8").strip()
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z \[mcp-guarder\] hello", line
    )


# ────────────────────────────────────────────────────────────────────────────
# 只读工具（CLI audit tail / grep）
# ────────────────────────────────────────────────────────────────────────────


def _write_records(path: Path, ids: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        for value in ids:
            fh.write(json.dumps({"audit_id": value, "event": "tools/call"}) + "\n")


def test_audit_files_for_globs_dates(audit_config: AuditConfig, guard_home: Path):
    for name in ("demo-2026-08-15.jsonl", "demo-2026-08-17.jsonl", "demo-2026-08-16.jsonl"):
        (guard_home / "audit" / name).write_text("", encoding="utf-8")
    (guard_home / "audit" / "other-2026-08-17.jsonl").write_text("", encoding="utf-8")

    files = audit.audit_files_for(audit_config, "demo")
    assert [f.name for f in files] == [
        "demo-2026-08-15.jsonl",
        "demo-2026-08-16.jsonl",
        "demo-2026-08-17.jsonl",
    ]


def test_audit_files_for_missing_dir_is_empty(guard_home: Path):
    cfg = AuditConfig(path=str(guard_home / "nope" / "{server}-{date}.jsonl"))
    assert audit.audit_files_for(cfg, "demo") == ()


def test_iter_records_skips_bad_lines(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    path = tmp_path / "a.jsonl"
    path.write_text(
        '{"audit_id":"A"}\n'
        "{not json at all\n"
        "\n"
        "[1,2,3]\n"
        '{"audit_id":"B"}\n',
        encoding="utf-8",
    )
    records = list(audit.iter_records(path))
    assert [r["audit_id"] for r in records] == ["A", "B"]
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "skipping malformed line" in captured.err
    assert "skipping non-object line" in captured.err


def test_iter_records_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert list(audit.iter_records(tmp_path / "nope.jsonl")) == []
    assert "cannot read" in capsys.readouterr().err


def test_tail_records_takes_last_n(tmp_path: Path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    _write_records(a, ["1", "2", "3"])
    _write_records(b, ["4", "5"])
    got = [r["audit_id"] for r in audit.tail_records([a, b], 3)]
    assert got == ["3", "4", "5"]
    assert [r["audit_id"] for r in audit.tail_records([a, b], 99)] == ["1", "2", "3", "4", "5"]
    assert list(audit.tail_records([a, b], 0)) == []


def test_tail_records_follow_picks_up_appends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(audit, "FOLLOW_POLL_SECONDS", 0.01)
    path = tmp_path / "a.jsonl"
    _write_records(path, ["A"])

    gen = audit.tail_records([path], 1, follow=True)
    assert next(gen)["audit_id"] == "A"  # 存量

    _write_records(path, ["B"])
    got: list[dict] = []
    worker = threading.Thread(target=lambda: got.append(next(gen)), daemon=True)
    worker.start()
    worker.join(timeout=5)
    assert got and got[0]["audit_id"] == "B"
    gen.close()


def test_tail_records_follow_ignores_partial_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """写了一半的行不许解析，等它写完再说。"""
    monkeypatch.setattr(audit, "FOLLOW_POLL_SECONDS", 0.01)
    path = tmp_path / "a.jsonl"
    _write_records(path, ["A"])

    gen = audit.tail_records([path], 1, follow=True)
    next(gen)

    with open(path, "a", encoding="utf-8") as fh:
        fh.write('{"audit_id":"B"')  # 半截，没有换行
        fh.flush()
        got: list[dict] = []
        worker = threading.Thread(target=lambda: got.append(next(gen)), daemon=True)
        worker.start()
        worker.join(timeout=0.5)
        assert got == [], "半截行不该被 yield 出来"
        fh.write(',"event":"ping"}\n')  # 补完
        fh.flush()
    worker.join(timeout=5)
    assert got and got[0]["audit_id"] == "B"
    gen.close()


def test_grep_records_matches_raw_line(tmp_path: Path):
    path = tmp_path / "a.jsonl"
    path.write_text(
        '{"audit_id":"A","decision":"deny","reason":"no matching rule"}\n'
        '{"audit_id":"B","decision":"allow"}\n',
        encoding="utf-8",
    )
    got = [r["audit_id"] for r in audit.grep_records([path], r'"decision":"deny"')]
    assert got == ["A"]
    assert [r["audit_id"] for r in audit.grep_records([path], "no matching rule")] == ["A"]
    assert list(audit.grep_records([path], "nothing-here")) == []


def test_grep_records_invalid_pattern(tmp_path: Path):
    with pytest.raises(GuarderError):
        list(audit.grep_records([tmp_path / "a.jsonl"], "([unclosed"))


def test_format_record_short_and_verbose():
    record = {
        "ts": "2026-08-17T10:32:41.518Z",
        "event": "tools/call",
        "tool": "read_file",
        "decision": "deny",
        "decision_by": "policy",
        "rule_id": "allow-read-in-project",
        "reason": "no matching rule",
    }
    line = audit.format_record(record)
    assert line == (
        "2026-08-17T10:32:41.518Z tools/call read_file deny/policy "
        "rule=allow-read-in-project no matching rule"
    )
    verbose = audit.format_record(record, verbose=True)
    assert json.loads(verbose)["tool"] == "read_file"
    assert "\n" in verbose


def test_format_record_tolerates_missing_keys():
    assert audit.format_record({}) == "- - - -/-"
