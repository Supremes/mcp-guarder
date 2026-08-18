"""``mcp_guarder.redact`` 的单元测试（SPEC §2 T5/T7 / §4 redact 段 / §7 M2-3、M2-4）。

覆盖重点：
- 5 条内置规则各命中一次（pattern 从配置读，不硬编码在实现里）
- allowlist 生效（AWS 文档里的 EXAMPLE key 不打码）
- 回流三条路径：``result.content[].text`` / ``result.content[].resource.text``
  / ``result.structuredContent``（后者递归到底）
- 命中计数准确、多路径合并求和
- **未命中时输出与输入完全一致**（既深度相等，也是同一个对象 —— 字节级保守转发的前提）
- ``mask`` / ``drop_field`` / ``deny_call`` 三种 action
- 检测器内部异常包成 DetectorError（fail-closed）
- 超大 payload 不挂死

这里**不依赖 config 模块**（它由别的 agent 实现），RedactConfig 直接手工构造，
正则用 ``types.SPEC_REDACT_RULES`` / ``SPEC_REDACT_ALLOWLIST`` 里 SPEC 抄下来的那份。
"""

from __future__ import annotations

import copy
import json
import re
import time

import pytest

from mcp_guarder.errors import ConfigError, DetectorError
from mcp_guarder.redact import (
    DROP,
    apply_at_paths,
    merge_counts,
    parse_scan_path,
    redact_inbound,
    redact_outbound,
    redact_text,
    redact_value,
)
from mcp_guarder.types import (
    SPEC_REDACT_ALLOWLIST,
    SPEC_REDACT_RULES,
    DetectorName,
    DetectorResult,
    PatternRule,
    RedactAction,
    RedactConfig,
    RedactionCount,
)

# ────────────────────────────────────────────────────────────────────────────
# 样本与工具
# ────────────────────────────────────────────────────────────────────────────

AKID = "AKIA1234567890ABCDEF"  # AKIA + 16 位
AKID_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"  # allowlist 里的 AWS 文档示例
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
OPENAI_KEY = "sk-" + "A" * 32
GITHUB_PAT = "ghp_" + "B" * 36
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"

ALL_FIVE = {
    "aws-akid": AKID,
    "bearer-jwt": JWT,
    "openai-key": OPENAI_KEY,
    "github-pat": GITHUB_PAT,
    "private-key-block": PRIVATE_KEY,
}


def spec_rules() -> tuple[PatternRule, ...]:
    """把 SPEC §4 那 5 条脱敏规则编译成 PatternRule（模拟 config 解析期干的事）。"""
    return tuple(PatternRule(id=rid, pattern=pat, regex=re.compile(pat)) for rid, pat in SPEC_REDACT_RULES)


def spec_allowlist() -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p) for p in SPEC_REDACT_ALLOWLIST)


def make_config(**overrides) -> RedactConfig:
    kwargs: dict = {"rules": spec_rules(), "allowlist": spec_allowlist()}
    kwargs.update(overrides)
    return RedactConfig(**kwargs)


def counts_dict(counts) -> dict[str, int]:
    return {c.rule_id: c.count for c in counts}


def call_message(arguments: dict) -> dict:
    """一条 tools/call 请求，带 _meta 之类的"未知字段"用来验证不被动。"""
    return {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": arguments,
            "_meta": {"claudecode/toolUseId": "toolu_01ABC", "vendorExtension": {"keep": "me"}},
        },
    }


def result_message(result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": 7, "result": result}


# ────────────────────────────────────────────────────────────────────────────
# 5 条内置规则 + allowlist
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("rule_id", "sample"), sorted(ALL_FIVE.items()))
def test_each_builtin_rule_hits_once(rule_id: str, sample: str) -> None:
    cfg = make_config()
    text, counts = redact_text(f"prefix {sample} suffix", config=cfg)
    assert counts_dict(counts) == {rule_id: 1}
    assert sample not in text
    assert f"[REDACTED:{rule_id}]" in text
    assert text.startswith("prefix ")
    assert text.endswith(" suffix")


def test_five_rules_in_one_outbound_call() -> None:
    cfg = make_config()
    message = call_message(
        {
            "akid": AKID,
            "token": f"Bearer {JWT}",
            "nested": {"openai": OPENAI_KEY, "list": [GITHUB_PAT, {"pem": PRIVATE_KEY + "\nMIIE..."}]},
        }
    )
    report = redact_outbound(message, config=cfg)

    assert counts_dict(report.counts) == {rid: 1 for rid in ALL_FIVE}
    assert report.deny is False
    assert report.skipped is False
    assert report.changed is True
    assert report.outcome().name is DetectorName.REDACT
    assert report.outcome().result is DetectorResult.MATCH

    blob = json.dumps(report.message)
    for sample in ALL_FIVE.values():
        assert sample not in blob
    # 未命中字段原样保留
    args = report.message["params"]["arguments"]
    assert args["token"] == "Bearer [REDACTED:bearer-jwt]"
    assert report.message["params"]["_meta"] == message["params"]["_meta"]
    assert report.message["params"]["name"] == "write_file"
    assert report.message["id"] == 7


def test_allowlist_keeps_aws_doc_example() -> None:
    cfg = make_config()
    text, counts = redact_text(f"doc={AKID_EXAMPLE} real={AKID}", config=cfg)
    assert AKID_EXAMPLE in text
    assert AKID not in text
    assert counts_dict(counts) == {"aws-akid": 1}


def test_allowlist_only_example_no_counts() -> None:
    cfg = make_config()
    original = f"see {AKID_EXAMPLE} in the docs"
    text, counts = redact_text(original, config=cfg)
    assert counts == ()
    assert text is original  # 没命中就原样返回同一个对象


# ────────────────────────────────────────────────────────────────────────────
# 回流三条路径
# ────────────────────────────────────────────────────────────────────────────


def test_inbound_content_text() -> None:
    cfg = make_config()
    message = result_message(
        {"content": [{"type": "text", "text": f"key={AKID}"}, {"type": "text", "text": "clean"}]}
    )
    report = redact_inbound(message, config=cfg)
    assert counts_dict(report.counts) == {"aws-akid": 1}
    assert report.message["result"]["content"][0]["text"] == "key=[REDACTED:aws-akid]"
    assert report.message["result"]["content"][1]["text"] == "clean"


def test_inbound_embedded_resource_text() -> None:
    """内嵌资源全文最容易漏 —— ``result.content[].resource.text``。"""
    cfg = make_config()
    message = result_message(
        {
            "content": [
                {
                    "type": "resource",
                    "resource": {
                        "uri": "file:///tmp/.env",
                        "mimeType": "text/plain",
                        "text": f"AWS={AKID}\nGH={GITHUB_PAT}\n",
                    },
                }
            ]
        }
    )
    report = redact_inbound(message, config=cfg)
    assert counts_dict(report.counts) == {"aws-akid": 1, "github-pat": 1}
    resource = report.message["result"]["content"][0]["resource"]
    assert resource["text"] == "AWS=[REDACTED:aws-akid]\nGH=[REDACTED:github-pat]\n"
    assert resource["uri"] == "file:///tmp/.env"  # 非目标字段不动
    assert resource["mimeType"] == "text/plain"


def test_inbound_structured_content_recurses_to_the_bottom() -> None:
    cfg = make_config()
    message = result_message(
        {
            "structuredContent": {
                "creds": {"aws": {"akid": AKID}, "tokens": [JWT, {"deep": {"deeper": OPENAI_KEY}}]},
                "count": 3,
                "ok": True,
                "nothing": None,
            }
        }
    )
    report = redact_inbound(message, config=cfg)
    assert counts_dict(report.counts) == {"aws-akid": 1, "bearer-jwt": 1, "openai-key": 1}
    sc = report.message["result"]["structuredContent"]
    assert sc["creds"]["aws"]["akid"] == "[REDACTED:aws-akid]"
    assert sc["creds"]["tokens"][0] == "[REDACTED:bearer-jwt]"
    assert sc["creds"]["tokens"][1]["deep"]["deeper"] == "[REDACTED:openai-key]"
    assert sc["count"] == 3 and sc["ok"] is True and sc["nothing"] is None


def test_inbound_all_three_paths_counts_are_summed() -> None:
    """同一条响应里三处都命中同一条规则 → 计数求和（审计的 redactions.inbound）。"""
    cfg = make_config()
    message = result_message(
        {
            "content": [
                {"type": "text", "text": f"{AKID} and {AKID}"},
                {"type": "resource", "resource": {"text": AKID}},
            ],
            "structuredContent": {"a": [AKID]},
            "isError": False,
        }
    )
    report = redact_inbound(message, config=cfg)
    assert counts_dict(report.counts) == {"aws-akid": 4}
    assert "AKIA" not in json.dumps(report.message)
    assert report.message["result"]["isError"] is False


def test_inbound_missing_paths_are_skipped_silently() -> None:
    cfg = make_config()
    # content 不是数组、structuredContent 不存在、result 里全是未知字段
    message = result_message({"content": {"weird": "shape"}, "vendorField": [1, 2, 3]})
    report = redact_inbound(message, config=cfg)
    assert report.counts == ()
    assert report.message is message


def test_inbound_deny_call_downgrades_to_mask() -> None:
    cfg = make_config(action=RedactAction.DENY_CALL)
    message = result_message({"content": [{"type": "text", "text": AKID}]})
    report = redact_inbound(message, config=cfg)
    assert report.deny is False  # 回流方向拒无可拒
    assert report.message["result"]["content"][0]["text"] == "[REDACTED:aws-akid]"
    assert counts_dict(report.counts) == {"aws-akid": 1}


# ────────────────────────────────────────────────────────────────────────────
# 未命中 == 完全不动
# ────────────────────────────────────────────────────────────────────────────


def test_no_hit_output_is_identical_and_same_object() -> None:
    cfg = make_config()
    message = call_message({"path": "/tmp/a.txt", "n": 1, "flag": False, "list": [1, {"k": "v"}], "nil": None})
    snapshot = copy.deepcopy(message)

    report = redact_outbound(message, config=cfg)
    assert report.counts == ()
    assert report.changed is False
    assert report.deny is False
    assert report.outcome().result is DetectorResult.CLEAN
    assert report.message == snapshot  # 深度相等
    assert report.message is message  # 而且压根没拷贝 → proxy 走字节级原样转发
    assert message == snapshot  # 输入本身也没被就地改过


def test_untouched_subtrees_are_reused_not_copied() -> None:
    """写时复制：只有命中链路上的容器换新，其余子树复用同一引用。"""
    cfg = make_config()
    untouched = {"deep": {"a": [1, 2, 3]}}
    message = call_message({"secret": AKID, "untouched": untouched})
    report = redact_outbound(message, config=cfg)

    assert report.message is not message
    assert report.message["params"]["arguments"]["untouched"] is untouched
    assert report.message["params"]["_meta"] is message["params"]["_meta"]
    # 原报文没被就地改
    assert message["params"]["arguments"]["secret"] == AKID


def test_dict_keys_are_never_rewritten() -> None:
    """脱敏只动字符串叶子的值，不动 key —— 改 key 等于改参数名。"""
    cfg = make_config()
    message = call_message({AKID: "value", "other": AKID})
    report = redact_outbound(message, config=cfg)
    args = report.message["params"]["arguments"]
    assert AKID in args  # key 原样
    assert args[AKID] == "value"
    assert args["other"] == "[REDACTED:aws-akid]"
    assert counts_dict(report.counts) == {"aws-akid": 1}


def test_disabled_is_skipped() -> None:
    cfg = make_config(enabled=False)
    message = call_message({"secret": AKID})
    report = redact_outbound(message, config=cfg)
    assert report.skipped is True
    assert report.message is message
    assert report.counts == ()
    assert report.outcome().result is DetectorResult.SKIPPED

    inbound = redact_inbound(result_message({"content": [{"text": AKID}]}), config=cfg)
    assert inbound.skipped is True


def test_empty_rules_means_no_hits() -> None:
    cfg = make_config(rules=())
    message = call_message({"secret": AKID})
    report = redact_outbound(message, config=cfg)
    assert report.skipped is False
    assert report.counts == ()
    assert report.message is message


# ────────────────────────────────────────────────────────────────────────────
# 三种 action
# ────────────────────────────────────────────────────────────────────────────


def test_action_mask_uses_template() -> None:
    cfg = make_config(mask_template="<<{rule_id}>>")
    text, counts = redact_text(f"x {AKID} y", config=cfg)
    assert text == "x <<aws-akid>> y"
    assert counts == (RedactionCount("aws-akid", 1),)


def test_action_mask_template_without_placeholder() -> None:
    cfg = make_config(mask_template="[REDACTED]")
    text, _ = redact_text(AKID, config=cfg)
    assert text == "[REDACTED]"


def test_action_drop_field_removes_the_field() -> None:
    cfg = make_config(action=RedactAction.DROP_FIELD)
    message = call_message({"secret": AKID, "keep": "hello", "nested": {"tok": JWT, "n": 1}})
    report = redact_outbound(message, config=cfg)

    args = report.message["params"]["arguments"]
    assert "secret" not in args
    assert args["keep"] == "hello"
    assert args["nested"] == {"n": 1}
    assert counts_dict(report.counts) == {"aws-akid": 1, "bearer-jwt": 1}
    assert report.deny is False


def test_action_drop_field_drops_list_elements() -> None:
    cfg = make_config(action=RedactAction.DROP_FIELD)
    message = call_message({"items": ["clean", AKID, "also-clean"]})
    report = redact_outbound(message, config=cfg)
    assert report.message["params"]["arguments"]["items"] == ["clean", "also-clean"]


def test_action_drop_field_on_scan_path_leaf() -> None:
    """命中的就是扫描路径的叶子本身（``result.content[].text``）→ 整个 text 字段被删。"""
    cfg = make_config(action=RedactAction.DROP_FIELD)
    message = result_message({"content": [{"type": "text", "text": AKID, "annotations": {"a": 1}}]})
    report = redact_inbound(message, config=cfg)
    item = report.message["result"]["content"][0]
    assert "text" not in item
    assert item["type"] == "text"
    assert item["annotations"] == {"a": 1}


def test_action_deny_call_sets_deny_and_still_masks_for_audit() -> None:
    """deny_call：proxy 不会把它发出去，但 report.message 必须是脱敏后的（审计要拿它记账）。"""
    cfg = make_config(action=RedactAction.DENY_CALL)
    message = call_message({"pem": PRIVATE_KEY})
    report = redact_outbound(message, config=cfg)
    assert report.deny is True
    assert counts_dict(report.counts) == {"private-key-block": 1}
    assert "PRIVATE KEY" not in json.dumps(report.message)  # secret 不落盘


def test_action_deny_call_without_hit_does_not_deny() -> None:
    cfg = make_config(action=RedactAction.DENY_CALL)
    message = call_message({"path": "/tmp/ok"})
    report = redact_outbound(message, config=cfg)
    assert report.deny is False
    assert report.message is message


# ────────────────────────────────────────────────────────────────────────────
# 计数与重叠
# ────────────────────────────────────────────────────────────────────────────


def test_counts_multiple_occurrences() -> None:
    cfg = make_config()
    text, counts = redact_text(f"{AKID} {AKID} {JWT}", config=cfg)
    assert counts_dict(counts) == {"aws-akid": 2, "bearer-jwt": 1}
    assert text == "[REDACTED:aws-akid] [REDACTED:aws-akid] [REDACTED:bearer-jwt]"


def test_mask_output_is_not_rematched_by_later_rules() -> None:
    """替换后的文本不能被后续规则重复命中（所有区间在原文上一次性算完）。"""
    rules = (
        PatternRule(id="first", pattern=r"secret-\d+", regex=re.compile(r"secret-\d+")),
        PatternRule(id="second", pattern=r"REDACTED", regex=re.compile(r"REDACTED")),
    )
    cfg = make_config(rules=rules, allowlist=())
    text, counts = redact_text("value=secret-42", config=cfg)
    assert text == "value=[REDACTED:first]"
    assert counts_dict(counts) == {"first": 1}  # second 一次都没命中


def test_overlapping_rules_first_declared_wins() -> None:
    rules = (
        PatternRule(id="broad", pattern=r"abcdef", regex=re.compile(r"abcdef")),
        PatternRule(id="narrow", pattern=r"cde", regex=re.compile(r"cde")),
    )
    cfg = make_config(rules=rules, allowlist=())
    text, counts = redact_text("xxabcdefxx", config=cfg)
    assert text == "xx[REDACTED:broad]xx"
    assert counts_dict(counts) == {"broad": 1}


def test_zero_length_match_is_ignored() -> None:
    rules = (PatternRule(id="empty", pattern=r"x*", regex=re.compile(r"x*")),)
    cfg = make_config(rules=rules, allowlist=())
    text, counts = redact_text("abc", config=cfg)
    assert text == "abc"
    assert counts == ()


def test_merge_counts_sums_and_keeps_first_seen_order() -> None:
    merged = merge_counts(
        (RedactionCount("b", 1), RedactionCount("a", 2)),
        (RedactionCount("a", 3),),
        (),
    )
    assert merged == (RedactionCount("b", 1), RedactionCount("a", 5))


# ────────────────────────────────────────────────────────────────────────────
# 路径表达式
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("params.arguments", ("params", "arguments")),
        ("result.content[].text", ("result", "content", "[]", "text")),
        ("result.content[].resource.text", ("result", "content", "[]", "resource", "text")),
        ("result.structuredContent", ("result", "structuredContent")),
        ("a[][]", ("a", "[]", "[]")),
        ("single", ("single",)),
    ],
)
def test_parse_scan_path_ok(raw: str, expected: tuple[str, ...]) -> None:
    assert parse_scan_path(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "result.content[0].text", "result..text", "result.*", "result.content[", "[]", "a.b[].", "with space"],
)
def test_parse_scan_path_rejects_bad_syntax(raw: str) -> None:
    with pytest.raises(ConfigError):
        parse_scan_path(raw)


def test_apply_at_paths_copy_on_write_and_merge() -> None:
    message = {"result": {"content": [{"text": "a"}, {"other": 1}], "keep": {"x": 1}}}
    keep = message["result"]["keep"]

    def upper(value):
        if isinstance(value, str):
            return value.upper(), (RedactionCount("up", 1),)
        return value, ()

    new_message, counts = apply_at_paths(message, ("result.content[].text", "result.missing"), upper)
    assert new_message["result"]["content"][0]["text"] == "A"
    assert new_message["result"]["content"][1] == {"other": 1}
    assert new_message["result"]["keep"] is keep
    assert counts == (RedactionCount("up", 1),)
    assert message["result"]["content"][0]["text"] == "a"  # 原对象没被就地改


def test_redact_value_returns_drop_sentinel_for_top_level_string() -> None:
    cfg = make_config(action=RedactAction.DROP_FIELD)
    value, counts = redact_value(AKID, config=cfg)
    assert value is DROP
    assert counts_dict(counts) == {"aws-akid": 1}


# ────────────────────────────────────────────────────────────────────────────
# fail-closed：检测器异常
# ────────────────────────────────────────────────────────────────────────────


class _BoomRegex:
    """假的编译正则：finditer 一调用就炸，用来验证异常被包成 DetectorError。"""

    def finditer(self, _text: str):
        raise RuntimeError("boom")


def test_detector_error_wraps_internal_failure_outbound() -> None:
    cfg = make_config(rules=(PatternRule(id="boom", pattern="x", regex=_BoomRegex()),))  # type: ignore[arg-type]
    with pytest.raises(DetectorError) as excinfo:
        redact_outbound(call_message({"a": "text"}), config=cfg)
    assert excinfo.value.detector is DetectorName.REDACT
    assert "detector failure (redact)" in excinfo.value.model_text
    assert isinstance(excinfo.value.cause, RuntimeError)


def test_detector_error_wraps_internal_failure_inbound() -> None:
    cfg = make_config(rules=(PatternRule(id="boom", pattern="x", regex=_BoomRegex()),))  # type: ignore[arg-type]
    with pytest.raises(DetectorError):
        redact_inbound(result_message({"content": [{"text": "hi"}]}), config=cfg)


def test_bad_scan_path_at_runtime_is_wrapped_as_detector_error() -> None:
    """配置层本该拦住非法路径；万一漏到运行期，也必须 fail-closed 成 DetectorError。"""
    cfg = make_config(outbound_scan=("params.arguments[0]",))
    with pytest.raises(DetectorError):
        redact_outbound(call_message({"a": "b"}), config=cfg)


def test_pathological_nesting_fails_closed() -> None:
    """超深嵌套 → RecursionError → DetectorError（deny），不许把裸异常放出去。"""
    cfg = make_config()
    deep: dict = {"leaf": AKID}
    for _ in range(3000):
        deep = {"n": deep}
    with pytest.raises(DetectorError):
        redact_outbound(call_message(deep), config=cfg)


# ────────────────────────────────────────────────────────────────────────────
# 超大 payload
# ────────────────────────────────────────────────────────────────────────────


def test_large_payload_is_fast_and_accurate() -> None:
    cfg = make_config()
    filler = ("lorem ipsum dolor sit amet 0123456789 " * 30_000)  # ~1.1MB
    # 前后留空格：secret 紧贴字母时 `\bAKIA...\b` 本来就不该命中（正则语义如此，不是实现问题）
    big = f"{filler} {AKID} {filler} {JWT} {filler}"
    message = result_message({"content": [{"type": "text", "text": big}]})

    started = time.monotonic()
    report = redact_inbound(message, config=cfg)
    elapsed = time.monotonic() - started

    assert counts_dict(report.counts) == {"aws-akid": 1, "bearer-jwt": 1}
    out = report.message["result"]["content"][0]["text"]
    assert AKID not in out and JWT not in out
    assert len(out) == len(big) - len(AKID) - len(JWT) + len("[REDACTED:aws-akid]") + len("[REDACTED:bearer-jwt]")
    assert elapsed < 10.0, f"redact took {elapsed:.2f}s on a ~3MB payload"


def test_many_matches_in_one_string() -> None:
    cfg = make_config()
    text = " ".join([AKID] * 5_000)
    _, counts = redact_text(text, config=cfg)
    assert counts_dict(counts) == {"aws-akid": 5_000}
