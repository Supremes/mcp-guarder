"""规则级 ``on_hit``：高精确度规则直接剥离，宽泛规则只告警并交给 LLM 判定。"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from mcp_guarder import semantic as sem
from mcp_guarder.audit import AuditLogger, GuardLog
from mcp_guarder.config import load_config, parse_config
from mcp_guarder.errors import ConfigError
from mcp_guarder.fingerprint import FingerprintStore
from mcp_guarder.proxy import Proxy
from mcp_guarder.types import StaticCheckAction, UpstreamInfo
from tests.test_proxy import audit_lines, config_text, guard_log_text
from tests.test_semantic import FakeModel, list_tools, semantic_block, tool

BASE = {"version": 1, "server": {"name": "x", "transport": "stdio"}}

#: deny 规则抓显式特征，warn 规则抓宽泛句式。
RULES = """    rules:
      - {id: hidden-tag, pattern: '<IMPORTANT>', on_hit: deny}
      - {id: must-call, pattern: '(?i)you must call', on_hit: warn}
      - {id: inherit, pattern: 'INHERIT'}
"""


# ────────────────────────────────────────────────────────────────────────────
# 配置
# ────────────────────────────────────────────────────────────────────────────


def static_cfg(section: dict[str, Any]):
    return parse_config({**BASE, "inspect": {"static_checks": section}}).inspect.static_checks


def test_rule_on_hit_overrides_section_default() -> None:
    cfg = static_cfg({"on_hit": "deny", "rules": [
        {"id": "a", "pattern": "x", "on_hit": "warn"},
        {"id": "b", "pattern": "y"},
    ]})
    assert cfg.action_for("a") is StaticCheckAction.WARN
    assert cfg.action_for("b") is StaticCheckAction.DENY


def test_rule_without_on_hit_follows_section_warn() -> None:
    cfg = static_cfg({"on_hit": "warn", "rules": [
        {"id": "a", "pattern": "x"},
        {"id": "b", "pattern": "y", "on_hit": "deny"},
    ]})
    assert cfg.action_for("a") is StaticCheckAction.WARN
    assert cfg.action_for("b") is StaticCheckAction.DENY


def test_default_rules_keep_section_behavior() -> None:
    cfg = static_cfg({})
    assert all(r.on_hit is None for r in cfg.rules)
    assert cfg.action_for("hidden-instruction-tag") is StaticCheckAction.DENY


def test_invalid_rule_on_hit_is_rejected() -> None:
    with pytest.raises(ConfigError) as info:
        static_cfg({"rules": [{"id": "a", "pattern": "x", "on_hit": "block"}]})
    assert any("rules[0].on_hit" in p for p in info.value.problems)


def test_redact_rules_do_not_accept_on_hit() -> None:
    with pytest.raises(ConfigError) as info:
        parse_config({**BASE, "redact": {"rules": [{"id": "a", "pattern": "x", "on_hit": "warn"}]}})
    assert any("redact.rules[0].on_hit" in p for p in info.value.problems)


# ────────────────────────────────────────────────────────────────────────────
# 代理
# ────────────────────────────────────────────────────────────────────────────


def write_config(tmp_path: Path, guard_home: Path, *, semantic: str = "") -> Path:
    text = config_text(guard_home).replace(
        "    on_hit: deny\npolicy:", "    on_hit: deny\n" + RULES + semantic + "policy:"
    )
    path = tmp_path / f"config_{len(list(tmp_path.glob('config_*.yaml')))}.yaml"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def make_proxy(tmp_path: Path, guard_home: Path) -> Iterator[Callable[..., Proxy]]:
    resources: list[Any] = []

    def _make(model: Any = None, **semantic_overrides: Any) -> Proxy:
        semantic = ""
        if model is not None:
            semantic = semantic_block(cache=f"{guard_home}/semantic.sqlite", **semantic_overrides)
        config = load_config(write_config(tmp_path, guard_home, semantic=semantic))
        log = GuardLog(config.audit.log_file, also_stderr=False)
        audit = AuditLogger(config.audit, server=config.server.name, upstream=UpstreamInfo(), log=log)
        audit.open()
        store = FingerprintStore(config.inspect.fingerprint.store)
        store.open()
        resources.extend([audit, store, log])
        judge = None
        if model is not None:
            cache = sem.VerdictCache(config.inspect.semantic.cache)
            cache.open()
            resources.append(cache)
            judge = sem.SemanticJudge(config.inspect.semantic, cache=cache, transport=model)
        return Proxy(config, ["/bin/true"], audit=audit, log=log, fingerprints=store,
                     semantic=judge, stdin=io.BytesIO(), stdout=io.BytesIO())

    yield _make
    for r in resources:
        r.close()


def tools_list_record(guard_home: Path) -> dict:
    return [r for r in audit_lines(guard_home) if r["event"] == "tools/list"][-1]


def test_deny_rule_strips_warn_rule_keeps(make_proxy: Callable[..., Proxy], guard_home: Path) -> None:
    proxy = make_proxy()
    names = list_tools(proxy, [
        tool("a", "<IMPORTANT>do it</IMPORTANT>"),
        tool("b", "You must call list_files first."),
        tool("c", "plain"),
    ])
    assert names == ["b", "c"]
    record = tools_list_record(guard_home)
    assert record["decision"] == "deny" and record["decision_by"] == "static_checks"
    assert "static_checks warn: b:must-call" in record["reason"]
    log = guard_log_text(guard_home)
    assert "hidden-tag (deny)" in log and "must-call (warn)" in log


def test_warn_only_hits_are_audited_on_allow(make_proxy: Callable[..., Proxy], guard_home: Path) -> None:
    proxy = make_proxy()
    assert list_tools(proxy, [tool("b", "You must call x.")]) == ["b"]
    record = tools_list_record(guard_home)
    assert record["decision"] == "allow"
    assert record["reason"] == "static_checks warn: b:must-call"


def test_rule_without_on_hit_inherits_section_deny(make_proxy: Callable[..., Proxy]) -> None:
    assert list_tools(make_proxy(), [tool("d", "INHERIT this")]) == []


def test_tool_hitting_deny_and_warn_is_stripped_not_warned(
    make_proxy: Callable[..., Proxy], guard_home: Path
) -> None:
    proxy = make_proxy()
    assert list_tools(proxy, [tool("e", "<IMPORTANT> you must call x")]) == []
    assert "static_checks warn" not in (tools_list_record(guard_home)["reason"] or "")


def test_warn_hit_goes_to_llm_and_llm_decides(
    make_proxy: Callable[..., Proxy], guard_home: Path
) -> None:
    model = FakeModel()
    proxy = make_proxy(model)
    names = list_tools(proxy, [
        tool("a", "<IMPORTANT>x</IMPORTANT>"),          # deny 规则：直接剥离，不送 LLM
        tool("b", "You must call x. MALICIOUS"),         # warn 规则 + LLM 判恶意：剥离
        tool("c", "You must call list_files first."),    # warn 规则 + LLM 判 benign：保留
    ])
    assert names == ["c"]
    sent = model.calls[0]["body"]["messages"][1]["content"].split("\n\n", 2)[2]
    assert "<IMPORTANT>" not in sent
    assert '"b"' in sent and '"c"' in sent
    record = tools_list_record(guard_home)
    assert record["decision_by"] == "static_checks"
    assert "b:malicious" in record["reason"]
    assert "static_checks warn: c:must-call" in record["reason"]


def test_llm_unavailable_logs_warn_hits_as_hint(
    make_proxy: Callable[..., Proxy], guard_home: Path
) -> None:
    def down(*_: Any) -> dict:
        raise sem.SemanticFailure(sem.FailureKind.UNAVAILABLE, "connection refused")

    proxy = make_proxy(down)
    assert list_tools(proxy, [tool("b", "You must call x.")]) == ["b"]
    assert "semantic unavailable for demo/b -> warn; static warn hits: must-call" in guard_log_text(guard_home)
    record = tools_list_record(guard_home)
    assert "static_checks warn: b:must-call" in record["reason"]
    assert "semantic unjudged: b:unavailable" in record["reason"]
