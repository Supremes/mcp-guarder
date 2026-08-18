"""命令行入口（SPEC §3 stdio 调用形态 / §7 M3 的四个子命令）。

用法::

    # 代理模式（默认，没有子命令时走这条）
    mcp-guarder [--config x.yaml] -- <command> [args...]

    # M3 的运维子命令
    mcp-guarder diff <server> <tool>          # 投毒前后的统一 diff
    mcp-guarder trust <server> [tool]         # 接受新指纹（不然 server 正常升级只能手删 sqlite）
    mcp-guarder audit tail [-n N] [-f]
    mcp-guarder audit grep <pattern>

**``--`` 之后的东西原样透传给子进程**，不许做 shell 拼接（SPEC §3：实测 args 数组
不会被拼成字符串）。argparse 对 ``--`` 的处理不够可靠，先用 :func:`split_argv`
自己切一刀，再把前半段丢给 argparse。

铁律提醒：CLI 的所有人类可读输出（横幅、错误、diff）都走 **stderr 或独立命令的 stdout**；
代理模式下 stdout 是协议专用通道，一个字节都不能多写。
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
import traceback
from collections.abc import Sequence
from pathlib import Path

from mcp_guarder import audit as audit_mod
from mcp_guarder import config as config_mod
from mcp_guarder import fingerprint as fingerprint_mod
from mcp_guarder import proxy as proxy_mod
from mcp_guarder import static_checks as static_mod
from mcp_guarder.errors import ConfigError, GuarderError
from mcp_guarder.types import (
    EXIT_CONFIG_ERROR,
    EXIT_GENERIC_ERROR,
    EXIT_OK,
    GUARD_VERSION,
    GuarderConfig,
    JsonObj,
)

#: 用法提示（代理模式下没给命令时打的那行）。
USAGE = "usage: mcp-guarder [--config PATH] -- <command> [args...]"


def main(argv: Sequence[str] | None = None) -> int:
    """程序入口。返回进程退出码（``[project.scripts]`` 会 ``sys.exit(main())``）。

    顶层要把 :class:`~mcp_guarder.errors.GuarderError` 全接住：
    打 ``exc.format_report()``/``str(exc)`` 到 **stderr**，返回 ``exc.exit_code``。
    非预期异常也要接住（打 traceback 到 stderr，返回 1）——
    代理模式下让 traceback 冲进 stdout 是最严重的事故。
    """
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    head, command = split_argv(raw_argv)

    parser = build_parser()
    try:
        args = parser.parse_args(head)
    except SystemExit as exc:  # argparse 自己已经把用法打到 stderr 了
        return int(exc.code or 0)

    try:
        if args.command is None:
            return cmd_proxy(args, command)
        if command:
            eprint("`--` and its trailing command are only valid in proxy mode")
            return EXIT_CONFIG_ERROR
        if args.command == "diff":
            return cmd_diff(args)
        if args.command == "trust":
            return cmd_trust(args)
        if args.command == "audit":
            if args.audit_command == "tail":
                return cmd_audit_tail(args)
            if args.audit_command == "grep":
                return cmd_audit_grep(args)
            eprint("usage: mcp-guarder audit {tail,grep} ...")
            return EXIT_CONFIG_ERROR
        eprint(f"unknown subcommand: {args.command}")
        return EXIT_CONFIG_ERROR
    except ConfigError as exc:
        eprint(exc.format_report())
        return exc.exit_code
    except GuarderError as exc:
        eprint(f"{audit_mod.LOG_PREFIX} {exc}")
        return exc.exit_code
    except KeyboardInterrupt:
        return EXIT_OK
    except BaseException:  # noqa: BLE001 —— traceback 只许进 stderr，绝不进 stdout
        traceback.print_exc(file=sys.stderr)
        return EXIT_GENERIC_ERROR


def build_parser() -> argparse.ArgumentParser:
    """搭 argparse。

    - 全局：``--config PATH``、``--version``。
    - 子命令：``diff`` / ``trust`` / ``audit``（``audit`` 下面还有 ``tail`` / ``grep``）。
    - **没给子命令就是代理模式**，此时必须给了 ``--`` 和后面的 command。
    """
    parser = argparse.ArgumentParser(
        prog="mcp-guarder",
        description="MCP 安全网关：投毒检测 / 默认拒绝的权限门 / 双向脱敏 / 结构化审计",
        usage=USAGE,
    )
    parser.add_argument("--config", dest="config", default=None, help="配置文件路径")
    parser.add_argument("--version", action="version", version=f"mcp-guarder {GUARD_VERSION}")

    subparsers = parser.add_subparsers(dest="command")

    p_diff = subparsers.add_parser("diff", help="对比某个 tool 的已信任版本与最新一次快照")
    p_diff.add_argument("server")
    p_diff.add_argument("tool")

    p_trust = subparsers.add_parser("trust", help="接受新指纹（删掉旧记录，下次重新 TOFU）")
    p_trust.add_argument("server")
    p_trust.add_argument("tool", nargs="?", default=None)

    p_audit = subparsers.add_parser("audit", help="审计日志的只读工具")
    audit_sub = p_audit.add_subparsers(dest="audit_command")

    p_tail = audit_sub.add_parser("tail", help="看最近若干条审计记录")
    p_tail.add_argument("-n", "--count", type=int, default=20)
    p_tail.add_argument("-f", "--follow", action="store_true")
    p_tail.add_argument("--server", default=None)
    p_tail.add_argument("-v", "--verbose", action="store_true")

    p_grep = audit_sub.add_parser("grep", help="正则匹配审计记录整行原文")
    p_grep.add_argument("pattern")
    p_grep.add_argument("--server", default=None)
    p_grep.add_argument("-v", "--verbose", action="store_true")

    return parser


def split_argv(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """按第一个 ``--`` 把参数切成 ``(网关自己的参数, 子进程命令行)``。

    没有 ``--`` 时子进程命令行为空列表（然后要么是子命令模式，要么报用法错误）。
    ``--`` 之后的内容**一个都不解析**，原样传下去。
    """
    items = list(argv)
    for index, item in enumerate(items):
        if item == "--":
            return items[:index], items[index + 1 :]
    return items, []


# ────────────────────────────────────────────────────────────────────────────
# 子命令
# ────────────────────────────────────────────────────────────────────────────


def cmd_proxy(args: argparse.Namespace, command: Sequence[str]) -> int:
    """代理模式：加载配置 → :func:`~mcp_guarder.proxy.run_proxy`。

    ``command`` 为空 → 打用法到 stderr，返回 2。
    配置加载失败 → :class:`ConfigError` 冒到 :func:`main`，退出码 2（SPEC §5：拒绝启动）。
    """
    if not command:
        eprint(USAGE)
        eprint("missing upstream command after `--`")
        return EXIT_CONFIG_ERROR
    config = resolve_config(args.config)
    config_path = Path(args.config) if args.config else config.source_path
    return proxy_mod.run_proxy(config, command, config_path=config_path)


def cmd_diff(args: argparse.Namespace) -> int:
    """``mcp-guarder diff <server> <tool>``（SPEC §7 M3-2）。

    从指纹库拿这个 tool **当前已信任的 digest**，再从快照目录找**最新一份别的快照**
    （rug pull 时 fingerprint 只存快照不更新指纹，所以「最新的那份」就是投毒后的版本），
    用 ``difflib.unified_diff`` 输出投毒前后的差异。

    输出走 stdout（这是独立命令，不是代理模式）。找不到快照就打一句提示并返回 1。
    控制字符输出前必须过 :func:`~mcp_guarder.static_checks.visible_escape`，
    否则 diff 里的 ANSI 会直接在终端上生效 —— 那就等于自己被投毒了。
    """
    config = resolve_config(args.config)
    snapshot_dir = config.audit.snapshot_dir
    store = fingerprint_mod.FingerprintStore(config.inspect.fingerprint.store)
    try:
        store.open()
        trusted_fp = store.get(args.server, args.tool)
    except GuarderError:
        raise
    except Exception as exc:  # noqa: BLE001
        eprint(f"cannot read fingerprint store {config.inspect.fingerprint.store}: {exc}")
        return EXIT_GENERIC_ERROR
    finally:
        try:
            store.close()
        except Exception:  # noqa: BLE001
            pass

    if trusted_fp is None:
        eprint(f"no trusted fingerprint for {args.server}/{args.tool}")
        return EXIT_GENERIC_ERROR

    trusted = fingerprint_mod.load_tool_snapshot(snapshot_dir, args.server, trusted_fp.digest)
    if trusted is None:
        eprint(
            f"no snapshot for the trusted version of {args.server}/{args.tool} "
            f"({fingerprint_mod.short_digest(trusted_fp.digest)}…)"
        )
        return EXIT_GENERIC_ERROR

    current, current_digest = _latest_other_snapshot(
        snapshot_dir, args.server, args.tool, trusted_fp.digest
    )
    if current is None:
        eprint(f"no newer snapshot for {args.server}/{args.tool} — nothing to diff")
        return EXIT_GENERIC_ERROR

    diff = difflib.unified_diff(
        _snapshot_lines(trusted),
        _snapshot_lines(current),
        fromfile=f"{args.server}/{args.tool} trusted {fingerprint_mod.short_digest(trusted_fp.digest)}",
        tofile=f"{args.server}/{args.tool} current {fingerprint_mod.short_digest(current_digest or '')}",
        lineterm="",
    )
    for line in diff:
        # 控制字符先转义再打印，别让 diff 里的 ANSI 在自己终端上生效。
        print(static_mod.visible_escape(line))
    return EXIT_OK


def _latest_other_snapshot(
    snapshot_dir: Path, server: str, tool: str, trusted_digest: str
) -> tuple[JsonObj | None, str | None]:
    """在快照目录里找这个 tool 除「已信任版本」之外**最新**的一份快照。

    快照按 digest 命名，目录里混着同一个 server 所有 tool 的快照，所以要读进来
    按 ``name`` 过滤；按 mtime 取最新的那份。
    """
    directory = fingerprint_mod.snapshot_path_for(snapshot_dir, server, trusted_digest).parent
    if not directory.is_dir():
        return None, None
    trusted_name = fingerprint_mod.snapshot_path_for(
        snapshot_dir, server, trusted_digest
    ).name
    candidates: list[tuple[float, Path]] = []
    for path in directory.glob("*.json"):
        if path.name == trusted_name:
            continue
        try:
            candidates.append((path.stat().st_mtime, path))
        except OSError:
            continue
    for _mtime, path in sorted(candidates, reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and data.get("name") == tool:
            return data, path.stem
    return None, None


def _snapshot_lines(tool: JsonObj) -> list[str]:
    """把一份 tool 快照渲染成便于 diff 的多行文本（key 排序，缩进 2）。"""
    return json.dumps(tool, ensure_ascii=False, indent=2, sort_keys=True).splitlines()


def cmd_trust(args: argparse.Namespace) -> int:
    """``mcp-guarder trust <server> [tool]``（SPEC §7 M3）。

    删掉该 server（或指定 tool）的指纹记录，下一次 ``tools/list`` 重新走 TOFU 首见流程。
    打印删了几条。**这是一个显式的信任操作，要在 guard.log 里留痕。**
    """
    config = resolve_config(args.config)
    store = fingerprint_mod.FingerprintStore(config.inspect.fingerprint.store)
    try:
        store.open()
        deleted = store.delete(args.server, args.tool)
    finally:
        try:
            store.close()
        except Exception:  # noqa: BLE001
            pass

    target = f"{args.server}/{args.tool}" if args.tool else args.server
    log = audit_mod.GuardLog(config.audit.log_file, also_stderr=False)
    try:
        log.warn(f"TRUST accepted new fingerprint for {target} (deleted {deleted} row(s))")
    finally:
        log.close()
    print(f"deleted {deleted} fingerprint row(s) for {target}")
    return EXIT_OK


def cmd_audit_tail(args: argparse.Namespace) -> int:
    """``mcp-guarder audit tail [-n N] [-f] [--server NAME]``。默认 20 条。"""
    config = resolve_config(args.config)
    server = args.server or config.server.name
    paths = audit_mod.audit_files_for(config.audit, server)
    if not paths:
        eprint(f"no audit files for server={server}")
        return EXIT_GENERIC_ERROR
    try:
        for record in audit_mod.tail_records(paths, args.count, follow=args.follow):
            print(audit_mod.format_record(record, verbose=args.verbose))
    except KeyboardInterrupt:
        pass
    return EXIT_OK


def cmd_audit_grep(args: argparse.Namespace) -> int:
    """``mcp-guarder audit grep <pattern> [--server NAME]``。正则匹配整行原文。"""
    config = resolve_config(args.config)
    server = args.server or config.server.name
    paths = audit_mod.audit_files_for(config.audit, server)
    if not paths:
        eprint(f"no audit files for server={server}")
        return EXIT_GENERIC_ERROR
    found = False
    for record in audit_mod.grep_records(paths, args.pattern):
        found = True
        print(audit_mod.format_record(record, verbose=args.verbose))
    return EXIT_OK if found else EXIT_GENERIC_ERROR


def resolve_config(path: Path | str | None) -> GuarderConfig:
    """薄封装 :func:`~mcp_guarder.config.load_config`，让所有子命令共用同一套错误处理。

    子命令（diff / trust / audit）也需要配置 —— 指纹库路径、审计目录都在里面。
    """
    return config_mod.load_config(path)


def eprint(message: str) -> None:
    """往 stderr 打一行。代理模式下**唯一**允许的人类可读输出通道。"""
    print(message, file=sys.stderr, flush=True)


__all__ = [
    "USAGE",
    "main",
    "build_parser",
    "split_argv",
    "cmd_proxy",
    "cmd_diff",
    "cmd_trust",
    "cmd_audit_tail",
    "cmd_audit_grep",
    "resolve_config",
    "eprint",
]


if __name__ == "__main__":  # pragma: no cover - 方便 `python -m mcp_guarder.cli`
    sys.exit(main())
