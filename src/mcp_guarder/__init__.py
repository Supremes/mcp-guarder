"""mcp-guarder —— MCP 安全网关（stdio wrapper）。

包内模块分层（**严禁反向依赖**）：

    types.py / errors.py      纯数据与异常，谁都能 import，自己不 import 任何兄弟模块
    config.py                 配置解析 + 校验 + ${PROJECT_DIR} 展开（只依赖 types/errors）
    fingerprint.py            TOFU 指纹 + 快照 + canonical_json/digest 工具
    static_checks.py          静态投毒规则扫描
    redact.py                 双向脱敏
    policy.py                 权限门
    audit.py                  JSONL 审计 + guard.log
    proxy.py                  转发主干，import 上面所有模块
    cli.py                    命令行入口，import proxy 与各子模块

规格唯一真相来源是仓库根目录的 SPEC.md，所有实现必须逐条对齐。
"""

from mcp_guarder.types import GUARD_VERSION

__version__ = GUARD_VERSION

__all__ = ["__version__", "GUARD_VERSION"]
