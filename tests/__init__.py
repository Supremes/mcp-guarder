"""mcp-guarder 测试包。

约定：
- 单测直接打模块里的纯函数（``policy.evaluate``、``redact.redact_text`` …），
  不要什么都拉起真进程。
- 端到端用例（stdout 洁净、透明性对拍、进程树清理）放 ``tests/test_proxy.py``，
  假 server 脚本由用例自己现写到 ``tmp_path``，别依赖网络或真的 MCP server。
- SPEC §7 M1-1 的透明性对拍工具在 ``tests/harness/replay.py``。
"""
