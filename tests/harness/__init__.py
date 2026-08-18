"""端到端测试用的小工具包（SPEC §7 M1 验收）。

:mod:`tests.harness.replay` 是透明性对拍工具：往被测进程打一串固定的
``initialize`` / ``tools/list`` / ``tools/call``，收集 stdout 的每一行，
再拿「裸跑 server」和「挂网关」两次的结果做**字节级**比较。
"""
