from linux_info_mcp.ssh import SshResult
from linux_info_mcp.tools import files as server_mod


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(server_mod, "run_ssh", fake)
    return captured


def test_server_tool_call_logging(monkeypatch, tmp_path):
    import asyncio
    import json
    import logging

    from linux_info_mcp import server as srv
    from linux_info_mcp.log import reset_for_tests, setup_logging

    reset_for_tests()
    p = tmp_path / "srv.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    monkeypatch.setenv("LINUX_INFO_LOG_LEVEL", "INFO")
    setup_logging()
    try:
        _stub(
            monkeypatch,
            SshResult(stdout=b"ok", stderr=b"", exit_code=0, truncated=False),
        )
        result = asyncio.run(srv._call_tool("read_file", {"host": "h1", "path": "/etc/hosts"}))
        assert result and result[0].type == "text"
        for h in logging.getLogger("linux_info_mcp").handlers:
            h.flush()
        entries = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
        tc = [e for e in entries if e["msg"] == "tool_call"]
        assert len(tc) == 1
        assert tc[0]["tool"] == "read_file"
        assert tc[0]["host"] == "h1"
        assert tc[0]["outcome"] == "ok"
        assert tc[0]["exit_code"] == 0
        assert "duration_ms" in tc[0]
        # No TRACE entries at INFO level
        assert not any(e["msg"] == "tool_call_in" for e in entries)
    finally:
        reset_for_tests()


def test_server_validation_error_logged(monkeypatch, tmp_path):
    import asyncio
    import json
    import logging

    from linux_info_mcp import server as srv
    from linux_info_mcp.log import reset_for_tests, setup_logging

    reset_for_tests()
    p = tmp_path / "srv.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    monkeypatch.setenv("LINUX_INFO_LOG_LEVEL", "INFO")
    setup_logging()
    try:
        result = asyncio.run(
            srv._call_tool("read_file", {"host": "-oProxyCommand=evil", "path": "/x"})
        )
        body = json.loads(result[0].text)
        assert "error" in body
        for h in logging.getLogger("linux_info_mcp").handlers:
            h.flush()
        entries = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
        tc = [e for e in entries if e["msg"] == "tool_call"]
        assert len(tc) == 1
        assert tc[0]["outcome"] == "validation_error"
        assert "error" in tc[0]
    finally:
        reset_for_tests()


def test_server_ssh_call_carries_tool_and_request_id(monkeypatch, tmp_path):
    import asyncio
    import json
    import logging
    import subprocess

    from linux_info_mcp import server as srv
    from linux_info_mcp.log import reset_for_tests, setup_logging

    reset_for_tests()
    p = tmp_path / "srv.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    monkeypatch.setenv("LINUX_INFO_LOG_LEVEL", "INFO")
    setup_logging()

    class FakeProc:
        stdout = b"ok"
        stderr = b""
        returncode = 0

    def fake_run(argv, **kw):
        return FakeProc()

    try:
        monkeypatch.setattr(subprocess, "run", fake_run)
        asyncio.run(srv._call_tool("read_file", {"host": "h1", "path": "/etc/hosts"}))
        for h in logging.getLogger("linux_info_mcp").handlers:
            h.flush()
        entries = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
        ssh = next(e for e in entries if e["msg"] == "ssh_call")
        tool = next(e for e in entries if e["msg"] == "tool_call")
        assert ssh["tool"] == "read_file"
        assert tool["tool"] == "read_file"
        assert ssh["request_id"] == tool["request_id"]
        assert len(ssh["request_id"]) == 12
    finally:
        reset_for_tests()


def test_call_tool_runs_concurrently(monkeypatch):
    import asyncio
    import time

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    sleep_s = 0.2
    schema = {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]}

    def slow_handler(args):
        time.sleep(sleep_s)
        return {
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
            "stderr_truncated": False,
        }

    fake_tools = {
        "slow_a": ToolSpec("slow_a", "", schema, slow_handler),
        "slow_b": ToolSpec("slow_b", "", schema, slow_handler),
        "slow_c": ToolSpec("slow_c", "", schema, slow_handler),
    }
    monkeypatch.setattr(srv, "_TOOLS", fake_tools)

    async def race():
        return await asyncio.gather(
            srv._call_tool("slow_a", {"host": "h1"}),
            srv._call_tool("slow_b", {"host": "h1"}),
            srv._call_tool("slow_c", {"host": "h1"}),
        )

    t0 = time.perf_counter()
    asyncio.run(race())
    elapsed = time.perf_counter() - t0
    # Serial would be 3 * 0.2 = 0.6s. Parallel via asyncio.to_thread should be < 0.4s.
    assert elapsed < 0.4, f"expected concurrent dispatch, got serial-like wall time: {elapsed:.3f}s"


def test_call_tool_request_id_isolated_under_concurrency(monkeypatch, tmp_path):
    import asyncio
    import json
    import logging
    import time

    from linux_info_mcp import server as srv
    from linux_info_mcp.log import reset_for_tests, setup_logging
    from linux_info_mcp.tools import ToolSpec

    reset_for_tests()
    p = tmp_path / "srv.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    monkeypatch.setenv("LINUX_INFO_LOG_LEVEL", "INFO")
    setup_logging()
    try:
        schema = {
            "type": "object",
            "properties": {"host": {"type": "string"}},
            "required": ["host"],
        }

        def slow_handler(args):
            time.sleep(0.05)
            return {
                "stdout": "",
                "stderr": "",
                "exit_code": 0,
                "truncated": False,
                "stderr_truncated": False,
            }

        fake_tools = {
            f"slow_{i}": ToolSpec(f"slow_{i}", "", schema, slow_handler) for i in range(5)
        }
        monkeypatch.setattr(srv, "_TOOLS", fake_tools)

        async def race():
            return await asyncio.gather(
                *(srv._call_tool(f"slow_{i}", {"host": "h1"}) for i in range(5))
            )

        asyncio.run(race())
        for h in logging.getLogger("linux_info_mcp").handlers:
            h.flush()
        entries = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
        tcs = [e for e in entries if e["msg"] == "tool_call"]
        assert len(tcs) == 5
        rids = [e["request_id"] for e in tcs]
        tools = [e["tool"] for e in tcs]
        assert len(set(rids)) == 5
        assert sorted(tools) == [f"slow_{i}" for i in range(5)]
        for e in tcs:
            expected_tool = e["tool"]
            assert e["request_id"] in rids
            same_rid = [x for x in entries if x.get("request_id") == e["request_id"]]
            assert all(x.get("tool") == expected_tool for x in same_rid)
    finally:
        reset_for_tests()
