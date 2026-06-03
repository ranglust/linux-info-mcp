import pytest

from linux_info_mcp.ssh import SshResult
from linux_info_mcp.tools import files as server_mod

# ---------------------------------------------------------------------------
# ToolSpec.parser field (output_mode)
# ---------------------------------------------------------------------------


def test_toolspec_parser_defaults_none():
    from linux_info_mcp.tools import ToolSpec

    spec = ToolSpec("t", "", {"type": "object"}, lambda a: {})
    assert spec.parser is None


def test_toolspec_parser_settable():
    from linux_info_mcp.tools import ToolSpec

    def p(s):
        return [s]

    spec = ToolSpec("t", "", {"type": "object"}, lambda a: {}, parser=p)
    assert spec.parser is p


def test_df_free_specs_have_reference_parsers():
    from linux_info_mcp import server as srv
    from linux_info_mcp.tools._parsers import parse_df, parse_free

    assert srv._TOOLS["df"].parser is parse_df
    assert srv._TOOLS["free"].parser is parse_free
    # A perf tool without a parser stays None.
    assert srv._TOOLS["iostat"].parser is None


# ---------------------------------------------------------------------------
# apply_output_mode
# ---------------------------------------------------------------------------


def _res(**kw):
    base = {
        "stdout": "data",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    base.update(kw)
    return base


def test_apply_raw_drops_parsed_and_sets_no_status():
    from linux_info_mcp.server import apply_output_mode

    out = apply_output_mode(_res(parsed=[1, 2]), "raw", lambda s: [1])
    assert "parsed" not in out
    assert "parse_status" not in out
    assert out["stdout"] == "data"


def test_apply_parsed_ok_drops_stdout():
    from linux_info_mcp.server import apply_output_mode

    out = apply_output_mode(_res(), "parsed", lambda s: [{"a": 1}])
    assert out["parsed"] == [{"a": 1}]
    assert "stdout" not in out
    assert out["parse_status"] == "ok"


def test_apply_both_keeps_stdout_and_parsed():
    from linux_info_mcp.server import apply_output_mode

    out = apply_output_mode(_res(), "both", lambda s: [{"a": 1}])
    assert out["stdout"] == "data"
    assert out["parsed"] == [{"a": 1}]
    assert out["parse_status"] == "ok"


def test_apply_parser_none_unsupported_keeps_stdout():
    from linux_info_mcp.server import apply_output_mode

    out = apply_output_mode(_res(), "parsed", None)
    assert out["parse_status"] == "unsupported"
    assert out["stdout"] == "data"
    assert "parsed" not in out


def test_apply_parser_raises_error_status_keeps_stdout():
    from linux_info_mcp.server import apply_output_mode

    def boom(s):
        raise ValueError("bad")

    out = apply_output_mode(_res(), "parsed", boom)
    assert out["parse_status"].startswith("error:")
    assert "ValueError" in out["parse_status"]
    assert out["stdout"] == "data"
    assert "parsed" not in out


def test_apply_nonzero_skipped_keeps_stdout():
    from linux_info_mcp.server import apply_output_mode

    out = apply_output_mode(_res(exit_code=1), "parsed", lambda s: [1])
    assert out["parse_status"] == "skipped_nonzero"
    assert out["stdout"] == "data"
    assert "parsed" not in out


def test_apply_truncated_skipped_keeps_stdout_even_in_parsed():
    from linux_info_mcp.server import apply_output_mode

    out = apply_output_mode(_res(truncated=True), "parsed", lambda s: [1])
    assert out["parse_status"] == "skipped_truncated"
    assert out["stdout"] == "data"
    assert "parsed" not in out


def test_apply_stdout_not_str_unsupported():
    from linux_info_mcp.server import apply_output_mode

    out = apply_output_mode(_res(stdout=None), "parsed", lambda s: [1])
    assert out["parse_status"] == "unsupported"


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


# ---------------------------------------------------------------------------
# output_mode: _call_tool integration
# ---------------------------------------------------------------------------

_OM_SCHEMA = {
    "type": "object",
    "properties": {"host": {"type": "string"}},
    "required": ["host"],
}


def _om_tool():
    from linux_info_mcp.tools import ToolSpec

    def handler(args):
        return {
            "stdout": "X",
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
            "stderr_truncated": False,
        }

    return ToolSpec("pt", "", _OM_SCHEMA, handler, parser=lambda s: [{"v": s}])


def _call(name, args, monkeypatch):
    import asyncio
    import json

    from linux_info_mcp import server as srv

    monkeypatch.setattr(srv, "_TOOLS", {"pt": _om_tool()})
    return json.loads(asyncio.run(srv._call_tool(name, args))[0].text)


def test_call_tool_single_host_parsed(monkeypatch):
    monkeypatch.delenv("LINUX_INFO_OUTPUT_MODE", raising=False)
    body = _call("pt", {"host": "h1", "output_mode": "parsed"}, monkeypatch)
    assert body["parsed"] == [{"v": "X"}]
    assert "stdout" not in body
    assert body["parse_status"] == "ok"


def test_call_tool_single_host_raw_default(monkeypatch):
    monkeypatch.delenv("LINUX_INFO_OUTPUT_MODE", raising=False)
    body = _call("pt", {"host": "h1"}, monkeypatch)
    assert body["stdout"] == "X"
    assert "parsed" not in body
    assert "parse_status" not in body


def test_call_tool_single_host_both(monkeypatch):
    monkeypatch.delenv("LINUX_INFO_OUTPUT_MODE", raising=False)
    body = _call("pt", {"host": "h1", "output_mode": "both"}, monkeypatch)
    assert body["stdout"] == "X"
    assert body["parsed"] == [{"v": "X"}]
    assert body["parse_status"] == "ok"


def test_call_tool_multi_host_parsed_per_host(monkeypatch):
    monkeypatch.delenv("LINUX_INFO_OUTPUT_MODE", raising=False)
    body = _call("pt", {"hosts": ["h1", "h2"], "output_mode": "parsed"}, monkeypatch)
    assert body["multi_host"] is True
    for r in body["results"]:
        assert r["parse_status"] == "ok"
        assert r["parsed"] == [{"v": "X"}]
        assert "stdout" not in r


def test_call_tool_env_overrides_arg(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_OUTPUT_MODE", "parsed")
    body = _call("pt", {"host": "h1", "output_mode": "raw"}, monkeypatch)
    assert body["parsed"] == [{"v": "X"}]
    assert "stdout" not in body


def test_call_tool_invalid_output_mode_arg_is_validation_error(monkeypatch):
    monkeypatch.delenv("LINUX_INFO_OUTPUT_MODE", raising=False)
    body = _call("pt", {"host": "h1", "output_mode": "yourmoma"}, monkeypatch)
    assert "error" in body
    assert "parsed" not in body


def test_call_tool_invalid_output_mode_env_is_validation_error(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_OUTPUT_MODE", "yourmoma")
    body = _call("pt", {"host": "h1"}, monkeypatch)
    assert "error" in body


def test_call_tool_logs_output_mode_and_parse_status(monkeypatch, tmp_path):
    import asyncio
    import json
    import logging

    from linux_info_mcp import server as srv
    from linux_info_mcp.log import reset_for_tests, setup_logging

    reset_for_tests()
    p = tmp_path / "srv.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    monkeypatch.setenv("LINUX_INFO_LOG_LEVEL", "INFO")
    monkeypatch.delenv("LINUX_INFO_OUTPUT_MODE", raising=False)
    setup_logging()
    try:
        monkeypatch.setattr(srv, "_TOOLS", {"pt": _om_tool()})
        asyncio.run(srv._call_tool("pt", {"host": "h1", "output_mode": "parsed"}))
        for h in logging.getLogger("linux_info_mcp").handlers:
            h.flush()
        entries = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
        tc = next(e for e in entries if e["msg"] == "tool_call")
        assert tc["output_mode"] == "parsed"
        assert tc["parse_status"] == "ok"
    finally:
        reset_for_tests()


# ---------------------------------------------------------------------------
# multi-host fan-out
# ---------------------------------------------------------------------------

_MH_SCHEMA = {
    "type": "object",
    "properties": {"host": {"type": "string"}},
    "required": ["host"],
}


def _echo_handler(args):
    return {
        "stdout": args["host"],
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }


def test_multi_host_fanout_returns_per_host_results(monkeypatch):
    import asyncio
    import json

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    monkeypatch.setattr(srv, "_TOOLS", {"echo": ToolSpec("echo", "", _MH_SCHEMA, _echo_handler)})
    result = asyncio.run(srv._call_tool("echo", {"hosts": ["h1", "h2", "h3"]}))
    body = json.loads(result[0].text)
    assert body["multi_host"] is True
    assert body["host_count"] == 3
    assert [r["host"] for r in body["results"]] == ["h1", "h2", "h3"]
    assert [r["stdout"] for r in body["results"]] == ["h1", "h2", "h3"]


def test_multi_host_single_element_still_multi_shape(monkeypatch):
    import asyncio
    import json

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    monkeypatch.setattr(srv, "_TOOLS", {"echo": ToolSpec("echo", "", _MH_SCHEMA, _echo_handler)})
    result = asyncio.run(srv._call_tool("echo", {"hosts": ["only"]}))
    body = json.loads(result[0].text)
    assert body["multi_host"] is True
    assert body["host_count"] == 1
    assert body["results"][0]["host"] == "only"


def test_single_host_shape_unchanged(monkeypatch):
    import asyncio
    import json

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    monkeypatch.setattr(srv, "_TOOLS", {"echo": ToolSpec("echo", "", _MH_SCHEMA, _echo_handler)})
    result = asyncio.run(srv._call_tool("echo", {"host": "h1"}))
    body = json.loads(result[0].text)
    assert "multi_host" not in body
    assert body["stdout"] == "h1"
    assert body["exit_code"] == 0


def test_multi_host_per_host_error_isolated(monkeypatch):
    import asyncio
    import json

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    def handler(args):
        if args["host"] == "bad":
            raise RuntimeError("boom")
        return {
            "stdout": "ok",
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
            "stderr_truncated": False,
        }

    monkeypatch.setattr(srv, "_TOOLS", {"t": ToolSpec("t", "", _MH_SCHEMA, handler)})
    result = asyncio.run(srv._call_tool("t", {"hosts": ["good", "bad"]}))
    body = json.loads(result[0].text)
    by_host = {r["host"]: r for r in body["results"]}
    assert by_host["good"]["stdout"] == "ok"
    assert "boom" in by_host["bad"]["error"]
    assert by_host["bad"]["outcome"] == "handler_error"


def test_multi_host_per_host_validation_error_isolated(monkeypatch):
    import asyncio
    import json

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    def handler(args):
        if args["host"] == "h2":
            raise ValueError("nope")
        return {
            "stdout": "ok",
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
            "stderr_truncated": False,
        }

    monkeypatch.setattr(srv, "_TOOLS", {"t": ToolSpec("t", "", _MH_SCHEMA, handler)})
    result = asyncio.run(srv._call_tool("t", {"hosts": ["h1", "h2"]}))
    body = json.loads(result[0].text)
    by_host = {r["host"]: r for r in body["results"]}
    assert by_host["h2"]["outcome"] == "validation_error"
    assert "nope" in by_host["h2"]["error"]


def test_multi_host_rejects_over_limit(monkeypatch):
    import asyncio
    import json

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    monkeypatch.setenv("LINUX_INFO_MAX_HOSTS", "2")
    monkeypatch.setattr(srv, "_TOOLS", {"echo": ToolSpec("echo", "", _MH_SCHEMA, _echo_handler)})
    result = asyncio.run(srv._call_tool("echo", {"hosts": ["h1", "h2", "h3"]}))
    body = json.loads(result[0].text)
    assert "error" in body
    assert "exceeds limit" in body["error"]


def test_multi_host_rejects_both_host_and_hosts(monkeypatch):
    import asyncio
    import json

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    monkeypatch.setattr(srv, "_TOOLS", {"echo": ToolSpec("echo", "", _MH_SCHEMA, _echo_handler)})
    result = asyncio.run(srv._call_tool("echo", {"host": "h1", "hosts": ["h2"]}))
    body = json.loads(result[0].text)
    assert "error" in body


def test_multi_host_runs_in_parallel(monkeypatch):
    import asyncio
    import time

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    def slow(args):
        time.sleep(0.2)
        return {
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
            "stderr_truncated": False,
        }

    monkeypatch.setattr(srv, "_TOOLS", {"slow": ToolSpec("slow", "", _MH_SCHEMA, slow)})
    t0 = time.perf_counter()
    asyncio.run(srv._call_tool("slow", {"hosts": ["a", "b", "c", "d"]}))
    elapsed = time.perf_counter() - t0
    # Serial would be 4 * 0.2 = 0.8s. With default 4 workers, < 0.5s.
    assert elapsed < 0.5, f"expected parallel fan-out, got {elapsed:.3f}s"


def test_multi_host_respects_parallelism_env(monkeypatch):
    import asyncio
    import time

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    monkeypatch.setenv("LINUX_INFO_PARALLELISM", "1")

    def slow(args):
        time.sleep(0.1)
        return {
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
            "stderr_truncated": False,
        }

    monkeypatch.setattr(srv, "_TOOLS", {"slow": ToolSpec("slow", "", _MH_SCHEMA, slow)})
    t0 = time.perf_counter()
    asyncio.run(srv._call_tool("slow", {"hosts": ["a", "b", "c"]}))
    elapsed = time.perf_counter() - t0
    # 1 worker => serial: 3 * 0.1 = 0.3s.
    assert elapsed >= 0.3, f"expected serial with parallelism=1, got {elapsed:.3f}s"


def test_multi_host_context_propagates_to_workers(monkeypatch):
    import asyncio
    import json

    from linux_info_mcp import server as srv
    from linux_info_mcp.log import get_call_ctx
    from linux_info_mcp.tools import ToolSpec

    def handler(args):
        ctx = get_call_ctx()
        return {
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
            "stderr_truncated": False,
            "ctx_tool": ctx.get("tool"),
            "ctx_rid": ctx.get("request_id"),
        }

    monkeypatch.setattr(srv, "_TOOLS", {"ctxt": ToolSpec("ctxt", "", _MH_SCHEMA, handler)})
    result = asyncio.run(srv._call_tool("ctxt", {"hosts": ["h1", "h2"]}))
    body = json.loads(result[0].text)
    rids = {r["ctx_rid"] for r in body["results"]}
    tools = {r["ctx_tool"] for r in body["results"]}
    assert tools == {"ctxt"}
    assert len(rids) == 1 and None not in rids


def test_multi_host_partial_outcome_logged(monkeypatch, tmp_path):
    import asyncio
    import json
    import logging

    from linux_info_mcp import server as srv
    from linux_info_mcp.log import reset_for_tests, setup_logging
    from linux_info_mcp.tools import ToolSpec

    reset_for_tests()
    p = tmp_path / "srv.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    monkeypatch.setenv("LINUX_INFO_LOG_LEVEL", "INFO")
    setup_logging()
    try:

        def handler(args):
            ec = 1 if args["host"] == "h2" else 0
            return {
                "stdout": "",
                "stderr": "",
                "exit_code": ec,
                "truncated": False,
                "stderr_truncated": False,
            }

        monkeypatch.setattr(srv, "_TOOLS", {"t": ToolSpec("t", "", _MH_SCHEMA, handler)})
        asyncio.run(srv._call_tool("t", {"hosts": ["h1", "h2"]}))
        for h in logging.getLogger("linux_info_mcp").handlers:
            h.flush()
        entries = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
        tc = next(e for e in entries if e["msg"] == "tool_call")
        assert tc["outcome"] == "partial"
        assert tc["host_count"] == 2
        assert tc["host"] is None
    finally:
        reset_for_tests()


def test_list_tools_advertises_hosts_and_relaxes_host(monkeypatch):
    import asyncio

    from linux_info_mcp import server as srv

    tools = asyncio.run(srv._list_tools())
    by_name = {t.name: t for t in tools}
    rf = by_name["read_file"]
    assert "hosts" in rf.inputSchema["properties"]
    assert rf.inputSchema["properties"]["hosts"]["type"] == ["array", "null"]
    assert "host" not in rf.inputSchema.get("required", [])
    # original ToolSpec schema untouched
    assert "host" in srv._TOOLS["read_file"].input_schema["required"]


def test_list_tools_advertises_output_mode(monkeypatch):
    import asyncio

    from linux_info_mcp import server as srv

    tools = asyncio.run(srv._list_tools())
    rf = {t.name: t for t in tools}["read_file"]
    om = rf.inputSchema["properties"]["output_mode"]
    assert set(om["enum"]) == {"raw", "parsed", "both", None}
    # original ToolSpec schema untouched
    assert "output_mode" not in srv._TOOLS["read_file"].input_schema["properties"]


def test_list_tools_description_mentions_multi_host():
    import asyncio

    from linux_info_mcp import server as srv

    tools = asyncio.run(srv._list_tools())
    for t in tools:
        assert "`hosts`" in t.description, f"{t.name} description omits multi-host"
    # original ToolSpec description untouched
    assert "`hosts`" not in srv._TOOLS["read_file"].description


# ---------------------------------------------------------------------------
# privilege-error detection
# ---------------------------------------------------------------------------

_PRIV_SCHEMA = {
    "type": "object",
    "properties": {"host": {"type": "string"}},
    "required": ["host"],
}


def _priv_tool(stderr: str, exit_code: int = 1):
    def handler(args):
        return {
            "stdout": "",
            "stderr": stderr,
            "exit_code": exit_code,
            "truncated": False,
            "stderr_truncated": False,
        }

    return handler


@pytest.mark.parametrize(
    "stderr",
    [
        "smartctl: Permission denied",
        "dmidecode: Operation not permitted",
        "you must be root to run this",
        "must be superuser",
        "Are you root?",
        "this requires CAP_NET_ADMIN",
        "Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock",
    ],
)
def test_privilege_error_flagged_single(monkeypatch, stderr):
    import asyncio
    import json

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    monkeypatch.setattr(srv, "_TOOLS", {"t": ToolSpec("t", "", _PRIV_SCHEMA, _priv_tool(stderr))})
    body = json.loads(asyncio.run(srv._call_tool("t", {"host": "h1"}))[0].text)
    assert body.get("privilege_error") is True


def test_privilege_error_absent_on_other_failure(monkeypatch):
    import asyncio
    import json

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    h = _priv_tool("no such file or directory", exit_code=1)
    monkeypatch.setattr(srv, "_TOOLS", {"t": ToolSpec("t", "", _PRIV_SCHEMA, h)})
    body = json.loads(asyncio.run(srv._call_tool("t", {"host": "h1"}))[0].text)
    assert "privilege_error" not in body


def test_privilege_error_absent_on_success(monkeypatch):
    import asyncio
    import json

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    # exit 0 but stderr mentions permission — must NOT flag (no failure).
    h = _priv_tool("permission denied", exit_code=0)
    monkeypatch.setattr(srv, "_TOOLS", {"t": ToolSpec("t", "", _PRIV_SCHEMA, h)})
    body = json.loads(asyncio.run(srv._call_tool("t", {"host": "h1"}))[0].text)
    assert "privilege_error" not in body


def test_privilege_error_flagged_multi_host_per_host(monkeypatch):
    import asyncio
    import json

    from linux_info_mcp import server as srv
    from linux_info_mcp.tools import ToolSpec

    def handler(args):
        if args["host"] == "denied":
            return {
                "stdout": "",
                "stderr": "Permission denied",
                "exit_code": 1,
                "truncated": False,
                "stderr_truncated": False,
            }
        return {
            "stdout": "ok",
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
            "stderr_truncated": False,
        }

    monkeypatch.setattr(srv, "_TOOLS", {"t": ToolSpec("t", "", _PRIV_SCHEMA, handler)})
    body = json.loads(asyncio.run(srv._call_tool("t", {"hosts": ["ok", "denied"]}))[0].text)
    by_host = {r["host"]: r for r in body["results"]}
    assert by_host["denied"].get("privilege_error") is True
    assert "privilege_error" not in by_host["ok"]
