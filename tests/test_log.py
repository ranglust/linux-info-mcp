import json
import logging

import pytest

from linux_info_mcp.log import TRACE, get_logger, reset_for_tests, setup_logging


@pytest.fixture(autouse=True)
def _reset():
    reset_for_tests()
    yield
    reset_for_tests()


def _read_lines(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_disabled_when_env_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("LINUX_INFO_LOG_FILE", raising=False)
    setup_logging()
    log = get_logger("test")
    log.info("nothing", extra={"x": 1})
    assert not list(tmp_path.iterdir())
    assert logging.getLogger("linux_info_mcp").handlers == []


def test_disabled_when_env_blank(monkeypatch, tmp_path):
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", "   ")
    setup_logging()
    assert logging.getLogger("linux_info_mcp").handlers == []


def test_writes_json_when_enabled(monkeypatch, tmp_path):
    p = tmp_path / "log.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    monkeypatch.setenv("LINUX_INFO_LOG_LEVEL", "INFO")
    setup_logging()
    log = get_logger("test")
    log.info("hello", extra={"host": "h1", "duration_ms": 12.5})
    for h in logging.getLogger("linux_info_mcp").handlers:
        h.flush()
    entries = _read_lines(p)
    assert len(entries) == 1
    e = entries[0]
    assert e["level"] == "INFO"
    assert e["msg"] == "hello"
    assert e["host"] == "h1"
    assert e["duration_ms"] == 12.5
    assert e["logger"] == "linux_info_mcp.test"
    assert "ts" in e


def test_creates_missing_parent_dirs(monkeypatch, tmp_path):
    p = tmp_path / "a" / "b" / "c" / "log.jsonl"
    assert not p.parent.exists()
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    setup_logging()
    log = get_logger("test")
    log.info("hi")
    for h in logging.getLogger("linux_info_mcp").handlers:
        h.flush()
    assert p.exists()
    assert p.parent.is_dir()


def test_trace_level_filters(monkeypatch, tmp_path):
    p = tmp_path / "log.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    monkeypatch.setenv("LINUX_INFO_LOG_LEVEL", "INFO")
    setup_logging()
    log = get_logger("test")
    log.trace("trace_only", extra={"k": 1})  # type: ignore[attr-defined]
    log.info("info_msg")
    for h in logging.getLogger("linux_info_mcp").handlers:
        h.flush()
    msgs = [e["msg"] for e in _read_lines(p)]
    assert "info_msg" in msgs
    assert "trace_only" not in msgs


def test_trace_level_emits_when_set(monkeypatch, tmp_path):
    p = tmp_path / "log.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    monkeypatch.setenv("LINUX_INFO_LOG_LEVEL", "TRACE")
    setup_logging()
    log = get_logger("test")
    log.trace("trace_only", extra={"k": 1})  # type: ignore[attr-defined]
    for h in logging.getLogger("linux_info_mcp").handlers:
        h.flush()
    entries = _read_lines(p)
    assert any(e["msg"] == "trace_only" and e["level"] == "TRACE" and e["k"] == 1 for e in entries)


def test_setup_idempotent(monkeypatch, tmp_path):
    p = tmp_path / "log.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    setup_logging()
    setup_logging()
    handlers = logging.getLogger("linux_info_mcp").handlers
    assert len(handlers) == 1


def test_unknown_level_falls_back_to_info(monkeypatch, tmp_path):
    p = tmp_path / "log.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    monkeypatch.setenv("LINUX_INFO_LOG_LEVEL", "NOPE")
    setup_logging()
    assert logging.getLogger("linux_info_mcp").level == logging.INFO


def test_trace_level_constant():
    assert TRACE == 5
    assert TRACE < logging.DEBUG


def test_call_ctx_filter_injects_tool_and_request_id(monkeypatch, tmp_path):
    from linux_info_mcp.log import reset_call_ctx, set_call_ctx

    p = tmp_path / "log.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    setup_logging()
    log = get_logger("test")
    rid, token = set_call_ctx("read_file")
    try:
        log.info("event_a", extra={"host": "h1"})
    finally:
        reset_call_ctx(token)
    log.info("event_b_no_ctx", extra={"host": "h2"})
    for h in logging.getLogger("linux_info_mcp").handlers:
        h.flush()
    entries = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    a = next(e for e in entries if e["msg"] == "event_a")
    b = next(e for e in entries if e["msg"] == "event_b_no_ctx")
    assert a["tool"] == "read_file"
    assert a["request_id"] == rid
    assert "tool" not in b
    assert "request_id" not in b


def test_pid_field_always_emitted(monkeypatch, tmp_path):
    import os

    p = tmp_path / "log.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    setup_logging()
    log = get_logger("test")
    log.info("event_no_ctx")
    from linux_info_mcp.log import reset_call_ctx, set_call_ctx

    _, token = set_call_ctx("read_file")
    try:
        log.info("event_with_ctx")
    finally:
        reset_call_ctx(token)
    for h in logging.getLogger("linux_info_mcp").handlers:
        h.flush()
    entries = _read_lines(p)
    expected_pid = os.getpid()
    assert all(e["pid"] == expected_pid for e in entries)


def test_call_ctx_isolated_between_calls(monkeypatch, tmp_path):
    from linux_info_mcp.log import reset_call_ctx, set_call_ctx

    p = tmp_path / "log.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    setup_logging()
    log = get_logger("test")
    rid1, t1 = set_call_ctx("a")
    log.info("first")
    reset_call_ctx(t1)
    rid2, t2 = set_call_ctx("b")
    log.info("second")
    reset_call_ctx(t2)
    for h in logging.getLogger("linux_info_mcp").handlers:
        h.flush()
    entries = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    first = next(e for e in entries if e["msg"] == "first")
    second = next(e for e in entries if e["msg"] == "second")
    assert first["tool"] == "a" and first["request_id"] == rid1
    assert second["tool"] == "b" and second["request_id"] == rid2
    assert rid1 != rid2


def test_exception_serialized(monkeypatch, tmp_path):
    p = tmp_path / "log.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    setup_logging()
    log = get_logger("test")
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        log.exception("oops")
    for h in logging.getLogger("linux_info_mcp").handlers:
        h.flush()
    entries = _read_lines(p)
    assert any("boom" in e.get("exc", "") for e in entries)
