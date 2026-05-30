import subprocess

import pytest

from linux_info_mcp import ssh as ssh_mod


def test_build_read_no_grep():
    cmd = ssh_mod.build_remote_cmd_read("/etc/hosts", None, None)
    assert cmd == "LC_ALL=C cat -- /etc/hosts"


def test_build_read_with_grep():
    cmd = ssh_mod.build_remote_cmd_read("/var/log/syslog", "error", ["-i", "-n"])
    assert cmd == "LC_ALL=C cat -- /var/log/syslog | grep -i -n -e error --"


def test_build_read_grep_pattern_starting_with_dash():
    cmd = ssh_mod.build_remote_cmd_read("/etc/hosts", "-rf", ["-F"])
    # pattern placed after -e so leading dash is not parsed as a flag
    assert "-e -rf --" in cmd
    assert cmd.endswith("--")


def test_build_read_grep_pattern_with_shell_metachars():
    cmd = ssh_mod.build_remote_cmd_read("/etc/hosts", "foo;rm -rf /", None)
    assert "-e 'foo;rm -rf /' --" in cmd


def test_build_read_quotes_path_with_spaces():
    cmd = ssh_mod.build_remote_cmd_read("/tmp/has space.txt", None, None)
    assert "'/tmp/has space.txt'" in cmd


def test_build_find_basic():
    cmd = ssh_mod.build_remote_cmd_find("/var/log", {})
    assert cmd == "LC_ALL=C find /var/log"


def test_build_find_predicates_order():
    preds = {
        "maxdepth": 3,
        "mindepth": 1,
        "type": "f",
        "name": "*.log",
        "iname": "*.LOG",
        "path_glob": "*/old/*",
        "mtime": "-7",
        "size": "+1k",
    }
    cmd = ssh_mod.build_remote_cmd_find("/var/log", preds)
    assert cmd == (
        "LC_ALL=C find /var/log -maxdepth 3 -mindepth 1 -type f "
        "-name '*.log' -iname '*.LOG' -path '*/old/*' -mtime -7 -size +1k"
    )


def test_build_binary():
    cmd = ssh_mod.build_remote_cmd_binary("/bin/ls", 100, 256)
    assert cmd == "LC_ALL=C dd if=/bin/ls ibs=1 skip=100 count=256 status=none | base64"


# run_ssh

class _FakeProc:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_run_ssh_argv_shape(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SSH_CMD", "ssh -F /tmp/cfg -o ConnectTimeout=5")
    monkeypatch.setenv("LINUX_INFO_TIMEOUT", "12")
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _FakeProc(stdout=b"hi", stderr=b"", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = ssh_mod.run_ssh("host1", "echo hi")
    assert captured["argv"] == [
        "ssh", "-F", "/tmp/cfg", "-o", "ConnectTimeout=5", "host1", "--", "echo hi",
    ]
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["timeout"] == 12.0
    assert res.stdout == b"hi"
    assert res.exit_code == 0
    assert res.truncated is False


def test_run_ssh_default_argv(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _FakeProc(stdout=b"", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    ssh_mod.run_ssh("h", "true")
    assert captured["argv"][0] == "ssh"
    assert captured["argv"][-3:] == ["h", "--", "true"]


def test_run_ssh_truncates(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_BYTES", "10")
    big = b"x" * 5000

    def fake_run(argv, **kwargs):
        return _FakeProc(stdout=big, returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = ssh_mod.run_ssh("h", "cat big")
    assert res.truncated is True
    assert len(res.stdout) == 10


def test_run_ssh_no_truncate_when_under(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_BYTES", "100")

    def fake_run(argv, **kwargs):
        return _FakeProc(stdout=b"abc", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = ssh_mod.run_ssh("h", "echo abc")
    assert res.truncated is False
    assert res.stdout == b"abc"


def test_run_ssh_propagates_exit_code(monkeypatch):
    def fake_run(argv, **kwargs):
        return _FakeProc(stdout=b"", stderr=b"nope", returncode=2)

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = ssh_mod.run_ssh("h", "false")
    assert res.exit_code == 2
    assert res.stderr == b"nope"


def test_run_ssh_timeout(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_BYTES", "1024")
    monkeypatch.setenv("LINUX_INFO_TIMEOUT", "1")

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=argv, timeout=1.0, output=b"partial", stderr=b"stuck"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = ssh_mod.run_ssh("h", "sleep 999")
    assert res.exit_code == 124
    assert res.stdout == b"partial"
    assert res.stderr.endswith(b"[timeout]")
    assert b"stuck" in res.stderr
    assert res.truncated is False


def test_run_ssh_timeout_truncates_stdout(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_BYTES", "5")

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=argv, timeout=1.0, output=b"x" * 100, stderr=b""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = ssh_mod.run_ssh("h", "sleep 999")
    assert res.exit_code == 124
    assert res.truncated is True
    assert len(res.stdout) == 5


def test_run_ssh_timeout_handles_none_streams(monkeypatch):
    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=1.0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = ssh_mod.run_ssh("h", "sleep 999")
    assert res.exit_code == 124
    assert res.stdout == b""
    assert res.stderr == b"\n[timeout]"


def test_run_ssh_caps_stderr(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_BYTES", "10")

    def fake_run(argv, **kwargs):
        return _FakeProc(stdout=b"", stderr=b"e" * 5000, returncode=1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = ssh_mod.run_ssh("h", "false")
    assert len(res.stderr) == 10


def test_run_ssh_records_duration(monkeypatch):
    def fake_run(argv, **kwargs):
        return _FakeProc(stdout=b"", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = ssh_mod.run_ssh("h", "true")
    assert res.duration_ms >= 0.0
    assert isinstance(res.duration_ms, float)


def test_run_ssh_records_duration_on_timeout(monkeypatch):
    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=1.0, output=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = ssh_mod.run_ssh("h", "sleep")
    assert res.duration_ms >= 0.0
    assert res.exit_code == 124


def test_run_ssh_logs_when_file_configured(monkeypatch, tmp_path):
    import json
    import logging

    from linux_info_mcp.log import reset_for_tests, setup_logging

    reset_for_tests()
    p = tmp_path / "ssh.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    monkeypatch.setenv("LINUX_INFO_LOG_LEVEL", "INFO")
    setup_logging()
    try:

        def fake_run(argv, **kwargs):
            return _FakeProc(stdout=b"hi", stderr=b"", returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)
        ssh_mod.run_ssh("examplehost", "echo hi")
        for h in logging.getLogger("linux_info_mcp").handlers:
            h.flush()
        entries = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
        ssh_calls = [e for e in entries if e["msg"] == "ssh_call"]
        assert len(ssh_calls) == 1
        e = ssh_calls[0]
        assert e["host"] == "examplehost"
        assert e["exit_code"] == 0
        assert e["outcome"] == "ok"
        assert e["stdout_bytes"] == 2
        assert "duration_ms" in e
        # INFO level: TRACE entries (ssh_call_io, ssh_call_start) must be absent
        assert not any(e["msg"] == "ssh_call_io" for e in entries)
    finally:
        reset_for_tests()


def test_run_ssh_logs_trace_io_when_trace_level(monkeypatch, tmp_path):
    import json
    import logging

    from linux_info_mcp.log import reset_for_tests, setup_logging

    reset_for_tests()
    p = tmp_path / "ssh.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(p))
    monkeypatch.setenv("LINUX_INFO_LOG_LEVEL", "TRACE")
    setup_logging()
    try:

        def fake_run(argv, **kwargs):
            return _FakeProc(stdout=b"payload", stderr=b"", returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)
        ssh_mod.run_ssh("h2", "echo payload")
        for h in logging.getLogger("linux_info_mcp").handlers:
            h.flush()
        entries = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
        msgs = {e["msg"] for e in entries}
        assert {"ssh_call_start", "ssh_call", "ssh_call_io"} <= msgs
        io = next(e for e in entries if e["msg"] == "ssh_call_io")
        assert io["stdout"] == "payload"
    finally:
        reset_for_tests()
