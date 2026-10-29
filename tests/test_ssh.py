import contextlib
import io
import subprocess

from linux_info_mcp import ssh as ssh_mod


def test_build_read_no_grep():
    cmd = ssh_mod.build_remote_cmd_read("/etc/hosts", None, None)
    assert cmd == "LC_ALL=C cat -- /etc/hosts"


def test_build_read_with_grep():
    cmd = ssh_mod.build_remote_cmd_read("/var/log/syslog", "error", ["-i", "-n"])
    assert cmd == "LC_ALL=C cat -- /var/log/syslog | grep -i -n -e error -- || [ $? -eq 1 ]"


def test_build_read_grep_pattern_starting_with_dash():
    cmd = ssh_mod.build_remote_cmd_read("/etc/hosts", "-rf", ["-F"])
    assert "-e -rf --" in cmd
    assert cmd.endswith("-- || [ $? -eq 1 ]")


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
    assert cmd == "LC_ALL=C dd if=/bin/ls ibs=1 skip=100 count=256 status=none | base64 -w 0"


# run_ssh — mocks subprocess.Popen


class _FakePopen:
    def __init__(self, stdout=b"", stderr=b"", returncode=0, raise_timeout=False):
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self._returncode = returncode
        self._raise_timeout = raise_timeout
        self.returncode = returncode if not raise_timeout else -9
        self._killed = False
        self._waited = False

    def wait(self, timeout=None):
        if self._raise_timeout and not self._waited:
            self._waited = True
            raise subprocess.TimeoutExpired(cmd="x", timeout=timeout or 1.0)
        self._waited = True
        return self.returncode

    def kill(self):
        self._killed = True


def _patch_popen(monkeypatch, captured: dict | None = None, **proc_kwargs):
    def fake_popen(argv, **kwargs):
        if captured is not None:
            captured["argv"] = argv
            captured["kwargs"] = kwargs
        return _FakePopen(**proc_kwargs)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)


# _ssh_argv — connection-mux default


def test_ssh_argv_default_has_mux(monkeypatch):
    monkeypatch.delenv("LINUX_INFO_SSH_CMD", raising=False)
    monkeypatch.delenv("LINUX_INFO_SSH_MUX", raising=False)
    argv = ssh_mod._ssh_argv()
    assert argv[0] == "ssh"
    assert "ControlMaster=auto" in argv
    assert "ControlPersist=60s" in argv
    assert any(a.startswith("ControlPath=") for a in argv)


def test_ssh_argv_controlpath_uses_hash_token_in_tmpdir(monkeypatch):
    import tempfile

    monkeypatch.delenv("LINUX_INFO_SSH_CMD", raising=False)
    monkeypatch.delenv("LINUX_INFO_SSH_MUX", raising=False)
    argv = ssh_mod._ssh_argv()
    ctl = next(a for a in argv if a.startswith("ControlPath="))
    path = ctl.split("=", 1)[1]
    assert "lim-%C" in path
    assert path.startswith(tempfile.gettempdir())


def test_ssh_argv_custom_cmd_wins_no_mux(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SSH_CMD", "ssh -F /home/me/.ssh/config")
    argv = ssh_mod._ssh_argv()
    assert argv == ["ssh", "-F", "/home/me/.ssh/config"]
    assert not any("ControlMaster" in a for a in argv)


def test_ssh_argv_mux_disabled(monkeypatch):
    monkeypatch.delenv("LINUX_INFO_SSH_CMD", raising=False)
    for off in ("0", "false", "no", "off", "OFF"):
        monkeypatch.setenv("LINUX_INFO_SSH_MUX", off)
        assert ssh_mod._ssh_argv() == ["ssh"]


def test_run_ssh_argv_shape(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SSH_CMD", "ssh -F /tmp/cfg -o ConnectTimeout=5")
    monkeypatch.setenv("LINUX_INFO_TIMEOUT", "12")
    captured: dict = {}
    _patch_popen(monkeypatch, captured, stdout=b"hi", returncode=0)
    res = ssh_mod.run_ssh("host1", "echo hi")
    assert captured["argv"] == [
        "ssh",
        "-F",
        "/tmp/cfg",
        "-o",
        "ConnectTimeout=5",
        "host1",
        "--",
        "echo hi",
    ]
    assert captured["kwargs"]["shell"] is False
    assert res.stdout == b"hi"
    assert res.exit_code == 0
    assert res.truncated is False


def test_run_ssh_default_argv(monkeypatch):
    captured: dict = {}
    _patch_popen(monkeypatch, captured, stdout=b"", returncode=0)
    ssh_mod.run_ssh("h", "true")
    assert captured["argv"][0] == "ssh"
    assert captured["argv"][-3:] == ["h", "--", "true"]


def test_run_ssh_truncates(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_BYTES", "10")
    big = b"x" * 5000
    _patch_popen(monkeypatch, stdout=big, returncode=0)
    res = ssh_mod.run_ssh("h", "cat big")
    assert res.truncated is True
    assert len(res.stdout) == 10


def test_run_ssh_no_truncate_when_exact_cap(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_BYTES", "10")
    exact = b"x" * 10
    _patch_popen(monkeypatch, stdout=exact, returncode=0)
    res = ssh_mod.run_ssh("h", "cat ten")
    assert res.truncated is False
    assert len(res.stdout) == 10


def test_run_ssh_no_truncate_when_under(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_BYTES", "100")
    _patch_popen(monkeypatch, stdout=b"abc", returncode=0)
    res = ssh_mod.run_ssh("h", "echo abc")
    assert res.truncated is False
    assert res.stdout == b"abc"


def test_run_ssh_propagates_exit_code(monkeypatch):
    _patch_popen(monkeypatch, stdout=b"", stderr=b"nope", returncode=2)
    res = ssh_mod.run_ssh("h", "false")
    assert res.exit_code == 2
    assert res.stderr == b"nope"


def test_run_ssh_timeout(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_BYTES", "1024")
    monkeypatch.setenv("LINUX_INFO_TIMEOUT", "1")
    _patch_popen(monkeypatch, stdout=b"partial", stderr=b"stuck", raise_timeout=True)
    res = ssh_mod.run_ssh("h", "sleep 999")
    assert res.exit_code == 124
    assert res.stdout == b"partial"
    assert res.stderr.endswith(b"[timeout]")
    assert b"stuck" in res.stderr
    assert res.truncated is False


def test_run_ssh_timeout_truncates_stdout(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_BYTES", "5")
    _patch_popen(monkeypatch, stdout=b"x" * 100, stderr=b"", raise_timeout=True)
    res = ssh_mod.run_ssh("h", "sleep 999")
    assert res.exit_code == 124
    assert res.truncated is True
    assert len(res.stdout) == 5


def test_run_ssh_timeout_handles_empty_streams(monkeypatch):
    _patch_popen(monkeypatch, stdout=b"", stderr=b"", raise_timeout=True)
    res = ssh_mod.run_ssh("h", "sleep 999")
    assert res.exit_code == 124
    assert res.stdout == b""
    assert res.stderr == b"\n[timeout]"


def test_run_ssh_caps_stderr_and_flags_truncation(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_BYTES", "10")
    _patch_popen(monkeypatch, stdout=b"", stderr=b"e" * 5000, returncode=1)
    res = ssh_mod.run_ssh("h", "false")
    assert len(res.stderr) == 10
    assert res.stderr_truncated is True


def test_run_ssh_records_duration(monkeypatch):
    _patch_popen(monkeypatch, stdout=b"", returncode=0)
    res = ssh_mod.run_ssh("h", "true")
    assert res.duration_ms >= 0.0
    assert isinstance(res.duration_ms, float)


def test_run_ssh_records_duration_on_timeout(monkeypatch):
    _patch_popen(monkeypatch, stdout=b"", stderr=b"", raise_timeout=True)
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
        _patch_popen(monkeypatch, stdout=b"hi", stderr=b"", returncode=0)
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
        assert "stderr_truncated" in e
        assert not any(x["msg"] == "ssh_call_io" for x in entries)
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
        _patch_popen(monkeypatch, stdout=b"payload", stderr=b"", returncode=0)
        ssh_mod.run_ssh("h2", "echo payload")
        for h in logging.getLogger("linux_info_mcp").handlers:
            h.flush()
        entries = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
        msgs = {e["msg"] for e in entries}
        assert {"ssh_call_start", "ssh_call", "ssh_call_io"} <= msgs
        io_entry = next(e for e in entries if e["msg"] == "ssh_call_io")
        assert io_entry["stdout"] == "payload"
    finally:
        reset_for_tests()


# cold-start gate — first connection runs alone, others wait to reuse its auth


def _concurrent_popen(monkeypatch, returncode=0, hold=0.2):
    import threading
    import time

    state = {"active": 0, "max_active": 0, "calls": 0}
    lock = threading.Lock()

    class _SlowPopen(_FakePopen):
        def wait(self, timeout=None):
            time.sleep(hold)
            with lock:
                state["active"] -= 1
            return super().wait(timeout)

    def fake_popen(argv, **kwargs):
        with lock:
            state["calls"] += 1
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
        return _SlowPopen(returncode=returncode)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return state


def _fan_out(n):
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=n) as ex:
        return list(ex.map(lambda i: ssh_mod.run_ssh(f"h{i}", "true"), range(n)))


def test_gate_cold_start_runs_first_connection_alone(monkeypatch):
    import threading

    order: list[str] = []
    first_started = threading.Event()
    release_first = threading.Event()

    class _P(_FakePopen):
        def __init__(self, host):
            super().__init__()
            self.host = host

        def wait(self, timeout=None):
            if self.host == "h0":
                first_started.set()
                release_first.wait(5)
            return super().wait(timeout)

    def fake_popen(argv, **kwargs):
        host = argv[-3]
        order.append(host)
        return _P(host)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    t0 = threading.Thread(target=ssh_mod.run_ssh, args=("h0", "true"))
    t0.start()
    assert first_started.wait(5)
    others = [threading.Thread(target=ssh_mod.run_ssh, args=(f"h{i}", "true")) for i in (1, 2, 3)]
    for t in others:
        t.start()
    for t in others:
        t.join(0.2)
    assert order == ["h0"]  # followers blocked while leader authenticates
    release_first.set()
    t0.join(5)
    for t in others:
        t.join(5)
    assert sorted(order) == ["h0", "h1", "h2", "h3"]


def test_gate_warm_allows_parallel(monkeypatch):
    state = _concurrent_popen(monkeypatch, hold=0.0)
    ssh_mod.run_ssh("h", "true")  # warms the gate
    state = _concurrent_popen(monkeypatch, hold=0.2)
    _fan_out(4)
    assert state["max_active"] > 1


def test_gate_disabled_runs_parallel_from_cold(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SSH_WARMUP", "off")
    state = _concurrent_popen(monkeypatch, hold=0.2)
    _fan_out(4)
    assert state["max_active"] > 1


def test_gate_cold_fan_out_leader_first_then_parallel(monkeypatch):
    state = _concurrent_popen(monkeypatch, hold=0.2)
    _fan_out(4)
    assert state["calls"] == 4
    # leader alone, then 3 followers together
    assert state["max_active"] == 3


def test_gate_remote_nonzero_still_warms(monkeypatch):
    _concurrent_popen(monkeypatch, returncode=1, hold=0.0)
    ssh_mod.run_ssh("h", "false")
    assert ssh_mod._gate_is_warm(__import__("time").monotonic())


def test_gate_connection_failure_255_stays_cold(monkeypatch):
    import time

    _concurrent_popen(monkeypatch, returncode=255, hold=0.0)
    ssh_mod.run_ssh("h", "true")
    assert not ssh_mod._gate_is_warm(time.monotonic())


def test_gate_timeout_stays_cold(monkeypatch):
    import time

    monkeypatch.setenv("LINUX_INFO_TIMEOUT", "1")
    _patch_popen(monkeypatch, raise_timeout=True)
    res = ssh_mod.run_ssh("h", "true")
    assert res.exit_code == 124
    assert not ssh_mod._gate_is_warm(time.monotonic())


def test_gate_failure_cools_warm_gate(monkeypatch):
    import time

    _concurrent_popen(monkeypatch, hold=0.0)
    ssh_mod.run_ssh("h", "true")
    assert ssh_mod._gate_is_warm(time.monotonic())
    _concurrent_popen(monkeypatch, returncode=255, hold=0.0)
    ssh_mod.run_ssh("h", "true")
    assert not ssh_mod._gate_is_warm(time.monotonic())


def test_gate_warm_ttl_expiry(monkeypatch):
    import time

    monkeypatch.setenv("LINUX_INFO_SSH_WARM_TTL", "0")
    _concurrent_popen(monkeypatch, hold=0.0)
    ssh_mod.run_ssh("h", "true")
    assert not ssh_mod._gate_is_warm(time.monotonic())


def test_gate_warm_ttl_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SSH_WARM_TTL", "abc")
    assert ssh_mod._warm_ttl() == 60.0


def test_gate_follower_falls_back_after_deadline(monkeypatch):
    import time

    assert ssh_mod._gate_enter(time.monotonic() + 5) is True  # simulate stuck leader
    t0 = time.monotonic()
    assert ssh_mod._gate_enter(time.monotonic() + 0.1) is False
    assert time.monotonic() - t0 < 2


def test_gate_releases_leader_on_exception(monkeypatch):
    import time

    def boom(argv, **kwargs):
        raise FileNotFoundError("ssh")

    monkeypatch.setattr(subprocess, "Popen", boom)
    with contextlib.suppress(FileNotFoundError):
        ssh_mod.run_ssh("h", "true")
    assert ssh_mod._gate_enter(time.monotonic() + 0.1) is True


def test_gate_logs_wait_and_leader(monkeypatch, tmp_path):
    import json

    from linux_info_mcp.log import setup_logging

    log = tmp_path / "l.jsonl"
    monkeypatch.setenv("LINUX_INFO_LOG_FILE", str(log))
    setup_logging()
    _patch_popen(monkeypatch, returncode=0)
    ssh_mod.run_ssh("h", "true")
    ssh_mod.run_ssh("h", "true")
    lines = [json.loads(x) for x in log.read_text().splitlines() if '"ssh_call"' in x]
    assert [ln["gate_leader"] for ln in lines] == [True, False]
    assert all("gate_wait_ms" in ln for ln in lines)
