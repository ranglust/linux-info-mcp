import pytest

import linux_info_mcp.tools.journalctl as mod
from linux_info_mcp.ssh import SshResult


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


# ---------- builder ----------


def test_builder_default():
    cmd = mod.build_remote_cmd_journalctl()
    assert cmd == "LC_ALL=C journalctl --no-pager -n 100 -o short-iso"


def test_builder_all_flags():
    cmd = mod.build_remote_cmd_journalctl(
        lines=50,
        unit="nginx.service",
        identifier="sshd",
        priority="err",
        boot=-1,
        since="2 hours ago",
        until="now",
        grep_pattern="oops",
        reverse=True,
        output="json",
    )
    # stable order: -n, -u, -t, -p, -b, --since=, --until=, --grep=, -r, -o
    assert cmd == (
        "LC_ALL=C journalctl --no-pager "
        "-n 50 "
        "-u nginx.service "
        "-t sshd "
        "-p err "
        "-b -1 "
        "--since='2 hours ago' "
        "--until=now "
        "--grep=oops "
        "-r "
        "-o json"
    )


def test_builder_grep_pattern_shlex_quoted():
    cmd = mod.build_remote_cmd_journalctl(grep_pattern="error\\|fail")
    # value contains backslash and pipe — must be shlex-quoted, prefixed by --grep=
    assert "--grep='error\\|fail'" in cmd
    # ensure equals form (no separate flag/value tokens)
    assert " --grep error" not in cmd


def test_builder_priority_range():
    cmd = mod.build_remote_cmd_journalctl(priority="err..info")
    assert " -p err..info" in cmd


def test_builder_boot_negative():
    cmd = mod.build_remote_cmd_journalctl(boot=-2)
    # token must appear as exact "-2" argument to -b
    assert " -b -2" in cmd
    parts = cmd.split()
    i = parts.index("-b")
    assert parts[i + 1] == "-2"


def test_builder_boot_zero():
    cmd = mod.build_remote_cmd_journalctl(boot=0)
    assert " -b 0" in cmd
    parts = cmd.split()
    i = parts.index("-b")
    assert parts[i + 1] == "0"


def test_builder_reverse_true():
    cmd = mod.build_remote_cmd_journalctl(reverse=True)
    assert " -r " in cmd or cmd.endswith(" -r")
    # default cmd doesn't end with -r since -o follows; just confirm presence
    assert "-r" in cmd.split()


def test_builder_reverse_false_omits():
    cmd = mod.build_remote_cmd_journalctl(reverse=False)
    assert "-r" not in cmd.split()


# ---------- validators ----------


def test_validate_priority_accepts():
    assert mod.validate_priority("emerg") == "emerg"
    assert mod.validate_priority("0") == "0"
    assert mod.validate_priority("7") == "7"
    assert mod.validate_priority("err..info") == "err..info"


def test_validate_priority_rejects():
    with pytest.raises(ValueError):
        mod.validate_priority("notarealprio")
    with pytest.raises(ValueError):
        mod.validate_priority("err..nope")
    with pytest.raises(ValueError):
        mod.validate_priority("8")
    with pytest.raises(ValueError):
        mod.validate_priority("")


def test_validate_boot_accepts():
    assert mod.validate_boot(0) == 0
    assert mod.validate_boot(-1) == -1
    assert mod.validate_boot(-10) == -10


def test_validate_boot_rejects():
    with pytest.raises(ValueError):
        mod.validate_boot(1)
    with pytest.raises(ValueError):
        mod.validate_boot(-11)
    with pytest.raises(ValueError):
        mod.validate_boot("0")
    with pytest.raises(ValueError):
        mod.validate_boot(True)


def test_validate_output_accepts_all_whitelist():
    for fmt in (
        "short",
        "short-iso",
        "short-precise",
        "cat",
        "json",
        "json-pretty",
        "verbose",
    ):
        assert mod.validate_output_format(fmt) == fmt


def test_validate_output_rejects():
    with pytest.raises(ValueError):
        mod.validate_output_format("pretty")
    with pytest.raises(ValueError):
        mod.validate_output_format("")


def test_validate_time_string_rejects_newline():
    with pytest.raises(ValueError):
        mod.validate_time_string("2 hours\nago", "since")


def test_validate_grep_pattern_journal_rejects_nul():
    with pytest.raises(ValueError):
        mod.validate_grep_pattern_journal("ab\x00cd")


# ---------- handler ----------


def test_handler_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_journalctl({"host": "-oProxyCommand=evil"})


def test_handler_rejects_bad_unit(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_journalctl({"host": "h1", "unit": "a;b"})


def test_handler_rejects_bad_output(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_journalctl({"host": "h1", "output": "pretty"})


def test_handler_rejects_bad_priority(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_journalctl({"host": "h1", "priority": "notarealprio"})


def test_handler_rejects_since_with_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_journalctl({"host": "h1", "since": "2 hours\nago"})


def test_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"line\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_journalctl({"host": "h1"})
    assert out == {
        "stdout": "line\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
    }
    assert captured["host"] == "h1"
    assert "journalctl" in captured["cmd"]
    assert "--no-pager" in captured["cmd"]
    assert "-n 100" in captured["cmd"]
    assert "-o short-iso" in captured["cmd"]


def test_handler_passes_validated_args_through(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"", stderr=b"", exit_code=0, truncated=False),
    )
    mod.handle_journalctl(
        {
            "host": "h1",
            "unit": "nginx.service",
            "lines": 5,
            "since": "2 hours ago",
            "priority": "err..info",
            "boot": -2,
            "reverse": True,
            "output": "json",
        }
    )
    cmd = captured["cmd"]
    assert "-u nginx.service" in cmd
    assert "-n 5" in cmd
    assert "--since='2 hours ago'" in cmd
    assert "-p err..info" in cmd
    assert "-b -2" in cmd
    assert "-r" in cmd.split()
    assert "-o json" in cmd


def test_journalctl_truncated_propagates(monkeypatch):
    def fake(host, cmd):
        return SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True)

    monkeypatch.setattr(mod, "run_ssh", fake)
    out = mod.handle_journalctl({"host": "h"})
    assert out["truncated"] is True
