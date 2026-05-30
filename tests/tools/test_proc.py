import pytest

from linux_info_mcp.ssh import SshResult
import linux_info_mcp.tools.proc as mod


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


# ---------------------------------------------------------------------------
# lsof
# ---------------------------------------------------------------------------


def test_lsof_default_builder():
    assert mod.build_remote_cmd_lsof() == "LC_ALL=C lsof -n -P"


def test_lsof_pid_builder():
    cmd = mod.build_remote_cmd_lsof(pid=1234)
    assert cmd == "LC_ALL=C lsof -n -P -p 1234"


def test_lsof_user_builder():
    cmd = mod.build_remote_cmd_lsof(user="root")
    assert cmd == "LC_ALL=C lsof -n -P -u root"


def test_lsof_network_only_builder():
    cmd = mod.build_remote_cmd_lsof(network_only=True)
    assert cmd == "LC_ALL=C lsof -n -P -i"


def test_lsof_path_after_dashdash():
    cmd = mod.build_remote_cmd_lsof(path="/var/log/messages")
    assert cmd == "LC_ALL=C lsof -n -P -- /var/log/messages"


def test_lsof_all_combined_builder():
    cmd = mod.build_remote_cmd_lsof(network_only=True, user="root", path="/tmp")
    assert cmd == "LC_ALL=C lsof -n -P -i -u root -- /tmp"


def test_lsof_builder_rejects_pid_and_user():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_lsof(pid=1, user="root")


def test_lsof_handler_rejects_pid_and_user(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof({"host": "h1", "pid": 1, "user": "root"})


def test_lsof_handler_rejects_pid_zero(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof({"host": "h1", "pid": 0})


def test_lsof_handler_rejects_pid_too_big(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof({"host": "h1", "pid": 4194305})


def test_lsof_handler_rejects_pid_bool(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof({"host": "h1", "pid": True})


def test_lsof_handler_rejects_bad_user(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof({"host": "h1", "user": "1bad"})


def test_lsof_handler_rejects_user_with_semicolon(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof({"host": "h1", "user": "root; rm -rf /"})


def test_lsof_handler_rejects_path_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof({"host": "h1", "path": "/etc\n/passwd"})


def test_lsof_handler_rejects_path_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof({"host": "h1", "path": "/etc\x00bad"})


def test_lsof_handler_rejects_bad_network_only(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof({"host": "h1", "network_only": "yes"})


def test_lsof_handler_path_quotes_spaces(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_lsof({"host": "h1", "path": "/has space/x"})
    assert "-- '/has space/x'" in captured["cmd"]


def test_lsof_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"o\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_lsof({"host": "h1", "pid": 42, "network_only": True})
    assert out == {"stdout": "o\n", "stderr": "", "exit_code": 0, "truncated": False}
    assert captured["host"] == "h1"
    assert captured["cmd"] == "LC_ALL=C lsof -n -P -i -p 42"


def test_lsof_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_lsof({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# pgrep
# ---------------------------------------------------------------------------


def test_pgrep_default_builder():
    cmd = mod.build_remote_cmd_pgrep(pattern="sshd")
    assert cmd == "LC_ALL=C pgrep -l -- sshd"


def test_pgrep_all_flags_builder():
    cmd = mod.build_remote_cmd_pgrep(
        pattern="ngin*",
        full=True,
        exact=True,
        list_name=True,
        user="www-data",
        newest=True,
        parent_pid=1000,
    )
    assert cmd == "LC_ALL=C pgrep -f -x -l -n -u www-data -P 1000 -- 'ngin*'"


def test_pgrep_oldest_builder():
    cmd = mod.build_remote_cmd_pgrep(pattern="x", list_name=False, oldest=True)
    assert cmd == "LC_ALL=C pgrep -o -- x"


def test_pgrep_builder_rejects_newest_and_oldest():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_pgrep(pattern="x", newest=True, oldest=True)


def test_pgrep_handler_default_list_name(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_pgrep({"host": "h1", "pattern": "sshd"})
    assert captured["cmd"] == "LC_ALL=C pgrep -l -- sshd"


def test_pgrep_handler_disable_list_name(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_pgrep({"host": "h1", "pattern": "sshd", "list_name": False})
    assert captured["cmd"] == "LC_ALL=C pgrep -- sshd"


def test_pgrep_handler_quotes_pattern_with_meta(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_pgrep({"host": "h1", "pattern": "foo; rm -rf /"})
    assert "'foo; rm -rf /'" in captured["cmd"]


def test_pgrep_handler_rejects_pattern_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pgrep({"host": "h1", "pattern": "foo\nbar"})


def test_pgrep_handler_rejects_pattern_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pgrep({"host": "h1", "pattern": "foo\x00bar"})


def test_pgrep_handler_rejects_empty_pattern(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pgrep({"host": "h1", "pattern": ""})


def test_pgrep_handler_rejects_pattern_too_long(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pgrep({"host": "h1", "pattern": "a" * 257})


def test_pgrep_handler_rejects_bad_user(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pgrep({"host": "h1", "pattern": "x", "user": "-oProxyCommand=evil"})


def test_pgrep_handler_rejects_bad_parent_pid(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pgrep({"host": "h1", "pattern": "x", "parent_pid": 0})


def test_pgrep_handler_rejects_newest_and_oldest(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pgrep(
            {"host": "h1", "pattern": "x", "newest": True, "oldest": True}
        )


def test_pgrep_handler_rejects_bad_list_name(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pgrep({"host": "h1", "pattern": "x", "list_name": "yes"})


def test_pgrep_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"123 sshd\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_pgrep(
        {
            "host": "h1",
            "pattern": "sshd",
            "full": True,
            "exact": True,
            "user": "root",
            "parent_pid": 1,
        }
    )
    assert out == {
        "stdout": "123 sshd\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
    }
    assert (
        captured["cmd"]
        == "LC_ALL=C pgrep -f -x -l -u root -P 1 -- sshd"
    )


def test_pgrep_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_pgrep({"host": "h1", "pattern": "x"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# pidof
# ---------------------------------------------------------------------------


def test_pidof_default_builder():
    cmd = mod.build_remote_cmd_pidof(program="sshd")
    assert cmd == "LC_ALL=C pidof -- sshd"


def test_pidof_single_shot_builder():
    cmd = mod.build_remote_cmd_pidof(program="nginx", single_shot=True)
    assert cmd == "LC_ALL=C pidof -s -- nginx"


def test_pidof_handler_rejects_leading_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pidof({"host": "h1", "program": "-sshd"})


def test_pidof_handler_rejects_semicolon(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pidof({"host": "h1", "program": "sshd; rm -rf /"})


def test_pidof_handler_rejects_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pidof({"host": "h1", "program": "ssh\nd"})


def test_pidof_handler_rejects_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pidof({"host": "h1", "program": "ssh\x00d"})


def test_pidof_handler_rejects_proxycommand(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pidof({"host": "h1", "program": "-oProxyCommand=evil"})


def test_pidof_handler_rejects_empty(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pidof({"host": "h1", "program": ""})


def test_pidof_handler_rejects_too_long(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pidof({"host": "h1", "program": "a" * 129})


def test_pidof_handler_rejects_slash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_pidof({"host": "h1", "program": "bin/sshd"})


def test_pidof_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"42\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_pidof({"host": "h1", "program": "sshd", "single_shot": True})
    assert out == {"stdout": "42\n", "stderr": "", "exit_code": 0, "truncated": False}
    assert captured["cmd"] == "LC_ALL=C pidof -s -- sshd"


def test_pidof_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_pidof({"host": "h1", "program": "sshd"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# top
# ---------------------------------------------------------------------------


def test_top_default_builder():
    assert mod.build_remote_cmd_top() == "LC_ALL=C top -bn1 -w 512"


def test_top_user_builder():
    cmd = mod.build_remote_cmd_top(user="root")
    assert cmd == "LC_ALL=C top -bn1 -w 512 -u root"


def test_top_sort_cpu_builder():
    cmd = mod.build_remote_cmd_top(sort_field="%CPU")
    assert cmd == "LC_ALL=C top -bn1 -w 512 -o %CPU"


def test_top_combined_builder():
    cmd = mod.build_remote_cmd_top(user="nobody", sort_field="%MEM")
    assert cmd == "LC_ALL=C top -bn1 -w 512 -o %MEM -u nobody"


def test_top_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_top({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C top -bn1 -w 512"


def test_top_handler_sort_mem(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_top({"host": "h1", "sort": "mem"})
    assert captured["cmd"] == "LC_ALL=C top -bn1 -w 512 -o %MEM"


def test_top_handler_sort_pid(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_top({"host": "h1", "sort": "pid"})
    assert captured["cmd"] == "LC_ALL=C top -bn1 -w 512 -o PID"


def test_top_handler_sort_time(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_top({"host": "h1", "sort": "time"})
    assert captured["cmd"] == "LC_ALL=C top -bn1 -w 512 -o TIME+"


def test_top_handler_user(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_top({"host": "h1", "user": "root"})
    assert captured["cmd"] == "LC_ALL=C top -bn1 -w 512 -u root"


def test_top_handler_rejects_bad_sort(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_top({"host": "h1", "sort": "ram"})


def test_top_handler_rejects_sort_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_top({"host": "h1", "sort": "%CPU; rm -rf /"})


def test_top_handler_rejects_bad_user(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_top({"host": "h1", "user": "1bad"})


def test_top_handler_rejects_user_proxycommand(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_top({"host": "h1", "user": "-oProxyCommand=evil"})


def test_top_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"top\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_top({"host": "h1", "sort": "cpu", "user": "root"})
    assert out == {"stdout": "top\n", "stderr": "", "exit_code": 0, "truncated": False}
    assert captured["cmd"] == "LC_ALL=C top -bn1 -w 512 -o %CPU -u root"


def test_top_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_top({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# TOOLS registration
# ---------------------------------------------------------------------------


def test_tools_registry_names():
    names = [t.name for t in mod.TOOLS]
    assert names == ["lsof", "pgrep", "pidof", "top"]
    for spec in mod.TOOLS:
        assert "host" in spec.input_schema["required"]
        assert callable(spec.handler)


def test_pgrep_pidof_require_extra_fields():
    by_name = {t.name: t for t in mod.TOOLS}
    assert by_name["pgrep"].input_schema["required"] == ["host", "pattern"]
    assert by_name["pidof"].input_schema["required"] == ["host", "program"]
