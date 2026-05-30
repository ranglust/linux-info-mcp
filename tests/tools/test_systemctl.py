import pytest

import linux_info_mcp.tools.systemctl as mod
from linux_info_mcp.ssh import SshResult


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


# --- systemctl_status: builder ---


def test_status_builder_default_lines():
    cmd = mod.build_remote_cmd_systemctl_status("nginx.service", 10)
    assert cmd == "LC_ALL=C systemctl status --no-pager --lines=10 -- nginx.service"


def test_status_builder_keeps_lines_zero():
    cmd = mod.build_remote_cmd_systemctl_status("nginx.service", 0)
    assert "--lines=0" in cmd


# --- systemctl_status: handler validation ---


def test_status_rejects_bad_host(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_status({"host": "-oProxyCommand=evil", "unit": "nginx.service"})


def test_status_rejects_unit_with_semicolon(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_status({"host": "h1", "unit": "nginx;rm"})


def test_status_rejects_unit_with_newline(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_status({"host": "h1", "unit": "nginx\n"})


def test_status_rejects_unit_flag_like(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_status({"host": "h1", "unit": "--all"})


def test_status_rejects_lines_negative(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_status({"host": "h1", "unit": "nginx.service", "lines": -1})


def test_status_rejects_lines_too_large(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_status({"host": "h1", "unit": "nginx.service", "lines": 10001})


# --- systemctl_status: handler happy path ---


def test_status_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(
            stdout=b"\xe2\x97\x8f nginx.service - foo\n",
            stderr=b"",
            exit_code=0,
            truncated=False,
        ),
    )
    out = mod.handle_systemctl_status({"host": "h1", "unit": "nginx.service"})
    assert out == {
        "stdout": "● nginx.service - foo\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["host"] == "h1"
    assert captured["cmd"] == "LC_ALL=C systemctl status --no-pager --lines=10 -- nginx.service"


def test_status_passes_through_inactive_exit_code(monkeypatch):
    _stub(
        monkeypatch,
        SshResult(stdout=b"inactive\n", stderr=b"", exit_code=3, truncated=False),
    )
    out = mod.handle_systemctl_status({"host": "h1", "unit": "nginx.service"})
    assert out["exit_code"] == 3


# --- systemctl_list: builder ---


def test_list_builder_default_kind_is_units():
    cmd = mod.build_remote_cmd_systemctl_list("units", None, None, False, None)
    assert cmd == ("LC_ALL=C systemctl list-units --no-pager --no-legend --plain")


def test_list_builder_unit_files():
    cmd = mod.build_remote_cmd_systemctl_list("unit-files", None, None, False, None)
    assert "list-unit-files" in cmd


def test_list_builder_unit_types_forwarded():
    cmd = mod.build_remote_cmd_systemctl_list("units", "service,timer", None, False, None)
    assert "-t service,timer" in cmd


def test_list_builder_states_forwarded():
    cmd = mod.build_remote_cmd_systemctl_list("units", None, "failed,active", False, None)
    assert "--state=failed,active" in cmd


def test_list_builder_all_flag():
    cmd = mod.build_remote_cmd_systemctl_list("units", None, None, True, None)
    assert cmd.endswith("--all")


def test_list_builder_pattern_after_double_dash_quoted():
    cmd = mod.build_remote_cmd_systemctl_list("units", None, None, False, "*.timer")
    # shlex.quote turns "*.timer" into '*.timer' so the local shell won't glob-expand.
    assert cmd.endswith("-- '*.timer'")


# --- systemctl_list: handler validation ---


def test_list_rejects_bad_host(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_list({"host": "-oProxyCommand=evil"})


def test_list_rejects_bad_kind(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_list({"host": "h1", "kind": "other"})


def test_list_default_kind_is_units(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_systemctl_list({"host": "h1"})
    assert "list-units" in captured["cmd"]


def test_list_kind_unit_files(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_systemctl_list({"host": "h1", "kind": "unit-files"})
    assert "list-unit-files" in captured["cmd"]


def test_list_unit_type_forwarded(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_systemctl_list({"host": "h1", "unit_type": "service,timer"})
    assert "-t service,timer" in captured["cmd"]


def test_list_unit_type_rejects_injection(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_list({"host": "h1", "unit_type": "service;rm"})


def test_list_unit_type_rejects_empty_element(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_list({"host": "h1", "unit_type": "service,,timer"})


def test_list_state_forwarded(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_systemctl_list({"host": "h1", "state": "failed,active"})
    assert "--state=failed,active" in captured["cmd"]


def test_list_state_rejects_uppercase(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_list({"host": "h1", "state": "Failed"})


def test_list_state_rejects_space(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_list({"host": "h1", "state": "state with space"})


def test_list_all_flag(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_systemctl_list({"host": "h1", "all": True})
    assert "--all" in captured["cmd"]


def test_list_pattern_quoted_after_dashdash(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_systemctl_list({"host": "h1", "pattern": "*.timer"})
    assert captured["cmd"].endswith("-- '*.timer'")


def test_list_pattern_metachar_is_quoted_not_rejected(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_systemctl_list({"host": "h1", "pattern": "foo;rm"})
    # The dangerous chars survive only inside single quotes (shlex.quote).
    assert "'foo;rm'" in captured["cmd"]


def test_list_pattern_rejects_nul(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_list({"host": "h1", "pattern": "foo\x00bar"})


def test_list_pattern_rejects_newline(monkeypatch):
    with pytest.raises(ValueError):
        mod.handle_systemctl_list({"host": "h1", "pattern": "foo\nbar"})


def test_list_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(
            stdout=b"nginx.service loaded active running\n",
            stderr=b"",
            exit_code=0,
            truncated=False,
        ),
    )
    out = mod.handle_systemctl_list(
        {
            "host": "h1",
            "unit_type": "service",
            "state": "active",
            "all": True,
            "pattern": "*.service",
        }
    )
    assert out == {
        "stdout": "nginx.service loaded active running\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    cmd = captured["cmd"]
    assert cmd.startswith("LC_ALL=C systemctl list-units --no-pager --no-legend --plain")
    assert "-t service" in cmd
    assert "--state=active" in cmd
    assert "--all" in cmd
    assert cmd.endswith("-- '*.service'")


def test_systemctl_status_truncated_propagates(monkeypatch):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        return SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True)

    monkeypatch.setattr(mod, "run_ssh", fake)
    out = mod.handle_systemctl_status({"host": "h", "unit": "nginx.service"})
    assert out["truncated"] is True


def test_systemctl_list_truncated_propagates(monkeypatch):
    def fake(host, cmd):
        return SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True)

    monkeypatch.setattr(mod, "run_ssh", fake)
    out = mod.handle_systemctl_list({"host": "h"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# systemctl_list_timers
# ---------------------------------------------------------------------------


def test_list_timers_default_builder():
    assert mod.build_remote_cmd_systemctl_list_timers(all_flag=False) == (
        "LC_ALL=C systemctl list-timers --no-pager"
    )


def test_list_timers_all_builder():
    assert mod.build_remote_cmd_systemctl_list_timers(all_flag=True) == (
        "LC_ALL=C systemctl list-timers --no-pager --all"
    )


def test_list_timers_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"t\n", b"", 0, False))
    out = mod.handle_systemctl_list_timers({"host": "h1"})
    assert out == {
        "stdout": "t\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C systemctl list-timers --no-pager"


def test_list_timers_handler_all(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_systemctl_list_timers({"host": "h1", "all": True})
    assert captured["cmd"] == "LC_ALL=C systemctl list-timers --no-pager --all"


def test_list_timers_rejects_non_bool_all(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_systemctl_list_timers({"host": "h1", "all": "yes"})


def test_list_timers_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_systemctl_list_timers({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# systemctl_list_sockets
# ---------------------------------------------------------------------------


def test_list_sockets_default_builder():
    assert mod.build_remote_cmd_systemctl_list_sockets(all_flag=False) == (
        "LC_ALL=C systemctl list-sockets --no-pager"
    )


def test_list_sockets_all_builder():
    assert mod.build_remote_cmd_systemctl_list_sockets(all_flag=True) == (
        "LC_ALL=C systemctl list-sockets --no-pager --all"
    )


def test_list_sockets_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"s\n", b"", 0, False))
    out = mod.handle_systemctl_list_sockets({"host": "h1"})
    assert out["stdout"] == "s\n"
    assert captured["cmd"] == "LC_ALL=C systemctl list-sockets --no-pager"


def test_list_sockets_handler_all(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_systemctl_list_sockets({"host": "h1", "all": True})
    assert captured["cmd"] == "LC_ALL=C systemctl list-sockets --no-pager --all"


def test_list_sockets_rejects_non_bool_all(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_systemctl_list_sockets({"host": "h1", "all": "yes"})


def test_list_sockets_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_systemctl_list_sockets({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_tools_registry_names():
    names = [t.name for t in mod.TOOLS]
    assert names == [
        "systemctl_status",
        "systemctl_list",
        "systemctl_list_timers",
        "systemctl_list_sockets",
    ]
    for spec in mod.TOOLS:
        assert "host" in spec.input_schema["required"]
        assert callable(spec.handler)
