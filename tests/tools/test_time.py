import pytest

import linux_info_mcp.tools.time as mod
from linux_info_mcp.ssh import SshResult


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


# ---------------------------------------------------------------------------
# chronyc
# ---------------------------------------------------------------------------


def test_chronyc_default_builder():
    assert mod.build_remote_cmd_chronyc(subcommand="tracking") == "LC_ALL=C chronyc -n tracking"


@pytest.mark.parametrize(
    "sub",
    [
        "tracking",
        "sources",
        "sourcestats",
        "activity",
        "ntpdata",
        "clients",
        "serverstats",
        "selectdata",
        "smoothing",
    ],
)
def test_chronyc_all_subcommands(monkeypatch, sub):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"x\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_chronyc({"host": "h1", "subcommand": sub})
    assert out == {
        "stdout": "x\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == f"LC_ALL=C chronyc -n {sub}"
    assert captured["host"] == "h1"


@pytest.mark.parametrize(
    "bad",
    [
        "set-time",
        "set-timezone",
        "makestep",
        "add server pool.ntp.org iburst",
        "tracking; rm -rf /",
        "tracking && rm -rf /",
        "-oProxyCommand=evil",
        "-tracking",
        "",
        "TRACKING",
        "ntp",
    ],
)
def test_chronyc_rejects_bad_subcommand(monkeypatch, bad):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_chronyc({"host": "h1", "subcommand": bad})


def test_chronyc_rejects_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_chronyc({"host": "h1", "subcommand": "tracking\nsources"})


def test_chronyc_rejects_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_chronyc({"host": "h1", "subcommand": "tracking\x00"})


def test_chronyc_rejects_missing_subcommand(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_chronyc({"host": "h1"})


def test_chronyc_rejects_non_string(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_chronyc({"host": "h1", "subcommand": 123})


def test_chronyc_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_chronyc({"host": "-evil", "subcommand": "tracking"})


def test_chronyc_truncated_propagates(monkeypatch):
    def fake(host, cmd):
        return SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True)

    monkeypatch.setattr(mod, "run_ssh", fake)
    out = mod.handle_chronyc({"host": "h1", "subcommand": "tracking"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# timedatectl
# ---------------------------------------------------------------------------


def test_timedatectl_default_builder():
    assert (
        mod.build_remote_cmd_timedatectl(mode="status") == "LC_ALL=C timedatectl --no-pager status"
    )


@pytest.mark.parametrize(
    "mode",
    ["status", "show", "list-timezones", "show-timesync", "timesync-status"],
)
def test_timedatectl_all_modes(monkeypatch, mode):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"y\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_timedatectl({"host": "h1", "mode": mode})
    assert out == {
        "stdout": "y\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == f"LC_ALL=C timedatectl --no-pager {mode}"
    assert captured["host"] == "h1"


def test_timedatectl_list_timezones_quoted():
    cmd = mod.build_remote_cmd_timedatectl(mode="list-timezones")
    assert "'list-timezones'" in cmd or "list-timezones" in cmd


@pytest.mark.parametrize(
    "bad",
    [
        "set-time",
        "set-timezone",
        "set-ntp",
        "set-local-rtc",
        "status; rm -rf /",
        "status && rm -rf /",
        "-oProxyCommand=evil",
        "-status",
        "",
        "STATUS",
        "show-all",
    ],
)
def test_timedatectl_rejects_bad_mode(monkeypatch, bad):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_timedatectl({"host": "h1", "mode": bad})


def test_timedatectl_rejects_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_timedatectl({"host": "h1", "mode": "status\nshow"})


def test_timedatectl_rejects_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_timedatectl({"host": "h1", "mode": "status\x00"})


def test_timedatectl_rejects_missing_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_timedatectl({"host": "h1"})


def test_timedatectl_rejects_non_string(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_timedatectl({"host": "h1", "mode": ["status"]})


def test_timedatectl_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_timedatectl({"host": "-evil", "mode": "status"})


def test_timedatectl_truncated_propagates(monkeypatch):
    def fake(host, cmd):
        return SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True)

    monkeypatch.setattr(mod, "run_ssh", fake)
    out = mod.handle_timedatectl({"host": "h1", "mode": "status"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# TOOLS registration
# ---------------------------------------------------------------------------


def test_tools_registry_names():
    names = [t.name for t in mod.TOOLS]
    assert names == ["chronyc", "timedatectl"]
    for spec in mod.TOOLS:
        assert "host" in spec.input_schema["required"]
        assert callable(spec.handler)
