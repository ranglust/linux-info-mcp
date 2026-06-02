import pytest

import linux_info_mcp.tools.lldp as mod
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
# builder
# ---------------------------------------------------------------------------


def test_builder_default():
    assert (
        mod.build_remote_cmd_lldp(what="neighbors") == "LC_ALL=C lldpcli -f keyvalue show neighbors"
    )


def test_builder_with_format_and_iface():
    cmd = mod.build_remote_cmd_lldp(what="neighbors", fmt="json", iface="eth0")
    assert cmd == "LC_ALL=C lldpcli -f json show neighbors ports eth0"


def test_builder_each_what():
    for what in ("neighbors", "interfaces", "statistics", "chassis"):
        assert mod.build_remote_cmd_lldp(what=what).endswith(f"show {what}")


# ---------------------------------------------------------------------------
# format validation
# ---------------------------------------------------------------------------


def test_format_default_keyvalue(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_lldp_neighbors({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C lldpcli -f keyvalue show neighbors"


@pytest.mark.parametrize("fmt", ["keyvalue", "json", "json0", "xml", "plain"])
def test_format_accepts_whitelist(monkeypatch, fmt):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_lldp_neighbors({"host": "h1", "format": fmt})
    assert captured["cmd"] == f"LC_ALL=C lldpcli -f {fmt} show neighbors"


@pytest.mark.parametrize("bad", ["yaml", "JSON", "key value", "", "json; rm -rf /", "-f"])
def test_format_rejects_non_whitelist(monkeypatch, bad):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lldp_neighbors({"host": "h1", "format": bad})


# ---------------------------------------------------------------------------
# iface validation
# ---------------------------------------------------------------------------


def test_iface_passed(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_lldp_statistics({"host": "h1", "iface": "eno1"})
    assert captured["cmd"] == "LC_ALL=C lldpcli -f keyvalue show statistics ports eno1"


@pytest.mark.parametrize(
    "bad", ["-rf", "eth0; rm -rf /", "eth0\nfoo", "eth0\x00", "a" * 33, "eth 0"]
)
def test_iface_rejects_bad(monkeypatch, bad):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lldp_neighbors({"host": "h1", "iface": bad})


def test_chassis_ignores_iface(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    # chassis schema has no iface; handler does not read it even if present
    mod.handle_lldp_chassis({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C lldpcli -f keyvalue show chassis"


# ---------------------------------------------------------------------------
# host validation / injection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "handler", ["lldp_neighbors", "lldp_interfaces", "lldp_statistics", "lldp_chassis"]
)
def test_host_injection_rejected(monkeypatch, handler):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    fn = getattr(mod, f"handle_{handler}")
    with pytest.raises(ValueError):
        fn({"host": "-oProxyCommand=evil"})


# ---------------------------------------------------------------------------
# handler shape + truncation propagation
# ---------------------------------------------------------------------------


def test_handler_shape(monkeypatch):
    _stub(monkeypatch, SshResult(stdout=b"out\n", stderr=b"err", exit_code=0, truncated=False))
    out = mod.handle_lldp_neighbors({"host": "h1"})
    assert out == {
        "stdout": "out\n",
        "stderr": "err",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }


def test_truncation_propagates(monkeypatch):
    _stub(
        monkeypatch,
        SshResult(stdout=b"x", stderr=b"y", exit_code=0, truncated=True, stderr_truncated=True),
    )
    out = mod.handle_lldp_interfaces({"host": "h1"})
    assert out["truncated"] is True
    assert out["stderr_truncated"] is True


def test_nonzero_exit_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(stdout=b"", stderr=b"no lldpd", exit_code=1, truncated=False))
    out = mod.handle_lldp_chassis({"host": "h1"})
    assert out["exit_code"] == 1
    assert out["stderr"] == "no lldpd"


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------


def test_tools_registered():
    names = {t.name for t in mod.TOOLS}
    assert names == {"lldp_neighbors", "lldp_interfaces", "lldp_statistics", "lldp_chassis"}
    for t in mod.TOOLS:
        assert t.input_schema["additionalProperties"] is False
        assert t.input_schema["required"] == ["host"]
