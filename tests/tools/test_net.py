import pytest

from linux_info_mcp.ssh import SshResult
import linux_info_mcp.tools.net as mod


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


# ---------------------------------------------------------------------------
# ss
# ---------------------------------------------------------------------------


def test_ss_default_builder():
    assert mod.build_remote_cmd_ss() == "LC_ALL=C ss"


def test_ss_all_flags_builder():
    cmd = mod.build_remote_cmd_ss(
        tcp=True,
        udp=True,
        listening=True,
        all=True,
        numeric=True,
        processes=True,
        extended=True,
        summary=True,
        memory=True,
        family="inet",
        state="established",
    )
    assert cmd == (
        "LC_ALL=C ss -t -u -l -a -n -p -e -s -m -f inet state established"
    )


def test_ss_handler_default(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"out\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_ss({"host": "h1"})
    assert out == {"stdout": "out\n", "stderr": "", "exit_code": 0, "truncated": False}
    assert captured["cmd"] == "LC_ALL=C ss"


def test_ss_handler_tcp_listening_numeric(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_ss({"host": "h1", "tcp": True, "listening": True, "numeric": True})
    assert captured["cmd"] == "LC_ALL=C ss -t -l -n"


def test_ss_handler_state_and_family(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_ss({"host": "h1", "family": "inet6", "state": "time-wait"})
    assert captured["cmd"] == "LC_ALL=C ss -f inet6 state time-wait"


def test_ss_handler_rejects_bad_state(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ss({"host": "h1", "state": "bogus"})


def test_ss_handler_rejects_bad_family(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ss({"host": "h1", "family": "ipx"})


def test_ss_handler_rejects_state_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ss({"host": "h1", "state": "established; rm -rf /"})


def test_ss_handler_rejects_family_flag_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ss({"host": "h1", "family": "-oProxyCommand=evil"})


def test_ss_handler_rejects_non_bool(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ss({"host": "h1", "tcp": "yes"})


def test_ss_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_ss({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# ip_addr
# ---------------------------------------------------------------------------


def test_ip_addr_default_builder():
    assert mod.build_remote_cmd_ip_addr() == "LC_ALL=C ip -o addr show"


def test_ip_addr_iface_builder():
    cmd = mod.build_remote_cmd_ip_addr(iface="eth0")
    assert cmd == "LC_ALL=C ip -o addr show dev eth0"


def test_ip_addr_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"a\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_ip_addr({"host": "h1", "iface": "ens3"})
    assert out == {"stdout": "a\n", "stderr": "", "exit_code": 0, "truncated": False}
    assert captured["cmd"] == "LC_ALL=C ip -o addr show dev ens3"


def test_ip_addr_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_ip_addr({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C ip -o addr show"


def test_ip_addr_rejects_iface_starting_with_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ip_addr({"host": "h1", "iface": "-oProxyCommand=evil"})


def test_ip_addr_rejects_iface_with_semicolon(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ip_addr({"host": "h1", "iface": "eth0; rm -rf /"})


def test_ip_addr_rejects_iface_with_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ip_addr({"host": "h1", "iface": "eth0\nfoo"})


def test_ip_addr_rejects_iface_with_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ip_addr({"host": "h1", "iface": "eth0\x00"})


def test_ip_addr_rejects_iface_too_long(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ip_addr({"host": "h1", "iface": "a" * 33})


def test_ip_addr_rejects_iface_empty(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ip_addr({"host": "h1", "iface": ""})


def test_ip_addr_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_ip_addr({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# ip_route
# ---------------------------------------------------------------------------


def test_ip_route_default_builder():
    assert mod.build_remote_cmd_ip_route() == "LC_ALL=C ip route show"


def test_ip_route_with_table_builder():
    cmd = mod.build_remote_cmd_ip_route(table="main")
    assert cmd == "LC_ALL=C ip route show table main"


def test_ip_route_family_inet_builder():
    cmd = mod.build_remote_cmd_ip_route(family_flag="-4")
    assert cmd == "LC_ALL=C ip -4 route show"


def test_ip_route_family_inet6_and_table_builder():
    cmd = mod.build_remote_cmd_ip_route(family_flag="-6", table="local")
    assert cmd == "LC_ALL=C ip -6 route show table local"


def test_ip_route_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"r\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_ip_route({"host": "h1", "family": "inet", "table": "all"})
    assert out == {"stdout": "r\n", "stderr": "", "exit_code": 0, "truncated": False}
    assert captured["cmd"] == "LC_ALL=C ip -4 route show table all"


def test_ip_route_rejects_bad_table(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ip_route({"host": "h1", "table": "bogus"})


def test_ip_route_rejects_bad_family(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ip_route({"host": "h1", "family": "ipx"})


def test_ip_route_rejects_table_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ip_route({"host": "h1", "table": "main; rm -rf /"})


def test_ip_route_rejects_table_with_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ip_route({"host": "h1", "table": "main\nlocal"})


def test_ip_route_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_ip_route({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# lsof_net
# ---------------------------------------------------------------------------


def test_lsof_net_default_builder():
    assert mod.build_remote_cmd_lsof_net() == "LC_ALL=C lsof -n -P -i"


def test_lsof_net_protocol_only_builder():
    cmd = mod.build_remote_cmd_lsof_net(protocol="tcp")
    assert cmd == "LC_ALL=C lsof -n -P -i tcp"


def test_lsof_net_port_only_builder():
    cmd = mod.build_remote_cmd_lsof_net(port=80)
    assert cmd == "LC_ALL=C lsof -n -P -i :80"


def test_lsof_net_protocol_and_port_builder():
    cmd = mod.build_remote_cmd_lsof_net(protocol="tcp6", port=443)
    assert cmd == "LC_ALL=C lsof -n -P -i tcp6:443"


def test_lsof_net_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"l\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_lsof_net({"host": "h1", "protocol": "udp", "port": 53})
    assert out == {"stdout": "l\n", "stderr": "", "exit_code": 0, "truncated": False}
    assert captured["cmd"] == "LC_ALL=C lsof -n -P -i udp:53"


def test_lsof_net_rejects_bad_protocol(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof_net({"host": "h1", "protocol": "sctp"})


def test_lsof_net_rejects_protocol_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof_net({"host": "h1", "protocol": "tcp; rm -rf /"})


def test_lsof_net_rejects_port_zero(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof_net({"host": "h1", "port": 0})


def test_lsof_net_rejects_port_too_high(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof_net({"host": "h1", "port": 65536})


def test_lsof_net_rejects_port_bool(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof_net({"host": "h1", "port": True})


def test_lsof_net_rejects_port_string(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsof_net({"host": "h1", "port": "80"})


def test_lsof_net_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_lsof_net({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# Host validation propagation
# ---------------------------------------------------------------------------


def test_ss_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ss({"host": "-evil"})


def test_ip_addr_rejects_host_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ip_addr({"host": "h1\nfoo"})


# ---------------------------------------------------------------------------
# TOOLS registration
# ---------------------------------------------------------------------------


def test_tools_registry_names():
    names = [t.name for t in mod.TOOLS]
    assert names == ["ss", "ip_addr", "ip_route", "lsof_net"]
    for spec in mod.TOOLS:
        assert spec.input_schema["required"] == ["host"]
        assert callable(spec.handler)
