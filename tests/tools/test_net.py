import pytest

import linux_info_mcp.tools.net as mod
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
    assert cmd == ("LC_ALL=C ss -t -u -l -a -n -p -e -s -m -f inet state established")


def test_ss_handler_default(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"out\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_ss({"host": "h1"})
    assert out == {
        "stdout": "out\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
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
    assert out == {
        "stdout": "a\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
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
    assert out == {
        "stdout": "r\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
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
    assert out == {
        "stdout": "l\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
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
    assert names == [
        "ss",
        "ip_addr",
        "ip_route",
        "lsof_net",
        "arp_table",
        "tc_qdisc",
        "ethtool",
        "conntrack",
        "net_protocol_stats",
        "nft_list",
        "iptables_list",
        "dig",
    ]
    for spec in mod.TOOLS:
        assert "host" in spec.input_schema["required"]
        assert callable(spec.handler)


# ---------------------------------------------------------------------------
# arp_table
# ---------------------------------------------------------------------------


def test_arp_table_default_builder():
    assert mod.build_remote_cmd_arp_table() == "LC_ALL=C ip -o neigh show"


def test_arp_table_iface_builder():
    assert mod.build_remote_cmd_arp_table(iface="eth0") == "LC_ALL=C ip -o neigh show dev eth0"


def test_arp_table_family_builder():
    assert mod.build_remote_cmd_arp_table(family_flag="-4") == "LC_ALL=C ip -o -4 neigh show"


def test_arp_table_family_and_iface_builder():
    cmd = mod.build_remote_cmd_arp_table(family_flag="-6", iface="ens3")
    assert cmd == "LC_ALL=C ip -o -6 neigh show dev ens3"


def test_arp_table_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"n\n", b"", 0, False))
    out = mod.handle_arp_table({"host": "h1", "family": "inet", "iface": "eth0"})
    assert out == {
        "stdout": "n\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C ip -o -4 neigh show dev eth0"


def test_arp_table_rejects_bad_family(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_arp_table({"host": "h1", "family": "ipx"})


def test_arp_table_rejects_iface_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_arp_table({"host": "h1", "iface": "eth0; rm -rf /"})


def test_arp_table_rejects_iface_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_arp_table({"host": "h1", "iface": "-oProxyCommand=evil"})


def test_arp_table_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_arp_table({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# tc_qdisc
# ---------------------------------------------------------------------------


def test_tc_qdisc_default_builder():
    assert mod.build_remote_cmd_tc_qdisc() == "LC_ALL=C tc -s qdisc show"


def test_tc_qdisc_iface_builder():
    assert mod.build_remote_cmd_tc_qdisc(iface="eth0") == "LC_ALL=C tc -s qdisc show dev eth0"


def test_tc_qdisc_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"q\n", b"", 0, False))
    out = mod.handle_tc_qdisc({"host": "h1", "iface": "ens3"})
    assert out["stdout"] == "q\n"
    assert captured["cmd"] == "LC_ALL=C tc -s qdisc show dev ens3"


def test_tc_qdisc_rejects_iface_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_tc_qdisc({"host": "h1", "iface": "eth0; rm -rf /"})


def test_tc_qdisc_rejects_iface_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_tc_qdisc({"host": "h1", "iface": "-oProxyCommand=evil"})


def test_tc_qdisc_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_tc_qdisc({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# ethtool
# ---------------------------------------------------------------------------


def test_ethtool_default_mode_builder():
    assert mod.build_remote_cmd_ethtool(iface="eth0", mode_flag="-i") == "LC_ALL=C ethtool -i eth0"


def test_ethtool_stats_builder():
    assert mod.build_remote_cmd_ethtool(iface="eth0", mode_flag="-S") == "LC_ALL=C ethtool -S eth0"


def test_ethtool_handler_default_is_driver(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"drv\n", b"", 0, False))
    out = mod.handle_ethtool({"host": "h1", "iface": "eth0"})
    assert out["stdout"] == "drv\n"
    assert captured["cmd"] == "LC_ALL=C ethtool -i eth0"


def test_ethtool_handler_each_mode(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    expect = {
        "stats": "-S",
        "driver": "-i",
        "ring": "-g",
        "features": "-k",
        "pause": "-a",
        "coalesce": "-c",
    }
    for mode, flag in expect.items():
        mod.handle_ethtool({"host": "h1", "iface": "eth0", "mode": mode})
        assert captured["cmd"] == f"LC_ALL=C ethtool {flag} eth0"


def test_ethtool_requires_iface(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises((ValueError, KeyError)):
        mod.handle_ethtool({"host": "h1"})


def test_ethtool_rejects_bad_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ethtool({"host": "h1", "iface": "eth0", "mode": "reset"})


def test_ethtool_rejects_iface_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ethtool({"host": "h1", "iface": "eth0; rm -rf /"})


def test_ethtool_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_ethtool({"host": "h1", "iface": "eth0"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# conntrack
# ---------------------------------------------------------------------------


def test_conntrack_default_stats_builder():
    assert mod.build_remote_cmd_conntrack(mode="stats") == "LC_ALL=C conntrack -S"


def test_conntrack_list_builder():
    assert mod.build_remote_cmd_conntrack(mode="list") == "LC_ALL=C conntrack -L"


def test_conntrack_list_proto_builder():
    cmd = mod.build_remote_cmd_conntrack(mode="list", protocol="tcp")
    assert cmd == "LC_ALL=C conntrack -L -p tcp"


def test_conntrack_handler_default_is_stats(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"s\n", b"", 0, False))
    mod.handle_conntrack({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C conntrack -S"


def test_conntrack_handler_list_udp(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_conntrack({"host": "h1", "mode": "list", "protocol": "udp"})
    assert captured["cmd"] == "LC_ALL=C conntrack -L -p udp"


def test_conntrack_rejects_protocol_with_stats(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_conntrack({"host": "h1", "mode": "stats", "protocol": "tcp"})


def test_conntrack_rejects_bad_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_conntrack({"host": "h1", "mode": "flush"})


def test_conntrack_rejects_bad_protocol(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_conntrack({"host": "h1", "mode": "list", "protocol": "sctp; rm -rf /"})


def test_conntrack_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_conntrack({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# net_protocol_stats
# ---------------------------------------------------------------------------


def test_net_protocol_stats_default_builder():
    assert mod.build_remote_cmd_net_protocol_stats(proto_flag=None) == "LC_ALL=C netstat -s"


def test_net_protocol_stats_flag_builders():
    assert (
        mod.build_remote_cmd_net_protocol_stats(proto_flag="--tcp") == "LC_ALL=C netstat -s --tcp"
    )
    assert (
        mod.build_remote_cmd_net_protocol_stats(proto_flag="--udp") == "LC_ALL=C netstat -s --udp"
    )
    assert (
        mod.build_remote_cmd_net_protocol_stats(proto_flag="--raw") == "LC_ALL=C netstat -s --raw"
    )


def test_net_protocol_stats_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"n\n", b"", 0, False))
    mod.handle_net_protocol_stats({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C netstat -s"


def test_net_protocol_stats_handler_each(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    for proto, flag in {"tcp": "--tcp", "udp": "--udp", "ip": "--raw"}.items():
        mod.handle_net_protocol_stats({"host": "h1", "protocol": proto})
        assert captured["cmd"] == f"LC_ALL=C netstat -s {flag}"


def test_net_protocol_stats_all_no_flag(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_net_protocol_stats({"host": "h1", "protocol": "all"})
    assert captured["cmd"] == "LC_ALL=C netstat -s"


def test_net_protocol_stats_rejects_bad_protocol(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_net_protocol_stats({"host": "h1", "protocol": "sctp"})


def test_net_protocol_stats_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_net_protocol_stats({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# nft_list
# ---------------------------------------------------------------------------


def test_nft_list_default_builder():
    assert mod.build_remote_cmd_nft_list() == "LC_ALL=C nft -nn list ruleset"


def test_nft_list_table_builder():
    cmd = mod.build_remote_cmd_nft_list(family="inet", table="filter")
    assert cmd == "LC_ALL=C nft -nn list table inet filter"


def test_nft_list_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"r\n", b"", 0, False))
    mod.handle_nft_list({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C nft -nn list ruleset"


def test_nft_list_handler_table(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_nft_list({"host": "h1", "family": "ip", "table": "nat"})
    assert captured["cmd"] == "LC_ALL=C nft -nn list table ip nat"


def test_nft_list_table_requires_family(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_nft_list({"host": "h1", "table": "filter"})


def test_nft_list_family_requires_table(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_nft_list({"host": "h1", "family": "inet"})


def test_nft_list_rejects_bad_family(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_nft_list({"host": "h1", "family": "ipx", "table": "filter"})


def test_nft_list_rejects_table_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_nft_list({"host": "h1", "family": "inet", "table": "filter; rm -rf /"})


def test_nft_list_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_nft_list({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# iptables_list
# ---------------------------------------------------------------------------


def test_iptables_list_default_builder():
    assert mod.build_remote_cmd_iptables_list(binary="iptables") == "LC_ALL=C iptables -n -v -L"


def test_iptables_list_table_builder():
    cmd = mod.build_remote_cmd_iptables_list(binary="iptables", table="nat")
    assert cmd == "LC_ALL=C iptables -n -v -L -t nat"


def test_iptables_list_ip6_builder():
    cmd = mod.build_remote_cmd_iptables_list(binary="ip6tables", table="filter")
    assert cmd == "LC_ALL=C ip6tables -n -v -L -t filter"


def test_iptables_list_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"r\n", b"", 0, False))
    mod.handle_iptables_list({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C iptables -n -v -L"


def test_iptables_list_handler_ipv6_table(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_iptables_list({"host": "h1", "family": "ipv6", "table": "mangle"})
    assert captured["cmd"] == "LC_ALL=C ip6tables -n -v -L -t mangle"


def test_iptables_list_rejects_bad_table(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_iptables_list({"host": "h1", "table": "bogus"})


def test_iptables_list_rejects_bad_family(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_iptables_list({"host": "h1", "family": "ipx"})


def test_iptables_list_rejects_table_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_iptables_list({"host": "h1", "table": "filter; rm -rf /"})


def test_iptables_list_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_iptables_list({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# dig
# ---------------------------------------------------------------------------


def test_dig_default_builder():
    assert mod.build_remote_cmd_dig(name="example.com") == "LC_ALL=C dig example.com"


def test_dig_type_and_server_builder():
    cmd = mod.build_remote_cmd_dig(name="example.com", record_type="MX", server="1.1.1.1")
    assert cmd == "LC_ALL=C dig @1.1.1.1 example.com MX"


def test_dig_all_plus_opts_builder():
    cmd = mod.build_remote_cmd_dig(
        name="example.com", short=True, tcp=True, trace=True, dnssec=True
    )
    assert cmd == "LC_ALL=C dig example.com +short +tcp +trace +dnssec"


def test_dig_reverse_builder():
    cmd = mod.build_remote_cmd_dig(name="8.8.8.8", reverse=True)
    assert cmd == "LC_ALL=C dig -x 8.8.8.8"


def test_dig_handler_default(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"out\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_dig({"host": "h1", "name": "example.com"})
    assert out == {
        "stdout": "out\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C dig example.com"


def test_dig_handler_type_lowercased(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_dig({"host": "h1", "name": "example.com", "record_type": "aaaa"})
    assert captured["cmd"] == "LC_ALL=C dig example.com AAAA"


def test_dig_handler_reverse(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_dig({"host": "h1", "name": "2001:db8::1", "reverse": True})
    assert captured["cmd"] == "LC_ALL=C dig -x 2001:db8::1"


def test_dig_handler_underscore_name(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_dig({"host": "h1", "name": "_dmarc.example.com", "record_type": "TXT"})
    assert captured["cmd"] == "LC_ALL=C dig _dmarc.example.com TXT"


def test_dig_rejects_missing_name(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dig({"host": "h1"})


def test_dig_rejects_bad_type(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dig({"host": "h1", "name": "example.com", "record_type": "AXFR"})


def test_dig_rejects_reverse_with_type(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dig({"host": "h1", "name": "8.8.8.8", "reverse": True, "record_type": "PTR"})


def test_dig_rejects_name_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dig({"host": "h1", "name": "example.com; rm -rf /"})


def test_dig_rejects_name_flag_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dig({"host": "h1", "name": "-oProxyCommand=evil"})


def test_dig_rejects_server_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dig({"host": "h1", "name": "example.com", "server": "1.1.1.1; evil"})


def test_dig_rejects_newline_in_name(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dig({"host": "h1", "name": "example.com\nfoo"})


def test_dig_rejects_nul_in_name(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dig({"host": "h1", "name": "example.com\x00"})


def test_dig_rejects_non_bool(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dig({"host": "h1", "name": "example.com", "short": "yes"})


def test_dig_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_dig({"host": "h1", "name": "example.com"})
    assert out["truncated"] is True
