import pytest

import linux_info_mcp.tools.sys as mod
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
# uptime
# ---------------------------------------------------------------------------


def test_uptime_default_builder():
    assert mod.build_remote_cmd_uptime() == "LC_ALL=C uptime"


def test_uptime_pretty_builder():
    assert mod.build_remote_cmd_uptime(pretty=True) == "LC_ALL=C uptime -p"


def test_uptime_since_builder():
    assert mod.build_remote_cmd_uptime(since=True) == "LC_ALL=C uptime -s"


def test_uptime_rejects_pretty_and_since():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_uptime(pretty=True, since=True)


def test_uptime_handler_rejects_pretty_and_since(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_uptime({"host": "h1", "pretty": True, "since": True})


def test_uptime_handler_rejects_non_bool(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_uptime({"host": "h1", "pretty": "yes"})


def test_uptime_handler_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_uptime({"host": "-oProxyCommand=evil"})


def test_uptime_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"up 1 day\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_uptime({"host": "h1", "pretty": True})
    assert out == {
        "stdout": "up 1 day\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C uptime -p"


def test_uptime_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_uptime({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# who
# ---------------------------------------------------------------------------


def test_who_default_builder():
    assert mod.build_remote_cmd_who() == "LC_ALL=C who"


def test_who_all_flags_builder():
    cmd = mod.build_remote_cmd_who(all=True, boot=True, login=True, runlevel=True, users=True)
    assert cmd == "LC_ALL=C who -a -b -l -r -q"


def test_who_handler_rejects_non_bool(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_who({"host": "h1", "all": "yes"})


def test_who_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"u\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_who({"host": "h1", "boot": True, "users": True})
    assert out["stdout"] == "u\n"
    assert captured["cmd"] == "LC_ALL=C who -b -q"


def test_who_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_who({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# last
# ---------------------------------------------------------------------------


def test_last_default_builder():
    assert mod.build_remote_cmd_last() == "LC_ALL=C last"


def test_last_lines_builder():
    assert mod.build_remote_cmd_last(lines=10) == "LC_ALL=C last -n 10"


def test_last_user_builder():
    assert mod.build_remote_cmd_last(user="root") == "LC_ALL=C last -- root"


def test_last_user_and_tty_builder():
    cmd = mod.build_remote_cmd_last(lines=5, user="root", tty="pts/0")
    assert cmd == "LC_ALL=C last -n 5 -- root pts/0"


def test_last_handler_rejects_lines_too_low(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_last({"host": "h1", "lines": 0})


def test_last_handler_rejects_lines_too_high(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_last({"host": "h1", "lines": 1001})


def test_last_handler_rejects_bad_user_uppercase(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_last({"host": "h1", "user": "Root"})


def test_last_handler_rejects_user_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_last({"host": "h1", "user": "root; rm -rf /"})


def test_last_handler_rejects_user_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_last({"host": "h1", "user": "root\nfoo"})


def test_last_handler_rejects_user_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_last({"host": "h1", "user": "root\x00"})


def test_last_handler_rejects_user_too_long(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_last({"host": "h1", "user": "a" * 33})


def test_last_handler_rejects_tty_leading_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_last({"host": "h1", "tty": "-oProxyCommand=evil"})


def test_last_handler_rejects_tty_bad_chars(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_last({"host": "h1", "tty": "pts 0"})


def test_last_handler_rejects_tty_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_last({"host": "h1", "tty": "pts/0\n"})


def test_last_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"l\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_last({"host": "h1", "lines": 5, "user": "root", "tty": "pts/0"})
    assert out["stdout"] == "l\n"
    assert captured["cmd"] == "LC_ALL=C last -n 5 -- root pts/0"


def test_last_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_last({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# lscpu
# ---------------------------------------------------------------------------


def test_lscpu_default_builder():
    assert mod.build_remote_cmd_lscpu() == "LC_ALL=C lscpu"


def test_lscpu_json_builder():
    assert mod.build_remote_cmd_lscpu(json_out=True) == "LC_ALL=C lscpu -J"


def test_lscpu_extended_builder():
    assert mod.build_remote_cmd_lscpu(extended=True) == "LC_ALL=C lscpu -e"


def test_lscpu_parseable_builder():
    assert mod.build_remote_cmd_lscpu(parseable=True) == "LC_ALL=C lscpu -p"


def test_lscpu_rejects_json_and_extended():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_lscpu(json_out=True, extended=True)


def test_lscpu_rejects_json_and_parseable():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_lscpu(json_out=True, parseable=True)


def test_lscpu_rejects_extended_and_parseable():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_lscpu(extended=True, parseable=True)


def test_lscpu_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"c\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_lscpu({"host": "h1", "json": True})
    assert out["stdout"] == "c\n"
    assert captured["cmd"] == "LC_ALL=C lscpu -J"


def test_lscpu_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_lscpu({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# lsmem
# ---------------------------------------------------------------------------


def test_lsmem_default_builder():
    assert mod.build_remote_cmd_lsmem() == "LC_ALL=C lsmem"


def test_lsmem_json_builder():
    assert mod.build_remote_cmd_lsmem(json_out=True) == "LC_ALL=C lsmem -J"


def test_lsmem_summary_builder():
    assert mod.build_remote_cmd_lsmem(summary=True) == "LC_ALL=C lsmem -s only"


def test_lsmem_bytes_builder():
    assert mod.build_remote_cmd_lsmem(bytes_unit=True) == "LC_ALL=C lsmem -b"


def test_lsmem_summary_and_bytes_builder():
    assert mod.build_remote_cmd_lsmem(summary=True, bytes_unit=True) == "LC_ALL=C lsmem -s only -b"


def test_lsmem_rejects_json_and_summary():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_lsmem(json_out=True, summary=True)


def test_lsmem_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"m\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_lsmem({"host": "h1", "bytes": True})
    assert out["stdout"] == "m\n"
    assert captured["cmd"] == "LC_ALL=C lsmem -b"


def test_lsmem_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_lsmem({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# dmidecode
# ---------------------------------------------------------------------------


def test_dmidecode_builder_bios():
    assert mod.build_remote_cmd_dmidecode(type="bios") == "LC_ALL=C dmidecode -t bios"


def test_dmidecode_handler_requires_type(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmidecode({"host": "h1"})


def test_dmidecode_handler_rejects_bad_type(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmidecode({"host": "h1", "type": "kernel"})


def test_dmidecode_handler_rejects_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmidecode({"host": "h1", "type": "bios; rm -rf /"})


def test_dmidecode_handler_rejects_leading_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmidecode({"host": "h1", "type": "-oProxyCommand=evil"})


def test_dmidecode_handler_rejects_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmidecode({"host": "h1", "type": "bios\n"})


def test_dmidecode_handler_rejects_uppercase(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmidecode({"host": "h1", "type": "BIOS"})


def test_dmidecode_handler_all_whitelisted_types(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"d\n", stderr=b"", exit_code=0, truncated=False),
    )
    for t in [
        "bios",
        "system",
        "baseboard",
        "chassis",
        "processor",
        "memory",
        "cache",
        "connector",
        "slot",
    ]:
        mod.handle_dmidecode({"host": "h1", "type": t})
        assert captured["cmd"] == f"LC_ALL=C dmidecode -t {t}"


def test_dmidecode_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"d\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_dmidecode({"host": "h1", "type": "memory"})
    assert out["stdout"] == "d\n"
    assert captured["cmd"] == "LC_ALL=C dmidecode -t memory"


def test_dmidecode_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_dmidecode({"host": "h1", "type": "bios"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# lspci
# ---------------------------------------------------------------------------


def test_lspci_default_builder():
    assert mod.build_remote_cmd_lspci() == "LC_ALL=C lspci"


def test_lspci_all_flags_builder():
    assert (
        mod.build_remote_cmd_lspci(numeric=True, verbose=True, kernel=True)
        == "LC_ALL=C lspci -nn -vv -k"
    )


def test_lspci_tree_builder():
    assert mod.build_remote_cmd_lspci(tree=True) == "LC_ALL=C lspci -t"


def test_lspci_rejects_tree_with_verbose():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_lspci(tree=True, verbose=True)


def test_lspci_rejects_tree_with_kernel():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_lspci(tree=True, kernel=True)


def test_lspci_handler_rejects_tree_with_verbose(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lspci({"host": "h1", "tree": True, "verbose": True})


def test_lspci_handler_rejects_non_bool(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lspci({"host": "h1", "numeric": "yes"})


def test_lspci_handler_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lspci({"host": "-oProxyCommand=evil"})


def test_lspci_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"00:00.0 Host bridge\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_lspci({"host": "h1", "numeric": True})
    assert out["stdout"] == "00:00.0 Host bridge\n"
    assert captured["cmd"] == "LC_ALL=C lspci -nn"


def test_lspci_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_lspci({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# lsusb
# ---------------------------------------------------------------------------


def test_lsusb_default_builder():
    assert mod.build_remote_cmd_lsusb() == "LC_ALL=C lsusb"


def test_lsusb_verbose_builder():
    assert mod.build_remote_cmd_lsusb(verbose=True) == "LC_ALL=C lsusb -v"


def test_lsusb_tree_builder():
    assert mod.build_remote_cmd_lsusb(tree=True) == "LC_ALL=C lsusb -t"


def test_lsusb_rejects_verbose_and_tree():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_lsusb(verbose=True, tree=True)


def test_lsusb_handler_rejects_verbose_and_tree(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsusb({"host": "h1", "verbose": True, "tree": True})


def test_lsusb_handler_rejects_non_bool(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsusb({"host": "h1", "tree": "yes"})


def test_lsusb_handler_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsusb({"host": "-oProxyCommand=evil"})


def test_lsusb_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"Bus 001 Device 001\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_lsusb({"host": "h1", "tree": True})
    assert out["stdout"] == "Bus 001 Device 001\n"
    assert captured["cmd"] == "LC_ALL=C lsusb -t"


def test_lsusb_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_lsusb({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# TOOLS registration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# sensors
# ---------------------------------------------------------------------------


def test_sensors_default_builder():
    assert mod.build_remote_cmd_sensors() == "LC_ALL=C sensors"


def test_sensors_json_builder():
    assert mod.build_remote_cmd_sensors(json=True) == "LC_ALL=C sensors -j"


def test_sensors_fahrenheit_builder():
    assert mod.build_remote_cmd_sensors(fahrenheit=True) == "LC_ALL=C sensors -f"


def test_sensors_json_and_fahrenheit_builder():
    assert mod.build_remote_cmd_sensors(json=True, fahrenheit=True) == "LC_ALL=C sensors -j -f"


def test_sensors_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"coretemp\n", b"", 0, False))
    out = mod.handle_sensors({"host": "h1", "json": True})
    assert out["stdout"] == "coretemp\n"
    assert out["exit_code"] == 0
    assert captured["cmd"] == "LC_ALL=C sensors -j"


def test_sensors_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_sensors({"host": "-oProxyCommand=evil"})


def test_sensors_rejects_non_bool_json(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_sensors({"host": "h1", "json": "yes"})


def test_sensors_truncation_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_sensors({"host": "h1"})
    assert out["truncated"] is True


def test_tools_registry_names():
    names = [t.name for t in mod.TOOLS]
    assert names == [
        "uptime",
        "who",
        "last",
        "lscpu",
        "lsmem",
        "dmidecode",
        "lspci",
        "lsusb",
        "sensors",
    ]
    for spec in mod.TOOLS:
        assert "host" in spec.input_schema["required"]
        assert callable(spec.handler)
