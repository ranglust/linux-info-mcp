import pytest

import linux_info_mcp.tools.kernel as mod
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
# dmesg
# ---------------------------------------------------------------------------


def test_dmesg_default_builder():
    assert mod.build_remote_cmd_dmesg() == "LC_ALL=C dmesg --no-pager"


def test_dmesg_human_builder():
    cmd = mod.build_remote_cmd_dmesg(human=True)
    assert cmd == "LC_ALL=C dmesg --no-pager -H"


def test_dmesg_time_iso_builder():
    cmd = mod.build_remote_cmd_dmesg(time_iso=True)
    assert cmd == "LC_ALL=C dmesg --no-pager --time-format=iso"


def test_dmesg_kernel_only_builder():
    cmd = mod.build_remote_cmd_dmesg(kernel_only=True)
    assert cmd == "LC_ALL=C dmesg --no-pager -k"


def test_dmesg_human_with_kernel_only_allowed():
    cmd = mod.build_remote_cmd_dmesg(human=True, kernel_only=True)
    assert cmd == "LC_ALL=C dmesg --no-pager -H -k"


def test_dmesg_level_facility_builder():
    cmd = mod.build_remote_cmd_dmesg(level="err", facility="kern")
    assert cmd == "LC_ALL=C dmesg --no-pager --level=err --facility=kern"


def test_dmesg_tail_lines_builder():
    cmd = mod.build_remote_cmd_dmesg(time_iso=True, tail_lines=50)
    assert cmd == "LC_ALL=C dmesg --no-pager --time-format=iso | tail -n 50"


def test_dmesg_rejects_human_with_time_iso():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_dmesg(human=True, time_iso=True)


def test_dmesg_handler_rejects_bad_level(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmesg({"host": "h1", "level": "warning"})


def test_dmesg_handler_rejects_bad_facility(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmesg({"host": "h1", "facility": "cron"})


def test_dmesg_handler_rejects_level_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmesg({"host": "h1", "level": "err; rm -rf /"})


def test_dmesg_handler_rejects_facility_flag_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmesg({"host": "h1", "facility": "-oProxyCommand=evil"})


def test_dmesg_handler_rejects_tail_lines_out_of_range(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmesg({"host": "h1", "tail_lines": 0})


def test_dmesg_handler_rejects_tail_lines_too_big(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmesg({"host": "h1", "tail_lines": 10001})


def test_dmesg_handler_rejects_host_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmesg({"host": "h1\nevil"})


def test_dmesg_handler_rejects_host_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmesg({"host": "h1\x00evil"})


def test_dmesg_handler_rejects_host_leading_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dmesg({"host": "-oProxyCommand=evil"})


def test_dmesg_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"d\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_dmesg({"host": "h1", "time_iso": True, "level": "err", "tail_lines": 100})
    assert out == {
        "stdout": "d\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == (
        "LC_ALL=C dmesg --no-pager --time-format=iso --level=err | tail -n 100"
    )


def test_dmesg_truncated_propagates(monkeypatch):
    _stub(
        monkeypatch,
        SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True),
    )
    out = mod.handle_dmesg({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# uname
# ---------------------------------------------------------------------------


def test_uname_all(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"Linux\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_uname({"host": "h1", "mode": "all"})
    assert captured["cmd"] == "LC_ALL=C uname -a"
    assert out["stdout"] == "Linux\n"


def test_uname_kernel_name(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_uname({"host": "h1", "mode": "kernel-name"})
    assert captured["cmd"] == "LC_ALL=C uname -s"


def test_uname_kernel_release(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_uname({"host": "h1", "mode": "kernel-release"})
    assert captured["cmd"] == "LC_ALL=C uname -r"


def test_uname_kernel_version(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_uname({"host": "h1", "mode": "kernel-version"})
    assert captured["cmd"] == "LC_ALL=C uname -v"


def test_uname_machine(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_uname({"host": "h1", "mode": "machine"})
    assert captured["cmd"] == "LC_ALL=C uname -m"


def test_uname_processor(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_uname({"host": "h1", "mode": "processor"})
    assert captured["cmd"] == "LC_ALL=C uname -p"


def test_uname_hardware_platform(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_uname({"host": "h1", "mode": "hardware-platform"})
    assert captured["cmd"] == "LC_ALL=C uname -i"


def test_uname_operating_system(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_uname({"host": "h1", "mode": "operating-system"})
    assert captured["cmd"] == "LC_ALL=C uname -o"


def test_uname_rejects_missing_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_uname({"host": "h1"})


def test_uname_rejects_bad_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_uname({"host": "h1", "mode": "bogus"})


def test_uname_rejects_injection_in_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_uname({"host": "h1", "mode": "all; rm -rf /"})


def test_uname_truncated_propagates(monkeypatch):
    _stub(
        monkeypatch,
        SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True),
    )
    out = mod.handle_uname({"host": "h1", "mode": "all"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# sysctl
# ---------------------------------------------------------------------------


def test_sysctl_key_builder():
    cmd = mod.build_remote_cmd_sysctl(key="kernel.hostname")
    assert cmd == "LC_ALL=C sysctl -- kernel.hostname"


def test_sysctl_all_builder():
    cmd = mod.build_remote_cmd_sysctl(all_keys=True)
    assert cmd == "LC_ALL=C sysctl -a"


def test_sysctl_all_with_pattern_builder():
    cmd = mod.build_remote_cmd_sysctl(all_keys=True, pattern="net.ipv4.*")
    assert cmd == "LC_ALL=C sysctl -a --pattern='net.ipv4.*'"


def test_sysctl_rejects_both_key_and_all():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_sysctl(key="kernel.hostname", all_keys=True)


def test_sysctl_rejects_neither_key_nor_all():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_sysctl()


def test_sysctl_handler_rejects_both(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_sysctl({"host": "h1", "key": "kernel.hostname", "all": True})


def test_sysctl_handler_rejects_neither(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_sysctl({"host": "h1"})


def test_sysctl_handler_rejects_bad_key(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_sysctl({"host": "h1", "key": "kernel.hostname; rm -rf /"})


def test_sysctl_handler_rejects_key_with_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_sysctl({"host": "h1", "key": "kernel\n.hostname"})


def test_sysctl_handler_rejects_key_with_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_sysctl({"host": "h1", "key": "kernel\x00hostname"})


def test_sysctl_handler_rejects_key_leading_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_sysctl({"host": "h1", "key": "-oProxyCommand=evil"})


def test_sysctl_handler_rejects_pattern_leading_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_sysctl({"host": "h1", "all": True, "pattern": "-oEvil"})


def test_sysctl_handler_rejects_pattern_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_sysctl({"host": "h1", "all": True, "pattern": "net; rm -rf /"})


def test_sysctl_handler_rejects_all_non_bool(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_sysctl({"host": "h1", "all": "yes"})


def test_sysctl_handler_happy_key(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"k = v\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_sysctl({"host": "h1", "key": "kernel.hostname"})
    assert out == {
        "stdout": "k = v\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C sysctl -- kernel.hostname"


def test_sysctl_handler_happy_all_pattern(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"out\n", stderr=b"", exit_code=0, truncated=False),
    )
    mod.handle_sysctl({"host": "h1", "all": True, "pattern": "net.ipv4.*"})
    assert captured["cmd"] == "LC_ALL=C sysctl -a --pattern='net.ipv4.*'"


def test_sysctl_truncated_propagates(monkeypatch):
    _stub(
        monkeypatch,
        SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True),
    )
    out = mod.handle_sysctl({"host": "h1", "all": True})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# TOOLS registration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# slabtop
# ---------------------------------------------------------------------------


def test_slabtop_builder():
    assert mod.build_remote_cmd_slabtop() == "LC_ALL=C slabtop -o"


def test_slabtop_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"slab\n", b"", 0, False))
    out = mod.handle_slabtop({"host": "h1"})
    assert out == {
        "stdout": "slab\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C slabtop -o"


def test_slabtop_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_slabtop({"host": "-evil"})


def test_slabtop_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_slabtop({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# numastat
# ---------------------------------------------------------------------------


def test_numastat_default_builder():
    assert mod.build_remote_cmd_numastat() == "LC_ALL=C numastat"


def test_numastat_pid_builder():
    assert mod.build_remote_cmd_numastat(pid=1234) == "LC_ALL=C numastat -p 1234"


def test_numastat_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"n\n", b"", 0, False))
    mod.handle_numastat({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C numastat"


def test_numastat_handler_pid(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_numastat({"host": "h1", "pid": 42})
    assert captured["cmd"] == "LC_ALL=C numastat -p 42"


def test_numastat_rejects_pid_zero(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_numastat({"host": "h1", "pid": 0})


def test_numastat_rejects_pid_bool(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_numastat({"host": "h1", "pid": True})


def test_numastat_rejects_pid_string(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_numastat({"host": "h1", "pid": "1; rm -rf /"})


def test_numastat_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_numastat({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# cgroup_stats
# ---------------------------------------------------------------------------


def test_cgroup_stats_cpu_builder():
    cmd = mod.build_remote_cmd_cgroup_stats(cgroup_path="user.slice", controller="cpu")
    assert cmd == "LC_ALL=C grep -H '' /sys/fs/cgroup/user.slice/cpu.stat"


def test_cgroup_stats_memory_builder():
    cmd = mod.build_remote_cmd_cgroup_stats(cgroup_path="user.slice", controller="memory")
    assert cmd == (
        "LC_ALL=C grep -H '' "
        "/sys/fs/cgroup/user.slice/memory.current "
        "/sys/fs/cgroup/user.slice/memory.stat "
        "/sys/fs/cgroup/user.slice/memory.pressure"
    )


def test_cgroup_stats_io_builder():
    cmd = mod.build_remote_cmd_cgroup_stats(cgroup_path="user.slice", controller="io")
    assert cmd == (
        "LC_ALL=C grep -H '' "
        "/sys/fs/cgroup/user.slice/io.stat "
        "/sys/fs/cgroup/user.slice/io.pressure"
    )


def test_cgroup_stats_all_builder():
    cmd = mod.build_remote_cmd_cgroup_stats(cgroup_path="x", controller="all")
    assert cmd == (
        "LC_ALL=C grep -H '' "
        "/sys/fs/cgroup/x/cpu.stat "
        "/sys/fs/cgroup/x/memory.current "
        "/sys/fs/cgroup/x/memory.stat "
        "/sys/fs/cgroup/x/memory.pressure "
        "/sys/fs/cgroup/x/io.stat "
        "/sys/fs/cgroup/x/io.pressure"
    )


def test_cgroup_stats_handler_default_is_all(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"c\n", b"", 0, False))
    mod.handle_cgroup_stats({"host": "h1", "cgroup_path": "user.slice"})
    assert captured["cmd"].startswith("LC_ALL=C grep -H '' /sys/fs/cgroup/user.slice/cpu.stat")


def test_cgroup_stats_requires_path(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises((ValueError, KeyError)):
        mod.handle_cgroup_stats({"host": "h1"})


def test_cgroup_stats_rejects_bad_controller(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_cgroup_stats({"host": "h1", "cgroup_path": "x", "controller": "pids"})


def test_cgroup_stats_rejects_traversal(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_cgroup_stats({"host": "h1", "cgroup_path": "../../etc/shadow"})


def test_cgroup_stats_rejects_leading_slash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_cgroup_stats({"host": "h1", "cgroup_path": "/etc"})


def test_cgroup_stats_rejects_path_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_cgroup_stats({"host": "h1", "cgroup_path": "x; rm -rf /"})


def test_cgroup_stats_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_cgroup_stats({"host": "h1", "cgroup_path": "x"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# systemd_analyze
# ---------------------------------------------------------------------------


def test_systemd_analyze_default_builder():
    assert mod.build_remote_cmd_systemd_analyze(mode="time") == (
        "LC_ALL=C systemd-analyze time --no-pager"
    )


def test_systemd_analyze_blame_builder():
    assert mod.build_remote_cmd_systemd_analyze(mode="blame") == (
        "LC_ALL=C systemd-analyze blame --no-pager"
    )


def test_systemd_analyze_critical_chain_builder():
    assert mod.build_remote_cmd_systemd_analyze(mode="critical-chain") == (
        "LC_ALL=C systemd-analyze critical-chain --no-pager"
    )


def test_systemd_analyze_critical_chain_unit_builder():
    cmd = mod.build_remote_cmd_systemd_analyze(mode="critical-chain", unit="sshd.service")
    assert cmd == "LC_ALL=C systemd-analyze critical-chain --no-pager sshd.service"


def test_systemd_analyze_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"t\n", b"", 0, False))
    mod.handle_systemd_analyze({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C systemd-analyze time --no-pager"


def test_systemd_analyze_rejects_bad_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_systemd_analyze({"host": "h1", "mode": "dump"})


def test_systemd_analyze_rejects_unit_without_critical_chain(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_systemd_analyze({"host": "h1", "mode": "time", "unit": "sshd.service"})


def test_systemd_analyze_rejects_unit_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_systemd_analyze(
            {"host": "h1", "mode": "critical-chain", "unit": "sshd; rm -rf /"}
        )


def test_systemd_analyze_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_systemd_analyze({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_tools_registry_names():
    names = [t.name for t in mod.TOOLS]
    assert names == [
        "dmesg",
        "uname",
        "sysctl",
        "slabtop",
        "numastat",
        "cgroup_stats",
        "systemd_analyze",
    ]
    for spec in mod.TOOLS:
        assert "host" in spec.input_schema["required"]
        assert callable(spec.handler)
