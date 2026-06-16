import linux_info_mcp.tools.triage as triage_mod
from linux_info_mcp.ssh import SshResult
from linux_info_mcp.tools.triage import (
    build_remote_cmd_triage,
    handle_triage,
    parse_triage,
)

# ---------------------------------------------------------------------------
# build_remote_cmd_triage
# ---------------------------------------------------------------------------


def test_triage_df_excludes_overlay():
    # docker overlay mounts duplicate the backing fs; exclude them from the disk probe.
    cmd = build_remote_cmd_triage()
    assert "-x overlay" in cmd


def test_build_cmd_is_single_fixed_sh_c():
    cmd = build_remote_cmd_triage()
    assert cmd.startswith("LC_ALL=C sh -c ")
    # All section markers are present in the fixed script.
    for marker in (
        "===loadavg===",
        "===nproc===",
        "===meminfo===",
        "===df===",
        "===failed_units===",
        "===psi_cpu===",
        "===oom===",
        "===END===",
    ):
        assert marker in cmd


# ---------------------------------------------------------------------------
# parse_triage — facts + warnings
# ---------------------------------------------------------------------------

_HEALTHY = """\
===loadavg===
0.10 0.20 0.15 1/200 12345
===nproc===
8
===meminfo===
MemTotal:       16384000 kB
MemAvailable:   12000000 kB
SwapTotal:       2048000 kB
SwapFree:        2048000 kB
===df===
Filesystem     1024-blocks    Used Available Capacity Mounted on
/dev/sda1         41252336 8765432  30387654      23% /
===failed_units===
===psi_cpu===
some avg10=0.50 avg60=0.40 avg300=0.30 total=123
full avg10=0.10 avg60=0.05 avg300=0.02 total=45
===psi_memory===
some avg10=0.00 avg60=0.00 avg300=0.00 total=0
===psi_io===
some avg10=1.00 avg60=0.50 avg300=0.20 total=999
===oom===
===END===
"""

_UNHEALTHY = """\
===loadavg===
20.00 18.00 15.00 9/400 99999
===nproc===
8
===meminfo===
MemTotal:       16384000 kB
MemAvailable:     500000 kB
SwapTotal:       2048000 kB
SwapFree:         512000 kB
===df===
Filesystem     1024-blocks    Used Available Capacity Mounted on
/dev/sda1         41252336 39000000   2252336      96% /
/dev/sdb1         10000000  3000000   7000000      30% /data
===failed_units===
nginx.service loaded failed failed A web server
postgresql.service loaded failed failed Database
===psi_cpu===
some avg10=35.00 avg60=20.00 avg300=10.00 total=99999
full avg10=15.00 avg60=8.00 avg300=4.00 total=55555
===psi_memory===
some avg10=0.00 avg60=0.00 avg300=0.00 total=0
===psi_io===
some avg10=1.00 avg60=0.50 avg300=0.20 total=999
===oom===
[12345.6] Out of memory: Killed process 4242 (java)
===END===
"""


def _kinds(warnings):
    return {w["kind"] for w in warnings}


def test_parse_healthy_has_no_warnings():
    out = parse_triage(_HEALTHY)
    assert out["warnings"] == []


def test_parse_healthy_facts():
    f = parse_triage(_HEALTHY)["facts"]
    assert f["load1"] == 0.10
    assert f["load5"] == 0.20
    assert f["load15"] == 0.15
    assert f["nproc"] == 8
    assert f["mem_total_kb"] == 16384000
    assert f["mem_available_kb"] == 12000000
    assert f["swap_total_kb"] == 2048000
    assert f["swap_free_kb"] == 2048000
    assert f["disks"] == [{"mount": "/", "use_pct": 23}]
    assert f["failed_units"] == []
    assert f["psi"]["cpu"] == 0.50
    assert f["psi"]["io"] == 1.00
    assert f["oom_recent"] == []


def test_parse_unhealthy_emits_all_warning_kinds():
    out = parse_triage(_UNHEALTHY)
    kinds = _kinds(out["warnings"])
    assert "high_load" in kinds
    assert "low_memory" in kinds
    assert "swap_pressure" in kinds
    assert "disk_full" in kinds
    assert "failed_units" in kinds
    assert "pressure" in kinds
    assert "oom_recent" in kinds


def test_parse_unhealthy_disk_full_is_crit_and_names_mount():
    out = parse_triage(_UNHEALTHY)
    disk = [w for w in out["warnings"] if w["kind"] == "disk_full"]
    assert len(disk) == 1  # only the 96% mount, not the 30% one
    assert disk[0]["severity"] == "crit"
    assert "/" in disk[0]["detail"]


def test_parse_unhealthy_failed_units_lists_names():
    out = parse_triage(_UNHEALTHY)
    fu = next(w for w in out["warnings"] if w["kind"] == "failed_units")
    assert "nginx.service" in fu["detail"]
    assert "postgresql.service" in fu["detail"]
    assert parse_triage(_UNHEALTHY)["facts"]["failed_units"] == [
        "nginx.service",
        "postgresql.service",
    ]


def test_parse_unhealthy_pressure_identifies_cpu():
    out = parse_triage(_UNHEALTHY)
    pressure = [w for w in out["warnings"] if w["kind"] == "pressure"]
    assert any("cpu" in w["detail"] for w in pressure)


def test_parse_unhealthy_oom_captured():
    out = parse_triage(_UNHEALTHY)
    assert out["facts"]["oom_recent"] == ["[12345.6] Out of memory: Killed process 4242 (java)"]


# ---------------------------------------------------------------------------
# degraded / empty sections must not crash
# ---------------------------------------------------------------------------


def test_parse_all_empty_sections_no_crash():
    text = (
        "===loadavg===\n===nproc===\n===meminfo===\n===df===\n"
        "===failed_units===\n===psi_cpu===\n===psi_memory===\n===psi_io===\n"
        "===oom===\n===END===\n"
    )
    out = parse_triage(text)
    assert out["warnings"] == []
    f = out["facts"]
    assert f["load1"] is None
    assert f["nproc"] is None
    assert f["disks"] == []
    assert f["failed_units"] == []
    assert f["psi"] == {"cpu": None, "memory": None, "io": None}
    assert f["oom_recent"] == []


def test_parse_total_garbage_no_crash():
    out = parse_triage("not even close to the expected format")
    assert isinstance(out["warnings"], list)
    assert isinstance(out["facts"], dict)


# ---------------------------------------------------------------------------
# handler + truncation propagation
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 360 additions: inodes, zombie/D-state, clock, conntrack, reboot, taint, nic
# ---------------------------------------------------------------------------


def test_build_cmd_has_360_markers():
    cmd = build_remote_cmd_triage()
    for marker in (
        "===df_inodes===",
        "===ps_states===",
        "===top_cpu===",
        "===clock===",
        "===conntrack===",
        "===reboot_required===",
        "===kernel_taint===",
        "===net_dev===",
    ):
        assert marker in cmd


_360_HEALTHY = """\
===loadavg===
0.10 0.20 0.15 1/200 1
===nproc===
8
===meminfo===
MemTotal:       16384000 kB
MemAvailable:   12000000 kB
SwapTotal:       2048000 kB
SwapFree:        2048000 kB
===df===
Filesystem     1024-blocks    Used Available Capacity Mounted on
/dev/sda1         41252336 8765432  30387654      23% /
===failed_units===
===psi_cpu===
some avg10=0.50 avg60=0.40 avg300=0.30 total=123
===psi_memory===
some avg10=0.00 avg60=0.00 avg300=0.00 total=0
===psi_io===
some avg10=1.00 avg60=0.50 avg300=0.20 total=999
===oom===
===df_inodes===
Filesystem      Inodes  IUsed   IFree IUse% Mounted on
/dev/sda1      2621440  85000 2536440    4% /
===ps_states===
Ss
R+
S
I
===top_cpu===
1234 postgres 12.0 5.0
5678 nginx 3.0 1.0
===clock===
Reference ID    : 0A2C023E (10.44.2.62)
System time     : 0.000000013 seconds fast of NTP time
Leap status     : Normal
===conntrack===
1234
262144
===reboot_required===
no
===kernel_taint===
0
===net_dev===
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 100 0 0 0 0 0 0 1000 100 0 0 0 0 0 0
  eth0: 50000 9000 0 0 0 0 0 0 60000 8000 0 0 0 0 0 0
===END===
"""

_360_UNHEALTHY = """\
===loadavg===
0.10 0.20 0.15 1/200 1
===nproc===
8
===meminfo===
MemTotal:       16384000 kB
MemAvailable:   12000000 kB
SwapTotal:       2048000 kB
SwapFree:        2048000 kB
===df===
Filesystem     1024-blocks    Used Available Capacity Mounted on
/dev/sda1         41252336 8765432  30387654      23% /
===failed_units===
===psi_cpu===
some avg10=0.50 avg60=0.40 avg300=0.30 total=123
===psi_memory===
some avg10=0.00 avg60=0.00 avg300=0.00 total=0
===psi_io===
some avg10=1.00 avg60=0.50 avg300=0.20 total=999
===oom===
===df_inodes===
Filesystem      Inodes  IUsed   IFree IUse% Mounted on
/dev/sda1      2621440 2600000  21440   99% /
===ps_states===
Ss
Z
D
D
D
D
D
D
===top_cpu===
1234 java 95.0 40.0
===clock===
Reference ID    : 0A2C023E (10.44.2.62)
System time     : 0.523000000 seconds slow of NTP time
Leap status     : Not synchronised
===conntrack===
259000
262144
===reboot_required===
yes
===kernel_taint===
512
===net_dev===
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 100 0 0 0 0 0 0 1000 100 0 0 0 0 0 0
  eth0: 50000 9000 500 200 0 0 0 0 60000 8000 0 0 0 0 0 0
===END===
"""


def test_360_healthy_facts_populated():
    f = parse_triage(_360_HEALTHY)["facts"]
    assert f["inodes"] == [{"mount": "/", "use_pct": 4}]
    assert f["zombie"] == 0
    assert f["dstate"] == 0
    assert f["top_cpu"][0] == {"pid": 1234, "comm": "postgres", "pcpu": 12.0, "pmem": 5.0}
    assert f["clock"] == {"offset_s": 0.000000013, "leap": "Normal"}
    assert f["conntrack"] == {"count": 1234, "max": 262144}
    assert f["reboot_required"] is False
    assert f["kernel_tainted"] == 0
    assert {n["iface"] for n in f["net_errors"]} == {"eth0"}  # lo excluded


def test_360_healthy_no_new_warnings():
    kinds = _kinds(parse_triage(_360_HEALTHY)["warnings"])
    for k in (
        "inodes_full",
        "zombie_procs",
        "stuck_procs",
        "clock_skew",
        "clock_unsynced",
        "conntrack_full",
        "reboot_required",
        "kernel_tainted",
        "nic_errors",
    ):
        assert k not in kinds


def test_360_unhealthy_emits_new_warning_kinds():
    out = parse_triage(_360_UNHEALTHY)
    kinds = _kinds(out["warnings"])
    assert "inodes_full" in kinds
    assert "zombie_procs" in kinds
    assert "stuck_procs" in kinds
    assert "clock_skew" in kinds
    assert "clock_unsynced" in kinds
    assert "conntrack_full" in kinds
    assert "reboot_required" in kinds
    assert "kernel_tainted" in kinds
    assert "nic_errors" in kinds


def test_360_unhealthy_inodes_crit():
    out = parse_triage(_360_UNHEALTHY)
    w = next(w for w in out["warnings"] if w["kind"] == "inodes_full")
    assert w["severity"] == "crit"
    assert "/" in w["detail"]


def test_360_unhealthy_conntrack_names_fraction():
    out = parse_triage(_360_UNHEALTHY)
    w = next(w for w in out["warnings"] if w["kind"] == "conntrack_full")
    assert "262144" in w["detail"]


def test_360_unhealthy_nic_names_iface():
    out = parse_triage(_360_UNHEALTHY)
    w = next(w for w in out["warnings"] if w["kind"] == "nic_errors")
    assert "eth0" in w["detail"]


def test_360_benign_taint_does_not_warn():
    # Out-of-tree module taint (bit 12 = 4096) is benign and must not warn;
    # most hosts running 3rd-party kernel modules carry it.
    text = _360_HEALTHY.replace("===kernel_taint===\n0\n", "===kernel_taint===\n4096\n")
    assert "kernel_tainted" not in _kinds(parse_triage(text)["warnings"])


def test_handle_triage_returns_warnings_facts(monkeypatch):
    monkeypatch.setattr(
        triage_mod,
        "run_ssh",
        lambda host, cmd: SshResult(
            stdout=_HEALTHY.encode(), stderr=b"", exit_code=0, truncated=False
        ),
    )
    out = handle_triage({"host": "h1"})
    assert out["warnings"] == []
    assert out["facts"]["nproc"] == 8
    assert out["exit_code"] == 0
    assert out["truncated"] is False


def test_handle_triage_truncation_propagates(monkeypatch):
    monkeypatch.setattr(
        triage_mod,
        "run_ssh",
        lambda host, cmd: SshResult(
            stdout=_HEALTHY.encode(), stderr=b"", exit_code=0, truncated=True
        ),
    )
    out = handle_triage({"host": "h1"})
    assert out["truncated"] is True


def test_handle_triage_validates_host():
    import pytest

    with pytest.raises(ValueError):
        handle_triage({"host": "-oProxyCommand=evil"})


def test_triage_registered_and_discovered():
    from linux_info_mcp import server as srv

    assert "triage" in srv._TOOLS
    assert srv._TOOLS["triage"].handler is handle_triage
