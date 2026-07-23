import pytest

import linux_info_mcp.tools.perf as mod
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
# iostat
# ---------------------------------------------------------------------------


def test_iostat_default_builder():
    assert mod.build_remote_cmd_iostat() == "LC_ALL=C iostat"


def test_iostat_all_flags_builder():
    cmd = mod.build_remote_cmd_iostat(
        extended=True,
        kilobytes=True,
        omit_zero=True,
        device_only=True,
        interval=2,
        count=5,
        devices=["sda", "nvme0n1"],
    )
    assert cmd == "LC_ALL=C iostat -x -k -z -d -p sda -p nvme0n1 2 5"


def test_iostat_megabytes_only():
    cmd = mod.build_remote_cmd_iostat(megabytes=True, cpu_only=True)
    assert cmd == "LC_ALL=C iostat -m -c"


def test_iostat_rejects_kilo_and_mega():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_iostat(kilobytes=True, megabytes=True)


def test_iostat_rejects_device_and_cpu_only():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_iostat(device_only=True, cpu_only=True)


def test_iostat_rejects_count_without_interval():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_iostat(count=3)


def test_iostat_handler_count_without_interval(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_iostat({"host": "h1", "count": 3})


def test_iostat_handler_rejects_bad_device(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_iostat({"host": "h1", "devices": ["sda; rm -rf /"]})


def test_iostat_handler_rejects_interval_out_of_range(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_iostat({"host": "h1", "interval": 0})


def test_iostat_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"out\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_iostat(
        {"host": "h1", "extended": True, "kilobytes": True, "interval": 1, "count": 2}
    )
    assert out == {
        "stdout": "out\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["host"] == "h1"
    assert captured["cmd"] == "LC_ALL=C iostat -x -k 1 2"


# ---------------------------------------------------------------------------
# vmstat
# ---------------------------------------------------------------------------


def test_vmstat_default_builder():
    assert mod.build_remote_cmd_vmstat() == "LC_ALL=C vmstat"


def test_vmstat_all_flags_builder():
    cmd = mod.build_remote_cmd_vmstat(
        wide=True, active=True, disk=True, unit="M", interval=1, count=4
    )
    assert cmd == "LC_ALL=C vmstat -w -a -d -S M 1 4"


def test_vmstat_summary_flag():
    cmd = mod.build_remote_cmd_vmstat(summary=True, unit="k")
    assert cmd == "LC_ALL=C vmstat -s -S k"


def test_vmstat_rejects_disk_and_summary():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_vmstat(disk=True, summary=True)


def test_vmstat_rejects_count_without_interval():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_vmstat(count=2)


def test_vmstat_handler_rejects_bad_unit(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_vmstat({"host": "h1", "unit": "gB"})


def test_vmstat_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"vm\n", stderr=b"e", exit_code=0, truncated=False),
    )
    out = mod.handle_vmstat({"host": "h1", "wide": True, "interval": 2})
    assert out == {
        "stdout": "vm\n",
        "stderr": "e",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C vmstat -w 2"


# ---------------------------------------------------------------------------
# free
# ---------------------------------------------------------------------------


def test_free_default_builder():
    assert mod.build_remote_cmd_free() == "LC_ALL=C free"


def test_free_all_flags_builder():
    cmd = mod.build_remote_cmd_free(unit_flag="-h", wide=True, total=True, interval=5, count=3)
    assert cmd == "LC_ALL=C free -h -w -t -s 5 -c 3"


def test_free_tera_flag_builder():
    cmd = mod.build_remote_cmd_free(unit_flag="--tera")
    assert cmd == "LC_ALL=C free --tera"


def test_free_handler_rejects_bad_unit(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_free({"host": "h1", "unit": "terabyte"})


def test_free_handler_count_without_interval(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_free({"host": "h1", "count": 2})


def test_free_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"f\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_free({"host": "h1", "unit": "mega", "total": True})
    assert out == {
        "stdout": "f\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C free -m -t"


# ---------------------------------------------------------------------------
# df
# ---------------------------------------------------------------------------


def test_df_default_builder():
    assert mod.build_remote_cmd_df() == "LC_ALL=C df"


def test_df_all_flags_builder():
    cmd = mod.build_remote_cmd_df(
        human=True,
        inodes=True,
        local=True,
        print_type=True,
        block_size="1K",
        exclude_type=["tmpfs", "devtmpfs"],
        paths=["/", "/var"],
    )
    assert cmd == ("LC_ALL=C df -h -i -l -T -B 1K -x tmpfs -x devtmpfs -- / /var")


def test_df_handler_rejects_bad_block_size(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_df({"host": "h1", "block_size": "0K"})


def test_df_handler_rejects_uppercase_exclude_type(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_df({"host": "h1", "exclude_type": ["EXT4"]})


def test_df_handler_rejects_path_with_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_df({"host": "h1", "paths": ["/var\n/etc"]})


def test_df_handler_paths_quote_spaces(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"", stderr=b"", exit_code=0, truncated=False),
    )
    mod.handle_df({"host": "h1", "paths": ["/tmp/has space", "/var"]})
    assert "-- '/tmp/has space' /var" in captured["cmd"]


def test_df_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"x\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_df({"host": "h1", "human": True, "paths": ["/"]})
    assert out == {
        "stdout": "x\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C df -h -- /"


# ---------------------------------------------------------------------------
# ps
# ---------------------------------------------------------------------------


def test_ps_default_builder_via_handler(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"p\n", stderr=b"", exit_code=0, truncated=False),
    )
    mod.handle_ps({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C ps auxf"


def test_ps_mode_aux_sort_mem(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"", stderr=b"", exit_code=0, truncated=False),
    )
    mod.handle_ps({"host": "h1", "mode": "aux-sort-mem"})
    assert captured["cmd"] == "LC_ALL=C ps aux --sort=-rss"


def test_ps_mode_forest(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_ps({"host": "h1", "mode": "forest"})
    assert captured["cmd"] == "LC_ALL=C ps -ef --forest"


def test_ps_user_flag(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_ps({"host": "h1", "mode": "aux", "user": "root"})
    assert captured["cmd"] == "LC_ALL=C ps aux -u root"


def test_ps_pid_flag(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_ps({"host": "h1", "mode": "ef", "pid": 1234})
    assert captured["cmd"] == "LC_ALL=C ps -ef -p 1234"


def test_ps_rejects_user_and_pid(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ps({"host": "h1", "user": "root", "pid": 1})


def test_ps_rejects_bad_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ps({"host": "h1", "mode": "auxr"})


def test_ps_rejects_bad_user(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ps({"host": "h1", "user": "1bad"})


def test_ps_rejects_pid_out_of_range(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ps({"host": "h1", "pid": 0})


def test_ps_handler_happy(monkeypatch):
    _stub(
        monkeypatch,
        SshResult(stdout=b"p\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_ps({"host": "h1", "mode": "aux"})
    assert out == {
        "stdout": "p\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }


# ---------------------------------------------------------------------------
# TOOLS registration
# ---------------------------------------------------------------------------


def test_tools_registry_names():
    names = [t.name for t in mod.TOOLS]
    assert names == ["iostat", "vmstat", "free", "df", "ps", "psi_stats", "meminfo"]
    for spec in mod.TOOLS:
        assert spec.input_schema["required"] == ["host"]
        assert callable(spec.handler)


def _stub_truncated(monkeypatch):
    def fake(host, cmd):
        return SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True)

    monkeypatch.setattr(mod, "run_ssh", fake)


def test_iostat_truncated_propagates(monkeypatch):
    _stub_truncated(monkeypatch)
    assert mod.handle_iostat({"host": "h"})["truncated"] is True


def test_vmstat_truncated_propagates(monkeypatch):
    _stub_truncated(monkeypatch)
    assert mod.handle_vmstat({"host": "h"})["truncated"] is True


def test_free_truncated_propagates(monkeypatch):
    _stub_truncated(monkeypatch)
    assert mod.handle_free({"host": "h"})["truncated"] is True


def test_df_truncated_propagates(monkeypatch):
    _stub_truncated(monkeypatch)
    assert mod.handle_df({"host": "h"})["truncated"] is True


def test_ps_truncated_propagates(monkeypatch):
    _stub_truncated(monkeypatch)
    assert mod.handle_ps({"host": "h"})["truncated"] is True


# ---------------------------------------------------------------------------
# psi_stats
# ---------------------------------------------------------------------------


def test_psi_stats_default_builder():
    assert mod.build_remote_cmd_psi_stats(resource="all") == (
        "LC_ALL=C grep -H '' /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io"
    )


def test_psi_stats_single_builder():
    assert mod.build_remote_cmd_psi_stats(resource="cpu") == "LC_ALL=C cat /proc/pressure/cpu"
    assert mod.build_remote_cmd_psi_stats(resource="memory") == "LC_ALL=C cat /proc/pressure/memory"
    assert mod.build_remote_cmd_psi_stats(resource="io") == "LC_ALL=C cat /proc/pressure/io"


def test_psi_stats_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"some avg10\n", b"", 0, False))
    out = mod.handle_psi_stats({"host": "h1"})
    assert out == {
        "stdout": "some avg10\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == (
        "LC_ALL=C grep -H '' /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io"
    )


def test_psi_stats_handler_single(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_psi_stats({"host": "h1", "resource": "io"})
    assert captured["cmd"] == "LC_ALL=C cat /proc/pressure/io"


def test_psi_stats_rejects_bad_resource(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_psi_stats({"host": "h1", "resource": "disk"})


def test_psi_stats_rejects_resource_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_psi_stats({"host": "h1", "resource": "cpu; rm -rf /"})


def test_psi_stats_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_psi_stats({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# meminfo
# ---------------------------------------------------------------------------


def test_meminfo_default_builder():
    assert mod.build_remote_cmd_meminfo() == "LC_ALL=C cat /proc/meminfo"


def test_meminfo_fields_builder():
    cmd = mod.build_remote_cmd_meminfo(fields=["MemFree", "Committed_AS"])
    assert cmd == "LC_ALL=C cat /proc/meminfo | grep -E '^(MemFree|Committed_AS):' || [ $? -eq 1 ]"


def test_meminfo_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"MemTotal: 1 kB\n", b"", 0, False))
    out = mod.handle_meminfo({"host": "h1"})
    assert out["stdout"] == "MemTotal: 1 kB\n"
    assert captured["cmd"] == "LC_ALL=C cat /proc/meminfo"


def test_meminfo_handler_fields(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_meminfo({"host": "h1", "fields": ["Slab", "Dirty"]})
    assert (
        captured["cmd"] == "LC_ALL=C cat /proc/meminfo | grep -E '^(Slab|Dirty):' || [ $? -eq 1 ]"
    )


def test_meminfo_rejects_field_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_meminfo({"host": "h1", "fields": ["MemFree; rm -rf /"]})


def test_meminfo_rejects_field_with_pipe(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_meminfo({"host": "h1", "fields": ["Mem|Free"]})


def test_meminfo_rejects_field_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_meminfo({"host": "h1", "fields": ["Mem\nFree"]})


def test_meminfo_rejects_non_list_fields(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_meminfo({"host": "h1", "fields": "MemFree"})


def test_meminfo_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_meminfo({"host": "h1"})
    assert out["truncated"] is True
