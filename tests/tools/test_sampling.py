import pytest

import linux_info_mcp.tools.sampling as mod
from linux_info_mcp.ssh import SshResult


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


_OK = SshResult(stdout=b"out", stderr=b"", exit_code=0, truncated=False, stderr_truncated=False)


# ---------------------------------------------------------------------------
# sar
# ---------------------------------------------------------------------------


def test_sar_default_builder():
    assert mod.build_remote_cmd_sar(metric_flags=["-u"]) == "LC_ALL=C sar -u"


def test_sar_default_metric_is_cpu(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_sar({"host": "h"})
    assert cap["cmd"] == "LC_ALL=C sar -u"


def test_sar_mem_from_file_with_window(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_sar(
        {
            "host": "h",
            "metrics": ["mem"],
            "file": "/var/log/sysstat/sa23",
            "start": "19:00:00",
            "end": "19:30:00",
        }
    )
    assert cap["cmd"] == "LC_ALL=C sar -r -f /var/log/sysstat/sa23 -s 19:00:00 -e 19:30:00"


def test_sar_paging_metric(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_sar({"host": "h", "metrics": ["paging"], "file": "/var/log/sysstat/sa23"})
    assert cap["cmd"] == "LC_ALL=C sar -B -f /var/log/sysstat/sa23"


def test_sar_swap_metric(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_sar({"host": "h", "metrics": ["swap"], "file": "/var/log/sysstat/sa23"})
    assert cap["cmd"] == "LC_ALL=C sar -W -f /var/log/sysstat/sa23"


def test_sar_multi_metric_order_and_dedup(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_sar({"host": "h", "metrics": ["cpu", "mem", "cpu"]})
    assert cap["cmd"] == "LC_ALL=C sar -u -r"


def test_sar_net_and_disk_multitoken():
    cmd = mod.build_remote_cmd_sar(metric_flags=["-n", "DEV", "-d", "-p"])
    assert cmd == "LC_ALL=C sar -n DEV -d -p"


def test_sar_all_metric_alone(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_sar({"host": "h", "metrics": ["all", "mem"]})
    assert cap["cmd"] == "LC_ALL=C sar -A"


def test_sar_live_interval_count(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_sar({"host": "h", "metrics": ["cpu"], "interval": 2, "count": 5})
    assert cap["cmd"] == "LC_ALL=C sar -u 2 5"


def test_sar_rejects_count_without_interval():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_sar(metric_flags=["-u"], count=3)


def test_sar_rejects_interval_with_file():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_sar(metric_flags=["-u"], file="/var/log/sysstat/sa23", interval=1)


def test_sar_rejects_start_without_file():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_sar(metric_flags=["-u"], start="19:00:00")


def test_sar_rejects_unknown_metric():
    with pytest.raises(ValueError):
        mod.handle_sar({"host": "h", "metrics": ["bogus"]})


def test_sar_rejects_bad_time():
    with pytest.raises(ValueError):
        mod.handle_sar({"host": "h", "file": "/var/log/sysstat/sa23", "start": "25:99"})


def test_sar_rejects_path_injection():
    for bad in ["-oProxyCommand=evil", "a\nb", "a\x00b"]:
        with pytest.raises(ValueError):
            mod.handle_sar({"host": "h", "file": bad})


def test_sar_quotes_shell_metachars(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_sar({"host": "h", "file": "/var/log/sa;rm -rf /"})
    assert "'/var/log/sa;rm -rf /'" in cap["cmd"]


def test_sar_sudo(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    assert mod.build_remote_cmd_sar(metric_flags=["-u"]) == "LC_ALL=C sudo -n sar -u"


def test_sar_truncation_propagates(monkeypatch):
    res = SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True, stderr_truncated=False)
    _stub(monkeypatch, res)
    out = mod.handle_sar({"host": "h"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# atop
# ---------------------------------------------------------------------------


def test_atop_default_live_builder():
    assert mod.build_remote_cmd_atop(view_tokens=[], interval=1, count=1) == "LC_ALL=C atop 1 1"


def test_atop_live_defaults_interval_count(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_atop({"host": "h", "mode": "memory"})
    assert cap["cmd"] == "LC_ALL=C atop -m 1 1"


def test_atop_replay_with_mode_and_window(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_atop(
        {
            "host": "h",
            "file": "/var/log/atop/atop_20260623",
            "mode": "memory",
            "begin": "19:20",
            "end": "19:27",
        }
    )
    assert cap["cmd"] == "LC_ALL=C atop -r /var/log/atop/atop_20260623 -m -b 19:20 -e 19:27"


def test_atop_parseable_labels(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_atop({"host": "h", "labels": ["CPU", "MEM"], "interval": 2, "count": 3})
    assert cap["cmd"] == "LC_ALL=C atop -P CPU,MEM 2 3"


def test_atop_rejects_mode_and_labels():
    with pytest.raises(ValueError):
        mod.handle_atop({"host": "h", "mode": "memory", "labels": ["CPU"]})


def test_atop_rejects_unknown_mode():
    with pytest.raises(ValueError):
        mod.handle_atop({"host": "h", "mode": "bogus"})


def test_atop_rejects_unknown_label():
    with pytest.raises(ValueError):
        mod.handle_atop({"host": "h", "labels": ["BOGUS"]})


def test_atop_rejects_begin_without_file():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_atop(view_tokens=[], begin="19:20")


def test_atop_rejects_interval_with_file():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_atop(view_tokens=["-m"], file="/var/log/atop/a", interval=1)


def test_atop_rejects_path_injection():
    for bad in ["-rootkit", "a\nb", "a\x00b"]:
        with pytest.raises(ValueError):
            mod.handle_atop({"host": "h", "file": bad})


def test_atop_quotes_shell_metachars(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_atop({"host": "h", "mode": "memory", "file": "/var/log/atop/x;reboot"})
    assert "'/var/log/atop/x;reboot'" in cap["cmd"]


def test_atop_rejects_bad_time():
    with pytest.raises(ValueError):
        mod.handle_atop({"host": "h", "file": "/var/log/atop/a", "begin": "99:99"})


def test_atop_sudo(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    cmd = mod.build_remote_cmd_atop(view_tokens=["-m"], interval=1, count=1)
    assert cmd == "LC_ALL=C sudo -n atop -m 1 1"


def test_atop_truncation_propagates(monkeypatch):
    res = SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True, stderr_truncated=False)
    _stub(monkeypatch, res)
    out = mod.handle_atop({"host": "h", "mode": "memory"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# pmrep
# ---------------------------------------------------------------------------


def test_pmrep_default_builder():
    assert mod.build_remote_cmd_pmrep(config=":vmstat") == "LC_ALL=C pmrep -t 1 -s 1 :vmstat"


def test_pmrep_default_config(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_pmrep({"host": "h"})
    assert cap["cmd"] == "LC_ALL=C pmrep -t 1 -s 1 :vmstat"


def test_pmrep_config_interval_samples(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_pmrep({"host": "h", "config": "iostat", "interval": 2, "samples": 5})
    assert cap["cmd"] == "LC_ALL=C pmrep -t 2 -s 5 :iostat"


def test_pmrep_archive(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_pmrep({"host": "h", "config": "sar", "archive": "/var/log/pcp/pmlogger/h/20260623"})
    assert cap["cmd"] == "LC_ALL=C pmrep -a /var/log/pcp/pmlogger/h/20260623 -t 1 -s 1 :sar"


def test_pmrep_rejects_unknown_config():
    with pytest.raises(ValueError):
        mod.handle_pmrep({"host": "h", "config": "bogus"})


def test_pmrep_rejects_archive_injection():
    for bad in ["-oProxyCommand=evil", "a\nb", "a\x00b"]:
        with pytest.raises(ValueError):
            mod.handle_pmrep({"host": "h", "archive": bad})


def test_pmrep_quotes_shell_metachars(monkeypatch):
    cap = _stub(monkeypatch, _OK)
    mod.handle_pmrep({"host": "h", "archive": "/var/log/pcp/a;rm -rf /"})
    assert "'/var/log/pcp/a;rm -rf /'" in cap["cmd"]


def test_pmrep_sudo(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    assert (
        mod.build_remote_cmd_pmrep(config=":vmstat") == "LC_ALL=C sudo -n pmrep -t 1 -s 1 :vmstat"
    )


def test_pmrep_truncation_propagates(monkeypatch):
    res = SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True, stderr_truncated=False)
    _stub(monkeypatch, res)
    out = mod.handle_pmrep({"host": "h"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_tools_registered():
    names = {t.name for t in mod.TOOLS}
    assert names == {"atop", "sar", "pmrep"}
