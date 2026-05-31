import pytest

import linux_info_mcp.tools.disk as mod
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
# du
# ---------------------------------------------------------------------------


def test_du_default_builder():
    assert mod.build_remote_cmd_du(path="/var") == "LC_ALL=C du -- /var"


def test_du_all_flags_builder():
    cmd = mod.build_remote_cmd_du(
        path="/var/log",
        human=True,
        summary=True,
        max_depth=2,
        apparent=True,
        one_filesystem=True,
        threshold="100M",
    )
    assert cmd == ("LC_ALL=C du -h -s --max-depth=2 --apparent-size -x -t 100M -- /var/log")


def test_du_threshold_negative():
    cmd = mod.build_remote_cmd_du(path="/x", threshold="-1G")
    assert cmd == "LC_ALL=C du -t -1G -- /x"


def test_du_path_with_space_quoted():
    cmd = mod.build_remote_cmd_du(path="/var/has space")
    assert cmd == "LC_ALL=C du -- '/var/has space'"


def test_du_handler_rejects_bad_threshold(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_du({"host": "h1", "path": "/", "threshold": "100MB"})


def test_du_handler_rejects_threshold_with_semicolon(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_du({"host": "h1", "path": "/", "threshold": "1G; rm -rf /"})


def test_du_handler_rejects_threshold_with_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_du({"host": "h1", "path": "/", "threshold": "1G\nfoo"})


def test_du_handler_rejects_max_depth_out_of_range(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_du({"host": "h1", "path": "/", "max_depth": 11})


def test_du_handler_rejects_path_with_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_du({"host": "h1", "path": "/var\n/etc"})


def test_du_handler_rejects_path_with_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_du({"host": "h1", "path": "/var\x00/etc"})


def test_du_handler_rejects_missing_path(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(KeyError):
        mod.handle_du({"host": "h1"})


def test_du_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"4\t/var\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_du({"host": "h1", "path": "/var", "summary": True, "human": True})
    assert out == {
        "stdout": "4\t/var\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C du -h -s -- /var"


def test_du_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_du({"host": "h1", "path": "/"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# lsblk
# ---------------------------------------------------------------------------


def test_lsblk_default_builder():
    assert mod.build_remote_cmd_lsblk() == "LC_ALL=C lsblk"


def test_lsblk_json_builder():
    assert mod.build_remote_cmd_lsblk(json_out=True) == "LC_ALL=C lsblk -J"


def test_lsblk_pairs_builder():
    assert mod.build_remote_cmd_lsblk(pairs=True) == "LC_ALL=C lsblk -P"


def test_lsblk_tree_false_adds_l():
    assert mod.build_remote_cmd_lsblk(tree=False) == "LC_ALL=C lsblk -l"


def test_lsblk_tree_false_with_json_no_l():
    assert mod.build_remote_cmd_lsblk(tree=False, json_out=True) == "LC_ALL=C lsblk -J"


def test_lsblk_all_flags_builder():
    cmd = mod.build_remote_cmd_lsblk(
        json_out=True,
        paths=True,
        fs=True,
        discard=True,
        topology=True,
        device="/dev/sda",
    )
    assert cmd == "LC_ALL=C lsblk -J -p -f -D -t -- /dev/sda"


def test_lsblk_rejects_json_and_pairs():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_lsblk(json_out=True, pairs=True)


def test_lsblk_handler_rejects_json_and_pairs(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsblk({"host": "h1", "json": True, "pairs": True})


def test_lsblk_handler_rejects_device_with_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsblk({"host": "h1", "device": "/dev/sda\nfoo"})


def test_lsblk_handler_rejects_device_with_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_lsblk({"host": "h1", "device": "/dev/sda\x00"})


def test_lsblk_handler_quotes_injection_in_device(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_lsblk({"host": "h1", "device": "/dev/sda; rm -rf /"})
    assert captured["cmd"] == "LC_ALL=C lsblk -- '/dev/sda; rm -rf /'"


def test_lsblk_handler_dash_device_after_dashdash(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_lsblk({"host": "h1", "device": "-oProxyCommand=evil"})
    assert captured["cmd"] == "LC_ALL=C lsblk -- -oProxyCommand=evil"


def test_lsblk_handler_default_tree(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_lsblk({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C lsblk"


def test_lsblk_handler_tree_false(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_lsblk({"host": "h1", "tree": False})
    assert captured["cmd"] == "LC_ALL=C lsblk -l"


def test_lsblk_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"NAME\nsda\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_lsblk({"host": "h1", "fs": True, "paths": True})
    assert out == {
        "stdout": "NAME\nsda\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C lsblk -p -f"


def test_lsblk_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_lsblk({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# blkid
# ---------------------------------------------------------------------------


def test_blkid_default_builder():
    assert mod.build_remote_cmd_blkid() == "LC_ALL=C blkid"


def test_blkid_with_device_builder():
    assert mod.build_remote_cmd_blkid(device="/dev/sda1") == "LC_ALL=C blkid -- /dev/sda1"


def test_blkid_probe_with_device_builder():
    assert (
        mod.build_remote_cmd_blkid(device="/dev/sda1", probe=True)
        == "LC_ALL=C blkid -p -- /dev/sda1"
    )


def test_blkid_rejects_probe_without_device():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_blkid(probe=True)


def test_blkid_handler_rejects_probe_without_device(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_blkid({"host": "h1", "probe": True})


def test_blkid_handler_rejects_device_with_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_blkid({"host": "h1", "device": "/dev/sda\n"})


def test_blkid_handler_rejects_device_with_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_blkid({"host": "h1", "device": "/dev/sda\x00"})


def test_blkid_handler_quotes_injection(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_blkid({"host": "h1", "device": "/dev/sda; rm -rf /"})
    assert captured["cmd"] == "LC_ALL=C blkid -- '/dev/sda; rm -rf /'"


def test_blkid_handler_dash_device_after_dashdash(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_blkid({"host": "h1", "device": "-oProxyCommand=evil"})
    assert captured["cmd"] == "LC_ALL=C blkid -- -oProxyCommand=evil"


def test_blkid_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"out\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_blkid({"host": "h1", "device": "/dev/sda1", "probe": True})
    assert out == {
        "stdout": "out\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C blkid -p -- /dev/sda1"


def test_blkid_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_blkid({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# smartctl
# ---------------------------------------------------------------------------


def test_smartctl_info_mode(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_smartctl({"host": "h1", "device": "/dev/sda", "mode": "info"})
    assert captured["cmd"] == "LC_ALL=C smartctl -i -- /dev/sda"


def test_smartctl_health_mode(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_smartctl({"host": "h1", "device": "/dev/sda", "mode": "health"})
    assert captured["cmd"] == "LC_ALL=C smartctl -H -- /dev/sda"


def test_smartctl_attributes_mode(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_smartctl({"host": "h1", "device": "/dev/sda", "mode": "attributes"})
    assert captured["cmd"] == "LC_ALL=C smartctl -A -- /dev/sda"


def test_smartctl_all_mode(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_smartctl({"host": "h1", "device": "/dev/sda", "mode": "all"})
    assert captured["cmd"] == "LC_ALL=C smartctl -a -- /dev/sda"


def test_smartctl_capabilities_mode(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_smartctl({"host": "h1", "device": "/dev/sda", "mode": "capabilities"})
    assert captured["cmd"] == "LC_ALL=C smartctl -c -- /dev/sda"


def test_smartctl_rejects_bad_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_smartctl({"host": "h1", "device": "/dev/sda", "mode": "selftest"})


def test_smartctl_rejects_missing_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_smartctl({"host": "h1", "device": "/dev/sda"})


def test_smartctl_rejects_device_with_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_smartctl({"host": "h1", "device": "/dev/sda\nfoo", "mode": "info"})


def test_smartctl_rejects_device_with_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_smartctl({"host": "h1", "device": "/dev/sda\x00", "mode": "info"})


def test_smartctl_handler_quotes_injection(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_smartctl({"host": "h1", "device": "/dev/sda; rm -rf /", "mode": "info"})
    assert captured["cmd"] == "LC_ALL=C smartctl -i -- '/dev/sda; rm -rf /'"


def test_smartctl_dash_device_after_dashdash(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_smartctl({"host": "h1", "device": "-oProxyCommand=evil", "mode": "info"})
    assert captured["cmd"] == "LC_ALL=C smartctl -i -- -oProxyCommand=evil"


def test_smartctl_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"smart\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_smartctl({"host": "h1", "device": "/dev/sda", "mode": "all"})
    assert out == {
        "stdout": "smart\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C smartctl -a -- /dev/sda"


def test_smartctl_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_smartctl({"host": "h1", "device": "/dev/sda", "mode": "info"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# TOOLS registration
# ---------------------------------------------------------------------------


def test_tools_registry_names():
    names = [t.name for t in mod.TOOLS]
    assert names == ["du", "lsblk", "blkid", "smartctl"]
    for spec in mod.TOOLS:
        assert "host" in spec.input_schema["required"]
        assert callable(spec.handler)


def test_du_schema_requires_path():
    spec = next(t for t in mod.TOOLS if t.name == "du")
    assert "path" in spec.input_schema["required"]


def test_smartctl_schema_requires_device_and_mode():
    spec = next(t for t in mod.TOOLS if t.name == "smartctl")
    req = spec.input_schema["required"]
    assert "device" in req
    assert "mode" in req
