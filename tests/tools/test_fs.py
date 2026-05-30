import pytest

from linux_info_mcp.ssh import SshResult
import linux_info_mcp.tools.fs as mod


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


# ---------------------------------------------------------------------------
# mount
# ---------------------------------------------------------------------------


def test_mount_default_builder():
    assert mod.build_remote_cmd_mount() == "LC_ALL=C mount"


def test_mount_verbose_only():
    assert mod.build_remote_cmd_mount(verbose=True) == "LC_ALL=C mount -v"


def test_mount_fstype_only():
    assert mod.build_remote_cmd_mount(fstype="ext4") == "LC_ALL=C mount -t ext4"


def test_mount_all_flags_builder():
    cmd = mod.build_remote_cmd_mount(fstype="xfs", verbose=True)
    assert cmd == "LC_ALL=C mount -v -t xfs"


def test_mount_handler_default(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"out\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_mount({"host": "h1"})
    assert out == {"stdout": "out\n", "stderr": "", "exit_code": 0, "truncated": False}
    assert captured["cmd"] == "LC_ALL=C mount"
    assert captured["host"] == "h1"


def test_mount_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"o", stderr=b"", exit_code=0, truncated=False),
    )
    mod.handle_mount({"host": "h1", "fstype": "ext4", "verbose": True})
    assert captured["cmd"] == "LC_ALL=C mount -v -t ext4"


def test_mount_handler_rejects_uppercase_fstype(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_mount({"host": "h1", "fstype": "EXT4"})


def test_mount_handler_rejects_fstype_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_mount({"host": "h1", "fstype": "ext4; rm -rf /"})


def test_mount_handler_rejects_fstype_leading_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_mount({"host": "h1", "fstype": "-oProxyCommand=evil"})


def test_mount_handler_rejects_fstype_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_mount({"host": "h1", "fstype": "ext\n4"})


def test_mount_handler_rejects_fstype_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_mount({"host": "h1", "fstype": "ext\x004"})


def test_mount_handler_rejects_fstype_too_long(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_mount({"host": "h1", "fstype": "a" * 33})


def test_mount_handler_rejects_bad_verbose(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_mount({"host": "h1", "verbose": "yes"})


def test_mount_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_mount({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# findmnt
# ---------------------------------------------------------------------------


def test_findmnt_default_builder():
    assert mod.build_remote_cmd_findmnt() == "LC_ALL=C findmnt"


def test_findmnt_json_only():
    assert mod.build_remote_cmd_findmnt(json=True) == "LC_ALL=C findmnt -J"


def test_findmnt_tree_only():
    assert mod.build_remote_cmd_findmnt(tree=True) == "LC_ALL=C findmnt -T"


def test_findmnt_rejects_json_and_tree():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_findmnt(json=True, tree=True)


def test_findmnt_target_uses_equals_form():
    cmd = mod.build_remote_cmd_findmnt(target="/var")
    assert cmd == "LC_ALL=C findmnt --target=/var"


def test_findmnt_source_uses_equals_form():
    cmd = mod.build_remote_cmd_findmnt(source="/dev/sda1")
    assert cmd == "LC_ALL=C findmnt --source=/dev/sda1"


def test_findmnt_fstype_separate_flag():
    cmd = mod.build_remote_cmd_findmnt(fstype="xfs")
    assert cmd == "LC_ALL=C findmnt -t xfs"


def test_findmnt_all_options():
    cmd = mod.build_remote_cmd_findmnt(
        json=True, target="/", source="/dev/sda1", fstype="ext4"
    )
    assert cmd == (
        "LC_ALL=C findmnt -J --target=/ --source=/dev/sda1 -t ext4"
    )


def test_findmnt_target_quotes_spaces():
    cmd = mod.build_remote_cmd_findmnt(target="/has space")
    assert cmd == "LC_ALL=C findmnt --target='/has space'"


def test_findmnt_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"x\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_findmnt({"host": "h1", "json": True, "fstype": "xfs"})
    assert out == {"stdout": "x\n", "stderr": "", "exit_code": 0, "truncated": False}
    assert captured["cmd"] == "LC_ALL=C findmnt -J -t xfs"


def test_findmnt_handler_rejects_json_and_tree(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_findmnt({"host": "h1", "json": True, "tree": True})


def test_findmnt_handler_rejects_target_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_findmnt({"host": "h1", "target": "/etc\n/passwd"})


def test_findmnt_handler_rejects_target_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_findmnt({"host": "h1", "target": "/etc\x00"})


def test_findmnt_handler_rejects_source_leading_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_findmnt({"host": "h1", "source": "-oProxyCommand=evil"})


def test_findmnt_handler_rejects_source_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_findmnt({"host": "h1", "source": "/dev/sda; rm -rf /"})


def test_findmnt_handler_rejects_source_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_findmnt({"host": "h1", "source": "/dev/sda\n"})


def test_findmnt_handler_rejects_source_too_long(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_findmnt({"host": "h1", "source": "a" * 257})


def test_findmnt_handler_rejects_bad_fstype(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_findmnt({"host": "h1", "fstype": "EXT4"})


def test_findmnt_handler_accepts_uri_source(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"", stderr=b"", exit_code=0, truncated=False),
    )
    mod.handle_findmnt({"host": "h1", "source": "nfs.example.com:/export"})
    assert captured["cmd"] == "LC_ALL=C findmnt --source=nfs.example.com:/export"


def test_findmnt_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_findmnt({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# stat_fs
# ---------------------------------------------------------------------------


def test_stat_fs_default_builder():
    cmd = mod.build_remote_cmd_stat_fs(path="/var")
    assert cmd == "LC_ALL=C stat -f -- /var"


def test_stat_fs_terse_builder():
    cmd = mod.build_remote_cmd_stat_fs(path="/var", format="terse")
    assert cmd == "LC_ALL=C stat -f -t -- /var"


def test_stat_fs_human_omits_flag():
    cmd = mod.build_remote_cmd_stat_fs(path="/var", format="human")
    assert cmd == "LC_ALL=C stat -f -- /var"


def test_stat_fs_default_explicit_omits_flag():
    cmd = mod.build_remote_cmd_stat_fs(path="/var", format="default")
    assert cmd == "LC_ALL=C stat -f -- /var"


def test_stat_fs_quotes_path():
    cmd = mod.build_remote_cmd_stat_fs(path="/has space")
    assert cmd == "LC_ALL=C stat -f -- '/has space'"


def test_stat_fs_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"info\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_stat_fs({"host": "h1", "path": "/"})
    assert out == {"stdout": "info\n", "stderr": "", "exit_code": 0, "truncated": False}
    assert captured["cmd"] == "LC_ALL=C stat -f -- /"


def test_stat_fs_handler_terse(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"", stderr=b"", exit_code=0, truncated=False),
    )
    mod.handle_stat_fs({"host": "h1", "path": "/var", "format": "terse"})
    assert captured["cmd"] == "LC_ALL=C stat -f -t -- /var"


def test_stat_fs_handler_requires_path(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat_fs({"host": "h1"})


def test_stat_fs_handler_rejects_empty_path(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat_fs({"host": "h1", "path": ""})


def test_stat_fs_handler_rejects_path_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat_fs({"host": "h1", "path": "/etc\n/passwd"})


def test_stat_fs_handler_rejects_path_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat_fs({"host": "h1", "path": "/etc\x00"})


def test_stat_fs_handler_rejects_unknown_format(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat_fs({"host": "h1", "path": "/", "format": "json"})


def test_stat_fs_handler_path_with_injection_is_quoted(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"", stderr=b"", exit_code=0, truncated=False),
    )
    mod.handle_stat_fs({"host": "h1", "path": "/tmp/a; rm -rf /"})
    assert captured["cmd"] == "LC_ALL=C stat -f -- '/tmp/a; rm -rf /'"


def test_stat_fs_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_stat_fs({"host": "h1", "path": "/"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# host validation propagation
# ---------------------------------------------------------------------------


def test_mount_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_mount({"host": "-oProxyCommand=evil"})


def test_findmnt_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_findmnt({"host": "host with space"})


def test_stat_fs_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat_fs({"host": "h\nbad", "path": "/"})


# ---------------------------------------------------------------------------
# TOOLS registration
# ---------------------------------------------------------------------------


def test_tools_registry_names():
    names = [t.name for t in mod.TOOLS]
    assert names == ["mount", "findmnt", "stat_fs"]
    for spec in mod.TOOLS:
        assert callable(spec.handler)
        assert "host" in spec.input_schema["required"]


def test_stat_fs_schema_requires_path():
    spec = next(t for t in mod.TOOLS if t.name == "stat_fs")
    assert spec.input_schema["required"] == ["host", "path"]
