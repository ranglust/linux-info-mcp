import pytest

import linux_info_mcp.tools.fs as mod
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
    assert out == {
        "stdout": "out\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
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
    cmd = mod.build_remote_cmd_findmnt(json=True, target="/", source="/dev/sda1", fstype="ext4")
    assert cmd == ("LC_ALL=C findmnt -J --target=/ --source=/dev/sda1 -t ext4")


def test_findmnt_target_quotes_spaces():
    cmd = mod.build_remote_cmd_findmnt(target="/has space")
    assert cmd == "LC_ALL=C findmnt --target='/has space'"


def test_findmnt_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"x\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_findmnt({"host": "h1", "json": True, "fstype": "xfs"})
    assert out == {
        "stdout": "x\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
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


def test_stat_fs_builder_rejects_unknown_format():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_stat_fs(path="/var", format="human")


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
    assert out == {
        "stdout": "info\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
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
# stat
# ---------------------------------------------------------------------------


def test_stat_default_builder():
    assert mod.build_remote_cmd_stat(paths=["/etc"]) == "LC_ALL=C stat -- /etc"


def test_stat_all_flags_builder():
    cmd = mod.build_remote_cmd_stat(
        paths=["/a", "/b c"],
        dereference=True,
        file_system=True,
        cached="never",
    )
    assert cmd == "LC_ALL=C stat -L -f --cached=never -- /a '/b c'"


def test_stat_terse_builder():
    assert mod.build_remote_cmd_stat(paths=["/x"], terse=True) == "LC_ALL=C stat -t -- /x"


def test_stat_format_builder_quotes():
    cmd = mod.build_remote_cmd_stat(paths=["/x"], format="%n %U:%G %a")
    assert cmd == "LC_ALL=C stat --format='%n %U:%G %a' -- /x"


def test_stat_builder_terse_format_exclusive():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_stat(paths=["/x"], terse=True, format="%n")


def test_stat_builder_rejects_bad_cached():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_stat(paths=["/x"], cached="sometimes")


def test_stat_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"out\n", b"", 0, False))
    out = mod.handle_stat({"host": "h1", "paths": ["/etc/passwd"]})
    assert out == {
        "stdout": "out\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C stat -- /etc/passwd"


def test_stat_handler_format_perms(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_stat({"host": "h1", "paths": ["/k.pem"], "format": "%U %G %a %A"})
    assert captured["cmd"] == "LC_ALL=C stat --format='%U %G %a %A' -- /k.pem"


@pytest.mark.parametrize(
    "fmt",
    ["%n", "%%", "100%% %s", "%-10n|%5s", "%.3Y", "%Hd:%Ld %Hr %Lr", "%C", "%W %w", "plain"],
)
def test_stat_handler_accepts_file_formats(monkeypatch, fmt):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_stat({"host": "h1", "paths": ["/"], "format": fmt})


@pytest.mark.parametrize("fmt", ["%n %c %S %l %T", "%a %b %d %f %i %s %t"])
def test_stat_handler_accepts_fs_formats(monkeypatch, fmt):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_stat({"host": "h1", "paths": ["/"], "format": fmt, "file_system": True})


@pytest.mark.parametrize(
    "fmt",
    ["%", "abc%", "%q", "%H", "%Lx", "%1234n", "%n\n", "%n\x00", "", "%" + "n" * 600],
)
def test_stat_handler_rejects_bad_file_formats(monkeypatch, fmt):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat({"host": "h1", "paths": ["/"], "format": fmt})


@pytest.mark.parametrize("fmt", ["%U", "%A", "%y", "%Hd"])
def test_stat_handler_rejects_file_directives_in_fs_mode(monkeypatch, fmt):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat({"host": "h1", "paths": ["/"], "format": fmt, "file_system": True})


def test_stat_handler_format_injection_is_quoted(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_stat({"host": "h1", "paths": ["/"], "format": "%n'; rm -rf / #"})
    assert captured["cmd"] == "LC_ALL=C stat --format='%n'\"'\"'; rm -rf / #' -- /"


def test_stat_handler_format_dollar_not_expanded(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_stat({"host": "h1", "paths": ["/"], "format": "$(id) %n"})
    assert captured["cmd"] == "LC_ALL=C stat --format='$(id) %n' -- /"


def test_stat_handler_terse_and_format_rejected(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat({"host": "h1", "paths": ["/"], "terse": True, "format": "%n"})


@pytest.mark.parametrize(
    "paths",
    [None, [], "/etc", ["-L"], ["/ok", "-oProxyCommand=evil"], ["/a\n/b"], ["/a\x00"], [""], [1]],
)
def test_stat_handler_rejects_bad_paths(monkeypatch, paths):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    args = {"host": "h1"}
    if paths is not None:
        args["paths"] = paths
    with pytest.raises(ValueError):
        mod.handle_stat(args)


def test_stat_handler_rejects_too_many_paths(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat({"host": "h1", "paths": [f"/p{i}" for i in range(101)]})


def test_stat_handler_path_injection_is_quoted(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_stat({"host": "h1", "paths": ["/a; rm -rf /", "/b"]})
    assert captured["cmd"] == "LC_ALL=C stat -- '/a; rm -rf /' /b"


@pytest.mark.parametrize("key", ["dereference", "file_system", "terse"])
def test_stat_handler_rejects_non_bool(monkeypatch, key):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat({"host": "h1", "paths": ["/"], key: "yes"})


@pytest.mark.parametrize("cached", ["sometimes", "", 1, "--evil"])
def test_stat_handler_rejects_bad_cached(monkeypatch, cached):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat({"host": "h1", "paths": ["/"], "cached": cached})


def test_stat_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_stat({"host": "h1", "paths": ["/"]})
    assert out["truncated"] is True


def test_stat_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_stat({"host": "-oProxyCommand=evil", "paths": ["/"]})


def test_stat_schema_requires_paths():
    spec = next(t for t in mod.TOOLS if t.name == "stat")
    assert spec.input_schema["required"] == ["host", "paths"]


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
    assert names == ["mount", "findmnt", "stat_fs", "stat"]
    for spec in mod.TOOLS:
        assert callable(spec.handler)
        assert "host" in spec.input_schema["required"]


def test_stat_fs_schema_requires_path():
    spec = next(t for t in mod.TOOLS if t.name == "stat_fs")
    assert spec.input_schema["required"] == ["host", "path"]
