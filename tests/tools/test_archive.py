import base64

import pytest

from linux_info_mcp.ssh import SshResult
from linux_info_mcp.tools import archive as mod


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


def test_archive_list_tar_gz_autodetect(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"a\nb\n", b"", 0, False))
    out = mod.handle_archive_list({"host": "h1", "path": "/t/x.tar.gz"})
    assert out["stdout"] == "a\nb\n"
    assert captured["cmd"] == "LC_ALL=C tar -t -z -f /t/x.tar.gz"


def test_archive_list_tgz_maps_to_tar_gz(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_archive_list({"host": "h1", "path": "/t/x.tgz"})
    assert captured["cmd"] == "LC_ALL=C tar -t -z -f /t/x.tgz"


def test_archive_list_zstd(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_archive_list({"host": "h1", "path": "/t/x.tar.zst"})
    assert captured["cmd"] == "LC_ALL=C tar -t --zstd -f /t/x.tar.zst"


def test_archive_list_plain_tar(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_archive_list({"host": "h1", "path": "/t/x.tar"})
    assert captured["cmd"] == "LC_ALL=C tar -t -f /t/x.tar"


def test_archive_list_zip(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_archive_list({"host": "h1", "path": "/t/x.zip"})
    assert captured["cmd"] == "LC_ALL=C unzip -l /t/x.zip"


def test_archive_list_format_override(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_archive_list({"host": "h1", "path": "/t/blob", "format": "tar.xz"})
    assert captured["cmd"] == "LC_ALL=C tar -t -J -f /t/blob"


def test_archive_list_unknown_ext_rejected(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_archive_list({"host": "h1", "path": "/t/blob"})


def test_archive_list_bad_format_rejected(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_archive_list({"host": "h1", "path": "/t/x.tar", "format": "rar; id"})


def test_archive_read_tar_member_text(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"content\n", b"", 0, False))
    out = mod.handle_archive_read({"host": "h1", "path": "/t/x.tar.gz", "member": "etc/hosts"})
    assert out["stdout"] == "content\n"
    assert captured["cmd"] == "LC_ALL=C tar -xO -z -f /t/x.tar.gz -- etc/hosts"


def test_archive_read_tar_member_grep(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"err\n", b"", 0, False))
    mod.handle_archive_read(
        {
            "host": "h1",
            "path": "/t/x.tar",
            "member": "log.txt",
            "grep_pattern": "err",
            "grep_flags": ["-n"],
        }
    )
    assert (
        captured["cmd"]
        == "LC_ALL=C tar -xO -f /t/x.tar -- log.txt | grep -n -e err -- || [ $? -eq 1 ]"
    )


def test_archive_read_zip_member(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"z\n", b"", 0, False))
    mod.handle_archive_read({"host": "h1", "path": "/t/x.zip", "member": "dir/f.txt"})
    assert captured["cmd"] == "LC_ALL=C unzip -p /t/x.zip dir/f.txt"


def test_archive_read_binary(monkeypatch):
    payload = b"\x00\x01rawbytes"
    captured = _stub(monkeypatch, SshResult(base64.b64encode(payload), b"", 0, False))
    out = mod.handle_archive_read(
        {"host": "h1", "path": "/t/x.tar.zst", "member": "bin/blob", "binary": True}
    )
    assert base64.b64decode(out["data_base64"]) == payload
    assert out["bytes_read"] == len(payload)
    assert captured["cmd"] == "LC_ALL=C tar -xO --zstd -f /t/x.tar.zst -- bin/blob | base64 -w 0"


def test_archive_read_binary_with_grep_rejected(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_archive_read(
            {"host": "h1", "path": "/t/x.tar", "member": "f", "binary": True, "grep_pattern": "x"}
        )


def test_archive_read_member_leading_dash_rejected(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_archive_read({"host": "h1", "path": "/t/x.tar", "member": "--checkpoint=1"})


def test_archive_read_member_newline_rejected(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_archive_read({"host": "h1", "path": "/t/x.tar", "member": "a\nrm -rf /"})


def test_archive_read_member_shell_metachars_quoted(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_archive_read({"host": "h1", "path": "/t/x.tar", "member": "a b;rm -rf /"})
    assert captured["cmd"] == "LC_ALL=C tar -xO -f /t/x.tar -- 'a b;rm -rf /'"


def test_archive_read_bad_host_rejected(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_archive_read({"host": "-oProxyCommand=evil", "path": "/t/x.tar", "member": "f"})


def test_archive_list_truncation_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x" * 10, b"", 0, True))
    out = mod.handle_archive_list({"host": "h1", "path": "/t/x.tar"})
    assert out["truncated"] is True


def test_archive_read_truncation_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"data", b"", 0, True))
    out = mod.handle_archive_read({"host": "h1", "path": "/t/x.tar", "member": "f"})
    assert out["truncated"] is True


def test_archive_read_binary_corrupt_stream_signals_failure(monkeypatch):
    _stub(monkeypatch, SshResult(b"abc", b"", 0, False))
    out = mod.handle_archive_read({"host": "h1", "path": "/t/x.tar", "member": "f", "binary": True})
    assert out["bytes_read"] == 0
    assert out["exit_code"] == 1
    assert "[base64 decode failed]" in out["stderr"]
