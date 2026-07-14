import base64

import pytest

from linux_info_mcp.ssh import SshResult
from linux_info_mcp.tools import files as mod


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


def test_read_file_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"line1\nline2\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_read_file({"host": "h1", "path": "/etc/hosts"})
    assert out == {
        "stdout": "line1\nline2\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["host"] == "h1"
    assert captured["cmd"] == "LC_ALL=C cat -- /etc/hosts"


def test_read_file_with_grep(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"err\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_read_file(
        {
            "host": "h1",
            "path": "/var/log/syslog",
            "grep_pattern": "err",
            "grep_flags": ["-i", "-n"],
        }
    )
    assert out["stdout"] == "err\n"
    assert "grep -i -n -e err --" in captured["cmd"]


def test_read_file_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_read_file({"host": "-oProxyCommand=evil", "path": "/etc/hosts"})


def test_read_file_rejects_leading_dash_path(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_read_file({"host": "h1", "path": "-rf"})


def test_find_files_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"/var/log/a.log\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_find_files(
        {"host": "h1", "path": "/var/log", "type": "f", "name": "*.log", "maxdepth": 2}
    )
    assert out["exit_code"] == 0
    assert out["stdout"] == "/var/log/a.log\n"
    assert captured["cmd"] == "LC_ALL=C find /var/log -maxdepth 2 -type f -name '*.log'"


def test_find_files_rejects_bad_type(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_find_files({"host": "h1", "path": "/var", "type": "x"})


def test_find_files_rejects_leading_dash_path_delete(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_find_files({"host": "h1", "path": "-delete"})


def test_find_files_rejects_leading_dash_path_fls(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_find_files({"host": "h1", "path": "-fls"})


def test_read_binary_happy(monkeypatch):
    payload = b"\x00\x01\x02hello"
    b64 = base64.b64encode(payload)
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b64 + b"\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_read_binary({"host": "h1", "path": "/bin/ls", "offset": 0, "length": 8})
    assert out["bytes_read"] == len(payload)
    assert base64.b64decode(out["data_base64"]) == payload
    assert out["exit_code"] == 0
    assert out["truncated"] is False
    assert "dd if=/bin/ls ibs=1 skip=0 count=8" in captured["cmd"]


def test_read_binary_rejects_negative_offset(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_read_binary({"host": "h1", "path": "/bin/ls", "offset": -1, "length": 4})


def test_read_binary_truncation_propagates(monkeypatch):
    payload = b"abc"
    b64 = base64.b64encode(payload)
    _stub(
        monkeypatch,
        SshResult(stdout=b64, stderr=b"", exit_code=0, truncated=True),
    )
    out = mod.handle_read_binary({"host": "h1", "path": "/big", "offset": 0, "length": 3})
    assert out["truncated"] is True


def test_read_binary_corrupt_stream_signals_failure(monkeypatch):
    _stub(
        monkeypatch,
        SshResult(stdout=b"abc", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_read_binary({"host": "h1", "path": "/x", "offset": 0, "length": 4})
    assert out["bytes_read"] == 0
    assert out["exit_code"] == 1
    assert "[base64 decode failed]" in out["stderr"]


def test_read_file_decompress_autodetect(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"log\n", b"", 0, False))
    out = mod.handle_read_file({"host": "h1", "path": "/var/log/syslog.1.gz", "decompress": True})
    assert out["stdout"] == "log\n"
    assert captured["cmd"] == "LC_ALL=C gzip -dc -- /var/log/syslog.1.gz"


def test_read_file_decompress_zstd_with_grep(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"err\n", b"", 0, False))
    mod.handle_read_file(
        {
            "host": "h1",
            "path": "/a/b.zst",
            "decompress": True,
            "grep_pattern": "err",
            "grep_flags": ["-i"],
        }
    )
    assert captured["cmd"] == "LC_ALL=C zstd -dc -- /a/b.zst | grep -i -e err --"


def test_read_file_codec_override(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_read_file({"host": "h1", "path": "/data.log", "codec": "xz"})
    assert captured["cmd"] == "LC_ALL=C xz -dc -- /data.log"


def test_read_file_no_decompress_by_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_read_file({"host": "h1", "path": "/a/b.gz"})
    assert captured["cmd"] == "LC_ALL=C cat -- /a/b.gz"


def test_read_file_decompress_unknown_ext_rejected(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_read_file({"host": "h1", "path": "/a/b.log", "decompress": True})


def test_read_file_bad_codec_rejected(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_read_file({"host": "h1", "path": "/a/b.gz", "codec": "gzip; rm -rf /"})


def test_read_binary_decompress(monkeypatch):
    payload = b"decompressed"
    captured = _stub(monkeypatch, SshResult(base64.b64encode(payload), b"", 0, False))
    out = mod.handle_read_binary(
        {"host": "h1", "path": "/a/b.zst", "offset": 0, "length": 12, "decompress": True}
    )
    assert base64.b64decode(out["data_base64"]) == payload
    assert captured["cmd"] == (
        "LC_ALL=C zstd -dc -- /a/b.zst | dd ibs=1 skip=0 count=12 status=none | base64 -w 0"
    )


def test_read_binary_no_codec_uses_dd_if(monkeypatch):
    captured = _stub(monkeypatch, SshResult(base64.b64encode(b"abc"), b"", 0, False))
    mod.handle_read_binary({"host": "h1", "path": "/bin/ls", "offset": 0, "length": 3})
    assert (
        captured["cmd"] == "LC_ALL=C dd if=/bin/ls ibs=1 skip=0 count=3 status=none | base64 -w 0"
    )


def test_read_file_truncation_propagates(monkeypatch):
    _stub(
        monkeypatch,
        SshResult(stdout=b"x" * 10, stderr=b"", exit_code=0, truncated=True),
    )
    out = mod.handle_read_file({"host": "h1", "path": "/big"})
    assert out["truncated"] is True
