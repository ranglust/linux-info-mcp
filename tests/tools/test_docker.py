import pytest

from linux_info_mcp.ssh import SshResult
import linux_info_mcp.tools.docker as mod


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


# ---------------------------------------------------------------------------
# docker_ps
# ---------------------------------------------------------------------------


def test_ps_default_builder():
    assert mod.build_remote_cmd_docker_ps() == "LC_ALL=C docker ps"


def test_ps_all_flags_builder():
    cmd = mod.build_remote_cmd_docker_ps(
        all=True, size=True, quiet=True, no_trunc=True,
        format_flag="--format=json",
        filters=[("status", "running"), ("name", "web")],
    )
    assert cmd == (
        "LC_ALL=C docker ps -a -s -q --no-trunc --format=json "
        "--filter status=running --filter name=web"
    )


def test_ps_last_with_n():
    cmd = mod.build_remote_cmd_docker_ps(last=5)
    assert cmd == "LC_ALL=C docker ps -n 5"


def test_ps_latest():
    cmd = mod.build_remote_cmd_docker_ps(latest=True)
    assert cmd == "LC_ALL=C docker ps -l"


def test_ps_rejects_all_with_latest():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_docker_ps(all=True, latest=True)


def test_ps_rejects_all_with_last():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_docker_ps(all=True, last=3)


def test_ps_rejects_latest_with_last():
    with pytest.raises(ValueError):
        mod.build_remote_cmd_docker_ps(latest=True, last=3)


def test_ps_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"out\n", b"", 0, False))
    out = mod.handle_docker_ps({"host": "h1", "all": True, "format": "json"})
    assert out == {"stdout": "out\n", "stderr": "", "exit_code": 0, "truncated": False}
    assert captured["cmd"] == "LC_ALL=C docker ps -a --format=json"


def test_ps_handler_filter_dict(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_docker_ps({"host": "h1", "filter": {"status": "running"}})
    assert "--filter status=running" in captured["cmd"]


def test_ps_handler_filter_list_value(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_docker_ps({"host": "h1", "filter": {"label": ["app=web", "tier=front"]}})
    assert captured["cmd"].count("--filter") == 2
    assert "--filter label=app=web" in captured["cmd"]
    assert "--filter label=tier=front" in captured["cmd"]


def test_ps_handler_rejects_bad_filter_key(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_ps({"host": "h1", "filter": {"command": "rm"}})


def test_ps_handler_rejects_bad_filter_value(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_ps({"host": "h1", "filter": {"name": "web; rm -rf /"}})


def test_ps_handler_rejects_filter_value_leading_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_ps({"host": "h1", "filter": {"name": "-evil"}})


def test_ps_handler_rejects_filter_value_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_ps({"host": "h1", "filter": {"name": "web\nx"}})


def test_ps_handler_rejects_filter_value_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_ps({"host": "h1", "filter": {"name": "web\x00"}})


def test_ps_handler_rejects_bad_format(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_ps({"host": "h1", "format": "{{.Anything}}"})


def test_ps_handler_rejects_bad_last(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_ps({"host": "h1", "last": 0})


def test_ps_handler_rejects_non_bool_all(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_ps({"host": "h1", "all": "yes"})


def test_ps_handler_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_ps({"host": "-evil"})


def test_ps_truncation_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_docker_ps({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# docker_inspect
# ---------------------------------------------------------------------------


def test_inspect_default_builder():
    cmd = mod.build_remote_cmd_docker_inspect(targets=["abc123"])
    assert cmd == "LC_ALL=C docker inspect -- abc123"


def test_inspect_multiple_targets():
    cmd = mod.build_remote_cmd_docker_inspect(targets=["c1", "c2", "img:tag"])
    assert cmd == "LC_ALL=C docker inspect -- c1 c2 img:tag"


def test_inspect_with_type_and_format():
    cmd = mod.build_remote_cmd_docker_inspect(
        targets=["c1"], type_="container", format_flag="--format={{.Id}}", size=True,
    )
    assert cmd == (
        "LC_ALL=C docker inspect --type=container --format={{.Id}} -s -- c1"
    )


def test_inspect_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"[]\n", b"", 0, False))
    out = mod.handle_docker_inspect({"host": "h1", "targets": ["abc"], "type": "image"})
    assert out["exit_code"] == 0
    assert "--type=image" in captured["cmd"]
    assert captured["cmd"].endswith("-- abc")


def test_inspect_handler_format_id(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_docker_inspect({"host": "h1", "targets": ["c1"], "format": "id"})
    assert "--format={{.Id}}" in captured["cmd"]


def test_inspect_handler_format_json(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_docker_inspect({"host": "h1", "targets": ["c1"], "format": "json"})
    assert "--format" not in captured["cmd"]


def test_inspect_handler_rejects_missing_targets(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_inspect({"host": "h1"})


def test_inspect_handler_rejects_empty_targets(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_inspect({"host": "h1", "targets": []})


def test_inspect_handler_rejects_too_many_targets(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_inspect({"host": "h1", "targets": ["c"] * 101})


def test_inspect_handler_rejects_target_leading_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_inspect({"host": "h1", "targets": ["-rm"]})


def test_inspect_handler_rejects_target_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_inspect({"host": "h1", "targets": ["c1; rm -rf /"]})


def test_inspect_handler_rejects_target_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_inspect({"host": "h1", "targets": ["c1\nrm"]})


def test_inspect_handler_rejects_target_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_inspect({"host": "h1", "targets": ["c1\x00"]})


def test_inspect_handler_rejects_bad_type(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_inspect({"host": "h1", "targets": ["c1"], "type": "exec"})


def test_inspect_handler_rejects_bad_format(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_inspect({"host": "h1", "targets": ["c1"], "format": "{{.Anything}}"})


def test_inspect_truncation_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_docker_inspect({"host": "h1", "targets": ["c1"]})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# docker_images
# ---------------------------------------------------------------------------


def test_images_default_builder():
    assert mod.build_remote_cmd_docker_images() == "LC_ALL=C docker images"


def test_images_all_flags_builder():
    cmd = mod.build_remote_cmd_docker_images(
        all=True, digests=True, quiet=True, no_trunc=True,
        format_flag="--format=json",
        filters=[("dangling", "true"), ("reference", "myrepo:*")],
        repository="alpine",
    )
    assert cmd == (
        "LC_ALL=C docker images -a --digests -q --no-trunc --format=json "
        "--filter dangling=true --filter 'reference=myrepo:*' -- alpine"
    )


def test_images_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"REPO TAG\n", b"", 0, False))
    out = mod.handle_docker_images({"host": "h1", "all": True})
    assert out["exit_code"] == 0
    assert captured["cmd"] == "LC_ALL=C docker images -a"


def test_images_handler_repository(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_docker_images({"host": "h1", "repository": "myrepo:1.0"})
    assert captured["cmd"].endswith("-- myrepo:1.0")


def test_images_handler_rejects_bad_repository(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_images({"host": "h1", "repository": "alpine; rm -rf /"})


def test_images_handler_rejects_repository_leading_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_images({"host": "h1", "repository": "-evil"})


def test_images_handler_rejects_repository_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_images({"host": "h1", "repository": "alpine\n"})


def test_images_handler_rejects_repository_nul(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_images({"host": "h1", "repository": "alpine\x00"})


def test_images_handler_rejects_bad_filter_key(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_images({"host": "h1", "filter": {"name": "x"}})


def test_images_handler_rejects_bad_filter_value(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_images({"host": "h1", "filter": {"reference": "x; rm -rf /"}})


def test_images_handler_rejects_bad_format(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_images({"host": "h1", "format": "{{.Bad}}"})


def test_images_handler_rejects_non_bool_quiet(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_docker_images({"host": "h1", "quiet": 1})


def test_images_truncation_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_docker_images({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_tools_registered():
    names = [t.name for t in mod.TOOLS]
    assert names == ["docker_ps", "docker_inspect", "docker_images"]
    for t in mod.TOOLS:
        assert t.input_schema["type"] == "object"
        assert "host" in t.input_schema["required"]
