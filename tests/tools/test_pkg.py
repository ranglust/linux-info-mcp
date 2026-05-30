import pytest

from linux_info_mcp.ssh import SshResult
import linux_info_mcp.tools.pkg as mod


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


# ---------------------------------------------------------------------------
# pattern validator
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "-bad",
        "--remove",
        "; rm -rf /",
        "foo;bar",
        "foo bar",
        "foo\nbar",
        "foo\x00bar",
        "-oProxyCommand=evil",
        "a" * 129,
        "foo$bar",
        "foo|bar",
        "foo`bar`",
    ],
)
def test_pkg_pattern_rejects_bad(bad):
    with pytest.raises(ValueError):
        mod._validate_pkg_pattern(bad)


@pytest.mark.parametrize(
    "good",
    [
        "bash",
        "lib*",
        "openssh-server",
        "python3.11",
        "foo+bar",
        "a?b",
        "x.y.z",
        "a" * 128,
    ],
)
def test_pkg_pattern_accepts_good(good):
    assert mod._validate_pkg_pattern(good) == good


def test_pkg_pattern_rejects_non_string():
    with pytest.raises(ValueError):
        mod._validate_pkg_pattern(123)


# ---------------------------------------------------------------------------
# dpkg_list
# ---------------------------------------------------------------------------


def test_dpkg_list_default_builder():
    assert mod.build_remote_cmd_dpkg_list() == "LC_ALL=C dpkg -l"


def test_dpkg_list_with_pattern_builder():
    cmd = mod.build_remote_cmd_dpkg_list(pattern="bash")
    assert cmd == "LC_ALL=C dpkg -l -- bash"


def test_dpkg_list_pattern_with_glob_quoted():
    cmd = mod.build_remote_cmd_dpkg_list(pattern="lib*")
    assert cmd == "LC_ALL=C dpkg -l -- 'lib*'"


def test_dpkg_list_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"ii bash\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_dpkg_list({"host": "h1", "pattern": "bash"})
    assert out == {
        "stdout": "ii bash\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
    }
    assert captured["host"] == "h1"
    assert captured["cmd"] == "LC_ALL=C dpkg -l -- bash"


def test_dpkg_list_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_dpkg_list({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C dpkg -l"


@pytest.mark.parametrize(
    "bad",
    ["-r", "--remove", "; rm -rf /", "pkg\n", "pkg\x00", "-oProxyCommand=evil"],
)
def test_dpkg_list_rejects_injection(monkeypatch, bad):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dpkg_list({"host": "h1", "pattern": bad})


def test_dpkg_list_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_dpkg_list({"host": "-evilhost"})


def test_dpkg_list_truncated_propagates(monkeypatch):
    _stub(
        monkeypatch,
        SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True),
    )
    out = mod.handle_dpkg_list({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# rpm_list
# ---------------------------------------------------------------------------


def test_rpm_list_default_builder():
    assert mod.build_remote_cmd_rpm_list() == "LC_ALL=C rpm -qa"


def test_rpm_list_with_pattern_builder():
    cmd = mod.build_remote_cmd_rpm_list(pattern="kernel*")
    assert cmd == "LC_ALL=C rpm -qa -- 'kernel*'"


def test_rpm_list_with_last_builder():
    cmd = mod.build_remote_cmd_rpm_list(last=True)
    assert cmd == "LC_ALL=C rpm -qa --last"


def test_rpm_list_with_last_and_pattern_builder():
    cmd = mod.build_remote_cmd_rpm_list(pattern="bash", last=True)
    assert cmd == "LC_ALL=C rpm -qa --last -- bash"


def test_rpm_list_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"bash-5.1\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_rpm_list({"host": "h1", "pattern": "bash", "last": True})
    assert out == {
        "stdout": "bash-5.1\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C rpm -qa --last -- bash"


def test_rpm_list_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_rpm_list({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C rpm -qa"


def test_rpm_list_rejects_bad_last_type(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_rpm_list({"host": "h1", "last": "yes"})


@pytest.mark.parametrize(
    "bad",
    ["-r", "--erase", "; rm -rf /", "pkg\n", "pkg\x00", "-oProxyCommand=evil"],
)
def test_rpm_list_rejects_injection(monkeypatch, bad):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_rpm_list({"host": "h1", "pattern": bad})


def test_rpm_list_truncated_propagates(monkeypatch):
    _stub(
        monkeypatch,
        SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True),
    )
    out = mod.handle_rpm_list({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# apt_list_installed
# ---------------------------------------------------------------------------


def test_apt_list_installed_default_builder():
    assert (
        mod.build_remote_cmd_apt_list_installed()
        == "LC_ALL=C apt list --installed"
    )


def test_apt_list_installed_with_pattern_builder():
    cmd = mod.build_remote_cmd_apt_list_installed(pattern="openssh*")
    assert cmd == "LC_ALL=C apt list --installed -- 'openssh*'"


def test_apt_list_installed_handler_happy(monkeypatch):
    captured = _stub(
        monkeypatch,
        SshResult(stdout=b"bash/now\n", stderr=b"", exit_code=0, truncated=False),
    )
    out = mod.handle_apt_list_installed({"host": "h1", "pattern": "bash"})
    assert out == {
        "stdout": "bash/now\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C apt list --installed -- bash"


def test_apt_list_installed_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_apt_list_installed({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C apt list --installed"


@pytest.mark.parametrize(
    "bad",
    [
        "-r",
        "--remove",
        "; rm -rf /",
        "pkg\n",
        "pkg\x00",
        "-oProxyCommand=evil",
        " --remove",
    ],
)
def test_apt_list_installed_rejects_injection(monkeypatch, bad):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_apt_list_installed({"host": "h1", "pattern": bad})


def test_apt_list_installed_truncated_propagates(monkeypatch):
    _stub(
        monkeypatch,
        SshResult(stdout=b"x", stderr=b"", exit_code=0, truncated=True),
    )
    out = mod.handle_apt_list_installed({"host": "h1"})
    assert out["truncated"] is True


# ---------------------------------------------------------------------------
# TOOLS registration
# ---------------------------------------------------------------------------


def test_tools_registry_names():
    names = [t.name for t in mod.TOOLS]
    assert names == ["dpkg_list", "rpm_list", "apt_list_installed"]
    for spec in mod.TOOLS:
        assert spec.input_schema["required"] == ["host"]
        assert callable(spec.handler)
        assert spec.description
