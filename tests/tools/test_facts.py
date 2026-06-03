import pytest

import linux_info_mcp.tools.facts as mod
from linux_info_mcp.ssh import SshResult


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


# A representative bundled-output blob, in the exact section order the builder emits.
SAMPLE = """===os_release===
NAME="Ubuntu"
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
===uname===
Linux 5.15.0-91-generic x86_64
===nproc===
8
===mem_total===
MemTotal:       16384000 kB
===virt===
kvm
===container===
none
===dmi_vendor===
QEMU
===dmi_product===
Standard PC (Q35 + ICH9, 2009)
===capabilities===
docker yes
podman no
systemctl yes
nft no
conntrack no
ethtool yes
smartctl yes
numastat no
slabtop yes
===uptime===
123456.78 987654.32
===now_utc===
2026-06-01T12:00:00Z
===whoami===
root
===END===
"""


# ---- builder ----


def test_host_facts_builder_is_fixed_and_quoted():
    cmd = mod.build_remote_cmd_host_facts()
    assert cmd.startswith("LC_ALL=C sh -c ")
    # No host or user value is interpolated; the script is a constant.
    assert "===os_release===" in cmd
    assert "===END===" in cmd


def test_host_facts_probes_expanded_capabilities():
    # The capability probe must cover the optional binaries behind each tool group
    # so callers can skip a round-trip when the binary is absent.
    cmd = mod.build_remote_cmd_host_facts()
    for tool in (
        "lldpctl",
        "chronyc",
        "dmidecode",
        "iostat",
        "vmstat",
        "ss",
        "lsof",
        "tc",
        "iptables",
        "blockdev",
        "dpkg",
        "rpm",
        "lsblk",
    ):
        assert tool in mod._CAP_TOOLS, f"{tool} missing from _CAP_TOOLS"
        assert tool in cmd


# ---- parser ----


def test_parse_facts_distro():
    f = mod._parse_facts(SAMPLE)
    assert f["distro"]["ID"] == "ubuntu"
    assert f["distro"]["VERSION_ID"] == "22.04"
    assert f["distro"]["PRETTY_NAME"] == "Ubuntu 22.04.3 LTS"


def test_parse_facts_kernel_arch():
    f = mod._parse_facts(SAMPLE)
    assert f["kernel"] == "5.15.0-91-generic"
    assert f["arch"] == "x86_64"


def test_parse_facts_nproc_and_mem():
    f = mod._parse_facts(SAMPLE)
    assert f["nproc"] == 8
    assert f["mem_total_kb"] == 16384000


def test_parse_facts_virt():
    f = mod._parse_facts(SAMPLE)
    assert f["hypervisor"] == "kvm"
    assert f["container"] == "none"
    assert f["dmi_vendor"] == "QEMU"
    assert f["dmi_product"].startswith("Standard PC")
    assert f["is_virtual"] is True


def test_parse_facts_is_virtual_false_on_bare_metal():
    blob = SAMPLE.replace("kvm", "none").replace("QEMU", "Dell Inc.")
    f = mod._parse_facts(blob)
    assert f["hypervisor"] == "none"
    assert f["is_virtual"] is False


def test_parse_facts_is_virtual_true_from_dmi_only():
    # hypervisor=none but DMI vendor is a VM signature
    blob = SAMPLE.replace("kvm", "none").replace("QEMU", "VMware, Inc.")
    f = mod._parse_facts(blob)
    assert f["hypervisor"] == "none"
    assert f["is_virtual"] is True


def test_parse_facts_capabilities():
    f = mod._parse_facts(SAMPLE)
    caps = f["capabilities"]
    assert caps["docker"] is True
    assert caps["podman"] is False
    assert caps["nft"] is False
    assert caps["slabtop"] is True


def test_parse_facts_uptime_now_whoami():
    f = mod._parse_facts(SAMPLE)
    assert f["uptime_s"] == 123456
    assert f["now_utc"] == "2026-06-01T12:00:00Z"
    assert f["whoami"] == "root"


def test_parse_facts_tolerates_missing_sections():
    # Empty probes (missing binary) must not crash the parser.
    blob = """===os_release===
===uname===
===nproc===
===mem_total===
===virt===
===container===
===dmi_vendor===
===dmi_product===
===capabilities===
===uptime===
===now_utc===
===whoami===
===END===
"""
    f = mod._parse_facts(blob)
    assert f["distro"] == {}
    assert f["kernel"] is None
    assert f["arch"] is None
    assert f["nproc"] is None
    assert f["mem_total_kb"] is None
    assert f["hypervisor"] == "none"
    assert f["capabilities"] == {}
    assert f["uptime_s"] is None
    assert f["is_virtual"] is False


# ---- handler ----


def test_host_facts_handler_parses_and_passes_through(monkeypatch):
    captured = _stub(monkeypatch, SshResult(SAMPLE.encode(), b"", 0, False))
    out = mod.handle_host_facts({"host": "h1"})
    assert captured["cmd"] == mod.build_remote_cmd_host_facts()
    assert out["exit_code"] == 0
    assert out["truncated"] is False
    assert out["stderr_truncated"] is False
    assert out["stdout"] == SAMPLE
    assert out["facts"]["distro"]["ID"] == "ubuntu"
    assert out["facts"]["capabilities"]["docker"] is True
    assert out["facts"]["is_virtual"] is True


def test_host_facts_handler_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_host_facts({"host": "-evil"})


def test_host_facts_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(SAMPLE.encode(), b"", 0, True))
    out = mod.handle_host_facts({"host": "h1"})
    assert out["truncated"] is True


def test_host_facts_handles_empty_stdout(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"boom", 1, False))
    out = mod.handle_host_facts({"host": "h1"})
    assert out["exit_code"] == 1
    assert out["facts"]["distro"] == {}
    assert out["facts"]["is_virtual"] is False


def test_tools_registry():
    names = [t.name for t in mod.TOOLS]
    assert names == ["host_facts"]
    spec = mod.TOOLS[0]
    assert spec.input_schema["required"] == ["host"]
    assert callable(spec.handler)
