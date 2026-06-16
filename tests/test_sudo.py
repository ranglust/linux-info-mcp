import pytest

from linux_info_mcp import ssh as ssh_mod
from linux_info_mcp.tools import disk, kernel, lldp, net, sys

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on", "  on  "])
def test_sudo_enabled_truthy(monkeypatch, val):
    monkeypatch.setenv("LINUX_INFO_SUDO", val)
    assert ssh_mod.sudo_enabled() is True
    assert ssh_mod.sudo_tokens() == ["sudo", "-n"]
    assert ssh_mod.sudo_prefix() == "sudo -n "


@pytest.mark.parametrize("val", ["0", "false", "no", "off", "", "maybe"])
def test_sudo_enabled_falsy(monkeypatch, val):
    monkeypatch.setenv("LINUX_INFO_SUDO", val)
    assert ssh_mod.sudo_enabled() is False
    assert ssh_mod.sudo_tokens() == []
    assert ssh_mod.sudo_prefix() == ""


def test_sudo_default_unset():
    assert ssh_mod.sudo_enabled() is False


# ---------------------------------------------------------------------------
# builders prefix sudo when enabled
# ---------------------------------------------------------------------------


def test_smartctl_sudo(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    assert (
        disk.build_remote_cmd_smartctl(device="/dev/sda", mode_flag="-i")
        == "LC_ALL=C sudo -n smartctl -i -- /dev/sda"
    )


def test_dmidecode_sudo(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    assert sys.build_remote_cmd_dmidecode(type="system") == "LC_ALL=C sudo -n dmidecode -t system"


def test_dmesg_sudo(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    assert kernel.build_remote_cmd_dmesg() == "LC_ALL=C sudo -n dmesg"


def test_dmesg_sudo_keeps_tail_outside(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    cmd = kernel.build_remote_cmd_dmesg(tail_lines=50)
    assert cmd == "LC_ALL=C sudo -n dmesg | tail -n 50"


def test_ethtool_sudo(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    assert (
        net.build_remote_cmd_ethtool(iface="eth0", mode_flag="-i")
        == "LC_ALL=C sudo -n ethtool -i eth0"
    )


def test_nft_list_sudo(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    assert net.build_remote_cmd_nft_list() == "LC_ALL=C sudo -n nft -nn list ruleset"
    assert (
        net.build_remote_cmd_nft_list(family="inet", table="filter")
        == "LC_ALL=C sudo -n nft -nn list table inet filter"
    )


def test_conntrack_sudo(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    assert net.build_remote_cmd_conntrack() == "LC_ALL=C sudo -n conntrack -S"
    assert net.build_remote_cmd_conntrack(mode="list") == "LC_ALL=C sudo -n conntrack -L"


def test_iptables_sudo(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    assert (
        net.build_remote_cmd_iptables_list(binary="iptables")
        == "LC_ALL=C sudo -n iptables -n -v -L"
    )


def test_lldp_sudo(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    assert (
        lldp.build_remote_cmd_lldp(what="neighbors")
        == "LC_ALL=C sudo -n lldpcli -f keyvalue show neighbors"
    )


# ---------------------------------------------------------------------------
# default (no sudo) and selectivity
# ---------------------------------------------------------------------------


def test_builders_no_sudo_by_default():
    assert disk.build_remote_cmd_smartctl(device="/dev/sda", mode_flag="-i").startswith(
        "LC_ALL=C smartctl"
    )
    assert net.build_remote_cmd_nft_list() == "LC_ALL=C nft -nn list ruleset"
    assert kernel.build_remote_cmd_dmesg() == "LC_ALL=C dmesg"


def test_non_privileged_tool_not_prefixed(monkeypatch):
    # ss is not privilege-prone; sudo must not leak onto it even when enabled.
    monkeypatch.setenv("LINUX_INFO_SUDO", "1")
    assert "sudo" not in net.build_remote_cmd_ss()
    assert net.build_remote_cmd_ip_addr() == "LC_ALL=C ip -o addr show"
