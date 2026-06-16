"""Host facts meta-tool: one SSH round-trip, bundled read-only probes."""

from __future__ import annotations

import shlex

from ..ssh import run_ssh
from ..validate import validate_host
from . import ToolSpec
from ._common import decode_text as _decode_text

# Optional binaries behind tool groups. Surfaced as facts.capabilities so a caller
# can skip a round-trip to a tool whose binary is absent. Curated to genuinely
# optional binaries (no always-present coreutils).
_CAP_TOOLS = [
    "docker",
    "podman",
    "systemctl",
    "nft",
    "iptables",
    "conntrack",
    "ethtool",
    "tc",
    "ss",
    "lsof",
    "smartctl",
    "blockdev",
    "lsblk",
    "numastat",
    "slabtop",
    "lldpctl",
    "chronyc",
    "dmidecode",
    "iostat",
    "vmstat",
    "dpkg",
    "rpm",
    "sensors",
]

_VM_DMI_SIGNATURES = (
    "vmware",
    "qemu",
    "kvm",
    "xen",
    "virtualbox",
    "innotek",
    "microsoft",
    "bochs",
    "bhyve",
    "parallels",
    "oracle",
)

# Fixed bundled script. No user interpolation. Each probe degrades to empty via 2>/dev/null||true.
_SCRIPT = (
    "echo '===os_release==='; cat /etc/os-release 2>/dev/null || true; "
    "echo '===uname==='; uname -srm 2>/dev/null || true; "
    "echo '===nproc==='; nproc 2>/dev/null || true; "
    "echo '===mem_total==='; grep -i MemTotal /proc/meminfo 2>/dev/null || true; "
    "echo '===virt==='; systemd-detect-virt 2>/dev/null || true; "
    "echo '===container==='; systemd-detect-virt -c 2>/dev/null || true; "
    "echo '===dmi_vendor==='; cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true; "
    "echo '===dmi_product==='; cat /sys/class/dmi/id/product_name 2>/dev/null || true; "
    "echo '===capabilities==='; "
    "for t in " + " ".join(_CAP_TOOLS) + "; do "
    'if command -v "$t" >/dev/null 2>&1; then echo "$t yes"; else echo "$t no"; fi; '
    "done; "
    "echo '===uptime==='; cat /proc/uptime 2>/dev/null || true; "
    "echo '===now_utc==='; date -u +%FT%TZ 2>/dev/null || true; "
    "echo '===whoami==='; id -un 2>/dev/null || true; "
    "echo '===END==='"
)


def build_remote_cmd_host_facts() -> str:
    """Build the fixed bundled probe script as a single LC_ALL=C sh -c command."""
    return "LC_ALL=C sh -c " + shlex.quote(_SCRIPT)


def _split_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("===") and line.endswith("===") and len(line) > 6:
            current = line[3:-3]
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return sections


def _section_text(sections: dict, name: str) -> str:
    return "\n".join(sections.get(name, [])).strip()


def _parse_kv(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k:
            out[k] = v
    return out


def _first_int(s: str):
    for tok in s.split():
        if tok.isdigit():
            return int(tok)
    return None


def _parse_facts(text: str) -> dict:
    sec = _split_sections(text)

    os_rel = _parse_kv(sec.get("os_release", []))
    distro = {k: os_rel[k] for k in ("ID", "VERSION_ID", "PRETTY_NAME") if k in os_rel}

    uname = _section_text(sec, "uname").split()
    kernel = uname[1] if len(uname) >= 2 else None
    arch = uname[-1] if len(uname) >= 3 else None

    nproc = _first_int(_section_text(sec, "nproc"))
    mem_total_kb = _first_int(_section_text(sec, "mem_total"))

    hypervisor = _section_text(sec, "virt") or "none"
    container = _section_text(sec, "container") or "none"
    dmi_vendor = _section_text(sec, "dmi_vendor")
    dmi_product = _section_text(sec, "dmi_product")

    dmi_blob = (dmi_vendor + " " + dmi_product).lower()
    dmi_is_vm = any(sig in dmi_blob for sig in _VM_DMI_SIGNATURES)
    is_virtual = (hypervisor not in ("", "none")) or dmi_is_vm

    capabilities: dict[str, bool] = {}
    for line in sec.get("capabilities", []):
        parts = line.split()
        if len(parts) == 2:
            capabilities[parts[0]] = parts[1] == "yes"

    uptime_field = _section_text(sec, "uptime").split()
    uptime_s = None
    if uptime_field:
        try:
            uptime_s = int(float(uptime_field[0]))
        except ValueError:
            uptime_s = None

    now_utc = _section_text(sec, "now_utc") or None
    whoami = _section_text(sec, "whoami") or None

    return {
        "distro": distro,
        "kernel": kernel,
        "arch": arch,
        "nproc": nproc,
        "mem_total_kb": mem_total_kb,
        "hypervisor": hypervisor,
        "container": container,
        "dmi_vendor": dmi_vendor or None,
        "dmi_product": dmi_product or None,
        "is_virtual": is_virtual,
        "capabilities": capabilities,
        "uptime_s": uptime_s,
        "now_utc": now_utc,
        "whoami": whoami,
    }


def handle_host_facts(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_host_facts()
    res = run_ssh(host, cmd)
    stdout = _decode_text(res.stdout)
    return {
        "facts": _parse_facts(stdout),
        "stdout": stdout,
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


HOST_FACTS_SCHEMA = {
    "type": "object",
    "properties": {"host": {"type": "string"}},
    "required": ["host"],
    "additionalProperties": False,
}


TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="host_facts",
        description=(
            "Gather host facts in one SSH round-trip: distro, kernel/arch, nproc, mem, "
            "virtualization (hypervisor/container/DMI + derived is_virtual), tool capabilities, "
            "uptime, now_utc, whoami. Returns {facts, stdout, stderr, exit_code, truncated}. "
            "Call this first and check facts.capabilities (a tool->bool map of optional "
            "binaries like iostat, lldpctl, chronyc, dmidecode, smartctl) to skip a round-trip "
            "to a tool whose binary is absent."
        ),
        input_schema=HOST_FACTS_SCHEMA,
        handler=handle_host_facts,
    ),
]
