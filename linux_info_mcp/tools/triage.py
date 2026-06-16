"""Triage meta-tool: one SSH round-trip health summary -> {warnings, facts}."""

from __future__ import annotations

import shlex

from ..ssh import run_ssh
from ..validate import validate_host
from . import ToolSpec
from ._common import decode_text as _decode_text

# Thresholds (named so the policy is auditable in one place).
LOAD_PER_CPU_WARN = 1.5
LOAD_PER_CPU_CRIT = 4.0
MEM_AVAIL_FRAC_WARN = 0.10
MEM_AVAIL_FRAC_CRIT = 0.05
SWAP_USED_FRAC_WARN = 0.50
DISK_USE_PCT_WARN = 90
DISK_USE_PCT_CRIT = 95
PSI_AVG10_WARN = 20.0
INODES_USE_PCT_WARN = 90
INODES_USE_PCT_CRIT = 95
ZOMBIE_WARN = 1
DSTATE_WARN = 5
CLOCK_OFFSET_WARN_S = 0.1
CONNTRACK_FRAC_WARN = 0.90
CONNTRACK_FRAC_CRIT = 0.95
NIC_ERR_RATIO_WARN = 0.01
NIC_ERR_MIN_ABS = 100
# Kernel taint bits that indicate an actual fault. Benign bits (out-of-tree /
# unsigned modules) taint the kernel on most hosts running 3rd-party drivers
# (CrowdStrike, zfs, nvidia, ...) and would make this warning fire everywhere.
CONCERNING_TAINT_MASK = (
    (1 << 2)  # CPU out of spec
    | (1 << 4)  # machine check
    | (1 << 5)  # bad page
    | (1 << 7)  # kernel died recently (oops/BUG)
    | (1 << 9)  # warning issued
)

# Fixed bundled script. No user interpolation. Each probe degrades via 2>/dev/null||true.
_SCRIPT = (
    "echo '===loadavg==='; cat /proc/loadavg 2>/dev/null || true; "
    "echo '===nproc==='; nproc 2>/dev/null || true; "
    "echo '===meminfo==='; "
    "grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true; "
    "echo '===df==='; df -P -l -x tmpfs -x devtmpfs -x overlay 2>/dev/null || true; "
    "echo '===failed_units==='; "
    "systemctl --failed --no-legend --plain 2>/dev/null || true; "
    "echo '===psi_cpu==='; cat /proc/pressure/cpu 2>/dev/null || true; "
    "echo '===psi_memory==='; cat /proc/pressure/memory 2>/dev/null || true; "
    "echo '===psi_io==='; cat /proc/pressure/io 2>/dev/null || true; "
    "echo '===oom==='; "
    "dmesg 2>/dev/null | grep -iE 'out of memory|killed process' | tail -n 5 || true; "
    "echo '===df_inodes==='; df -P -i -l -x tmpfs -x devtmpfs -x overlay 2>/dev/null || true; "
    "echo '===ps_states==='; ps -eo stat= 2>/dev/null || true; "
    "echo '===top_cpu==='; "
    "ps -eo pid=,comm=,pcpu=,pmem= --sort=-pcpu 2>/dev/null | head -n 5 || true; "
    "echo '===clock==='; chronyc -n tracking 2>/dev/null || true; "
    "echo '===conntrack==='; "
    "cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max "
    "2>/dev/null || true; "
    "echo '===reboot_required==='; "
    "{ test -f /var/run/reboot-required && echo yes || echo no; } 2>/dev/null || true; "
    "echo '===kernel_taint==='; cat /proc/sys/kernel/tainted 2>/dev/null || true; "
    "echo '===net_dev==='; cat /proc/net/dev 2>/dev/null || true; "
    "echo '===END==='"
)


def build_remote_cmd_triage() -> str:
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


def _parse_loadavg(text: str):
    parts = text.split()
    out: list = []
    for p in parts[:3]:
        try:
            out.append(float(p))
        except ValueError:
            out.append(None)
    while len(out) < 3:
        out.append(None)
    return out[0], out[1], out[2]


def _first_int(s: str):
    for tok in s.split():
        if tok.isdigit():
            return int(tok)
    return None


def _parse_meminfo(text: str) -> dict:
    out: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        key = key.strip()
        if key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
            val = _first_int(rest)
            if val is not None:
                out[key] = val
    return out


def _parse_disks(text: str) -> list[dict]:
    out: list[dict] = []
    lines = [line for line in text.splitlines() if line.strip()]
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 2:
            continue
        pct = None
        for tok in parts:
            if tok.endswith("%"):
                try:
                    pct = int(tok[:-1])
                except ValueError:
                    pct = None
                break
        if pct is None:
            continue
        out.append({"mount": parts[-1], "use_pct": pct})
    return out


def _parse_failed_units(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(line.split()[0])
    return out


def _parse_psi_some_avg10(text: str):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("some"):
            for tok in line.split():
                if tok.startswith("avg10="):
                    try:
                        return float(tok.split("=", 1)[1])
                    except ValueError:
                        return None
    return None


def _parse_oom(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _to_float(s: str):
    try:
        return float(s)
    except ValueError:
        return None


def _parse_ps_states(text: str) -> tuple[int, int]:
    """Count zombie (Z) and uninterruptible-sleep (D) processes from ps stat column."""
    zombie = dstate = 0
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        c = s[0]
        if c == "Z":
            zombie += 1
        elif c == "D":
            dstate += 1
    return zombie, dstate


def _parse_top_cpu(text: str) -> list[dict]:
    out: list[dict] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        out.append(
            {
                "pid": pid,
                "comm": " ".join(parts[1:-2]),
                "pcpu": _to_float(parts[-2]),
                "pmem": _to_float(parts[-1]),
            }
        )
    return out


def _parse_clock(text: str) -> dict:
    offset = None
    leap = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("System time") and ":" in s:
            toks = s.split(":", 1)[1].split()
            if toks:
                offset = _to_float(toks[0])
        elif s.startswith("Leap status") and ":" in s:
            leap = s.split(":", 1)[1].strip() or None
    return {"offset_s": offset, "leap": leap}


def _parse_conntrack(text: str) -> dict:
    nums = [int(line.strip()) for line in text.splitlines() if line.strip().isdigit()]
    if len(nums) >= 2:
        return {"count": nums[0], "max": nums[1]}
    return {"count": None, "max": None}


def _parse_reboot_required(text: str) -> bool:
    return text.strip().lower().startswith("yes")


def _parse_net_errors(text: str) -> list[dict]:
    """Parse /proc/net/dev rx/tx err+drop counters per interface (skip lo)."""
    out: list[dict] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        name = name.strip()
        if name == "lo":
            continue
        f = rest.split()
        if len(f) < 16:
            continue
        try:
            out.append(
                {
                    "iface": name,
                    "rx_packets": int(f[1]),
                    "rx_errs": int(f[2]),
                    "rx_drop": int(f[3]),
                    "tx_packets": int(f[9]),
                    "tx_errs": int(f[10]),
                    "tx_drop": int(f[11]),
                }
            )
        except ValueError:
            continue
    return out


def _build_warnings(facts: dict) -> list[dict]:
    warnings: list[dict] = []

    load1 = facts["load1"]
    nproc = facts["nproc"]
    if load1 is not None and nproc:
        ratio = load1 / nproc
        if ratio >= LOAD_PER_CPU_WARN:
            sev = "crit" if ratio >= LOAD_PER_CPU_CRIT else "warn"
            warnings.append(
                {
                    "kind": "high_load",
                    "severity": sev,
                    "detail": f"load1 {load1} over {nproc} CPUs (ratio {ratio:.2f})",
                }
            )

    total = facts["mem_total_kb"]
    avail = facts["mem_available_kb"]
    if total and avail is not None:
        frac = avail / total
        if frac < MEM_AVAIL_FRAC_WARN:
            sev = "crit" if frac < MEM_AVAIL_FRAC_CRIT else "warn"
            warnings.append(
                {
                    "kind": "low_memory",
                    "severity": sev,
                    "detail": f"MemAvailable {avail} kB is {frac * 100:.1f}% of total",
                }
            )

    sw_total = facts["swap_total_kb"]
    sw_free = facts["swap_free_kb"]
    if sw_total and sw_free is not None:
        used_frac = (sw_total - sw_free) / sw_total
        if used_frac > SWAP_USED_FRAC_WARN:
            warnings.append(
                {
                    "kind": "swap_pressure",
                    "severity": "warn",
                    "detail": f"swap {used_frac * 100:.0f}% used",
                }
            )

    for disk in facts["disks"]:
        pct = disk["use_pct"]
        if pct >= DISK_USE_PCT_WARN:
            sev = "crit" if pct >= DISK_USE_PCT_CRIT else "warn"
            warnings.append(
                {
                    "kind": "disk_full",
                    "severity": sev,
                    "detail": f"{disk['mount']} at {pct}%",
                }
            )

    failed = facts["failed_units"]
    if failed:
        warnings.append(
            {
                "kind": "failed_units",
                "severity": "warn",
                "detail": f"{len(failed)} failed: {', '.join(failed)}",
            }
        )

    for resource, avg10 in facts["psi"].items():
        if avg10 is not None and avg10 > PSI_AVG10_WARN:
            warnings.append(
                {
                    "kind": "pressure",
                    "severity": "warn",
                    "detail": f"{resource} PSI some avg10={avg10}",
                }
            )

    oom = facts["oom_recent"]
    if oom:
        warnings.append(
            {
                "kind": "oom_recent",
                "severity": "crit",
                "detail": f"{len(oom)} recent OOM/kill line(s)",
            }
        )

    for disk in facts.get("inodes", []):
        pct = disk["use_pct"]
        if pct >= INODES_USE_PCT_WARN:
            sev = "crit" if pct >= INODES_USE_PCT_CRIT else "warn"
            warnings.append(
                {
                    "kind": "inodes_full",
                    "severity": sev,
                    "detail": f"{disk['mount']} inodes at {pct}%",
                }
            )

    zombie = facts.get("zombie")
    if zombie and zombie >= ZOMBIE_WARN:
        warnings.append(
            {"kind": "zombie_procs", "severity": "warn", "detail": f"{zombie} zombie process(es)"}
        )
    dstate = facts.get("dstate")
    if dstate and dstate >= DSTATE_WARN:
        warnings.append(
            {
                "kind": "stuck_procs",
                "severity": "warn",
                "detail": f"{dstate} process(es) in D state",
            }
        )

    clock = facts.get("clock") or {}
    offset = clock.get("offset_s")
    if offset is not None and abs(offset) > CLOCK_OFFSET_WARN_S:
        warnings.append(
            {"kind": "clock_skew", "severity": "warn", "detail": f"NTP offset {offset}s"}
        )
    leap = clock.get("leap")
    if leap is not None and leap.lower() != "normal":
        warnings.append(
            {"kind": "clock_unsynced", "severity": "warn", "detail": f"chrony leap status: {leap}"}
        )

    ct = facts.get("conntrack") or {}
    count, ct_max = ct.get("count"), ct.get("max")
    if count is not None and ct_max:
        frac = count / ct_max
        if frac >= CONNTRACK_FRAC_WARN:
            sev = "crit" if frac >= CONNTRACK_FRAC_CRIT else "warn"
            warnings.append(
                {
                    "kind": "conntrack_full",
                    "severity": sev,
                    "detail": f"conntrack {count}/{ct_max} ({frac * 100:.0f}%)",
                }
            )

    if facts.get("reboot_required"):
        warnings.append(
            {
                "kind": "reboot_required",
                "severity": "warn",
                "detail": "reboot required (pending kernel/library update)",
            }
        )

    taint = facts.get("kernel_tainted")
    if taint and (taint & CONCERNING_TAINT_MASK):
        warnings.append(
            {
                "kind": "kernel_tainted",
                "severity": "warn",
                "detail": f"kernel taint flags = {taint} (fault bits set)",
            }
        )

    for nic in facts.get("net_errors", []):
        rx_bad = nic["rx_errs"] + nic["rx_drop"]
        tx_bad = nic["tx_errs"] + nic["tx_drop"]
        rx_ratio = rx_bad / (nic["rx_packets"] + 1)
        tx_ratio = tx_bad / (nic["tx_packets"] + 1)
        if (rx_bad >= NIC_ERR_MIN_ABS and rx_ratio > NIC_ERR_RATIO_WARN) or (
            tx_bad >= NIC_ERR_MIN_ABS and tx_ratio > NIC_ERR_RATIO_WARN
        ):
            warnings.append(
                {
                    "kind": "nic_errors",
                    "severity": "warn",
                    "detail": f"{nic['iface']} rx_err/drop={rx_bad} tx_err/drop={tx_bad}",
                }
            )

    return warnings


def parse_triage(text: str) -> dict:
    """Parse the bundled triage stdout into {warnings, facts}. Never raises."""
    sec = _split_sections(text)
    load1, load5, load15 = _parse_loadavg(_section_text(sec, "loadavg"))
    mem = _parse_meminfo(_section_text(sec, "meminfo"))
    zombie, dstate = _parse_ps_states(_section_text(sec, "ps_states"))
    facts = {
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "nproc": _first_int(_section_text(sec, "nproc")),
        "mem_total_kb": mem.get("MemTotal"),
        "mem_available_kb": mem.get("MemAvailable"),
        "swap_total_kb": mem.get("SwapTotal"),
        "swap_free_kb": mem.get("SwapFree"),
        "disks": _parse_disks(_section_text(sec, "df")),
        "failed_units": _parse_failed_units(_section_text(sec, "failed_units")),
        "psi": {
            "cpu": _parse_psi_some_avg10(_section_text(sec, "psi_cpu")),
            "memory": _parse_psi_some_avg10(_section_text(sec, "psi_memory")),
            "io": _parse_psi_some_avg10(_section_text(sec, "psi_io")),
        },
        "oom_recent": _parse_oom(_section_text(sec, "oom")),
        "inodes": _parse_disks(_section_text(sec, "df_inodes")),
        "zombie": zombie,
        "dstate": dstate,
        "top_cpu": _parse_top_cpu(_section_text(sec, "top_cpu")),
        "clock": _parse_clock(_section_text(sec, "clock")),
        "conntrack": _parse_conntrack(_section_text(sec, "conntrack")),
        "reboot_required": _parse_reboot_required(_section_text(sec, "reboot_required")),
        "kernel_tainted": _first_int(_section_text(sec, "kernel_taint")),
        "net_errors": _parse_net_errors(_section_text(sec, "net_dev")),
    }
    return {"warnings": _build_warnings(facts), "facts": facts}


def handle_triage(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_triage()
    res = run_ssh(host, cmd)
    stdout = _decode_text(res.stdout)
    parsed = parse_triage(stdout)
    return {
        "warnings": parsed["warnings"],
        "facts": parsed["facts"],
        "stdout": stdout,
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {"host": {"type": "string"}},
    "required": ["host"],
    "additionalProperties": False,
}


TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="triage",
        description=(
            "One SSH round-trip health triage: load-vs-CPU, memory/swap pressure, disk "
            "fullness, inode exhaustion, failed systemd units, PSI stall pressure, recent "
            "OOM/kills, zombie/D-state processes, top CPU consumers, NTP clock skew, "
            "conntrack table fullness, pending-reboot, kernel taint, NIC error/drop rates. "
            "Returns {warnings: [{kind, severity, detail}], facts: {...}, stdout, stderr, "
            "exit_code, truncated}. Empty warnings = healthy. Probes degrade gracefully when "
            "a source is restricted or absent."
        ),
        input_schema=TRIAGE_SCHEMA,
        handler=handle_triage,
    ),
]
