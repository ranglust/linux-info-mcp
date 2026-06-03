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

    return warnings


def parse_triage(text: str) -> dict:
    """Parse the bundled triage stdout into {warnings, facts}. Never raises."""
    sec = _split_sections(text)
    load1, load5, load15 = _parse_loadavg(_section_text(sec, "loadavg"))
    mem = _parse_meminfo(_section_text(sec, "meminfo"))
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
            "fullness, failed systemd units, PSI stall pressure, recent OOM/kills. Returns "
            "{warnings: [{kind, severity, detail}], facts: {...}, stdout, stderr, exit_code, "
            "truncated}. Empty warnings = healthy. Probes degrade gracefully when a source "
            "is restricted or absent."
        ),
        input_schema=TRIAGE_SCHEMA,
        handler=handle_triage,
    ),
]
