"""Kernel tools: dmesg, uname, sysctl."""

from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh, sudo_tokens
from ..validate import (
    reject_unsafe_chars,
    validate_cgroup_path,
    validate_host,
    validate_int_in_range,
    validate_unit_name,
)
from . import ToolSpec
from ._common import decode_text as _decode_text
from ._common import validate_bool as _bool
from ._common import validate_pid

# ---------------------------------------------------------------------------
# dmesg
# ---------------------------------------------------------------------------

_DMESG_LEVELS = {"emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"}
_DMESG_FACILITIES = {"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news"}


def _validate_dmesg_level(level) -> str:
    # dmesg --level accepts a comma-separated list; validate each token.
    if not isinstance(level, str) or not level:
        raise ValueError(f"level must be one of {sorted(_DMESG_LEVELS)}")
    for tok in level.split(","):
        if tok not in _DMESG_LEVELS:
            raise ValueError(f"level tokens must each be one of {sorted(_DMESG_LEVELS)}")
    return level


def _validate_dmesg_facility(facility) -> str:
    if not isinstance(facility, str) or facility not in _DMESG_FACILITIES:
        raise ValueError(f"facility must be one of {sorted(_DMESG_FACILITIES)}")
    return facility


def build_remote_cmd_dmesg(
    *,
    human: bool = False,
    time_iso: bool = False,
    kernel_only: bool = False,
    level: str | None = None,
    facility: str | None = None,
    tail_lines: int | None = None,
) -> str:
    """Build LC_ALL=C dmesg command string."""
    if human and time_iso:
        raise ValueError("human is mutually exclusive with time_iso")
    parts = ["LC_ALL=C", *sudo_tokens(), "dmesg"]
    if human:
        parts.append("-H")
    if time_iso:
        parts.append("--time-format=iso")
    if kernel_only:
        parts.append("-k")
    if level is not None:
        parts.append(f"--level={shlex.quote(level)}")
    if facility is not None:
        parts.append(f"--facility={shlex.quote(facility)}")
    cmd = " ".join(parts)
    if tail_lines is not None:
        cmd = f"{cmd} | tail -n {shlex.quote(str(tail_lines))}"
    return cmd


def handle_dmesg(args: dict) -> dict:
    host = validate_host(args["host"])
    level = args.get("level")
    if level is not None:
        level = _validate_dmesg_level(level)
    facility = args.get("facility")
    if facility is not None:
        facility = _validate_dmesg_facility(facility)
    tail_lines = args.get("tail_lines")
    if tail_lines is not None:
        tail_lines = validate_int_in_range(tail_lines, lo=1, hi=10000, label="tail_lines")
    cmd = build_remote_cmd_dmesg(
        human=_bool(args.get("human"), "human"),
        time_iso=_bool(args.get("time_iso"), "time_iso"),
        kernel_only=_bool(args.get("kernel_only"), "kernel_only"),
        level=level,
        facility=facility,
        tail_lines=tail_lines,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


DMESG_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "human": {"type": ["boolean", "null"]},
        "time_iso": {"type": ["boolean", "null"]},
        "kernel_only": {"type": ["boolean", "null"]},
        "level": {"type": ["string", "null"]},
        "facility": {"type": ["string", "null"]},
        "tail_lines": {"type": ["integer", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# uname
# ---------------------------------------------------------------------------

_UNAME_MODE_MAP = {
    "all": "-a",
    "kernel-name": "-s",
    "kernel-release": "-r",
    "kernel-version": "-v",
    "machine": "-m",
    "processor": "-p",
    "hardware-platform": "-i",
    "operating-system": "-o",
}


def _validate_uname_mode(mode) -> str:
    if not isinstance(mode, str) or mode not in _UNAME_MODE_MAP:
        raise ValueError(f"mode must be one of {sorted(_UNAME_MODE_MAP)}")
    return _UNAME_MODE_MAP[mode]


def build_remote_cmd_uname(*, mode_flag: str) -> str:
    """Build LC_ALL=C uname command string."""
    return f"LC_ALL=C uname {mode_flag}"


def handle_uname(args: dict) -> dict:
    host = validate_host(args["host"])
    mode = args.get("mode")
    if mode is None:
        raise ValueError("mode is required")
    mode_flag = _validate_uname_mode(mode)
    cmd = build_remote_cmd_uname(mode_flag=mode_flag)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


UNAME_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "mode": {"type": "string"},
    },
    "required": ["host", "mode"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# sysctl
# ---------------------------------------------------------------------------

_SYSCTL_KEY_RE = re.compile(r"^[a-zA-Z0-9._-]{1,256}$")
_SYSCTL_PATTERN_RE = re.compile(r"^[a-zA-Z0-9._*-]{1,256}$")


def _validate_sysctl_key(key) -> str:
    if not isinstance(key, str) or not key:
        raise ValueError("key must be a non-empty string")
    reject_unsafe_chars(key, "key")
    if key.startswith("-"):
        raise ValueError("key must not start with '-'")
    if not _SYSCTL_KEY_RE.fullmatch(key):
        raise ValueError("key must match ^[a-zA-Z0-9._-]{1,256}$")
    return key


def _validate_sysctl_pattern(pattern) -> str:
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("pattern must be a non-empty string")
    reject_unsafe_chars(pattern, "pattern")
    if pattern.startswith("-"):
        raise ValueError("pattern must not start with '-'")
    if not _SYSCTL_PATTERN_RE.fullmatch(pattern):
        raise ValueError("pattern must match ^[a-zA-Z0-9._*-]{1,256}$")
    return pattern


def build_remote_cmd_sysctl(
    *,
    key: str | None = None,
    all_keys: bool = False,
    pattern: str | None = None,
) -> str:
    """Build LC_ALL=C sysctl command string."""
    if key is not None and all_keys:
        raise ValueError("key and all are mutually exclusive")
    if key is None and not all_keys:
        raise ValueError("exactly one of key or all is required")
    if pattern is not None and not all_keys:
        raise ValueError("pattern requires all=true")
    parts = ["LC_ALL=C", "sysctl"]
    if all_keys:
        parts.append("-a")
    if pattern is not None:
        parts.append(f"--pattern={shlex.quote(pattern)}")
    if key is not None:
        parts += ["--", shlex.quote(key)]
    return " ".join(parts)


def handle_sysctl(args: dict) -> dict:
    host = validate_host(args["host"])
    key_in = args.get("key")
    all_in = args.get("all")
    if all_in is not None and not isinstance(all_in, bool):
        raise ValueError("all must be a bool")
    all_keys = bool(all_in)
    if key_in is not None and all_keys:
        raise ValueError("key and all are mutually exclusive")
    if key_in is None and not all_keys:
        raise ValueError("exactly one of key or all is required")
    key = _validate_sysctl_key(key_in) if key_in is not None else None
    pattern_in = args.get("pattern")
    pattern = _validate_sysctl_pattern(pattern_in) if pattern_in is not None else None
    cmd = build_remote_cmd_sysctl(key=key, all_keys=all_keys, pattern=pattern)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


SYSCTL_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "key": {"type": ["string", "null"]},
        "all": {"type": ["boolean", "null"]},
        "pattern": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# slabtop
# ---------------------------------------------------------------------------


def build_remote_cmd_slabtop() -> str:
    """Build LC_ALL=C slabtop one-shot command string."""
    return "LC_ALL=C slabtop -o"


def handle_slabtop(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_slabtop()
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


SLABTOP_SCHEMA = {
    "type": "object",
    "properties": {"host": {"type": "string"}},
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# numastat
# ---------------------------------------------------------------------------


def build_remote_cmd_numastat(*, pid: int | None = None) -> str:
    """Build LC_ALL=C numastat command string. pid is an int -> safe interpolation."""
    parts = ["LC_ALL=C", "numastat"]
    if pid is not None:
        parts += ["-p", str(pid)]
    return " ".join(parts)


def handle_numastat(args: dict) -> dict:
    host = validate_host(args["host"])
    pid = args.get("pid")
    if pid is not None:
        pid = validate_pid(pid)
    cmd = build_remote_cmd_numastat(pid=pid)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


NUMASTAT_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "pid": {"type": ["integer", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# cgroup_stats
# ---------------------------------------------------------------------------

_CGROUP_CONTROLLER_FILES = {
    "cpu": ["cpu.stat"],
    "memory": ["memory.current", "memory.stat", "memory.pressure"],
    "io": ["io.stat", "io.pressure"],
}
_CGROUP_ALL_ORDER = ["cpu", "memory", "io"]


def _validate_cgroup_controller(controller) -> str:
    if controller is None:
        return "all"
    valid = set(_CGROUP_CONTROLLER_FILES) | {"all"}
    if not isinstance(controller, str) or controller not in valid:
        raise ValueError(f"controller must be one of {sorted(valid)}")
    return controller


def _cgroup_files_for(controller: str) -> list[str]:
    if controller == "all":
        files: list[str] = []
        for c in _CGROUP_ALL_ORDER:
            files += _CGROUP_CONTROLLER_FILES[c]
        return files
    return _CGROUP_CONTROLLER_FILES[controller]


def build_remote_cmd_cgroup_stats(*, cgroup_path: str, controller: str = "all") -> str:
    """Build LC_ALL=C grep over whitelisted cgroup stat files. Path quoted, filenames literal."""
    files = _cgroup_files_for(controller)
    base = shlex.quote(cgroup_path)
    targets = " ".join(f"/sys/fs/cgroup/{base}/{f}" for f in files)
    return f"LC_ALL=C grep -H '' {targets}"


def handle_cgroup_stats(args: dict) -> dict:
    host = validate_host(args["host"])
    path_in = args.get("cgroup_path")
    if path_in is None:
        raise ValueError("cgroup_path is required")
    cgroup_path = validate_cgroup_path(path_in)
    controller = _validate_cgroup_controller(args.get("controller"))
    cmd = build_remote_cmd_cgroup_stats(cgroup_path=cgroup_path, controller=controller)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


CGROUP_STATS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "cgroup_path": {"type": "string"},
        "controller": {
            "type": ["string", "null"],
            "enum": ["cpu", "memory", "io", "all", None],
        },
    },
    "required": ["host", "cgroup_path"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# systemd_analyze
# ---------------------------------------------------------------------------

_SYSTEMD_ANALYZE_MODES = {"time", "blame", "critical-chain"}


def _validate_systemd_analyze_mode(mode) -> str:
    if mode is None:
        return "time"
    if not isinstance(mode, str) or mode not in _SYSTEMD_ANALYZE_MODES:
        raise ValueError(f"mode must be one of {sorted(_SYSTEMD_ANALYZE_MODES)}")
    return mode


def build_remote_cmd_systemd_analyze(*, mode: str = "time", unit: str | None = None) -> str:
    """Build LC_ALL=C systemd-analyze command string."""
    parts = ["LC_ALL=C", "systemd-analyze", mode, "--no-pager"]
    if unit is not None:
        parts.append(shlex.quote(unit))
    return " ".join(parts)


def handle_systemd_analyze(args: dict) -> dict:
    host = validate_host(args["host"])
    mode = _validate_systemd_analyze_mode(args.get("mode"))
    unit = args.get("unit")
    if unit is not None:
        if mode != "critical-chain":
            raise ValueError("unit is only valid with mode=critical-chain")
        unit = validate_unit_name(unit)
    cmd = build_remote_cmd_systemd_analyze(mode=mode, unit=unit)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


SYSTEMD_ANALYZE_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "mode": {
            "type": ["string", "null"],
            "enum": ["time", "blame", "critical-chain", None],
        },
        "unit": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="dmesg",
        description=(
            "Run dmesg on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=DMESG_SCHEMA,
        handler=handle_dmesg,
    ),
    ToolSpec(
        name="uname",
        description=(
            "Run uname on a remote host via SSH using a preset mode. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=UNAME_SCHEMA,
        handler=handle_uname,
    ),
    ToolSpec(
        name="sysctl",
        description=(
            "Read kernel parameters via sysctl on a remote host via SSH. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=SYSCTL_SCHEMA,
        handler=handle_sysctl,
    ),
    ToolSpec(
        name="slabtop",
        description=(
            "Run 'slabtop -o' (one-shot kernel slab cache stats) on a remote host via SSH. "
            "Root required. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=SLABTOP_SCHEMA,
        handler=handle_slabtop,
    ),
    ToolSpec(
        name="numastat",
        description=(
            "Run numastat (NUMA memory allocation stats, optional -p pid) on a remote host via "
            "SSH. numactl package may be absent (127 passthrough). "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=NUMASTAT_SCHEMA,
        handler=handle_numastat,
    ),
    ToolSpec(
        name="cgroup_stats",
        description=(
            "Read cgroup v2 controller stat files (cpu|memory|io|all) under "
            "/sys/fs/cgroup/<path> on a remote host via SSH. Path is traversal-safe; leaf "
            "files are whitelisted. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=CGROUP_STATS_SCHEMA,
        handler=handle_cgroup_stats,
    ),
    ToolSpec(
        name="systemd_analyze",
        description=(
            "Run systemd-analyze (time|blame|critical-chain, default time) on a remote host via "
            "SSH; optional unit for critical-chain. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=SYSTEMD_ANALYZE_SCHEMA,
        handler=handle_systemd_analyze,
    ),
]
