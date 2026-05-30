"""Kernel tools: dmesg, uname, sysctl."""
from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh
from ..validate import (
    _reject_unsafe_chars,
    validate_host,
    validate_lines_int,
)
from . import ToolSpec


def _decode_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def _bool(value, label: str) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a bool")
    return value


# ---------------------------------------------------------------------------
# dmesg
# ---------------------------------------------------------------------------

_DMESG_LEVELS = {"emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"}
_DMESG_FACILITIES = {"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news"}


def _validate_dmesg_level(level) -> str:
    if not isinstance(level, str) or level not in _DMESG_LEVELS:
        raise ValueError(f"level must be one of {sorted(_DMESG_LEVELS)}")
    return level


def _validate_dmesg_facility(facility) -> str:
    if not isinstance(facility, str) or facility not in _DMESG_FACILITIES:
        raise ValueError(f"facility must be one of {sorted(_DMESG_FACILITIES)}")
    return facility


def build_remote_cmd_dmesg(
    *,
    human: bool = False,
    time_iso: bool = False,
    kernel_time: bool = False,
    level: str | None = None,
    facility: str | None = None,
    tail_lines: int | None = None,
) -> str:
    """Build LC_ALL=C dmesg command string."""
    if human and (time_iso or kernel_time):
        raise ValueError("human is mutually exclusive with time_iso and kernel_time")
    parts = ["LC_ALL=C", "dmesg", "--no-pager"]
    if human:
        parts.append("-H")
    if time_iso:
        parts.append("--time-format=iso")
    if kernel_time:
        parts.append("-k")
    if level is not None:
        parts.append(f"--level={shlex.quote(level)}")
    if facility is not None:
        parts.append(f"--facility={shlex.quote(facility)}")
    cmd = " ".join(parts)
    if tail_lines is not None:
        cmd = f"{cmd} | tail -n {tail_lines}"
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
        tail_lines = validate_lines_int(tail_lines, lo=1, hi=10000, label="tail_lines")
    cmd = build_remote_cmd_dmesg(
        human=_bool(args.get("human"), "human"),
        time_iso=_bool(args.get("time_iso"), "time_iso"),
        kernel_time=_bool(args.get("kernel_time"), "kernel_time"),
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
    }


DMESG_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "human": {"type": ["boolean", "null"]},
        "time_iso": {"type": ["boolean", "null"]},
        "kernel_time": {"type": ["boolean", "null"]},
        "level": {"type": ["string", "null"]},
        "facility": {"type": ["string", "null"]},
        "tail_lines": {"type": ["integer", "null"]},
    },
    "required": ["host"],
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
    if "mode" not in args or args.get("mode") is None:
        raise ValueError("mode is required")
    mode_flag = _validate_uname_mode(args["mode"])
    cmd = build_remote_cmd_uname(mode_flag=mode_flag)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


UNAME_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "mode": {"type": "string"},
    },
    "required": ["host", "mode"],
}


# ---------------------------------------------------------------------------
# sysctl
# ---------------------------------------------------------------------------

_SYSCTL_KEY_RE = re.compile(r"^[a-zA-Z0-9._-]{1,256}$")
_SYSCTL_PATTERN_RE = re.compile(r"^[a-zA-Z0-9._*-]{1,256}$")


def _validate_sysctl_key(key) -> str:
    if not isinstance(key, str) or not key:
        raise ValueError("key must be a non-empty string")
    _reject_unsafe_chars(key, "key")
    if key.startswith("-"):
        raise ValueError("key must not start with '-'")
    if not _SYSCTL_KEY_RE.fullmatch(key):
        raise ValueError("key must match ^[a-zA-Z0-9._-]{1,256}$")
    return key


def _validate_sysctl_pattern(pattern) -> str:
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("pattern must be a non-empty string")
    _reject_unsafe_chars(pattern, "pattern")
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
}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="dmesg",
        description=(
            "Run dmesg on a remote host via SSH. "
            "Returns stdout, stderr, exit_code, truncated."
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
]
