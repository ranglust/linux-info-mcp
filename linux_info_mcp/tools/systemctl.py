"""Systemctl tools: systemctl_status, systemctl_list."""
from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh
from ..validate import (
    _reject_unsafe_chars as _reject_unsafe,
    validate_host,
    validate_lines_int,
    validate_unit_name,
)
from . import ToolSpec

_KIND_WHITELIST = {"units", "unit-files"}
_UNIT_TYPE_WHITELIST = {
    "service", "timer", "socket", "target", "mount", "path",
    "slice", "scope", "device", "automount", "swap",
}
_STATE_RE = re.compile(r"^[a-z][a-z-]*$")


def _decode_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def validate_kind(kind: str) -> str:
    """systemctl list kind: 'units' or 'unit-files'."""
    if not isinstance(kind, str) or kind not in _KIND_WHITELIST:
        raise ValueError(f"kind must be one of {sorted(_KIND_WHITELIST)}")
    return kind


def validate_unit_type_list(value: str) -> str:
    """Comma-separated systemd unit types, each in the whitelist."""
    if not isinstance(value, str) or not value:
        raise ValueError("unit_type must be a non-empty string")
    _reject_unsafe(value, "unit_type")
    if value.startswith("-"):
        raise ValueError("unit_type must not start with '-'")
    parts = value.split(",")
    for p in parts:
        if not p:
            raise ValueError("unit_type contains empty element")
        if p not in _UNIT_TYPE_WHITELIST:
            raise ValueError(f"unit_type element not allowed: {p!r}")
    return value


def validate_state_list(value: str) -> str:
    """Comma-separated state names matching ^[a-z][a-z-]*$."""
    if not isinstance(value, str) or not value:
        raise ValueError("state must be a non-empty string")
    _reject_unsafe(value, "state")
    if value.startswith("-"):
        raise ValueError("state must not start with '-'")
    parts = value.split(",")
    for p in parts:
        if not p:
            raise ValueError("state contains empty element")
        if not _STATE_RE.match(p):
            raise ValueError(f"state element not allowed: {p!r}")
    return value


def validate_pattern(value: str) -> str:
    """Positional glob pattern; only NUL/newline rejected."""
    if not isinstance(value, str) or not value:
        raise ValueError("pattern must be a non-empty string")
    _reject_unsafe(value, "pattern")
    return value


def build_remote_cmd_systemctl_status(unit: str, lines: int) -> str:
    """Build remote command for systemctl status."""
    qunit = shlex.quote(unit)
    return f"LC_ALL=C systemctl status --no-pager --lines={lines} -- {qunit}"


def build_remote_cmd_systemctl_list(
    kind: str,
    unit_types: str | None,
    states: str | None,
    all_flag: bool,
    pattern: str | None,
) -> str:
    """Build remote command for systemctl list-units / list-unit-files."""
    parts = [
        "LC_ALL=C",
        "systemctl",
        f"list-{kind}",
        "--no-pager",
        "--no-legend",
        "--plain",
    ]
    if unit_types:
        parts += ["-t", shlex.quote(unit_types)]
    if states:
        parts += [f"--state={shlex.quote(states)}"]
    if all_flag:
        parts += ["--all"]
    if pattern:
        parts += ["--", shlex.quote(pattern)]
    return " ".join(parts)


def handle_systemctl_status(args: dict) -> dict:
    """Run `systemctl status` on a remote host."""
    host = validate_host(args["host"])
    unit = validate_unit_name(args["unit"])
    lines = args.get("lines")
    if lines is None:
        lines = 10
    lines = validate_lines_int(lines, lo=0, hi=10000, label="lines")
    cmd = build_remote_cmd_systemctl_status(unit, lines)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


def handle_systemctl_list(args: dict) -> dict:
    """Run `systemctl list-units` / `list-unit-files` on a remote host."""
    host = validate_host(args["host"])
    kind = args.get("kind")
    if kind is None:
        kind = "units"
    kind = validate_kind(kind)
    unit_type = args.get("unit_type")
    if unit_type is not None:
        unit_type = validate_unit_type_list(unit_type)
    state = args.get("state")
    if state is not None:
        state = validate_state_list(state)
    all_in = args.get("all")
    if all_in is not None and not isinstance(all_in, bool):
        raise ValueError("all must be a boolean")
    all_flag = bool(all_in)
    pattern = args.get("pattern")
    if pattern is not None:
        pattern = validate_pattern(pattern)
    cmd = build_remote_cmd_systemctl_list(kind, unit_type, state, all_flag, pattern)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


SYSTEMCTL_STATUS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "unit": {"type": "string"},
        "lines": {"type": ["integer", "null"]},
    },
    "required": ["host", "unit"],
}

SYSTEMCTL_LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "kind": {"type": ["string", "null"], "enum": ["units", "unit-files", None]},
        "unit_type": {"type": ["string", "null"]},
        "state": {"type": ["string", "null"]},
        "all": {"type": ["boolean", "null"]},
        "pattern": {"type": ["string", "null"]},
    },
    "required": ["host"],
}


TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="systemctl_status",
        description=(
            "Run `systemctl status` for a unit on a remote host via SSH. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=SYSTEMCTL_STATUS_SCHEMA,
        handler=handle_systemctl_status,
    ),
    ToolSpec(
        name="systemctl_list",
        description=(
            "List systemd units or unit-files on a remote host via SSH. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=SYSTEMCTL_LIST_SCHEMA,
        handler=handle_systemctl_list,
    ),
]
